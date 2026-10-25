#include "crawler_storage.hpp"
#include "hash_registry.hpp"
#include "logger.hpp"
#include "platform.hpp"
#include "simple_network.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include <libtorrent/add_torrent_params.hpp>
#include <libtorrent/address.hpp>
#include <libtorrent/alert_types.hpp>
#include <libtorrent/bdecode.hpp>
#include <libtorrent/session.hpp>
#include <libtorrent/session_params.hpp>
#include <libtorrent/settings_pack.hpp>
#include <libtorrent/sha1_hash.hpp>
#include <libtorrent/torrent_info.hpp>
#include <libtorrent/torrent_status.hpp>
#include <libtorrent/version.hpp>
#include <libtorrent/write_resume_data.hpp>

#if LIBTORRENT_VERSION_NUM < 20009
#error "libtorrent-rasterbar 2.0.9 or newer is required"
#endif

namespace fs = std::filesystem;
namespace lt = libtorrent;

namespace
{

using Clock = std::chrono::steady_clock;
using InfoHash = HashRegistry::InfoHash;

constexpr int kMinListeners = 1;
constexpr int kMaxListeners = 64;
constexpr int kMaxPort = 65535;
constexpr std::size_t kMaxBindAddresses = 16;
constexpr std::size_t kMaxActiveLimit = 100000;
constexpr std::size_t kMaxDedupCacheSize = 100000000;
constexpr auto kMaxDuration = std::chrono::hours(24 * 365);
constexpr auto kMaxStagger = std::chrono::milliseconds(10000);
constexpr auto kMaxIdleWait = std::chrono::milliseconds(250);
constexpr auto kStatsInterval = std::chrono::seconds(60);
constexpr auto kReconcileInterval = std::chrono::seconds(30);
constexpr auto kAlertDropLogInterval = std::chrono::seconds(60);
constexpr auto kCompletedCacheLifetime = std::chrono::minutes(10);
constexpr std::size_t kTrackerRpcWorkers = 8;
constexpr std::size_t kTrackerRpcQueueSize = 128;
constexpr std::size_t kTrackerRpcRequestSize = 256;
constexpr std::size_t kMaxTrackerPeers = 512;
// libtorrent's default (2000) overflows within seconds under dht_pkt_alert
// bursts; metadata_received_alert has the same (normal) priority.
constexpr int kAlertQueueSize = 10000;
// The limits libtorrent itself applies to incoming DHT messages.
constexpr int kDhtPacketDepthLimit = 10;
constexpr int kDhtPacketTokenLimit = 500;

struct Config
{
    // Every session listens on all of these addresses (same port), so
    // {"0.0.0.0", "::"} runs an IPv4 and an IPv6 DHT node in each session.
    std::vector<std::string> bind_addresses = {"0.0.0.0"};
    int listeners = 1;
    int first_port = 6881;
    std::size_t max_active = 200;
    // 0 means listeners * max_active.
    std::size_t max_active_total = 0;
    std::chrono::seconds metadata_timeout{30};
    std::chrono::seconds retry_delay{60};
    std::size_t dedup_cache_size = 262144;
    fs::path database_path = "dht_crawler.db";
    fs::path temp_dir = "tmp";
    fs::path torrent_dir = "torrents";
    fs::path dht_state_dir = "dht_state";
    bool reinitialize_dht = false;
    std::chrono::seconds dht_save_interval{900};
    std::chrono::milliseconds bootstrap_stagger{200};
    std::string tracker_rpc_bind = "127.0.0.1";
    int tracker_rpc_port = 19091;
    std::chrono::seconds tracker_lookup_timeout{8};
    bool tracker_rpc_enabled = true;
    std::string bootstrap_nodes =
        "dht.libtorrent.org:25401,"
        "router.utorrent.com:6881,"
        "dht.transmissionbt.com:6881,"
        "router.bittorrent.com:6881";
};

template <typename Integer>
bool parse_integer(std::string_view text, Integer &value)
{
    if (text.empty())
        return false;

    Integer parsed{};
    const char *begin = text.data();
    const char *end = begin + text.size();
    const auto result = std::from_chars(begin, end, parsed);
    if (result.ec != std::errc{} || result.ptr != end)
        return false;

    value = parsed;
    return true;
}

// Rejects values whose deadline arithmetic would overflow steady_clock.
bool parse_positive_seconds(std::string_view text, std::chrono::seconds &value)
{
    long long seconds = 0;
    if (!parse_integer(text, seconds)
        || seconds <= 0
        || seconds > std::chrono::duration_cast<std::chrono::seconds>(kMaxDuration).count())
    {
        return false;
    }
    value = std::chrono::seconds(seconds);
    return true;
}

// Appends the entries of a comma-separated bind list ("0.0.0.0,::"); IPv6
// entries may be bracketed ("[::]"). False on an empty entry.
bool append_bind_addresses(std::string_view text, std::vector<std::string> &addresses)
{
    std::size_t offset = 0;
    while (true)
    {
        const std::size_t comma = text.find(',', offset);
        std::string_view item = text.substr(
            offset,
            comma == std::string_view::npos ? std::string_view::npos : comma - offset);
        while (!item.empty() && item.front() == ' ')
            item.remove_prefix(1);
        while (!item.empty() && item.back() == ' ')
            item.remove_suffix(1);
        if (item.size() >= 2 && item.front() == '[' && item.back() == ']')
            item = item.substr(1, item.size() - 2);
        if (item.empty())
            return false;
        addresses.emplace_back(item);

        if (comma == std::string_view::npos)
            return true;
        offset = comma + 1;
    }
}

void print_usage(const std::string &program)
{
    logging::error()
        << "用法:\n"
        << "  " << program << " [bind_addr] [listeners]\n"
        << "  " << program << " [选项]\n\n"
        << "选项:\n"
        << "  --bind ADDRESS[,ADDRESS]   绑定地址，默认 0.0.0.0；可用逗号分隔或重复指定，\n"
        << "                             例如 0.0.0.0,:: 同时监听 IPv4 和 IPv6\n"
        << "  --listeners N              监听端口数量，范围 1-64\n"
        << "  --first-port PORT          起始端口，默认 6881\n"
        << "  --max-active N             每个会话最大并发元数据任务数，默认 200\n"
        << "  --max-active-total N       全进程最大并发元数据任务数，默认 listeners*max-active\n"
        << "  --metadata-timeout SEC     元数据获取超时，默认 30 秒\n"
        << "  --retry-delay SEC          失败重试间隔，默认 60 秒\n"
        << "  --dedup-cache-size N       去重缓存最大条目数，默认 262144\n"
        << "  --database PATH            SQLite 数据库路径\n"
        << "  --temp-dir PATH            libtorrent 临时目录\n"
        << "  --torrent-dir PATH         torrent 文件目录\n"
        << "  --dht-state-dir PATH       DHT 状态目录，默认 dht_state\n"
        << "  --dht-save-interval SEC    定期保存 DHT 状态的间隔，默认 900 秒\n"
        << "  --bootstrap-stagger-ms MS  相邻会话启动间隔，默认 200 毫秒\n"
        << "  --reinitialize-dht         忽略已有状态并重新初始化 DHT\n"
        << "  --tracker-rpc-bind ADDRESS tracker RPC 地址，默认 127.0.0.1\n"
        << "  --tracker-rpc-port PORT    tracker RPC 端口，默认 19091\n"
        << "  --tracker-timeout SEC      DHT 查询超时，默认 8 秒\n"
        << "  --disable-tracker-rpc      禁用 tracker RPC 服务\n"
        << "  --bootstrap-nodes NODES    DHT bootstrap 节点列表\n"
        << "  --help                     显示帮助";
}

std::optional<Config> parse_arguments(const std::vector<std::string> &arguments)
{
    Config config;
    bool bind_given = false;

    if (arguments.size() > 1 && (arguments[1].empty() || arguments[1][0] != '-'))
    {
        if (arguments.size() > 3)
            return std::nullopt;
        config.bind_addresses.clear();
        if (!append_bind_addresses(arguments[1], config.bind_addresses))
            return std::nullopt;
        if (arguments.size() == 3 && !parse_integer(std::string_view(arguments[2]), config.listeners))
            return std::nullopt;
    }
    else
    {
        for (std::size_t i = 1; i < arguments.size(); ++i)
        {
            const std::string_view option(arguments[i]);
            if (option == "--reinitialize-dht")
            {
                config.reinitialize_dht = true;
                continue;
            }
            if (option == "--disable-tracker-rpc")
            {
                config.tracker_rpc_enabled = false;
                continue;
            }

            if (i + 1 >= arguments.size())
                return std::nullopt;

            const std::string_view value(arguments[++i]);
            if (option == "--bind")
            {
                // The first --bind replaces the default; repeats add to it.
                if (!bind_given)
                    config.bind_addresses.clear();
                bind_given = true;
                if (!append_bind_addresses(value, config.bind_addresses))
                    return std::nullopt;
            }
            else if (option == "--listeners")
            {
                if (!parse_integer(value, config.listeners))
                    return std::nullopt;
            }
            else if (option == "--first-port")
            {
                if (!parse_integer(value, config.first_port))
                    return std::nullopt;
            }
            else if (option == "--max-active")
            {
                if (!parse_integer(value, config.max_active))
                    return std::nullopt;
            }
            else if (option == "--max-active-total")
            {
                if (!parse_integer(value, config.max_active_total))
                    return std::nullopt;
            }
            else if (option == "--metadata-timeout")
            {
                if (!parse_positive_seconds(value, config.metadata_timeout))
                    return std::nullopt;
            }
            else if (option == "--retry-delay")
            {
                if (!parse_positive_seconds(value, config.retry_delay))
                    return std::nullopt;
            }
            else if (option == "--dedup-cache-size")
            {
                if (!parse_integer(value, config.dedup_cache_size))
                    return std::nullopt;
            }
            else if (option == "--database")
                config.database_path = platform::path_from_utf8(value);
            else if (option == "--temp-dir")
                config.temp_dir = platform::path_from_utf8(value);
            else if (option == "--torrent-dir")
                config.torrent_dir = platform::path_from_utf8(value);
            else if (option == "--dht-state-dir")
                config.dht_state_dir = platform::path_from_utf8(value);
            else if (option == "--dht-save-interval")
            {
                if (!parse_positive_seconds(value, config.dht_save_interval))
                    return std::nullopt;
            }
            else if (option == "--bootstrap-stagger-ms")
            {
                long long milliseconds = -1;
                if (!parse_integer(value, milliseconds)
                    || milliseconds < 0
                    || milliseconds > kMaxStagger.count())
                {
                    return std::nullopt;
                }
                config.bootstrap_stagger = std::chrono::milliseconds(milliseconds);
            }
            else if (option == "--tracker-rpc-bind")
                config.tracker_rpc_bind = value;
            else if (option == "--tracker-rpc-port")
            {
                if (!parse_integer(value, config.tracker_rpc_port))
                    return std::nullopt;
            }
            else if (option == "--tracker-timeout")
            {
                if (!parse_positive_seconds(value, config.tracker_lookup_timeout))
                    return std::nullopt;
            }
            else if (option == "--bootstrap-nodes")
                config.bootstrap_nodes = value;
            else
                return std::nullopt;
        }
    }

    if (config.bind_addresses.empty()
        || config.bind_addresses.size() > kMaxBindAddresses
        || config.listeners < kMinListeners
        || config.listeners > kMaxListeners
        || config.first_port <= 0
        || config.first_port > kMaxPort
        || config.listeners - 1 > kMaxPort - config.first_port
        || config.max_active == 0
        || config.max_active > kMaxActiveLimit
        || config.max_active_total > kMaxActiveLimit * kMaxListeners
        || config.dedup_cache_size == 0
        || config.dedup_cache_size > kMaxDedupCacheSize
        || config.database_path.empty()
        || config.temp_dir.empty()
        || config.torrent_dir.empty()
        || config.dht_state_dir.empty()
        || config.tracker_rpc_bind.empty()
        || config.tracker_rpc_port <= 0
        || config.tracker_rpc_port > kMaxPort
        || config.tracker_lookup_timeout > std::chrono::seconds(300)
        || config.bootstrap_nodes.empty())
    {
        return std::nullopt;
    }

    lt::error_code error;
    std::vector<lt::address> parsed_addresses;
    for (const std::string &address : config.bind_addresses)
    {
        const lt::address parsed = lt::make_address(address, error);
        if (error)
        {
            logging::error() << "无效绑定地址: " << address
                             << " (" << error.message() << ")";
            return std::nullopt;
        }
        if (std::find(parsed_addresses.begin(), parsed_addresses.end(), parsed)
            != parsed_addresses.end())
        {
            logging::error() << "重复的绑定地址: " << address;
            return std::nullopt;
        }
        parsed_addresses.push_back(parsed);
    }

    lt::make_address(config.tracker_rpc_bind, error);
    if (error)
    {
        logging::error() << "无效 tracker RPC 绑定地址: "
                         << config.tracker_rpc_bind
                         << " (" << error.message() << ")";
        return std::nullopt;
    }

    return config;
}

InfoHash to_key(const lt::sha1_hash &hash)
{
    InfoHash key{};
    std::memcpy(key.data(), hash.data(), key.size());
    return key;
}

lt::sha1_hash from_key(const InfoHash &key)
{
    return lt::sha1_hash(reinterpret_cast<const char *>(key.data()));
}

int hex_value(char character)
{
    if (character >= '0' && character <= '9')
        return character - '0';
    if (character >= 'a' && character <= 'f')
        return character - 'a' + 10;
    if (character >= 'A' && character <= 'F')
        return character - 'A' + 10;
    return -1;
}

std::optional<lt::sha1_hash> hash_from_hex(std::string_view text)
{
    if (text.size() != static_cast<std::size_t>(lt::sha1_hash::size() * 2))
        return std::nullopt;

    lt::sha1_hash hash;
    for (int i = 0; i < lt::sha1_hash::size(); ++i)
    {
        const int high = hex_value(text[static_cast<std::size_t>(i * 2)]);
        const int low = hex_value(text[static_cast<std::size_t>(i * 2 + 1)]);
        if (high < 0 || low < 0)
            return std::nullopt;
        hash[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return hash;
}

// Same text on every platform (asio defers to the OS formatter, whose IPv6
// output and scope-id suffixes differ between Windows and glibc).
std::string format_address(const lt::address &address)
{
    if (address.is_v4())
    {
        const auto bytes = address.to_v4().to_bytes();
        std::array<std::uint8_t, 4> octets{};
        std::copy(bytes.begin(), bytes.end(), octets.begin());
        return simple_net::format_ipv4(octets);
    }
    const auto bytes = address.to_v6().to_bytes();
    std::array<std::uint8_t, 16> octets{};
    std::copy(bytes.begin(), bytes.end(), octets.begin());
    return simple_net::format_ipv6(octets);
}

std::string format_endpoint(const lt::tcp::endpoint &endpoint)
{
    const std::string address = format_address(endpoint.address());
    if (endpoint.address().is_v6())
        return "[" + address + "]:" + std::to_string(endpoint.port());
    return address + ":" + std::to_string(endpoint.port());
}

// libtorrent listen_interfaces for one session: every bind address on the
// session's port. libtorrent opens IPv6 sockets as IPv6-only, so "0.0.0.0"
// and "::" can share a port, and it runs one DHT node per listen socket.
std::string build_listen_interface(const Config &config, int session_id)
{
    const std::string port = std::to_string(config.first_port + session_id);
    std::string interfaces;
    for (const std::string &address : config.bind_addresses)
    {
        if (!interfaces.empty())
            interfaces += ',';
        // Validated addresses: only IPv6 ones contain ':'.
        if (address.find(':') != std::string::npos)
            interfaces += '[' + address + ']';
        else
            interfaces += address;
        interfaces += ':' + port;
    }
    return interfaces;
}

std::string build_listen_interfaces(const Config &config)
{
    std::string interfaces;
    for (int i = 0; i < config.listeners; ++i)
    {
        if (!interfaces.empty())
            interfaces += ',';
        interfaces += build_listen_interface(config, i);
    }
    return interfaces;
}

struct KeyHasher
{
    std::size_t operator()(const InfoHash &key) const noexcept
    {
        std::size_t value = 0;
        std::memcpy(&value, key.data(), sizeof(value));
        return value;
    }
};

template <typename Key>
struct DeadlineEntry
{
    Clock::time_point deadline;
    Key key;
};

template <typename Key>
struct LaterDeadlineFirst
{
    bool operator()(const DeadlineEntry<Key> &left, const DeadlineEntry<Key> &right) const
    {
        return left.deadline > right.deadline;
    }
};

template <typename Key>
using DeadlineQueue = std::priority_queue<
    DeadlineEntry<Key>,
    std::vector<DeadlineEntry<Key>>,
    LaterDeadlineFirst<Key>>;

struct LookupOutcome
{
    InfoHash hash;
    storage::LookupResult result;
};

// Wakes a session thread when libtorrent has alerts or the database reader
// has answered one of its lookups. Owned by CrawlerApp for the whole run so
// storage callbacks never race session construction.
struct Mailbox
{
    std::mutex mutex;
    std::condition_variable condition;
    bool alerts_ready = false;
    std::vector<LookupOutcome> outcomes;
};

struct PendingAdd
{
    lt::tcp::endpoint peer;
    Clock::time_point deadline;
};

struct ActiveTask
{
    InfoHash key;
    std::string hash_hex;
    lt::tcp::endpoint peer;
    Clock::time_point deadline;
};

class CrawlerApp
{
public:
    explicit CrawlerApp(Config config)
        : config_(prepare_config(std::move(config))),
          temp_dir_utf8_(platform::path_to_utf8(config_.temp_dir)),
          registry_(config_.dedup_cache_size),
          max_total_(
              config_.max_active_total != 0
                  ? config_.max_active_total
                  : config_.max_active * static_cast<std::size_t>(config_.listeners))
    {
        mailboxes_.reserve(static_cast<std::size_t>(config_.listeners));
        for (int id = 0; id < config_.listeners; ++id)
            mailboxes_.push_back(std::make_unique<Mailbox>());

        storage::Options options;
        options.database_path = config_.database_path;
        options.torrent_dir = config_.torrent_dir;
        storage_ = std::make_unique<storage::Storage>(
            options,
            [this](int tag, const InfoHash &hash, storage::LookupResult result) {
                on_lookup_result(tag, hash, result);
            },
            [this](const storage::PersistJob &job, bool persisted) {
                on_persisted(job, persisted);
            });
    }

    ~CrawlerApp()
    {
        try
        {
            shutdown();
        }
        catch (...)
        {
        }
    }

    CrawlerApp(const CrawlerApp &) = delete;
    CrawlerApp &operator=(const CrawlerApp &) = delete;

    int run()
    {
        logging::info() << "DHT 爬虫已启动，监听 " << build_listen_interfaces(config_)
                        << "，最大活动任务 " << config_.max_active
                        << "（全进程 " << max_total_ << "）";

        start_sessions();
        if (!platform::shutdown_requested())
            start_tracker_rpc();

        auto next_save = Clock::now() + config_.dht_save_interval;
        auto next_stats = Clock::now() + kStatsInterval;
        while (!platform::wait_for_shutdown(std::chrono::seconds(1)))
        {
            const auto now = Clock::now();
            if (now >= next_save)
            {
                save_dht_states();
                next_save = now + config_.dht_save_interval;
            }
            if (now >= next_stats)
            {
                log_global_stats();
                next_stats = now + kStatsInterval;
            }
        }

        logging::info() << "收到退出信号 (" << platform::shutdown_reason()
                        << ")，正在停止会话...";
        return shutdown();
    }

private:
    using TaskMap = std::unordered_map<lt::torrent_handle, ActiveTask>;

    enum class LookupStatus
    {
        ok,
        timeout,
        error
    };

    struct LookupReply
    {
        LookupStatus status = LookupStatus::error;
        std::vector<lt::tcp::endpoint> peers;
        std::string error;
    };

    struct PendingLookup
    {
        std::mutex mutex;
        std::condition_variable condition;
        bool completed = false;
        std::vector<lt::tcp::endpoint> peers;
        std::string error;
        std::size_t waiters = 0;
    };

    struct SessionContext
    {
        SessionContext(int session_id, Mailbox &session_mailbox, lt::session session_instance)
            : id(session_id),
              mailbox(session_mailbox),
              session(std::move(session_instance))
        {
        }

        std::size_t slots_used() const
        {
            return checking.size() + adding.size() + active_tasks.size();
        }

        int id = 0;
        Mailbox &mailbox;
        lt::session session;
        // Reused for every DHT packet to avoid a token allocation per packet.
        lt::bdecode_node packet;
        // Hashes waiting for the database lookup, keyed to the announcing peer.
        std::unordered_map<InfoHash, lt::tcp::endpoint, KeyHasher> checking;
        // async_add_torrent issued, add_torrent_alert not yet seen.
        std::unordered_map<InfoHash, PendingAdd, KeyHasher> adding;
        TaskMap active_tasks;
        DeadlineQueue<InfoHash> add_deadlines;
        DeadlineQueue<lt::torrent_handle> task_deadlines;
        bool reconcile_requested = false;
        Clock::time_point last_drop_log{};
        std::uint64_t requests = 0;
        std::uint64_t responses = 0;
        std::uint64_t dropped_busy = 0;
        std::uint64_t alert_drops = 0;
        std::uint64_t orphans_removed = 0;
        std::uint64_t metadata_recovered = 0;
    };

    static Config prepare_config(Config config)
    {
        auto create_directory = [](const fs::path &path, const char *label) {
            std::error_code error;
            fs::create_directories(path, error);
            if (error)
            {
                throw std::runtime_error(
                    std::string("创建") + label + "失败: "
                    + platform::path_to_utf8(path) + ": " + error.message());
            }
        };

        create_directory(config.temp_dir, "临时目录");
        create_directory(config.torrent_dir, " torrent 目录");
        create_directory(config.dht_state_dir, " DHT 状态目录");
        if (config.database_path.has_parent_path())
            create_directory(config.database_path.parent_path(), "数据库目录");

        const std::size_t stale =
            platform::remove_stale_temp_files(config.torrent_dir)
            + platform::remove_stale_temp_files(config.dht_state_dir);
        if (stale > 0)
            logging::info() << "已清理 " << stale << " 个残留临时文件";
        return config;
    }

    static fs::path dht_state_path(const Config &config, int session_id)
    {
        const int port = config.first_port + session_id;
        return config.dht_state_dir
            / ("session-" + std::to_string(session_id)
                + "-port-" + std::to_string(port) + ".state");
    }

    static std::vector<char> read_binary_file(const fs::path &path)
    {
        std::ifstream input(path, std::ios::binary | std::ios::ate);
        if (!input)
            throw std::runtime_error("无法打开 DHT 状态文件 " + platform::path_to_utf8(path));

        const std::streampos end = input.tellg();
        if (end <= 0)
            throw std::runtime_error("DHT 状态文件为空 " + platform::path_to_utf8(path));

        std::vector<char> buffer(static_cast<std::size_t>(end));
        input.seekg(0, std::ios::beg);
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        if (!input)
            throw std::runtime_error("读取 DHT 状态文件失败 " + platform::path_to_utf8(path));
        return buffer;
    }

    static lt::session create_session(
        const Config &config,
        int session_id,
        std::vector<lt::sha1_hash> &known_node_ids)
    {
        lt::settings_pack settings;
        settings.set_int(
            lt::settings_pack::alert_mask,
            lt::alert_category::dht_log
                | lt::alert_category::status
                | lt::alert_category::error
                | lt::alert_category::dht_operation);
        settings.set_int(lt::settings_pack::alert_queue_size, kAlertQueueSize);
        settings.set_bool(lt::settings_pack::enable_dht, true);
        settings.set_bool(lt::settings_pack::enable_lsd, false);
        settings.set_str(
            lt::settings_pack::dht_bootstrap_nodes,
            config.bootstrap_nodes);
        settings.set_str(
            lt::settings_pack::listen_interfaces,
            build_listen_interface(config, session_id));

        lt::session_params parameters(std::move(settings));
        const fs::path state_path = dht_state_path(config, session_id);
        const std::string state_name = platform::path_to_utf8(state_path);
        if (config.reinitialize_dht)
        {
            std::error_code error;
            const bool removed = fs::remove(state_path, error);
            if (error)
            {
                throw std::runtime_error(
                    "删除旧 DHT 状态失败 " + state_name + ": " + error.message());
            }

            logging::info() << "[Session " << session_id << "][DHT] "
                            << (removed ? "已删除旧状态并重新初始化"
                                        : "没有旧状态，正在重新初始化");
        }
        else
        {
            std::error_code error;
            const bool state_exists = fs::exists(state_path, error);
            if (error)
            {
                throw std::runtime_error(
                    "检查 DHT 状态文件失败 " + state_name + ": " + error.message());
            }

            if (state_exists)
            {
                try
                {
                    std::vector<char> buffer = read_binary_file(state_path);
                    lt::session_params restored = lt::read_session_params(
                        buffer,
                        lt::session_handle::save_dht_state);
                    if (restored.dht_state.nids.empty())
                    {
                        throw std::runtime_error(
                            "状态中没有可恢复的 DHT 节点 ID");
                    }

                    // A state file copied between sessions would make two
                    // sessions share a node ID and cover the same keyspace.
                    const bool duplicate = std::any_of(
                        restored.dht_state.nids.begin(),
                        restored.dht_state.nids.end(),
                        [&](const auto &item) {
                            return std::find(known_node_ids.begin(), known_node_ids.end(), item.second)
                                != known_node_ids.end();
                        });
                    if (duplicate)
                    {
                        logging::error() << "[Session " << session_id
                                         << "][DHT] 状态中的节点 ID 与其他会话重复，将生成新 ID";
                        restored.dht_state.nids.clear();
                    }
                    for (const auto &item : restored.dht_state.nids)
                        known_node_ids.push_back(item.second);

                    const std::size_t node_ids = restored.dht_state.nids.size();
                    const std::size_t nodes =
                        restored.dht_state.nodes.size()
                        + restored.dht_state.nodes6.size();
                    parameters.dht_state = std::move(restored.dht_state);
                    logging::info() << "[Session " << session_id
                                    << "][DHT] 已加载状态 " << state_name
                                    << "，节点 ID " << node_ids
                                    << "，引导节点 " << nodes;
                }
                catch (const std::exception &error)
                {
                    throw std::runtime_error(
                        "加载 DHT 状态失败 " + state_name
                        + ": " + error.what()
                        + "；如需丢弃旧状态，请使用 --reinitialize-dht");
                }
            }
        }

        return lt::session(std::move(parameters));
    }

    void start_sessions()
    {
        std::vector<lt::sha1_hash> known_node_ids;
        sessions_.reserve(static_cast<std::size_t>(config_.listeners));
        session_threads_.reserve(static_cast<std::size_t>(config_.listeners));
        for (int id = 0; id < config_.listeners; ++id)
        {
            // Staggered start: N sessions bootstrapping in the same instant
            // from one IP hit the same few routers with a burst they may
            // rate-limit.
            if (id > 0
                && config_.bootstrap_stagger.count() > 0
                && platform::wait_for_shutdown(config_.bootstrap_stagger))
            {
                break;
            }

            Mailbox *mailbox = mailboxes_[static_cast<std::size_t>(id)].get();
            sessions_.push_back(std::make_unique<SessionContext>(
                id, *mailbox, create_session(config_, id, known_node_ids)));
            SessionContext *context = sessions_.back().get();
            // Runs on libtorrent's network thread: only flag and notify.
            context->session.set_alert_notify([mailbox] {
                {
                    std::lock_guard<std::mutex> lock(mailbox->mutex);
                    mailbox->alerts_ready = true;
                }
                mailbox->condition.notify_one();
            });
            session_threads_.emplace_back(&CrawlerApp::run_session, this, context);
        }
    }

    int shutdown()
    {
        if (shut_down_)
            return exit_code_;
        shut_down_ = true;

        cancel_pending_lookups("DHT 爬虫正在退出");
        tracker_rpc_server_.stop();

        stopping_.store(true);
        for (const auto &mailbox : mailboxes_)
        {
            {
                std::lock_guard<std::mutex> lock(mailbox->mutex);
            }
            mailbox->condition.notify_all();
        }
        for (std::thread &thread : session_threads_)
        {
            if (thread.joinable())
                thread.join();
        }

        // Flush fetched metadata first: it is the data that cannot be
        // recovered, and Windows gives a closing console only seconds.
        storage_->stop();
        const storage::Stats stats = storage_->stats();
        logging::info() << "[DB] 已写入 " << stats.persisted
                        << " 条，失败 " << stats.persist_failures;

        const bool state_saved = save_dht_states();

        logging::info() << "正在清理任务...";
        for (auto &context : sessions_)
        {
            for (const auto &item : context->active_tasks)
                remove_torrent(*context, item.first);
            context->active_tasks.clear();
            context->adding.clear();
            context->checking.clear();
        }

        // abort() starts every session's shutdown at once; destroying the
        // proxies then waits for all of them in parallel instead of one
        // blocking session destructor after another.
        std::vector<lt::session_proxy> proxies;
        proxies.reserve(sessions_.size());
        for (auto &context : sessions_)
        {
            context->session.set_alert_notify({});
            proxies.push_back(context->session.abort());
        }
        proxies.clear();

        exit_code_ = state_saved ? 0 : 1;
        return exit_code_;
    }

    bool save_dht_states()
    {
        bool all_saved = true;
        for (const auto &context : sessions_)
        {
            const fs::path state_path = dht_state_path(config_, context->id);
            try
            {
                lt::session_params parameters = context->session.session_state(
                    lt::session_handle::save_dht_state);
                if (parameters.dht_state.nids.empty())
                {
                    throw std::runtime_error(
                        "当前会话没有可保存的 DHT 节点 ID");
                }

                const std::size_t node_ids = parameters.dht_state.nids.size();
                const std::size_t nodes =
                    parameters.dht_state.nodes.size()
                    + parameters.dht_state.nodes6.size();
                const std::vector<char> buffer = lt::write_session_params_buf(
                    parameters,
                    lt::session_handle::save_dht_state);
                platform::write_file_atomic(
                    state_path,
                    std::string_view(buffer.data(), buffer.size()),
                    true);

                logging::info() << "[Session " << context->id
                                << "][DHT] 已保存状态 " << platform::path_to_utf8(state_path)
                                << "，节点 ID " << node_ids
                                << "，引导节点 " << nodes;
            }
            catch (const std::exception &error)
            {
                all_saved = false;
                logging::error() << "[Session " << context->id
                                 << "][DHT] 保存状态失败: " << error.what();
            }
        }
        return all_saved;
    }

    void log_global_stats()
    {
        const HashRegistry::Stats registry = registry_.stats();
        const storage::Stats database = storage_->stats();
        logging::info() << "[Stats] InFlight: " << registry.in_flight
                        << " Cached: " << registry.settled
                        << " Evicted: " << registry.evicted
                        << " Slots: " << global_used_.load() << '/' << max_total_
                        << " DBQueue: " << database.queued_jobs
                        << " Lookups: " << database.queued_lookups
                        << " Saved: " << database.persisted
                        << " WAL: " << database.wal_bytes
                        << " LogDropped: " << logging::dropped();
    }

    void start_tracker_rpc()
    {
        if (!config_.tracker_rpc_enabled)
        {
            logging::info() << "[Tracker RPC] 已禁用";
            return;
        }

        try
        {
            simple_net::ServerOptions options;
            options.bind_address = config_.tracker_rpc_bind;
            options.port = static_cast<std::uint16_t>(config_.tracker_rpc_port);
            options.worker_count = kTrackerRpcWorkers;
            options.max_pending = kTrackerRpcQueueSize;
            options.delimiter = "\n";
            options.max_request_size = kTrackerRpcRequestSize;
            options.request_timeout = rpc_io_budget();
            tracker_rpc_server_.start(std::move(options), [this](simple_net::Connection &connection) {
                handle_tracker_rpc(connection);
            });
            logging::info() << "[Tracker RPC] 监听 "
                            << config_.tracker_rpc_bind << ':'
                            << config_.tracker_rpc_port;
        }
        catch (const std::exception &error)
        {
            logging::error() << "[Tracker RPC] 启动失败，DHT 爬虫继续运行: "
                             << error.what();
        }
    }

    std::chrono::milliseconds rpc_io_budget() const
    {
        return config_.tracker_lookup_timeout + std::chrono::seconds(2);
    }

    void handle_tracker_rpc(simple_net::Connection &connection)
    {
        std::string request = connection.request;
        request.resize(request.find('\n'));
        if (!request.empty() && request.back() == '\r')
            request.pop_back();

        std::istringstream parser(request);
        std::string protocol;
        std::string command;
        std::string hash_text;
        std::string extra;
        parser >> protocol >> command >> hash_text;
        parser >> extra;
        const std::optional<lt::sha1_hash> hash = hash_from_hex(hash_text);
        std::string network_error;
        if (protocol != "DHTP/1"
            || command != "GET_PEERS"
            || !hash
            || !extra.empty())
        {
            simple_net::write_all(
                connection.socket.get(),
                "DHTP/1 ERROR invalid-request\nEND\n",
                simple_net::Clock::now() + rpc_io_budget(),
                network_error,
                &tracker_rpc_server_.stopping());
            return;
        }

        logging::info() << "[Tracker RPC] " << connection.remote
                        << " 查询 " << hash_text;
        const LookupReply reply = lookup_dht_peers(*hash);

        std::ostringstream response;
        if (reply.status == LookupStatus::ok)
        {
            response << "DHTP/1 OK " << reply.peers.size() << '\n';
            for (const lt::tcp::endpoint &peer : reply.peers)
            {
                response << "PEER "
                         << (peer.address().is_v6() ? 6 : 4) << ' '
                         << format_address(peer.address()) << ' '
                         << peer.port() << '\n';
            }
        }
        else if (reply.status == LookupStatus::timeout)
        {
            response << "DHTP/1 TIMEOUT\n";
        }
        else
        {
            response << "DHTP/1 ERROR lookup-failed\n";
        }
        response << "END\n";

        simple_net::write_all(
            connection.socket.get(),
            response.str(),
            simple_net::Clock::now() + rpc_io_budget(),
            network_error,
            &tracker_rpc_server_.stopping());
    }

    LookupReply lookup_dht_peers(const lt::sha1_hash &hash)
    {
        std::shared_ptr<PendingLookup> pending;
        bool start_lookup = false;
        std::size_t session_index = 0;
        {
            // Checked under the same lock cancel_pending_lookups() takes, so
            // no lookup can register after shutdown cancelled the rest.
            std::lock_guard<std::mutex> lock(lookup_mutex_);
            if (lookup_stopping_ || sessions_.empty())
                return {LookupStatus::error, {}, "DHT 查询服务不可用"};

            auto iterator = pending_lookups_.find(hash);
            if (iterator != pending_lookups_.end())
            {
                pending = iterator->second;
            }
            else
            {
                pending = std::make_shared<PendingLookup>();
                pending_lookups_.emplace(hash, pending);
                session_index =
                    next_lookup_session_.fetch_add(1) % sessions_.size();
                start_lookup = true;
            }
            ++pending->waiters;
        }

        if (start_lookup)
        {
            try
            {
                sessions_[session_index]->session.dht_get_peers(hash);
            }
            catch (const std::exception &error)
            {
                complete_lookup(hash, {}, error.what());
            }
        }

        std::unique_lock<std::mutex> result_lock(pending->mutex);
        const bool completed = pending->condition.wait_for(
            result_lock,
            config_.tracker_lookup_timeout,
            [&pending] { return pending->completed; });
        if (completed)
        {
            if (!pending->error.empty())
                return {LookupStatus::error, {}, pending->error};
            return {LookupStatus::ok, pending->peers, {}};
        }
        result_lock.unlock();

        {
            std::lock_guard<std::mutex> lock(lookup_mutex_);
            auto iterator = pending_lookups_.find(hash);
            if (iterator != pending_lookups_.end()
                && iterator->second == pending)
            {
                if (pending->waiters > 0)
                    --pending->waiters;
                if (pending->waiters == 0)
                    pending_lookups_.erase(iterator);
            }
        }

        result_lock.lock();
        if (pending->completed)
        {
            if (!pending->error.empty())
                return {LookupStatus::error, {}, pending->error};
            return {LookupStatus::ok, pending->peers, {}};
        }
        return {LookupStatus::timeout, {}, "DHT 查询超时"};
    }

    void complete_lookup(
        const lt::sha1_hash &hash,
        std::vector<lt::tcp::endpoint> peers,
        std::string error = {})
    {
        std::shared_ptr<PendingLookup> pending;
        {
            std::lock_guard<std::mutex> lock(lookup_mutex_);
            auto iterator = pending_lookups_.find(hash);
            if (iterator == pending_lookups_.end())
                return;
            pending = std::move(iterator->second);
            pending_lookups_.erase(iterator);
        }

        std::sort(peers.begin(), peers.end());
        peers.erase(std::unique(peers.begin(), peers.end()), peers.end());
        if (peers.size() > kMaxTrackerPeers)
            peers.resize(kMaxTrackerPeers);
        {
            std::lock_guard<std::mutex> lock(pending->mutex);
            pending->peers = std::move(peers);
            pending->error = std::move(error);
            pending->completed = true;
        }
        pending->condition.notify_all();
    }

    void cancel_pending_lookups(const std::string &reason)
    {
        std::vector<std::shared_ptr<PendingLookup>> pending;
        {
            std::lock_guard<std::mutex> lock(lookup_mutex_);
            lookup_stopping_ = true;
            pending.reserve(pending_lookups_.size());
            for (auto &item : pending_lookups_)
                pending.push_back(std::move(item.second));
            pending_lookups_.clear();
        }

        for (const auto &lookup : pending)
        {
            {
                std::lock_guard<std::mutex> lock(lookup->mutex);
                lookup->error = reason;
                lookup->completed = true;
            }
            lookup->condition.notify_all();
        }
    }

    // Called on the storage reader thread.
    void on_lookup_result(int tag, const InfoHash &hash, storage::LookupResult result)
    {
        if (tag < 0 || static_cast<std::size_t>(tag) >= mailboxes_.size())
            return;
        Mailbox &mailbox = *mailboxes_[static_cast<std::size_t>(tag)];
        {
            std::lock_guard<std::mutex> lock(mailbox.mutex);
            mailbox.outcomes.push_back(LookupOutcome{hash, result});
        }
        mailbox.condition.notify_one();
    }

    // Called on the storage writer thread.
    void on_persisted(const storage::PersistJob &job, bool persisted)
    {
        const auto now = Clock::now();
        if (persisted)
        {
            registry_.settle_completed(job.hash, now + kCompletedCacheLifetime);
            logging::info() << "[Session " << job.origin
                            << "][DB] 已保存 " << job.hash_hex;
        }
        else
        {
            registry_.settle_failed(job.hash, now + config_.retry_delay);
            logging::error() << "[Session " << job.origin
                             << "][DB] 保存失败: " << job.hash_hex;
        }
    }

    bool reserve_global_slot()
    {
        std::size_t current = global_used_.load();
        do
        {
            if (current >= max_total_)
                return false;
        } while (!global_used_.compare_exchange_weak(current, current + 1));
        return true;
    }

    void release_global_slot()
    {
        global_used_.fetch_sub(1);
    }

    void run_session(SessionContext *context)
    {
        try
        {
            session_loop(*context);
        }
        catch (const std::exception &error)
        {
            logging::error() << "[Session " << context->id
                             << "] 会话线程异常退出: " << error.what();
        }
        catch (...)
        {
            logging::error() << "[Session " << context->id
                             << "] 会话线程异常退出: 未知异常";
        }
    }

    Clock::time_point next_wake(
        const SessionContext &context,
        Clock::time_point next_stats,
        Clock::time_point next_reconcile) const
    {
        Clock::time_point wake = std::min(
            {Clock::now() + kMaxIdleWait, next_stats, next_reconcile});
        if (!context.add_deadlines.empty())
            wake = std::min(wake, context.add_deadlines.top().deadline);
        if (!context.task_deadlines.empty())
            wake = std::min(wake, context.task_deadlines.top().deadline);
        return wake;
    }

    void wait_for_work(
        SessionContext &context,
        std::vector<LookupOutcome> &outcomes,
        Clock::time_point wake)
    {
        Mailbox &mailbox = context.mailbox;
        std::unique_lock<std::mutex> lock(mailbox.mutex);
        mailbox.condition.wait_until(lock, wake, [&] {
            return mailbox.alerts_ready || !mailbox.outcomes.empty() || stopping_.load();
        });
        // Cleared before pop_alerts(): an alert posted after the pop raises
        // the flag again, so no wake-up is lost.
        mailbox.alerts_ready = false;
        outcomes.swap(mailbox.outcomes);
    }

    void session_loop(SessionContext &context)
    {
        std::vector<lt::alert *> alerts;
        std::vector<LookupOutcome> outcomes;
        auto next_stats = Clock::now() + kStatsInterval;
        auto next_reconcile = Clock::now() + kReconcileInterval;
        while (!stopping_.load())
        {
            wait_for_work(context, outcomes, next_wake(context, next_stats, next_reconcile));
            if (stopping_.load())
                break;

            try
            {
                context.session.pop_alerts(&alerts);
                for (lt::alert *alert : alerts)
                {
                    try
                    {
                        handle_alert(context, alert);
                    }
                    catch (const std::exception &error)
                    {
                        logging::error() << "[Session " << context.id
                                         << "][Alert] 处理失败: " << error.what();
                    }
                    catch (...)
                    {
                        logging::error() << "[Session " << context.id
                                         << "][Alert] 处理失败: 未知异常";
                    }
                }
                alerts.clear();

                const auto now = Clock::now();
                for (const LookupOutcome &outcome : outcomes)
                    handle_lookup_outcome(context, outcome, now);
                outcomes.clear();

                expire_tasks(context, now);
                if (context.reconcile_requested || now >= next_reconcile)
                {
                    context.reconcile_requested = false;
                    next_reconcile = now + kReconcileInterval;
                    reconcile(context);
                }
                if (now >= next_stats)
                {
                    context.session.post_dht_stats();
                    next_stats = now + kStatsInterval;
                }
            }
            catch (const std::exception &error)
            {
                logging::error() << "[Session " << context.id
                                 << "] 事件循环错误: " << error.what();
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    }

    void handle_alert(SessionContext &context, lt::alert *alert)
    {
        if (auto *packet = lt::alert_cast<lt::dht_pkt_alert>(alert))
            handle_dht_packet(context, *packet);
        else if (auto *added = lt::alert_cast<lt::add_torrent_alert>(alert))
            on_torrent_added(context, *added);
        else if (auto *metadata = lt::alert_cast<lt::metadata_received_alert>(alert))
        {
            const auto iterator = context.active_tasks.find(metadata->handle);
            if (iterator != context.active_tasks.end())
                persist_task(context, iterator);
        }
        else if (auto *metadata_failed = lt::alert_cast<lt::metadata_failed_alert>(alert))
            fail_task(context, metadata_failed->handle, metadata_failed->error.message());
        else if (auto *torrent_error = lt::alert_cast<lt::torrent_error_alert>(alert))
            fail_task(context, torrent_error->handle, torrent_error->error.message());
        else if (auto *reply = lt::alert_cast<lt::dht_get_peers_reply_alert>(alert))
            complete_lookup(reply->info_hash, reply->peers());
        else if (auto *stats = lt::alert_cast<lt::dht_stats_alert>(alert))
            context.session.dht_live_nodes(stats->nid);
        else if (auto *nodes = lt::alert_cast<lt::dht_live_nodes_alert>(alert))
        {
            logging::info() << "[Session " << context.id
                            << "][Stats] Nodes: " << nodes->num_nodes()
                            << " Req: " << context.requests
                            << " Resp: " << context.responses
                            << " Checking: " << context.checking.size()
                            << " Active: " << context.active_tasks.size() + context.adding.size()
                            << " Persisting: " << storage_->stats().queued_jobs
                            << " Busy: " << context.dropped_busy
                            << " AlertDrops: " << context.alert_drops
                            << " Orphans: " << context.orphans_removed;
        }
        else if (auto *dropped = lt::alert_cast<lt::alerts_dropped_alert>(alert))
            on_alerts_dropped(context, *dropped);
        else if (lt::alert_cast<lt::listen_failed_alert>(alert)
            || lt::alert_cast<lt::session_error_alert>(alert))
        {
            logging::error() << "[Session " << context.id
                             << "][libtorrent] " << alert->message();
        }
    }

    void on_alerts_dropped(SessionContext &context, const lt::alerts_dropped_alert &alert)
    {
        ++context.alert_drops;
        const auto &types = alert.dropped_alerts;
        // A lost state-change alert would strand its task until the TTL;
        // reconcile() recovers it from the session's real torrent list.
        if (types.test(lt::add_torrent_alert::alert_type)
            || types.test(lt::metadata_received_alert::alert_type)
            || types.test(lt::metadata_failed_alert::alert_type)
            || types.test(lt::torrent_error_alert::alert_type))
        {
            context.reconcile_requested = true;
        }

        const auto now = Clock::now();
        if (now - context.last_drop_log >= kAlertDropLogInterval)
        {
            context.last_drop_log = now;
            logging::error() << "[Session " << context.id
                             << "][libtorrent] alert 队列溢出，部分 alert 已被丢弃 (累计 "
                             << context.alert_drops << " 次)";
        }
    }

    void handle_dht_packet(SessionContext &context, const lt::dht_pkt_alert &packet)
    {
        if (packet.direction != lt::dht_pkt_alert::incoming)
            return;

        const lt::span<char const> buffer = packet.pkt_buf();
        lt::error_code error;
        if (lt::bdecode(
                buffer.data(),
                buffer.data() + buffer.size(),
                context.packet,
                error,
                nullptr,
                kDhtPacketDepthLimit,
                kDhtPacketTokenLimit)
                != 0
            || context.packet.type() != lt::bdecode_node::dict_t)
        {
            return;
        }
        const lt::bdecode_node &message = context.packet;

        if (message.dict_find_string_value("y") != "q")
        {
            ++context.responses;
            return;
        }

        ++context.requests;
        if (message.dict_find_string_value("q") != "announce_peer")
            return;

        const lt::bdecode_node arguments = message.dict_find("a");
        if (arguments.type() != lt::bdecode_node::dict_t)
            return;

        const lt::bdecode_node hash_node = arguments.dict_find("info_hash");
        if (hash_node.type() != lt::bdecode_node::string_t)
            return;

        const auto hash_value = hash_node.string_value();
        if (hash_value.size() != lt::sha1_hash::size())
            return;

        const lt::sha1_hash hash(hash_value);
        if (hash.is_all_zeros())
            return;

        // BEP 5: a non-zero implied_port means "use the UDP source port".
        const long long implied_port =
            arguments.dict_find_int_value("implied_port", 0);
        long long port = packet.node.port();
        if (implied_port == 0)
            port = arguments.dict_find_int_value("port", 0);
        if (port <= 0 || port > kMaxPort)
            return;

        submit_announce(
            context,
            hash,
            lt::tcp::endpoint(
                packet.node.address(),
                static_cast<std::uint16_t>(port)));
    }

    void submit_announce(
        SessionContext &context,
        const lt::sha1_hash &hash,
        const lt::tcp::endpoint &peer)
    {
        if (stopping_.load())
            return;
        // Capacity first: a saturated crawler drops the announce without
        // penalising the hash, so the next announce (in any session) can
        // still pick it up.
        if (context.slots_used() >= config_.max_active || storage_->under_pressure())
        {
            ++context.dropped_busy;
            return;
        }

        const InfoHash key = to_key(hash);
        if (registry_.try_claim(key, Clock::now()) != HashRegistry::Claim::claimed)
            return;
        if (!reserve_global_slot())
        {
            registry_.release(key);
            ++context.dropped_busy;
            return;
        }

        try
        {
            const auto entry = context.checking.emplace(key, peer).first;
            if (!storage_->submit_lookup(context.id, key))
            {
                context.checking.erase(entry);
                registry_.release(key);
                release_global_slot();
                ++context.dropped_busy;
            }
        }
        catch (...)
        {
            context.checking.erase(key);
            registry_.release(key);
            release_global_slot();
            throw;
        }
    }

    void handle_lookup_outcome(
        SessionContext &context,
        const LookupOutcome &outcome,
        Clock::time_point now)
    {
        const auto iterator = context.checking.find(outcome.hash);
        if (iterator == context.checking.end())
            return;
        const lt::tcp::endpoint peer = iterator->second;
        context.checking.erase(iterator);

        if (outcome.result == storage::LookupResult::present)
        {
            registry_.settle_completed(outcome.hash, now + kCompletedCacheLifetime);
            release_global_slot();
            return;
        }
        if (outcome.result == storage::LookupResult::error || stopping_.load())
        {
            if (outcome.result == storage::LookupResult::error)
                registry_.settle_failed(outcome.hash, now + config_.retry_delay);
            else
                registry_.release(outcome.hash);
            release_global_slot();
            return;
        }

        try
        {
            start_fetch(context, outcome.hash, peer, now);
        }
        catch (const std::exception &error)
        {
            logging::error() << "[Session " << context.id
                             << "][Fetcher] 启动 " << storage::to_hex(outcome.hash)
                             << " 失败: " << error.what();
            registry_.settle_failed(outcome.hash, now + config_.retry_delay);
            release_global_slot();
        }
    }

    void start_fetch(
        SessionContext &context,
        const InfoHash &key,
        const lt::tcp::endpoint &peer,
        Clock::time_point now)
    {
        const Clock::time_point deadline = now + config_.metadata_timeout;
        context.adding.emplace(key, PendingAdd{peer, deadline});
        try
        {
            context.add_deadlines.push(DeadlineEntry<InfoHash>{deadline, key});

            lt::add_torrent_params parameters;
            parameters.info_hashes.v1 = from_key(key);
            parameters.save_path = temp_dir_utf8_;
            parameters.flags |= lt::torrent_flags::upload_mode;
            // The defaults include auto_managed|paused, which queues the
            // torrent behind active_downloads (3 per session): almost every
            // task would time out waiting instead of fetching metadata.
            parameters.flags &= ~(lt::torrent_flags::auto_managed | lt::torrent_flags::paused);
            context.session.async_add_torrent(std::move(parameters));
        }
        catch (...)
        {
            context.adding.erase(key);
            throw;
        }
    }

    void on_torrent_added(SessionContext &context, const lt::add_torrent_alert &alert)
    {
        const InfoHash key = to_key(alert.params.info_hashes.v1);
        const auto iterator = context.adding.find(key);
        if (iterator == context.adding.end())
        {
            // Already timed out (or shutting down): never keep the torrent.
            if (!alert.error && alert.handle.is_valid())
                remove_torrent(context, alert.handle);
            return;
        }

        const PendingAdd pending = iterator->second;
        context.adding.erase(iterator);
        if (alert.error || !alert.handle.is_valid())
        {
            logging::error() << "[Session " << context.id
                             << "][Fetcher] 启动 " << storage::to_hex(key)
                             << " 失败: " << alert.error.message();
            registry_.settle_failed(key, Clock::now() + config_.retry_delay);
            release_global_slot();
            return;
        }

        const auto [task, inserted] = context.active_tasks.emplace(
            alert.handle,
            ActiveTask{key, storage::to_hex(key), pending.peer, pending.deadline});
        if (!inserted)
        {
            // libtorrent returned a torrent that is already a task: this
            // slot belongs to nobody.
            registry_.settle_failed(key, Clock::now() + config_.retry_delay);
            release_global_slot();
            return;
        }
        context.task_deadlines.push(DeadlineEntry<lt::torrent_handle>{pending.deadline, alert.handle});
        alert.handle.connect_peer(task->second.peer);
    }

    void persist_task(SessionContext &context, TaskMap::iterator iterator)
    {
        const ActiveTask task = iterator->second;
        const lt::torrent_handle handle = iterator->first;
        bool handed_off = false;
        try
        {
            const std::shared_ptr<const lt::torrent_info> torrent_info = handle.torrent_file();
            if (!torrent_info)
                throw std::runtime_error("metadata alert 未提供 torrent_info");

            // write_torrent_file() only reads `ti`: it copies the verified
            // info dictionary verbatim and, with allow_missing_piece_layer,
            // never rebuilds v2 piece layers (the create_torrent path that
            // crashed libtorrent 2.0.5 in set_hash2()).
            lt::add_torrent_params parameters;
            parameters.ti = std::const_pointer_cast<lt::torrent_info>(torrent_info);

            storage::PersistJob job;
            job.hash = task.key;
            job.origin = context.id;
            job.hash_hex = task.hash_hex;
            job.name = torrent_info->name();
            job.peer = format_endpoint(task.peer);
            job.torrent_file = lt::write_torrent_file_buf(
                parameters,
                lt::write_flags::allow_missing_piece_layer);
            if (!storage_->submit_persist(job))
                throw std::runtime_error("写入队列已满");
            handed_off = true;
            logging::info() << "[Session " << context.id
                            << "][Fetcher] 已获取 " << task.hash_hex << " 的元数据";
        }
        catch (const std::exception &error)
        {
            logging::error() << "[Session " << context.id
                             << "][Fetcher] 保存 " << task.hash_hex
                             << " 失败: " << error.what();
        }

        // On hand-off the claim stays in flight until the writer settles it.
        if (!handed_off)
            registry_.settle_failed(task.key, Clock::now() + config_.retry_delay);
        remove_task(context, iterator);
    }

    void expire_tasks(SessionContext &context, Clock::time_point now)
    {
        while (!context.add_deadlines.empty() && context.add_deadlines.top().deadline <= now)
        {
            const DeadlineEntry<InfoHash> entry = context.add_deadlines.top();
            context.add_deadlines.pop();
            const auto iterator = context.adding.find(entry.key);
            if (iterator == context.adding.end() || iterator->second.deadline != entry.deadline)
                continue;

            logging::error() << "[Session " << context.id
                             << "][Fetcher] 超时: " << storage::to_hex(entry.key);
            context.adding.erase(iterator);
            registry_.settle_failed(entry.key, now + config_.retry_delay);
            release_global_slot();
        }

        while (!context.task_deadlines.empty() && context.task_deadlines.top().deadline <= now)
        {
            const DeadlineEntry<lt::torrent_handle> entry = context.task_deadlines.top();
            context.task_deadlines.pop();
            const auto iterator = context.active_tasks.find(entry.key);
            if (iterator == context.active_tasks.end() || iterator->second.deadline != entry.deadline)
                continue;

            logging::error() << "[Session " << context.id
                             << "][Fetcher] 超时: " << iterator->second.hash_hex;
            registry_.settle_failed(iterator->second.key, now + config_.retry_delay);
            remove_task(context, iterator);
        }
    }

    // Compares the session's real torrent list with the task table: torrents
    // nobody tracks (their add alert was dropped or arrived after the
    // timeout) are removed, and tasks whose metadata alert was dropped are
    // persisted. Together with the deadlines this guarantees no torrent
    // outlives metadata_timeout + kReconcileInterval.
    void reconcile(SessionContext &context)
    {
        const std::vector<lt::torrent_status> statuses = context.session.get_torrent_status(
            [](const lt::torrent_status &) { return true; });
        for (const lt::torrent_status &status : statuses)
        {
            const auto task = context.active_tasks.find(status.handle);
            if (task != context.active_tasks.end())
            {
                if (status.has_metadata)
                {
                    ++context.metadata_recovered;
                    persist_task(context, task);
                }
                continue;
            }
            if (context.adding.count(to_key(status.info_hashes.v1)) != 0)
                continue;

            ++context.orphans_removed;
            remove_torrent(context, status.handle);
        }
    }

    void fail_task(SessionContext &context, const lt::torrent_handle &handle, const std::string &reason)
    {
        const auto iterator = context.active_tasks.find(handle);
        if (iterator == context.active_tasks.end())
            return;

        logging::error() << "[Session " << context.id
                         << "][Fetcher] " << iterator->second.hash_hex
                         << " 失败: " << reason;
        registry_.settle_failed(iterator->second.key, Clock::now() + config_.retry_delay);
        remove_task(context, iterator);
    }

    void remove_torrent(SessionContext &context, const lt::torrent_handle &handle)
    {
        if (!handle.is_valid())
            return;
        try
        {
            context.session.remove_torrent(handle, lt::session::delete_files);
        }
        catch (const std::exception &error)
        {
            logging::error() << "[Session " << context.id
                             << "][Fetcher] 清理 torrent 失败: " << error.what();
        }
    }

    TaskMap::iterator remove_task(SessionContext &context, TaskMap::iterator iterator)
    {
        const lt::torrent_handle handle = iterator->first;
        auto next = context.active_tasks.erase(iterator);
        release_global_slot();
        remove_torrent(context, handle);
        return next;
    }

    Config config_;
    std::string temp_dir_utf8_;
    HashRegistry registry_;
    std::size_t max_total_;
    std::atomic<std::size_t> global_used_{0};
    std::atomic<bool> stopping_{false};
    std::vector<std::unique_ptr<Mailbox>> mailboxes_;
    // Declared after the registry and mailboxes its callbacks use, so it is
    // destroyed (and its threads joined) before them.
    std::unique_ptr<storage::Storage> storage_;
    std::vector<std::unique_ptr<SessionContext>> sessions_;
    std::vector<std::thread> session_threads_;
    simple_net::TcpServer tracker_rpc_server_;
    std::mutex lookup_mutex_;
    bool lookup_stopping_ = false;
    std::unordered_map<lt::sha1_hash, std::shared_ptr<PendingLookup>> pending_lookups_;
    std::atomic<std::size_t> next_lookup_session_{0};
    bool shut_down_ = false;
    int exit_code_ = 0;
};

} // namespace

int main(int argc, char *argv[])
{
    platform::ShutdownCompletionGuard shutdown_complete;
    const std::vector<std::string> arguments = platform::utf8_arguments(argc, argv);
    const std::string program = arguments.empty() ? "dht_db" : arguments.front();
    try
    {
        for (std::size_t i = 1; i < arguments.size(); ++i)
        {
            if (arguments[i] == "--help")
            {
                print_usage(program);
                return 0;
            }
        }

        std::optional<Config> config = parse_arguments(arguments);
        if (!config)
        {
            print_usage(program);
            return 1;
        }

        platform::install_shutdown_handlers();
        platform::raise_open_file_limit();
        logging::start();
        int result = 0;
        {
            CrawlerApp app(std::move(*config));
            result = app.run();
        }
        logging::stop();
        return result;
    }
    catch (const std::exception &error)
    {
        logging::error() << "致命错误: " << error.what();
        logging::stop();
        return 1;
    }
    catch (...)
    {
        logging::error() << "致命错误: 未知异常";
        logging::stop();
        return 1;
    }
}
