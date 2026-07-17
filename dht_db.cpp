#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
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
#include <libtorrent/create_torrent.hpp>
#include <libtorrent/entry.hpp>
#include <libtorrent/hex.hpp>
#include <libtorrent/session.hpp>
#include <libtorrent/settings_pack.hpp>
#include <libtorrent/sha1_hash.hpp>
#include <libtorrent/torrent_info.hpp>
#include <sqlite3.h>

namespace fs = std::filesystem;
namespace lt = libtorrent;

namespace
{

constexpr int kMinListeners = 1;
constexpr int kMaxListeners = 64;
constexpr int kMaxPort = 65535;
constexpr std::size_t kDatabaseBatchSize = 64;
constexpr auto kDatabaseBatchDelay = std::chrono::milliseconds(100);
constexpr auto kAlertWait = std::chrono::milliseconds(250);
constexpr auto kStatsInterval = std::chrono::seconds(60);
constexpr auto kCompletedCacheLifetime = std::chrono::minutes(10);

volatile std::sig_atomic_t g_stop_requested = 0;

void handle_signal(int)
{
    g_stop_requested = 1;
}

struct Config
{
    std::string bind_address = "0.0.0.0";
    int listeners = 1;
    int first_port = 6881;
    std::size_t max_active = 200;
    std::chrono::seconds metadata_timeout{30};
    std::chrono::seconds retry_delay{60};
    fs::path database_path = "dht_crawler.db";
    fs::path temp_dir = "tmp";
    fs::path torrent_dir = "torrents";
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

bool parse_positive_seconds(std::string_view text, std::chrono::seconds &value)
{
    long long seconds = 0;
    if (!parse_integer(text, seconds) || seconds <= 0)
        return false;
    value = std::chrono::seconds(seconds);
    return true;
}

void print_usage(const char *program)
{
    std::cerr
        << "用法:\n"
        << "  " << program << " [bind_addr] [listeners]\n"
        << "  " << program << " [选项]\n\n"
        << "选项:\n"
        << "  --bind ADDRESS             绑定地址，默认 0.0.0.0\n"
        << "  --listeners N              监听端口数量，范围 1-64\n"
        << "  --first-port PORT          起始端口，默认 6881\n"
        << "  --max-active N             最大并发元数据任务数，默认 200\n"
        << "  --metadata-timeout SEC     元数据获取超时，默认 30 秒\n"
        << "  --retry-delay SEC          失败重试间隔，默认 60 秒\n"
        << "  --database PATH            SQLite 数据库路径\n"
        << "  --temp-dir PATH            libtorrent 临时目录\n"
        << "  --torrent-dir PATH         torrent 文件目录\n"
        << "  --bootstrap-nodes NODES    DHT bootstrap 节点列表\n"
        << "  --help                     显示帮助\n";
}

std::optional<Config> parse_arguments(int argc, char *argv[])
{
    Config config;

    if (argc > 1 && argv[1][0] != '-')
    {
        if (argc > 3)
            return std::nullopt;
        config.bind_address = argv[1];
        if (argc == 3 && !parse_integer(std::string_view(argv[2]), config.listeners))
            return std::nullopt;
    }
    else
    {
        for (int i = 1; i < argc; ++i)
        {
            const std::string_view option(argv[i]);
            if (i + 1 >= argc)
                return std::nullopt;

            const std::string_view value(argv[++i]);
            if (option == "--bind")
                config.bind_address = value;
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
            else if (option == "--database")
                config.database_path = value;
            else if (option == "--temp-dir")
                config.temp_dir = value;
            else if (option == "--torrent-dir")
                config.torrent_dir = value;
            else if (option == "--bootstrap-nodes")
                config.bootstrap_nodes = value;
            else
                return std::nullopt;
        }
    }

    if (config.bind_address.empty()
        || config.listeners < kMinListeners
        || config.listeners > kMaxListeners
        || config.first_port <= 0
        || config.first_port > kMaxPort
        || config.listeners - 1 > kMaxPort - config.first_port
        || config.max_active == 0
        || config.database_path.empty()
        || config.temp_dir.empty()
        || config.torrent_dir.empty()
        || config.bootstrap_nodes.empty())
    {
        return std::nullopt;
    }

    lt::error_code error;
    lt::make_address(config.bind_address, error);
    if (error)
    {
        std::cerr << "无效绑定地址: " << config.bind_address
                  << " (" << error.message() << ")\n";
        return std::nullopt;
    }

    return config;
}

std::string hash_to_hex(const lt::sha1_hash &hash)
{
    return lt::aux::to_hex(hash.to_string());
}

std::string format_endpoint(const lt::tcp::endpoint &endpoint)
{
    const std::string address = endpoint.address().to_string();
    if (endpoint.address().is_v6())
        return "[" + address + "]:" + std::to_string(endpoint.port());
    return address + ":" + std::to_string(endpoint.port());
}

std::string build_listen_interfaces(const Config &config)
{
    const bool ipv6 = config.bind_address.find(':') != std::string::npos;
    std::string interfaces;
    for (int i = 0; i < config.listeners; ++i)
    {
        if (!interfaces.empty())
            interfaces += ',';
        if (ipv6)
            interfaces += '[' + config.bind_address + ']';
        else
            interfaces += config.bind_address;
        interfaces += ':' + std::to_string(config.first_port + i);
    }
    return interfaces;
}

std::string build_listen_interface(const Config &config, int session_id)
{
    const bool ipv6 = config.bind_address.find(':') != std::string::npos;
    std::string interface;
    if (ipv6)
        interface += '[' + config.bind_address + ']';
    else
        interface += config.bind_address;
    interface += ':' + std::to_string(config.first_port + session_id);
    return interface;
}

class Statement
{
public:
    Statement() = default;

    Statement(sqlite3 *database, const char *sql)
    {
        const int result = sqlite3_prepare_v2(database, sql, -1, &statement_, nullptr);
        if (result != SQLITE_OK)
            throw std::runtime_error(sqlite3_errmsg(database));
    }

    ~Statement()
    {
        if (statement_)
            sqlite3_finalize(statement_);
    }

    Statement(const Statement &) = delete;
    Statement &operator=(const Statement &) = delete;

    Statement(Statement &&other) noexcept
        : statement_(std::exchange(other.statement_, nullptr))
    {
    }

    Statement &operator=(Statement &&other) noexcept
    {
        if (this == &other)
            return *this;
        if (statement_)
            sqlite3_finalize(statement_);
        statement_ = std::exchange(other.statement_, nullptr);
        return *this;
    }

    sqlite3_stmt *get() const
    {
        return statement_;
    }

    void reset()
    {
        sqlite3_reset(statement_);
        sqlite3_clear_bindings(statement_);
    }

private:
    sqlite3_stmt *statement_ = nullptr;
};

class DatabaseConnection
{
public:
    explicit DatabaseConnection(const fs::path &path)
    {
        const std::string filename = path.string();
        const int result = sqlite3_open_v2(
            filename.c_str(),
            &database_,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
            nullptr);
        if (result != SQLITE_OK)
        {
            const std::string message =
                database_ ? sqlite3_errmsg(database_) : "无法分配 SQLite handle";
            if (database_)
                sqlite3_close(database_);
            database_ = nullptr;
            throw std::runtime_error("数据库打开失败: " + message);
        }

        sqlite3_busy_timeout(database_, 5000);
    }

    ~DatabaseConnection()
    {
        if (database_)
            sqlite3_close(database_);
    }

    DatabaseConnection(const DatabaseConnection &) = delete;
    DatabaseConnection &operator=(const DatabaseConnection &) = delete;

    sqlite3 *get() const
    {
        return database_;
    }

    void execute(const char *sql)
    {
        char *error_message = nullptr;
        const int result = sqlite3_exec(database_, sql, nullptr, nullptr, &error_message);
        if (result == SQLITE_OK)
            return;

        const std::string message =
            error_message ? error_message : sqlite3_errmsg(database_);
        sqlite3_free(error_message);
        throw std::runtime_error(message);
    }

private:
    sqlite3 *database_ = nullptr;
};

struct TorrentRecord
{
    std::string hash;
    std::string name;
    std::string peer;
};

struct DatabaseRequest
{
    TorrentRecord record;
    std::promise<bool> result;
};

class DatabaseManager
{
public:
    explicit DatabaseManager(const fs::path &path)
        : path_(path),
          reader_(path)
    {
        reader_.execute("PRAGMA journal_mode=WAL;");
        reader_.execute(
            "CREATE TABLE IF NOT EXISTS torrents ("
            "info_hash TEXT PRIMARY KEY NOT NULL,"
            "name TEXT NOT NULL,"
            "discovered_peer TEXT NOT NULL,"
            "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP"
            ");");
        contains_statement_ = Statement(
            reader_.get(),
            "SELECT 1 FROM torrents WHERE info_hash = ? LIMIT 1;");
        writer_thread_ = std::thread(&DatabaseManager::writer_loop, this);
    }

    ~DatabaseManager()
    {
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            stopping_ = true;
        }
        queue_condition_.notify_all();
        if (writer_thread_.joinable())
            writer_thread_.join();
    }

    DatabaseManager(const DatabaseManager &) = delete;
    DatabaseManager &operator=(const DatabaseManager &) = delete;

    bool contains(const std::string &hash)
    {
        sqlite3_stmt *statement = contains_statement_.get();
        contains_statement_.reset();
        if (sqlite3_bind_text(statement, 1, hash.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK)
            throw std::runtime_error(sqlite3_errmsg(reader_.get()));

        const int result = sqlite3_step(statement);
        if (result == SQLITE_ROW)
            return true;
        if (result == SQLITE_DONE)
            return false;
        throw std::runtime_error(sqlite3_errmsg(reader_.get()));
    }

    std::future<bool> enqueue(TorrentRecord record)
    {
        DatabaseRequest request{std::move(record), {}};
        std::future<bool> result = request.result.get_future();
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            if (stopping_)
            {
                request.result.set_value(false);
                return result;
            }
            queue_.push_back(std::move(request));
        }
        queue_condition_.notify_one();
        return result;
    }

private:
    static bool execute_batch(
        DatabaseConnection &connection,
        Statement &insert_statement,
        std::vector<DatabaseRequest> &batch)
    {
        std::string last_error;
        for (int attempt = 0; attempt < 3; ++attempt)
        {
            bool success = true;
            try
            {
                connection.execute("BEGIN IMMEDIATE;");
                for (DatabaseRequest &request : batch)
                {
                    sqlite3_stmt *statement = insert_statement.get();
                    insert_statement.reset();
                    const TorrentRecord &record = request.record;

                    if (sqlite3_bind_text(statement, 1, record.hash.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK
                        || sqlite3_bind_text(statement, 2, record.name.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK
                        || sqlite3_bind_text(statement, 3, record.peer.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK
                        || sqlite3_step(statement) != SQLITE_DONE)
                    {
                        last_error = sqlite3_errmsg(connection.get());
                        success = false;
                        break;
                    }
                }

                if (success)
                {
                    connection.execute("COMMIT;");
                    return true;
                }
                connection.execute("ROLLBACK;");
            }
            catch (const std::exception &error)
            {
                last_error = error.what();
                try
                {
                    connection.execute("ROLLBACK;");
                }
                catch (const std::exception &)
                {
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50 * (attempt + 1)));
        }
        std::cerr << "[DB] 批量写入失败: "
                  << (last_error.empty() ? "未知 SQLite 错误" : last_error) << '\n';
        return false;
    }

    void writer_loop()
    {
        try
        {
            DatabaseConnection writer(path_);
            Statement insert_statement(
                writer.get(),
                "INSERT OR IGNORE INTO torrents "
                "(info_hash, name, discovered_peer) VALUES (?, ?, ?);");

            while (true)
            {
                std::vector<DatabaseRequest> batch;
                {
                    std::unique_lock<std::mutex> lock(queue_mutex_);
                    queue_condition_.wait(lock, [this] {
                        return stopping_ || !queue_.empty();
                    });
                    if (stopping_ && queue_.empty())
                        break;

                    queue_condition_.wait_for(lock, kDatabaseBatchDelay, [this] {
                        return stopping_ || queue_.size() >= kDatabaseBatchSize;
                    });

                    const std::size_t count =
                        std::min(queue_.size(), kDatabaseBatchSize);
                    batch.reserve(count);
                    for (std::size_t i = 0; i < count; ++i)
                    {
                        batch.push_back(std::move(queue_.front()));
                        queue_.pop_front();
                    }
                }

                const bool success = execute_batch(writer, insert_statement, batch);
                for (DatabaseRequest &request : batch)
                    request.result.set_value(success);
            }
        }
        catch (const std::exception &error)
        {
            std::cerr << "[DB] 写线程异常退出: " << error.what() << '\n';
            fail_pending_requests();
        }
    }

    void fail_pending_requests()
    {
        std::deque<DatabaseRequest> pending;
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            stopping_ = true;
            pending.swap(queue_);
        }
        for (DatabaseRequest &request : pending)
            request.result.set_value(false);
    }

    fs::path path_;
    DatabaseConnection reader_;
    Statement contains_statement_;
    std::mutex queue_mutex_;
    std::condition_variable queue_condition_;
    std::deque<DatabaseRequest> queue_;
    bool stopping_ = false;
    std::thread writer_thread_;
};

enum class HashStatus
{
    active,
    persisting,
    completed,
    failed
};

struct HashState
{
    HashStatus status = HashStatus::active;
    std::chrono::steady_clock::time_point retry_after{};
};

struct ActiveTask
{
    lt::sha1_hash hash;
    std::string hash_hex;
    lt::tcp::endpoint peer;
    std::chrono::steady_clock::time_point deadline;
};

struct PendingWrite
{
    lt::sha1_hash hash;
    std::string hash_hex;
    std::future<bool> result;
};

class CrawlerApp
{
public:
    explicit CrawlerApp(Config config)
        : config_(prepare_config(std::move(config))),
          database_(config_.database_path)
    {
        sessions_.reserve(static_cast<std::size_t>(config_.listeners));
        for (int id = 0; id < config_.listeners; ++id)
            sessions_.push_back(std::make_unique<SessionContext>(id, create_session(config_, id)));
        session_threads_.reserve(sessions_.size());
    }

    int run()
    {
        std::cout << "DHT 爬虫已启动，监听 " << build_listen_interfaces(config_)
                  << "，最大活动任务 " << config_.max_active << '\n';

        for (auto &context : sessions_)
            session_threads_.emplace_back(&CrawlerApp::run_session, this, context.get());

        while (!g_stop_requested)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        std::cout << "收到退出信号，正在清理任务...\n";
        for (std::thread &thread : session_threads_)
        {
            if (thread.joinable())
                thread.join();
        }

        for (auto &context : sessions_)
        {
            for (const auto &item : context->active_tasks)
                remove_torrent(*context, item.first);
            context->active_tasks.clear();
        }
        return 0;
    }

private:
    using TaskMap = std::unordered_map<lt::torrent_handle, ActiveTask>;

    struct SessionContext
    {
        SessionContext(int session_id, lt::session session_instance)
            : id(session_id),
              session(std::move(session_instance))
        {
        }

        int id = 0;
        lt::session session;
        std::unordered_map<lt::sha1_hash, HashState> hash_states;
        TaskMap active_tasks;
        std::vector<PendingWrite> pending_writes;
        std::uint64_t requests = 0;
        std::uint64_t responses = 0;
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
                    + path.string() + ": " + error.message());
            }
        };

        create_directory(config.temp_dir, "临时目录");
        create_directory(config.torrent_dir, " torrent 目录");
        if (config.database_path.has_parent_path())
            create_directory(config.database_path.parent_path(), "数据库目录");
        return config;
    }

    static lt::session create_session(const Config &config, int session_id)
    {
        lt::settings_pack settings;
        settings.set_int(
            lt::settings_pack::alert_mask,
            lt::alert_category::dht_log
                | lt::alert_category::status
                | lt::alert_category::error);
        settings.set_bool(lt::settings_pack::enable_dht, true);
        settings.set_bool(lt::settings_pack::enable_lsd, false);
        settings.set_str(
            lt::settings_pack::dht_bootstrap_nodes,
            config.bootstrap_nodes);
        settings.set_str(
            lt::settings_pack::listen_interfaces,
            build_listen_interface(config, session_id));
        return lt::session(settings);
    }

    void run_session(SessionContext *context)
    {
        auto next_stats = std::chrono::steady_clock::now() + kStatsInterval;
        while (!g_stop_requested)
        {
            context->session.wait_for_alert(kAlertWait);
            drain_session(*context);

            const auto now = std::chrono::steady_clock::now();
            expire_tasks(*context, now);
            poll_database_writes(*context, now);
            expire_hash_states(*context, now);

            if (now >= next_stats)
            {
                context->session.post_dht_stats();
                next_stats = now + kStatsInterval;
            }
        }
    }

    void drain_session(SessionContext &context)
    {
        std::vector<lt::alert *> alerts;
        context.session.pop_alerts(&alerts);
        for (lt::alert *alert : alerts)
        {
            try
            {
                handle_alert(context, alert);
            }
            catch (const std::exception &error)
            {
                std::cerr << "[Session " << context.id
                          << "][Alert] 处理失败: " << error.what() << '\n';
            }
            catch (...)
            {
                std::cerr << "[Session " << context.id
                          << "][Alert] 处理失败: 未知异常\n";
            }
        }
    }

    void handle_alert(SessionContext &context, lt::alert *alert)
    {
        if (auto *packet = lt::alert_cast<lt::dht_pkt_alert>(alert))
            handle_dht_packet(context, *packet);
        else if (auto *metadata = lt::alert_cast<lt::metadata_received_alert>(alert))
            handle_metadata(context, *metadata);
        else if (auto *torrent_error = lt::alert_cast<lt::torrent_error_alert>(alert))
            fail_task(context, torrent_error->handle, torrent_error->error.message());
        else if (auto *stats = lt::alert_cast<lt::dht_stats_alert>(alert))
            context.session.dht_live_nodes(stats->nid);
        else if (auto *nodes = lt::alert_cast<lt::dht_live_nodes_alert>(alert))
        {
            std::cout << "[Session " << context.id
                      << "][Stats] Nodes: " << nodes->num_nodes()
                      << " Req: " << context.requests
                      << " Resp: " << context.responses
                      << " Active: " << context.active_tasks.size()
                      << " Persisting: " << context.pending_writes.size() << '\n';
        }
        else if (lt::alert_cast<lt::listen_failed_alert>(alert)
            || lt::alert_cast<lt::session_error_alert>(alert))
        {
            std::cerr << "[Session " << context.id
                      << "][libtorrent] " << alert->message() << '\n';
        }
    }

    void handle_dht_packet(SessionContext &context, const lt::dht_pkt_alert &packet)
    {
        if (packet.direction != lt::dht_pkt_alert::incoming)
            return;

        lt::error_code error;
        const lt::bdecode_node message = lt::bdecode(packet.pkt_buf(), error);
        if (error || message.type() != lt::bdecode_node::dict_t)
            return;

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

        const long long implied_port =
            arguments.dict_find_int_value("implied_port", 0);
        long long port = packet.node.port();
        if (implied_port == 0)
            port = arguments.dict_find_int_value("port", 0);
        if (port <= 0 || port > kMaxPort)
            return;

        submit_task(
            context,
            hash,
            lt::tcp::endpoint(
                packet.node.address(),
                static_cast<std::uint16_t>(port)));
    }

    void submit_task(SessionContext &context, const lt::sha1_hash &hash, const lt::tcp::endpoint &peer)
    {
        const auto now = std::chrono::steady_clock::now();
        auto state = context.hash_states.find(hash);
        if (state != context.hash_states.end())
        {
            if (state->second.status != HashStatus::failed
                || now < state->second.retry_after)
            {
                return;
            }
        }

        if (context.active_tasks.size() >= config_.max_active)
        {
            context.hash_states[hash] = {HashStatus::failed, now + config_.retry_delay};
            return;
        }

        const std::string hash_hex = hash_to_hex(hash);
        try
        {
            if (database_.contains(hash_hex))
            {
                context.hash_states[hash] = {
                    HashStatus::completed,
                    now + kCompletedCacheLifetime};
                return;
            }

            lt::add_torrent_params parameters;
            parameters.info_hashes.v1 = hash;
            parameters.save_path = config_.temp_dir.string();
            parameters.flags |= lt::torrent_flags::upload_mode;

            lt::torrent_handle handle = context.session.add_torrent(std::move(parameters));
            if (!handle.is_valid())
            {
                mark_failed(context, hash, now);
                return;
            }

            handle.connect_peer(peer);
            context.active_tasks.emplace(
                handle,
                ActiveTask{
                    hash,
                    hash_hex,
                    peer,
                    now + config_.metadata_timeout});
            context.hash_states[hash] = {HashStatus::active, {}};
        }
        catch (const std::exception &error)
        {
            std::cerr << "[Session " << context.id
                      << "][Fetcher] 启动 " << hash_hex
                      << " 失败: " << error.what() << '\n';
            mark_failed(context, hash, now);
        }
    }

    void handle_metadata(SessionContext &context, const lt::metadata_received_alert &alert)
    {
        auto task_iterator = context.active_tasks.find(alert.handle);
        if (task_iterator == context.active_tasks.end())
            return;

        ActiveTask task = task_iterator->second;
        try
        {
            const std::shared_ptr<const lt::torrent_info> torrent_info =
                alert.handle.torrent_file();
            if (!torrent_info)
                throw std::runtime_error("metadata alert 未提供 torrent_info");

            const fs::path torrent_path =
                config_.torrent_dir / (task.hash_hex + ".torrent");
            write_torrent_file(*torrent_info, torrent_path);

            TorrentRecord record{
                task.hash_hex,
                torrent_info->name(),
                format_endpoint(task.peer)};
            context.pending_writes.push_back(PendingWrite{
                task.hash,
                task.hash_hex,
                database_.enqueue(std::move(record))});
            context.hash_states[task.hash] = {HashStatus::persisting, {}};
            std::cout << "[Session " << context.id
                      << "][Fetcher] 已获取 " << task.hash_hex << " 的元数据\n";
        }
        catch (const std::exception &error)
        {
            std::cerr << "[Session " << context.id
                      << "][Fetcher] 保存 " << task.hash_hex
                      << " 失败: " << error.what() << '\n';
            mark_failed(context, task.hash, std::chrono::steady_clock::now());
        }

        remove_task(context, task_iterator);
    }

    void write_torrent_file(
        const lt::torrent_info &torrent_info,
        const fs::path &target_path)
    {
        if (fs::exists(target_path))
            return;

        lt::create_torrent torrent(torrent_info);
        const lt::entry entry = torrent.generate();
        std::vector<char> buffer;
        lt::bencode(std::back_inserter(buffer), entry);

        fs::path temporary_path = target_path;
        temporary_path += ".tmp";

        {
            std::ofstream output(
                temporary_path,
                std::ios::binary | std::ios::trunc);
            if (!output)
                throw std::runtime_error(
                    "无法打开临时文件 " + temporary_path.string());
            output.write(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            output.close();
            if (!output)
            {
                std::error_code ignored;
                fs::remove(temporary_path, ignored);
                throw std::runtime_error(
                    "写入临时文件失败 " + temporary_path.string());
            }
        }

        std::error_code error;
        fs::rename(temporary_path, target_path, error);
        if (error)
        {
            fs::remove(temporary_path);
            throw std::runtime_error(
                "发布 torrent 文件失败: " + error.message());
        }
    }

    void expire_tasks(SessionContext &context, std::chrono::steady_clock::time_point now)
    {
        for (auto iterator = context.active_tasks.begin(); iterator != context.active_tasks.end();)
        {
            if (iterator->second.deadline > now)
            {
                ++iterator;
                continue;
            }

            std::cerr << "[Session " << context.id
                      << "][Fetcher] 超时: " << iterator->second.hash_hex << '\n';
            mark_failed(context, iterator->second.hash, now);
            iterator = remove_task(context, iterator);
        }
    }

    void poll_database_writes(SessionContext &context, std::chrono::steady_clock::time_point now)
    {
        for (auto iterator = context.pending_writes.begin(); iterator != context.pending_writes.end();)
        {
            if (iterator->result.wait_for(std::chrono::seconds(0))
                != std::future_status::ready)
            {
                ++iterator;
                continue;
            }

            if (iterator->result.get())
            {
                context.hash_states[iterator->hash] = {
                    HashStatus::completed,
                    now + kCompletedCacheLifetime};
                std::cout << "[Session " << context.id
                          << "][DB] 已保存 " << iterator->hash_hex << '\n';
            }
            else
            {
                std::cerr << "[Session " << context.id
                          << "][DB] 保存失败: " << iterator->hash_hex << '\n';
                mark_failed(context, iterator->hash, now);
            }
            iterator = context.pending_writes.erase(iterator);
        }
    }

    void expire_hash_states(SessionContext &context, std::chrono::steady_clock::time_point now)
    {
        for (auto iterator = context.hash_states.begin(); iterator != context.hash_states.end();)
        {
            if ((iterator->second.status == HashStatus::failed
                    || iterator->second.status == HashStatus::completed)
                && iterator->second.retry_after <= now)
            {
                iterator = context.hash_states.erase(iterator);
            }
            else
            {
                ++iterator;
            }
        }
    }

    void fail_task(SessionContext &context, const lt::torrent_handle &handle, const std::string &reason)
    {
        auto iterator = context.active_tasks.find(handle);
        if (iterator == context.active_tasks.end())
            return;

        std::cerr << "[Session " << context.id
                  << "][Fetcher] " << iterator->second.hash_hex
                  << " 失败: " << reason << '\n';
        mark_failed(context, iterator->second.hash, std::chrono::steady_clock::now());
        remove_task(context, iterator);
    }

    void mark_failed(
        SessionContext &context,
        const lt::sha1_hash &hash,
        std::chrono::steady_clock::time_point now)
    {
        context.hash_states[hash] = {HashStatus::failed, now + config_.retry_delay};
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
            std::cerr << "[Session " << context.id
                      << "][Fetcher] 清理 torrent 失败: " << error.what() << '\n';
        }
    }

    TaskMap::iterator remove_task(SessionContext &context, TaskMap::iterator iterator)
    {
        const lt::torrent_handle handle = iterator->first;
        auto next = context.active_tasks.erase(iterator);
        remove_torrent(context, handle);
        return next;
    }

    Config config_;
    DatabaseManager database_;
    std::vector<std::unique_ptr<SessionContext>> sessions_;
    std::vector<std::thread> session_threads_;
};

} // namespace

int main(int argc, char *argv[])
{
    try
    {
        for (int i = 1; i < argc; ++i)
        {
            if (std::string_view(argv[i]) == "--help")
            {
                print_usage(argv[0]);
                return 0;
            }
        }

        std::optional<Config> config = parse_arguments(argc, argv);
        if (!config)
        {
            print_usage(argv[0]);
            return 1;
        }

        std::signal(SIGINT, handle_signal);
        std::signal(SIGTERM, handle_signal);

        CrawlerApp app(std::move(*config));
        return app.run();
    }
    catch (const std::exception &error)
    {
        std::cerr << "致命错误: " << error.what() << '\n';
        return 1;
    }
    catch (...)
    {
        std::cerr << "致命错误: 未知异常\n";
        return 1;
    }
}
