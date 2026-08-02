#include "simple_network.hpp"

#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include <arpa/inet.h>

namespace
{

constexpr int kMaxPort = 65535;
constexpr std::size_t kHttpWorkers = 8;
constexpr std::size_t kHttpQueueSize = 256;
constexpr std::size_t kMaxHttpRequestSize = 16 * 1024;
constexpr std::size_t kMaxRpcResponseSize = 64 * 1024;
constexpr std::size_t kMaxPeers = 512;

volatile std::sig_atomic_t g_stop_requested = 0;
std::mutex g_log_mutex;

void handle_signal(int)
{
    g_stop_requested = 1;
}

struct Config
{
    std::string bind_address = "0.0.0.0";
    int port = 8080;
    std::string crawler_host = "127.0.0.1";
    int crawler_port = 19091;
    int lookup_timeout_seconds = 10;
    int interval_seconds = 60;
};

struct PeerEndpoint
{
    int family = 0;
    std::string address;
    std::uint16_t port = 0;
};

enum class LookupStatus
{
    ok,
    timeout,
    error
};

struct LookupReply
{
    LookupStatus status = LookupStatus::error;
    std::vector<PeerEndpoint> peers;
    std::string error;
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

void print_usage(const char *program)
{
    std::cerr
        << "用法: " << program << " [选项]\n\n"
        << "选项:\n"
        << "  --bind ADDRESS          HTTP tracker 绑定地址，默认 0.0.0.0\n"
        << "  --port PORT             HTTP tracker 端口，默认 8080\n"
        << "  --crawler-host HOST     DHT 爬虫 RPC 地址，默认 127.0.0.1\n"
        << "  --crawler-port PORT     DHT 爬虫 RPC 端口，默认 19091\n"
        << "  --lookup-timeout SEC    RPC 查询超时，默认 10 秒\n"
        << "  --interval SEC          tracker 回复间隔，默认 60 秒\n"
        << "  --help                  显示帮助\n";
}

std::optional<Config> parse_arguments(int argc, char **argv)
{
    Config config;
    for (int i = 1; i < argc; ++i)
    {
        const std::string_view option(argv[i]);
        if (i + 1 >= argc)
            return std::nullopt;
        const std::string_view value(argv[++i]);

        if (option == "--bind")
            config.bind_address = value;
        else if (option == "--port")
        {
            if (!parse_integer(value, config.port))
                return std::nullopt;
        }
        else if (option == "--crawler-host")
            config.crawler_host = value;
        else if (option == "--crawler-port")
        {
            if (!parse_integer(value, config.crawler_port))
                return std::nullopt;
        }
        else if (option == "--lookup-timeout")
        {
            if (!parse_integer(value, config.lookup_timeout_seconds))
                return std::nullopt;
        }
        else if (option == "--interval")
        {
            if (!parse_integer(value, config.interval_seconds))
                return std::nullopt;
        }
        else
        {
            return std::nullopt;
        }
    }

    if (config.bind_address.empty()
        || config.port <= 0
        || config.port > kMaxPort
        || config.crawler_host.empty()
        || config.crawler_port <= 0
        || config.crawler_port > kMaxPort
        || config.lookup_timeout_seconds <= 0
        || config.lookup_timeout_seconds > 300
        || config.interval_seconds <= 0)
    {
        return std::nullopt;
    }
    return config;
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

std::optional<std::string> url_decode(std::string_view encoded)
{
    std::string decoded;
    decoded.reserve(encoded.size());
    for (std::size_t i = 0; i < encoded.size(); ++i)
    {
        if (encoded[i] == '%')
        {
            if (i + 2 >= encoded.size())
                return std::nullopt;
            const int high = hex_value(encoded[i + 1]);
            const int low = hex_value(encoded[i + 2]);
            if (high < 0 || low < 0)
                return std::nullopt;
            decoded.push_back(static_cast<char>((high << 4) | low));
            i += 2;
        }
        else if (encoded[i] == '+')
        {
            decoded.push_back(' ');
        }
        else
        {
            decoded.push_back(encoded[i]);
        }
    }
    return decoded;
}

std::unordered_map<std::string, std::string> parse_query(std::string_view query)
{
    std::unordered_map<std::string, std::string> values;
    std::size_t offset = 0;
    while (offset <= query.size())
    {
        const std::size_t separator = query.find('&', offset);
        const std::string_view item = query.substr(
            offset,
            separator == std::string_view::npos
                ? query.size() - offset
                : separator - offset);
        const std::size_t equals = item.find('=');
        const std::string_view key = item.substr(0, equals);
        const std::string_view encoded_value =
            equals == std::string_view::npos
                ? std::string_view{}
                : item.substr(equals + 1);

        const std::optional<std::string> decoded_key = url_decode(key);
        const std::optional<std::string> decoded_value = url_decode(encoded_value);
        if (decoded_key && decoded_value && !decoded_key->empty())
            values.emplace(*decoded_key, *decoded_value);

        if (separator == std::string_view::npos)
            break;
        offset = separator + 1;
    }
    return values;
}

std::optional<std::array<std::uint8_t, 20>> parse_info_hash(
    const std::string &value)
{
    std::array<std::uint8_t, 20> hash{};
    if (value.size() == hash.size())
    {
        for (std::size_t i = 0; i < hash.size(); ++i)
            hash[i] = static_cast<std::uint8_t>(value[i]);
        return hash;
    }

    if (value.size() == hash.size() * 2)
    {
        for (std::size_t i = 0; i < hash.size(); ++i)
        {
            const int high = hex_value(value[i * 2]);
            const int low = hex_value(value[i * 2 + 1]);
            if (high < 0 || low < 0)
                return std::nullopt;
            hash[i] = static_cast<std::uint8_t>((high << 4) | low);
        }
        return hash;
    }
    return std::nullopt;
}

std::string hash_to_hex(const std::array<std::uint8_t, 20> &hash)
{
    static constexpr char digits[] = "0123456789abcdef";
    std::string result(hash.size() * 2, '0');
    for (std::size_t i = 0; i < hash.size(); ++i)
    {
        result[i * 2] = digits[hash[i] >> 4];
        result[i * 2 + 1] = digits[hash[i] & 0x0f];
    }
    return result;
}

std::string bencode_string(std::string_view value)
{
    return std::to_string(value.size()) + ':' + std::string(value);
}

std::string failure_body(std::string_view reason)
{
    return "d14:failure reason" + bencode_string(reason) + 'e';
}

std::string compact_peers(
    const std::vector<PeerEndpoint> &peers,
    int family)
{
    std::string compact;
    for (const PeerEndpoint &peer : peers)
    {
        if (peer.family != family)
            continue;

        std::array<unsigned char, 16> address{};
        const int address_family = family == 4 ? AF_INET : AF_INET6;
        const std::size_t address_size = family == 4 ? 4 : 16;
        if (inet_pton(address_family, peer.address.c_str(), address.data()) != 1)
            continue;

        compact.append(
            reinterpret_cast<const char *>(address.data()),
            address_size);
        compact.push_back(static_cast<char>((peer.port >> 8) & 0xff));
        compact.push_back(static_cast<char>(peer.port & 0xff));
    }
    return compact;
}

std::string success_body(
    const std::vector<PeerEndpoint> &peers,
    int interval_seconds)
{
    const std::string peers4 = compact_peers(peers, 4);
    const std::string peers6 = compact_peers(peers, 6);

    std::string body =
        "d8:intervali" + std::to_string(interval_seconds)
        + "e12:min intervali" + std::to_string(interval_seconds)
        + "e5:peers" + bencode_string(peers4);
    if (!peers6.empty())
        body += "6:peers6" + bencode_string(peers6);
    body += 'e';
    return body;
}

std::string http_response(
    int status,
    std::string_view status_text,
    std::string_view content_type,
    const std::string &body)
{
    std::ostringstream response;
    response << "HTTP/1.1 " << status << ' ' << status_text << "\r\n"
             << "Content-Type: " << content_type << "\r\n"
             << "Content-Length: " << body.size() << "\r\n"
             << "Connection: close\r\n"
             << "Cache-Control: no-store\r\n\r\n"
             << body;
    return response.str();
}

LookupReply query_crawler(
    const Config &config,
    const std::string &hash_hex)
{
    const int timeout_ms = config.lookup_timeout_seconds * 1000;
    std::string network_error;
    const int socket = simple_net::connect_tcp(
        config.crawler_host,
        static_cast<std::uint16_t>(config.crawler_port),
        timeout_ms,
        network_error);
    if (socket < 0)
        return {LookupStatus::error, {}, network_error};

    const std::string request = "DHTP/1 GET_PEERS " + hash_hex + '\n';
    if (!simple_net::write_all(socket, request, network_error))
    {
        simple_net::close_socket(socket);
        return {LookupStatus::error, {}, network_error};
    }

    std::string response;
    const bool received = simple_net::read_until(
        socket,
        response,
        "\nEND\n",
        kMaxRpcResponseSize,
        network_error);
    simple_net::close_socket(socket);
    if (!received)
        return {LookupStatus::error, {}, network_error};

    std::istringstream lines(response);
    std::string header;
    if (!std::getline(lines, header))
        return {LookupStatus::error, {}, "空 RPC 响应"};
    if (!header.empty() && header.back() == '\r')
        header.pop_back();

    std::istringstream header_parser(header);
    std::string protocol;
    std::string status;
    header_parser >> protocol >> status;
    if (protocol != "DHTP/1")
        return {LookupStatus::error, {}, "无效 RPC 协议"};
    if (status == "TIMEOUT")
        return {LookupStatus::timeout, {}, "DHT 查询超时"};
    if (status != "OK")
        return {LookupStatus::error, {}, "DHT 爬虫查询失败"};

    std::size_t peer_count = 0;
    if (!(header_parser >> peer_count) || peer_count > kMaxPeers)
        return {LookupStatus::error, {}, "无效 peer 数量"};

    std::vector<PeerEndpoint> peers;
    peers.reserve(peer_count);
    for (std::size_t i = 0; i < peer_count; ++i)
    {
        std::string line;
        if (!std::getline(lines, line))
            return {LookupStatus::error, {}, "RPC peer 列表不完整"};
        if (!line.empty() && line.back() == '\r')
            line.pop_back();

        std::istringstream peer_parser(line);
        std::string type;
        PeerEndpoint peer;
        int port = 0;
        std::string extra;
        peer_parser >> type >> peer.family >> peer.address >> port;
        peer_parser >> extra;
        if (type != "PEER"
            || (peer.family != 4 && peer.family != 6)
            || port <= 0
            || port > kMaxPort
            || !extra.empty())
        {
            return {LookupStatus::error, {}, "无效 RPC peer"};
        }
        peer.port = static_cast<std::uint16_t>(port);
        peers.push_back(std::move(peer));
    }
    return {LookupStatus::ok, std::move(peers), {}};
}

class TrackerServer
{
public:
    explicit TrackerServer(Config config)
        : config_(std::move(config))
    {
    }

    int run()
    {
        server_.start(
            config_.bind_address,
            static_cast<std::uint16_t>(config_.port),
            kHttpWorkers,
            kHttpQueueSize,
            [this](int socket, const std::string &remote) {
                handle_http(socket, remote);
            });

        {
            std::lock_guard<std::mutex> lock(g_log_mutex);
            std::cout << "[Tracker] HTTP 监听 "
                      << config_.bind_address << ':' << config_.port
                      << "，DHT 爬虫 "
                      << config_.crawler_host << ':' << config_.crawler_port
                      << '\n';
        }

        while (!g_stop_requested)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

        {
            std::lock_guard<std::mutex> lock(g_log_mutex);
            std::cout << "[Tracker] 收到退出信号，正在停止...\n";
        }
        server_.stop();
        return 0;
    }

private:
    void handle_http(int socket, const std::string &remote)
    {
        simple_net::set_socket_timeouts(
            socket,
            config_.lookup_timeout_seconds * 1000 + 3000);

        std::string request;
        std::string network_error;
        if (!simple_net::read_until(
                socket,
                request,
                "\r\n\r\n",
                kMaxHttpRequestSize,
                network_error))
        {
            return;
        }

        const std::size_t line_end = request.find("\r\n");
        if (line_end == std::string::npos)
        {
            send_http_error(socket, 400, "Bad Request", "无效 HTTP 请求");
            return;
        }

        std::istringstream request_line(request.substr(0, line_end));
        std::string method;
        std::string target;
        std::string version;
        std::string extra;
        request_line >> method >> target >> version;
        request_line >> extra;
        if (method != "GET"
            || version.rfind("HTTP/", 0) != 0
            || !extra.empty())
        {
            send_http_error(socket, 400, "Bad Request", "仅支持 HTTP GET");
            return;
        }

        const std::size_t question = target.find('?');
        const std::string path = target.substr(0, question);
        const std::string_view query =
            question == std::string::npos
                ? std::string_view{}
                : std::string_view(target).substr(question + 1);

        if (path == "/health")
        {
            const std::string response =
                http_response(200, "OK", "text/plain", "ok\n");
            simple_net::write_all(socket, response, network_error);
            return;
        }
        if (path != "/announce")
        {
            send_http_error(socket, 404, "Not Found", "仅支持 /announce");
            return;
        }

        const auto parameters = parse_query(query);
        const auto hash_iterator = parameters.find("info_hash");
        if (hash_iterator == parameters.end())
        {
            send_tracker_failure(socket, "缺少 info_hash");
            return;
        }

        const std::optional<std::array<std::uint8_t, 20>> hash =
            parse_info_hash(hash_iterator->second);
        if (!hash)
        {
            send_tracker_failure(socket, "info_hash 必须是 20 字节");
            return;
        }
        const std::string hash_hex = hash_to_hex(*hash);

        int announced_port = 0;
        const auto port_iterator = parameters.find("port");
        if (port_iterator != parameters.end())
            parse_integer(port_iterator->second, announced_port);
        const auto event_iterator = parameters.find("event");
        const std::string event =
            event_iterator == parameters.end() ? "-" : event_iterator->second;

        {
            std::lock_guard<std::mutex> lock(g_log_mutex);
            std::cout << "[Tracker][请求] remote=" << remote
                      << " hash=" << hash_hex
                      << " port=" << announced_port
                      << " event=" << event << '\n';
        }

        LookupReply lookup = query_crawler(config_, hash_hex);
        if (lookup.status != LookupStatus::ok)
        {
            {
                std::lock_guard<std::mutex> lock(g_log_mutex);
                std::cerr << "[Tracker][失败] hash=" << hash_hex
                          << " reason=" << lookup.error << '\n';
            }
            send_tracker_failure(socket, lookup.error);
            return;
        }

        {
            std::lock_guard<std::mutex> lock(g_log_mutex);
            std::cout << "[Tracker][回复] hash=" << hash_hex
                      << " peers=" << lookup.peers.size() << '\n';
            for (const PeerEndpoint &peer : lookup.peers)
            {
                std::cout << "  peer="
                          << (peer.family == 6 ? "[" + peer.address + "]"
                                               : peer.address)
                          << ':' << peer.port << '\n';
            }
        }

        const std::string body =
            success_body(lookup.peers, config_.interval_seconds);
        const std::string response =
            http_response(200, "OK", "text/plain", body);
        simple_net::write_all(socket, response, network_error);
    }

    void send_http_error(
        int socket,
        int status,
        std::string_view status_text,
        std::string_view message)
    {
        const std::string response =
            http_response(status, status_text, "text/plain", std::string(message));
        std::string ignored;
        simple_net::write_all(socket, response, ignored);
    }

    void send_tracker_failure(int socket, std::string_view reason)
    {
        const std::string response =
            http_response(200, "OK", "text/plain", failure_body(reason));
        std::string ignored;
        simple_net::write_all(socket, response, ignored);
    }

    Config config_;
    simple_net::TcpServer server_;
};

} // namespace

int main(int argc, char **argv)
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

        const std::optional<Config> config = parse_arguments(argc, argv);
        if (!config)
        {
            print_usage(argv[0]);
            return 1;
        }

        std::signal(SIGINT, handle_signal);
        std::signal(SIGTERM, handle_signal);
        TrackerServer server(*config);
        return server.run();
    }
    catch (const std::exception &error)
    {
        std::cerr << "Tracker 致命错误: " << error.what() << '\n';
        return 1;
    }
}
