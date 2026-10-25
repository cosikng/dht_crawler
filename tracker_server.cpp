#include "logger.hpp"
#include "platform.hpp"
#include "simple_network.hpp"
#include "tracker_protocol.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

constexpr std::size_t kHttpWorkers = 8;
constexpr std::size_t kHttpQueueSize = 256;
constexpr std::size_t kHttpMaxConnections = 1024;
constexpr std::size_t kMaxHttpRequestSize = 16 * 1024;
constexpr std::size_t kMaxRpcResponseSize = 64 * 1024;

using tracker::kMaxPort;
using tracker::LookupReply;
using tracker::LookupStatus;
using tracker::parse_integer;
using tracker::PeerEndpoint;

struct Config
{
    std::string bind_address = "0.0.0.0";
    int port = 8080;
    std::string crawler_host = "127.0.0.1";
    int crawler_port = 19091;
    int lookup_timeout_seconds = 10;
    int interval_seconds = 60;
};

void print_usage(const std::string &program)
{
    logging::error()
        << "用法: " << program << " [选项]\n\n"
        << "选项:\n"
        << "  --bind ADDRESS          HTTP tracker 绑定地址，默认 0.0.0.0\n"
        << "  --port PORT             HTTP tracker 端口，默认 8080\n"
        << "  --crawler-host HOST     DHT 爬虫 RPC 地址，默认 127.0.0.1\n"
        << "  --crawler-port PORT     DHT 爬虫 RPC 端口，默认 19091\n"
        << "  --lookup-timeout SEC    RPC 查询超时，默认 10 秒\n"
        << "  --interval SEC          tracker 回复间隔，默认 60 秒\n"
        << "  --help                  显示帮助";
}

std::optional<Config> parse_arguments(const std::vector<std::string> &arguments)
{
    Config config;
    for (std::size_t i = 1; i < arguments.size(); ++i)
    {
        const std::string_view option(arguments[i]);
        if (i + 1 >= arguments.size())
            return std::nullopt;
        const std::string_view value(arguments[++i]);

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

LookupReply query_crawler(
    const Config &config,
    const std::string &hash_hex,
    const std::atomic<bool> &cancel)
{
    const auto timeout = std::chrono::seconds(config.lookup_timeout_seconds);
    const simple_net::Deadline deadline = simple_net::Clock::now() + timeout;
    std::string network_error;
    simple_net::Socket socket = simple_net::connect_tcp(
        config.crawler_host,
        static_cast<std::uint16_t>(config.crawler_port),
        std::chrono::duration_cast<std::chrono::milliseconds>(timeout),
        network_error,
        &cancel);
    if (!socket.valid())
        return {LookupStatus::error, {}, network_error};

    if (!simple_net::write_all(
            socket.get(), tracker::rpc_request(hash_hex), deadline, network_error, &cancel))
    {
        return {LookupStatus::error, {}, network_error};
    }

    std::string response;
    if (!simple_net::read_until(
            socket.get(),
            response,
            "\nEND\n",
            kMaxRpcResponseSize,
            deadline,
            network_error,
            &cancel))
    {
        return {LookupStatus::error, {}, network_error};
    }
    return tracker::parse_rpc_response(response);
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
        simple_net::ServerOptions options;
        options.bind_address = config_.bind_address;
        options.port = static_cast<std::uint16_t>(config_.port);
        options.worker_count = kHttpWorkers;
        options.max_pending = kHttpQueueSize;
        options.max_connections = kHttpMaxConnections;
        options.delimiter = "\r\n\r\n";
        options.max_request_size = kMaxHttpRequestSize;
        options.request_timeout = io_budget();
        server_.start(std::move(options), [this](simple_net::Connection &connection) {
            handle_http(connection);
        });

        logging::info() << "[Tracker] HTTP 监听 "
                        << config_.bind_address << ':' << config_.port
                        << "，DHT 爬虫 "
                        << config_.crawler_host << ':' << config_.crawler_port;

        while (!platform::wait_for_shutdown(std::chrono::seconds(1)))
        {
        }

        logging::info() << "[Tracker] 收到退出信号 (" << platform::shutdown_reason()
                        << ")，正在停止...";
        stopping_.store(true);
        server_.stop();
        const simple_net::ServerStats stats = server_.stats();
        logging::info() << "[Tracker] 已停止: accepted=" << stats.accepted
                        << " dispatched=" << stats.dispatched
                        << " rejected=" << stats.rejected
                        << " timed_out=" << stats.timed_out
                        << " oversized=" << stats.oversized
                        << " closed_early=" << stats.closed_early;
        return 0;
    }

private:
    std::chrono::milliseconds io_budget() const
    {
        return std::chrono::seconds(config_.lookup_timeout_seconds + 3);
    }

    void handle_http(simple_net::Connection &connection)
    {
        const std::optional<tracker::RequestLine> line =
            tracker::parse_request_line(connection.request);
        if (!line)
        {
            send_http_error(connection, 400, "Bad Request", "无效 HTTP 请求");
            return;
        }
        if (line->method != "GET"
            || line->version.rfind("HTTP/", 0) != 0
            || line->extra_tokens)
        {
            send_http_error(connection, 400, "Bad Request", "仅支持 HTTP GET");
            return;
        }

        const std::string &target = line->target;
        const std::size_t question = target.find('?');
        const std::string path = target.substr(0, question);
        const std::string_view query =
            question == std::string::npos
                ? std::string_view{}
                : std::string_view(target).substr(question + 1);

        if (path == "/health")
        {
            send(connection, tracker::http_response(200, "OK", "text/plain", "ok\n"));
            return;
        }
        if (path != "/announce")
        {
            send_http_error(connection, 404, "Not Found", "仅支持 /announce");
            return;
        }

        const auto parameters = tracker::parse_query(query);
        const auto hash_iterator = parameters.find("info_hash");
        if (hash_iterator == parameters.end())
        {
            send_tracker_failure(connection, "缺少 info_hash");
            return;
        }

        const std::optional<tracker::InfoHash> hash =
            tracker::parse_info_hash(hash_iterator->second);
        if (!hash)
        {
            send_tracker_failure(connection, "info_hash 必须是 20 字节");
            return;
        }
        const std::string hash_hex = tracker::hash_to_hex(*hash);

        int announced_port = 0;
        const auto port_iterator = parameters.find("port");
        if (port_iterator != parameters.end())
            parse_integer(port_iterator->second, announced_port);
        const auto event_iterator = parameters.find("event");
        const std::string event =
            event_iterator == parameters.end() ? "-" : event_iterator->second;

        logging::info() << "[Tracker][请求] remote=" << connection.remote
                        << " hash=" << hash_hex
                        << " port=" << announced_port
                        << " event=" << logging::sanitize(event, 32);

        const LookupReply lookup = query_crawler(config_, hash_hex, stopping_);
        if (lookup.status != LookupStatus::ok)
        {
            logging::error() << "[Tracker][失败] hash=" << hash_hex
                             << " reason=" << lookup.error;
            send_tracker_failure(connection, lookup.error);
            return;
        }

        {
            logging::Line reply = logging::info();
            reply << "[Tracker][回复] hash=" << hash_hex
                  << " peers=" << lookup.peers.size();
            for (const PeerEndpoint &peer : lookup.peers)
            {
                reply << "\n  peer="
                      << (peer.family == 6 ? "[" + peer.address + "]" : peer.address)
                      << ':' << peer.port;
            }
        }

        const std::string body =
            tracker::success_body(lookup.peers, config_.interval_seconds);
        send(connection, tracker::http_response(200, "OK", "text/plain", body));
    }

    void send(simple_net::Connection &connection, const std::string &response)
    {
        std::string ignored;
        simple_net::write_all(
            connection.socket.get(),
            response,
            simple_net::Clock::now() + io_budget(),
            ignored,
            &stopping_);
    }

    void send_http_error(
        simple_net::Connection &connection,
        int status,
        std::string_view status_text,
        std::string_view message)
    {
        send(connection, tracker::http_response(status, status_text, "text/plain", std::string(message)));
    }

    void send_tracker_failure(simple_net::Connection &connection, std::string_view reason)
    {
        send(connection, tracker::http_response(200, "OK", "text/plain", tracker::failure_body(reason)));
    }

    Config config_;
    std::atomic<bool> stopping_{false};
    simple_net::TcpServer server_;
};

} // namespace

int main(int argc, char **argv)
{
    platform::ShutdownCompletionGuard shutdown_complete;
    const std::vector<std::string> arguments = platform::utf8_arguments(argc, argv);
    const std::string program = arguments.empty() ? "tracker_server" : arguments.front();
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

        const std::optional<Config> config = parse_arguments(arguments);
        if (!config)
        {
            print_usage(program);
            return 1;
        }

        platform::install_shutdown_handlers();
        logging::start();
        int result = 0;
        {
            TrackerServer server(*config);
            result = server.run();
        }
        logging::stop();
        return result;
    }
    catch (const std::exception &error)
    {
        logging::error() << "Tracker 致命错误: " << error.what();
        logging::stop();
        return 1;
    }
}
