#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace simple_net
{

void close_socket(int socket);
void set_socket_timeouts(int socket, int timeout_ms);

bool write_all(int socket, std::string_view data, std::string &error);
bool read_until(
    int socket,
    std::string &data,
    std::string_view delimiter,
    std::size_t max_size,
    std::string &error);

int connect_tcp(
    const std::string &host,
    std::uint16_t port,
    int timeout_ms,
    std::string &error);

class TcpServer
{
public:
    using Handler = std::function<void(int, const std::string &)>;

    TcpServer() = default;
    ~TcpServer();

    TcpServer(const TcpServer &) = delete;
    TcpServer &operator=(const TcpServer &) = delete;

    void start(
        const std::string &bind_address,
        std::uint16_t port,
        std::size_t worker_count,
        std::size_t max_pending,
        Handler handler);
    void stop();
    bool running() const;

private:
    struct Connection
    {
        int socket = -1;
        std::string remote;
    };

    void accept_loop();
    void worker_loop();

    std::atomic<bool> stopping_{false};
    std::atomic<int> listener_{-1};
    std::size_t max_pending_ = 0;
    Handler handler_;
    std::thread accept_thread_;
    std::vector<std::thread> workers_;
    std::mutex queue_mutex_;
    std::condition_variable queue_condition_;
    std::deque<Connection> queue_;
};

} // namespace simple_net
