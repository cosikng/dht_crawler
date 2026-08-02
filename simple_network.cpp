#include "simple_network.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <utility>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace simple_net
{
namespace
{

std::string socket_error(const char *operation)
{
    return std::string(operation) + ": " + std::strerror(errno);
}

void configure_no_sigpipe(int socket)
{
#ifdef SO_NOSIGPIPE
    const int enabled = 1;
    setsockopt(socket, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled));
#else
    (void)socket;
#endif
}

int create_listener(const std::string &bind_address, std::uint16_t port)
{
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    addrinfo *addresses = nullptr;
    const std::string port_text = std::to_string(port);
    const char *host = bind_address.empty() ? nullptr : bind_address.c_str();
    const int lookup = getaddrinfo(host, port_text.c_str(), &hints, &addresses);
    if (lookup != 0)
    {
        throw std::runtime_error(
            "解析监听地址失败: " + std::string(gai_strerror(lookup)));
    }

    int listener = -1;
    std::string last_error = "没有可用监听地址";
    for (addrinfo *address = addresses; address; address = address->ai_next)
    {
        listener = ::socket(
            address->ai_family,
            address->ai_socktype,
            address->ai_protocol);
        if (listener < 0)
        {
            last_error = socket_error("socket");
            continue;
        }

        configure_no_sigpipe(listener);
        const int reuse = 1;
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        if (::bind(listener, address->ai_addr, address->ai_addrlen) == 0
            && ::listen(listener, 128) == 0)
        {
            break;
        }

        last_error = socket_error("bind/listen");
        close_socket(listener);
        listener = -1;
    }

    freeaddrinfo(addresses);
    if (listener < 0)
        throw std::runtime_error(last_error);
    return listener;
}

std::string remote_endpoint(
    const sockaddr_storage &address,
    socklen_t address_length)
{
    char host[NI_MAXHOST]{};
    char service[NI_MAXSERV]{};
    const int result = getnameinfo(
        reinterpret_cast<const sockaddr *>(&address),
        address_length,
        host,
        sizeof(host),
        service,
        sizeof(service),
        NI_NUMERICHOST | NI_NUMERICSERV);
    if (result != 0)
        return "unknown";

    if (address.ss_family == AF_INET6)
        return "[" + std::string(host) + "]:" + service;
    return std::string(host) + ":" + service;
}

} // namespace

void close_socket(int socket)
{
    if (socket >= 0)
        ::close(socket);
}

void set_socket_timeouts(int socket, int timeout_ms)
{
    const timeval timeout{
        timeout_ms / 1000,
        (timeout_ms % 1000) * 1000};
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

bool write_all(int socket, std::string_view data, std::string &error)
{
    std::size_t written = 0;
    while (written < data.size())
    {
#ifdef MSG_NOSIGNAL
        constexpr int flags = MSG_NOSIGNAL;
#else
        constexpr int flags = 0;
#endif
        const ssize_t result = ::send(
            socket,
            data.data() + written,
            data.size() - written,
            flags);
        if (result > 0)
        {
            written += static_cast<std::size_t>(result);
            continue;
        }
        if (result < 0 && errno == EINTR)
            continue;

        error = socket_error("send");
        return false;
    }
    return true;
}

bool read_until(
    int socket,
    std::string &data,
    std::string_view delimiter,
    std::size_t max_size,
    std::string &error)
{
    data.clear();
    char buffer[2048];
    while (data.size() < max_size)
    {
        const std::size_t remaining = max_size - data.size();
        const ssize_t result = ::recv(
            socket,
            buffer,
            std::min(remaining, sizeof(buffer)),
            0);
        if (result > 0)
        {
            data.append(buffer, static_cast<std::size_t>(result));
            if (data.find(delimiter) != std::string::npos)
                return true;
            continue;
        }
        if (result == 0)
        {
            error = "连接在消息完成前关闭";
            return false;
        }
        if (errno == EINTR)
            continue;

        error = socket_error("recv");
        return false;
    }

    error = "消息超过允许的最大长度";
    return false;
}

int connect_tcp(
    const std::string &host,
    std::uint16_t port,
    int timeout_ms,
    std::string &error)
{
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo *addresses = nullptr;
    const std::string port_text = std::to_string(port);
    const int lookup = getaddrinfo(
        host.c_str(),
        port_text.c_str(),
        &hints,
        &addresses);
    if (lookup != 0)
    {
        error = "解析地址失败: " + std::string(gai_strerror(lookup));
        return -1;
    }

    int connected = -1;
    for (addrinfo *address = addresses; address; address = address->ai_next)
    {
        const int socket = ::socket(
            address->ai_family,
            address->ai_socktype,
            address->ai_protocol);
        if (socket < 0)
        {
            error = socket_error("socket");
            continue;
        }

        configure_no_sigpipe(socket);
        const int original_flags = fcntl(socket, F_GETFL, 0);
        if (original_flags < 0
            || fcntl(socket, F_SETFL, original_flags | O_NONBLOCK) < 0)
        {
            error = socket_error("fcntl");
            close_socket(socket);
            continue;
        }

        int result = ::connect(socket, address->ai_addr, address->ai_addrlen);
        if (result < 0 && errno == EINPROGRESS)
        {
            pollfd descriptor{socket, POLLOUT, 0};
            result = ::poll(&descriptor, 1, timeout_ms);
            if (result > 0)
            {
                int connect_error = 0;
                socklen_t length = sizeof(connect_error);
                if (getsockopt(
                        socket,
                        SOL_SOCKET,
                        SO_ERROR,
                        &connect_error,
                        &length)
                    == 0
                    && connect_error == 0)
                {
                    result = 0;
                }
                else
                {
                    errno = connect_error;
                    result = -1;
                }
            }
            else if (result == 0)
            {
                errno = ETIMEDOUT;
                result = -1;
            }
        }

        if (result == 0)
        {
            fcntl(socket, F_SETFL, original_flags);
            set_socket_timeouts(socket, timeout_ms);
            connected = socket;
            break;
        }

        error = socket_error("connect");
        close_socket(socket);
    }

    freeaddrinfo(addresses);
    return connected;
}

TcpServer::~TcpServer()
{
    stop();
}

void TcpServer::start(
    const std::string &bind_address,
    std::uint16_t port,
    std::size_t worker_count,
    std::size_t max_pending,
    Handler handler)
{
    if (running())
        throw std::runtime_error("TCP 服务已经启动");
    if (worker_count == 0 || max_pending == 0 || !handler)
        throw std::runtime_error("无效的 TCP 服务配置");

    const int listener = create_listener(bind_address, port);
    stopping_.store(false);
    listener_.store(listener);
    max_pending_ = max_pending;
    handler_ = std::move(handler);

    try
    {
        workers_.reserve(worker_count);
        for (std::size_t i = 0; i < worker_count; ++i)
            workers_.emplace_back(&TcpServer::worker_loop, this);
        accept_thread_ = std::thread(&TcpServer::accept_loop, this);
    }
    catch (...)
    {
        stop();
        throw;
    }
}

void TcpServer::stop()
{
    if (!running() && workers_.empty() && !accept_thread_.joinable())
        return;

    stopping_.store(true);
    const int listener = listener_.exchange(-1);
    if (listener >= 0)
    {
        ::shutdown(listener, SHUT_RDWR);
        close_socket(listener);
    }

    if (accept_thread_.joinable())
        accept_thread_.join();

    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        for (const Connection &connection : queue_)
            close_socket(connection.socket);
        queue_.clear();
    }
    queue_condition_.notify_all();

    for (std::thread &worker : workers_)
    {
        if (worker.joinable())
            worker.join();
    }
    workers_.clear();
    handler_ = {};
}

bool TcpServer::running() const
{
    return listener_.load() >= 0;
}

void TcpServer::accept_loop()
{
    while (!stopping_.load())
    {
        const int listener = listener_.load();
        if (listener < 0)
            break;

        pollfd descriptor{listener, POLLIN, 0};
        const int ready = ::poll(&descriptor, 1, 500);
        if (ready < 0)
        {
            if (errno == EINTR)
                continue;
            break;
        }
        if (ready == 0 || !(descriptor.revents & POLLIN))
            continue;

        sockaddr_storage address{};
        socklen_t address_length = sizeof(address);
        const int socket = ::accept(
            listener,
            reinterpret_cast<sockaddr *>(&address),
            &address_length);
        if (socket < 0)
        {
            if (errno == EINTR)
                continue;
            if (stopping_.load())
                break;
            continue;
        }

        configure_no_sigpipe(socket);
        Connection connection{
            socket,
            remote_endpoint(address, address_length)};
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            if (stopping_.load() || queue_.size() >= max_pending_)
            {
                close_socket(socket);
                continue;
            }
            queue_.push_back(std::move(connection));
        }
        queue_condition_.notify_one();
    }
}

void TcpServer::worker_loop()
{
    while (true)
    {
        Connection connection;
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            queue_condition_.wait(lock, [this] {
                return stopping_.load() || !queue_.empty();
            });
            if (queue_.empty())
            {
                if (stopping_.load())
                    return;
                continue;
            }

            connection = std::move(queue_.front());
            queue_.pop_front();
        }

        try
        {
            handler_(connection.socket, connection.remote);
        }
        catch (...)
        {
        }
        ::shutdown(connection.socket, SHUT_RDWR);
        close_socket(connection.socket);
    }
}

} // namespace simple_net
