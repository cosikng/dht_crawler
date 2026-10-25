#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace simple_net
{

// Native socket handle without pulling OS headers into every includer:
// SOCKET is UINT_PTR on Windows, descriptors are int on POSIX.
#if defined(_WIN32)
using socket_t = std::uintptr_t;
inline constexpr socket_t kInvalidSocket = ~socket_t{0};
#else
using socket_t = int;
inline constexpr socket_t kInvalidSocket = -1;
#endif

using Clock = std::chrono::steady_clock;
using Deadline = Clock::time_point;

// Keeps Winsock initialised for its lifetime (WSAStartup/WSACleanup are
// reference counted by the OS). A no-op on POSIX. Every entry point of this
// library takes a reference, so callers never have to initialise anything.
class NetworkRuntime
{
public:
    NetworkRuntime();
    ~NetworkRuntime();

    NetworkRuntime(const NetworkRuntime &) = delete;
    NetworkRuntime &operator=(const NetworkRuntime &) = delete;
};

// Owns one socket handle and closes it on destruction.
class Socket
{
public:
    Socket() noexcept = default;
    explicit Socket(socket_t socket) noexcept;
    ~Socket();

    Socket(Socket &&other) noexcept;
    Socket &operator=(Socket &&other) noexcept;
    Socket(const Socket &) = delete;
    Socket &operator=(const Socket &) = delete;

    socket_t get() const noexcept
    {
        return socket_;
    }

    bool valid() const noexcept
    {
        return socket_ != kInvalidSocket;
    }

    void reset(socket_t socket = kInvalidSocket) noexcept;

private:
    socket_t socket_ = kInvalidSocket;
};

// All I/O below is deadline based (poll + non-blocking sockets) instead of
// SO_RCVTIMEO/SO_SNDTIMEO, whose units and per-call semantics differ between
// Winsock and POSIX. A deadline bounds the whole operation, so a peer that
// trickles bytes cannot keep a call alive indefinitely. When `cancel` is set
// and becomes true the call fails promptly.
bool write_all(
    socket_t socket,
    std::string_view data,
    Deadline deadline,
    std::string &error,
    const std::atomic<bool> *cancel = nullptr);

bool read_until(
    socket_t socket,
    std::string &data,
    std::string_view delimiter,
    std::size_t max_size,
    Deadline deadline,
    std::string &error,
    const std::atomic<bool> *cancel = nullptr);

Socket connect_tcp(
    const std::string &host,
    std::uint16_t port,
    std::chrono::milliseconds timeout,
    std::string &error,
    const std::atomic<bool> *cancel = nullptr);

// Sends FIN, discards whatever the peer still sends for up to `linger`, then
// closes. Closing with unread input makes both TCP stacks send RST, which can
// destroy a response the peer has not read yet.
void graceful_close(Socket &socket, std::chrono::milliseconds linger);

// Address formatting identical on every platform (RFC 5952 style, matching
// glibc inet_ntop, including the dotted form for ::ffff:a.b.c.d and
// ::a.b.c.d). Never appends a scope id.
std::string format_ipv4(const std::array<std::uint8_t, 4> &address);
std::string format_ipv6(const std::array<std::uint8_t, 16> &address);

// Parses a numeric IPv4 (family 4) or IPv6 (family 6) address into network
// byte order: 4 or 16 bytes.
std::optional<std::string> pack_ip_address(int family, const std::string &text);

struct ServerOptions
{
    std::string bind_address;
    std::uint16_t port = 0;
    std::size_t worker_count = 1;
    // Complete requests waiting for a worker; further ones are rejected.
    std::size_t max_pending = 0;
    // Connections still receiving their request; the listener is not polled
    // while this many are open, so excess clients wait in the kernel backlog.
    std::size_t max_connections = 1024;
    // A request is complete once this delimiter has been received.
    std::string delimiter;
    std::size_t max_request_size = 0;
    // Total time a client gets to deliver the complete request.
    std::chrono::milliseconds request_timeout{10000};
    std::chrono::milliseconds close_linger{250};
};

struct Connection
{
    Socket socket;
    std::string remote;
    // Everything received so far; contains the delimiter.
    std::string request;
};

struct ServerStats
{
    std::uint64_t accepted = 0;
    std::uint64_t dispatched = 0;
    std::uint64_t rejected = 0;
    std::uint64_t timed_out = 0;
    std::uint64_t oversized = 0;
    std::uint64_t closed_early = 0;
};

// One I/O thread runs a portable poll() reactor that accepts connections and
// reads each request up to the delimiter with a total deadline; complete
// requests are handed to a fixed worker pool. Idle or slow clients therefore
// never occupy a worker.
class TcpServer
{
public:
    using Handler = std::function<void(Connection &)>;

    TcpServer() = default;
    ~TcpServer();

    TcpServer(const TcpServer &) = delete;
    TcpServer &operator=(const TcpServer &) = delete;

    void start(ServerOptions options, Handler handler);
    void stop();
    bool running() const;
    // Set when stop() begins; handlers can pass it as a cancel flag.
    const std::atomic<bool> &stopping() const
    {
        return stopping_;
    }
    ServerStats stats() const;

private:
    struct Reading
    {
        Socket socket;
        std::string remote;
        std::string buffer;
        Deadline deadline;
    };

    void io_loop();
    void worker_loop();
    void accept_ready(std::vector<Reading> &reading, Deadline now, Deadline &accept_paused_until);
    bool dispatch(Connection connection);

    NetworkRuntime runtime_;
    ServerOptions options_;
    Handler handler_;
    std::atomic<bool> stopping_{false};
    std::atomic<bool> running_{false};
    Socket listener_;
    std::thread io_thread_;
    std::vector<std::thread> workers_;
    std::mutex queue_mutex_;
    std::condition_variable queue_condition_;
    std::deque<Connection> queue_;

    mutable std::mutex stats_mutex_;
    ServerStats stats_;
};

} // namespace simple_net
