#pragma once

// Native socket headers and thin wrappers over the calls whose spelling or
// semantics differ between Winsock and POSIX. Include this only from .cpp
// files so OS headers never leak into translation units that also include
// libtorrent/Boost.Asio.

#include "simple_network.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// WSAPoll and inet_pton/inet_ntop require Vista or newer.
#if !defined(_WIN32_WINNT) || _WIN32_WINNT < 0x0600
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <windows.h>
#include <type_traits>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace simple_net::os
{

#if defined(_WIN32)
static_assert(std::is_same_v<SOCKET, socket_t>, "socket_t must match SOCKET");
static_assert(INVALID_SOCKET == kInvalidSocket, "kInvalidSocket must match INVALID_SOCKET");

using socklen = int;
using pollfd_t = WSAPOLLFD;
constexpr int kShutdownSend = SD_SEND;
constexpr int kShutdownBoth = SD_BOTH;
#else
using socklen = socklen_t;
using pollfd_t = pollfd;
constexpr int kShutdownSend = SHUT_WR;
constexpr int kShutdownBoth = SHUT_RDWR;
#endif

// Error code of the last failed socket call on this thread.
inline int last_error() noexcept
{
#if defined(_WIN32)
    return WSAGetLastError();
#else
    return errno;
#endif
}

inline bool is_would_block(int code) noexcept
{
#if defined(_WIN32)
    return code == WSAEWOULDBLOCK;
#else
    return code == EAGAIN || code == EWOULDBLOCK;
#endif
}

inline bool is_interrupted(int code) noexcept
{
#if defined(_WIN32)
    return code == WSAEINTR;
#else
    return code == EINTR;
#endif
}

// A non-blocking connect() that has started but not finished.
inline bool is_connect_pending(int code) noexcept
{
#if defined(_WIN32)
    return code == WSAEWOULDBLOCK || code == WSAEINPROGRESS;
#else
    return code == EINPROGRESS || code == EINTR;
#endif
}

// Transient resource exhaustion reported by accept(); retrying immediately
// would spin.
inline bool is_resource_exhausted(int code) noexcept
{
#if defined(_WIN32)
    return code == WSAEMFILE || code == WSAENOBUFS;
#else
    return code == EMFILE || code == ENFILE || code == ENOBUFS || code == ENOMEM;
#endif
}

inline int close(socket_t socket) noexcept
{
#if defined(_WIN32)
    return ::closesocket(socket);
#else
    return ::close(socket);
#endif
}

inline bool set_non_blocking(socket_t socket, bool enabled) noexcept
{
#if defined(_WIN32)
    u_long mode = enabled ? 1 : 0;
    return ::ioctlsocket(socket, FIONBIO, &mode) == 0;
#else
    const int flags = ::fcntl(socket, F_GETFL, 0);
    if (flags < 0)
        return false;
    const int updated = enabled ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
    return ::fcntl(socket, F_SETFL, updated) == 0;
#endif
}

// Keeps sockets out of child processes on both platforms (POSIX inherits
// descriptors across exec, Windows inherits handles by default).
inline void set_no_inherit(socket_t socket) noexcept
{
#if defined(_WIN32)
    ::SetHandleInformation(reinterpret_cast<HANDLE>(socket), HANDLE_FLAG_INHERIT, 0);
#else
    const int flags = ::fcntl(socket, F_GETFD, 0);
    if (flags >= 0)
        ::fcntl(socket, F_SETFD, flags | FD_CLOEXEC);
#endif
}

template <typename Value>
inline int set_option(socket_t socket, int level, int name, const Value &value) noexcept
{
    // Winsock declares the option buffer as const char*, POSIX as const void*.
    return ::setsockopt(
        socket,
        level,
        name,
        reinterpret_cast<const char *>(&value),
        static_cast<socklen>(sizeof(value)));
}

// send()/recv() with the size type each platform expects. Returns the byte
// count, or -1 with last_error() set.
inline std::ptrdiff_t send_some(socket_t socket, const char *data, std::size_t size) noexcept
{
#if defined(_WIN32)
    const int chunk = size > 0x7fffffff ? 0x7fffffff : static_cast<int>(size);
    return ::send(socket, data, chunk, 0);
#elif defined(MSG_NOSIGNAL)
    return ::send(socket, data, size, MSG_NOSIGNAL);
#else
    return ::send(socket, data, size, 0);
#endif
}

inline std::ptrdiff_t recv_some(socket_t socket, char *data, std::size_t size) noexcept
{
#if defined(_WIN32)
    const int chunk = size > 0x7fffffff ? 0x7fffffff : static_cast<int>(size);
    return ::recv(socket, data, chunk, 0);
#else
    return ::recv(socket, data, size, 0);
#endif
}

// Windows answers an RST to its SYN by retrying the SYN for ~2 s before
// reporting WSAECONNREFUSED; Linux fails at once. On loopback, where no SYN
// can be lost, turn the retransmissions off so a closed port is reported
// identically and immediately on both platforms.
inline void prefer_immediate_refusal(socket_t socket, const sockaddr *address) noexcept
{
#if defined(_WIN32)
    bool loopback = false;
    if (address->sa_family == AF_INET)
    {
        sockaddr_in ipv4{};
        std::memcpy(&ipv4, address, sizeof(ipv4));
        loopback = (ntohl(ipv4.sin_addr.s_addr) >> 24) == 127;
    }
    else if (address->sa_family == AF_INET6)
    {
        sockaddr_in6 ipv6{};
        std::memcpy(&ipv6, address, sizeof(ipv6));
        loopback = IN6_IS_ADDR_LOOPBACK(&ipv6.sin6_addr) != 0;
    }
    if (!loopback)
        return;

    TCP_INITIAL_RTO_PARAMETERS parameters{};
    parameters.Rtt = TCP_INITIAL_RTO_UNSPECIFIED_RTT;
    parameters.MaxSynRetransmissions = TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS;
    DWORD returned = 0;
    ::WSAIoctl(
        socket,
        SIO_TCP_INITIAL_RTO,
        &parameters,
        sizeof(parameters),
        nullptr,
        0,
        &returned,
        nullptr,
        nullptr);
#else
    (void)socket;
    (void)address;
#endif
}

inline int poll(pollfd_t *descriptors, std::size_t count, int timeout_ms) noexcept
{
#if defined(_WIN32)
    return ::WSAPoll(descriptors, static_cast<ULONG>(count), timeout_ms);
#else
    return ::poll(descriptors, static_cast<nfds_t>(count), timeout_ms);
#endif
}

// Portable, platform-independent wording for socket and resolver errors so
// that log lines and tracker failure reasons do not depend on the OS locale
// or C library.
std::string error_text(int code);
std::string resolver_error_text(int code);

} // namespace simple_net::os
