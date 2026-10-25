#include "simple_network.hpp"

#include "socket_platform.hpp"

#include <algorithm>
#include <climits>
#include <cstdio>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace simple_net
{
namespace os
{
namespace
{

std::string native_message(int code)
{
#if defined(_WIN32)
    wchar_t *buffer = nullptr;
    const DWORD length = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM
            | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        static_cast<DWORD>(code),
        0,
        reinterpret_cast<wchar_t *>(&buffer),
        0,
        nullptr);
    if (length == 0 || !buffer)
        return "unknown error";

    std::wstring wide(buffer, length);
    ::LocalFree(buffer);
    while (!wide.empty() && (wide.back() == L'\r' || wide.back() == L'\n' || wide.back() == L' '))
        wide.pop_back();

    const int size = ::WideCharToMultiByte(
        CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    std::string text(static_cast<std::size_t>(std::max(size, 0)), '\0');
    if (size > 0)
    {
        ::WideCharToMultiByte(
            CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), text.data(), size, nullptr, nullptr);
    }
    return text;
#else
    return std::generic_category().message(code);
#endif
}

struct ErrorName
{
    int code;
    const char *text;
};

} // namespace

std::string error_text(int code)
{
#if defined(_WIN32)
    static const ErrorName names[] = {
        {WSAEWOULDBLOCK, "operation would block"},
        {WSAEINTR, "interrupted"},
        {WSAEINPROGRESS, "operation in progress"},
        {WSAEALREADY, "operation already in progress"},
        {WSAECONNREFUSED, "connection refused"},
        {WSAECONNRESET, "connection reset by peer"},
        {WSAECONNABORTED, "connection aborted"},
        {WSAENETRESET, "network dropped connection"},
        {WSAETIMEDOUT, "timed out"},
        {WSAEHOSTUNREACH, "host unreachable"},
        {WSAENETUNREACH, "network unreachable"},
        {WSAENETDOWN, "network down"},
        {WSAEADDRINUSE, "address already in use"},
        {WSAEADDRNOTAVAIL, "address not available"},
        {WSAEAFNOSUPPORT, "address family not supported"},
        {WSAEMFILE, "too many open files"},
        {WSAENOBUFS, "no buffer space available"},
        {WSAENOTCONN, "socket not connected"},
        {WSAESHUTDOWN, "broken pipe"},
        {WSAEACCES, "permission denied"},
        {WSAEINVAL, "invalid argument"},
        {WSAENOTSOCK, "not a socket"},
        {WSAEMSGSIZE, "message too long"},
        {WSANOTINITIALISED, "network subsystem not initialised"},
    };
#else
    static const ErrorName names[] = {
        {EWOULDBLOCK, "operation would block"},
        {EAGAIN, "operation would block"},
        {EINTR, "interrupted"},
        {EINPROGRESS, "operation in progress"},
        {EALREADY, "operation already in progress"},
        {ECONNREFUSED, "connection refused"},
        {ECONNRESET, "connection reset by peer"},
        {ECONNABORTED, "connection aborted"},
        {ENETRESET, "network dropped connection"},
        {ETIMEDOUT, "timed out"},
        {EHOSTUNREACH, "host unreachable"},
        {ENETUNREACH, "network unreachable"},
        {ENETDOWN, "network down"},
        {EADDRINUSE, "address already in use"},
        {EADDRNOTAVAIL, "address not available"},
        {EAFNOSUPPORT, "address family not supported"},
        {EMFILE, "too many open files"},
        {ENFILE, "too many open files"},
        {ENOBUFS, "no buffer space available"},
        {ENOMEM, "no buffer space available"},
        {ENOTCONN, "socket not connected"},
        {EPIPE, "broken pipe"},
        {EACCES, "permission denied"},
        {EPERM, "permission denied"},
        {EINVAL, "invalid argument"},
        {ENOTSOCK, "not a socket"},
        {EMSGSIZE, "message too long"},
    };
#endif
    for (const ErrorName &name : names)
    {
        if (name.code == code)
            return name.text;
    }
    return "system error " + std::to_string(code) + " (" + native_message(code) + ")";
}

std::string resolver_error_text(int code)
{
    // if-chains rather than a switch: several EAI_* values alias each other
    // on some platforms.
#ifdef EAI_NONAME
    if (code == EAI_NONAME)
        return "host not found";
#endif
#ifdef EAI_NODATA
    if (code == EAI_NODATA)
        return "host has no address";
#endif
#ifdef EAI_ADDRFAMILY
    if (code == EAI_ADDRFAMILY)
        return "host has no address";
#endif
#ifdef EAI_AGAIN
    if (code == EAI_AGAIN)
        return "temporary failure in name resolution";
#endif
#ifdef EAI_FAIL
    if (code == EAI_FAIL)
        return "non-recoverable failure in name resolution";
#endif
#ifdef EAI_FAMILY
    if (code == EAI_FAMILY)
        return "address family not supported";
#endif
#ifdef EAI_SOCKTYPE
    if (code == EAI_SOCKTYPE)
        return "socket type not supported";
#endif
#ifdef EAI_SERVICE
    if (code == EAI_SERVICE)
        return "service not supported";
#endif
#ifdef EAI_BADFLAGS
    if (code == EAI_BADFLAGS)
        return "invalid flags";
#endif
#ifdef EAI_MEMORY
    if (code == EAI_MEMORY)
        return "out of memory";
#endif
#ifdef EAI_SYSTEM
    if (code == EAI_SYSTEM)
        return error_text(errno);
#endif
    return "resolver error " + std::to_string(code);
}

} // namespace os

namespace
{

constexpr auto kCancelSlice = std::chrono::milliseconds(100);
constexpr auto kIoTick = std::chrono::milliseconds(100);
constexpr auto kAcceptBackoff = std::chrono::milliseconds(100);
constexpr int kAcceptBurst = 64;
constexpr int kListenBacklog = 128;

void ensure_runtime()
{
    static NetworkRuntime runtime;
}

struct AddressInfoDeleter
{
    void operator()(addrinfo *addresses) const noexcept
    {
        ::freeaddrinfo(addresses);
    }
};

using AddressList = std::unique_ptr<addrinfo, AddressInfoDeleter>;

std::string failure(const char *operation, int code)
{
    return std::string(operation) + ": " + os::error_text(code);
}

int poll_timeout(Deadline deadline, const std::atomic<bool> *cancel, std::chrono::milliseconds cap)
{
    const Deadline now = Clock::now();
    if (deadline <= now)
        return 0;
    auto remaining = std::chrono::ceil<std::chrono::milliseconds>(deadline - now);
    remaining = std::min(remaining, cap);
    if (cancel)
        remaining = std::min(remaining, kCancelSlice);
    return static_cast<int>(std::min<long long>(remaining.count(), INT_MAX));
}

enum class Wait
{
    ready,
    timeout,
    cancelled,
    failed
};

Wait wait_socket(
    socket_t socket,
    short events,
    Deadline deadline,
    const std::atomic<bool> *cancel,
    int &error)
{
    while (true)
    {
        if (cancel && cancel->load())
            return Wait::cancelled;
        if (Clock::now() >= deadline)
            return Wait::timeout;

        os::pollfd_t descriptor{};
        descriptor.fd = socket;
        descriptor.events = events;
        const int ready = os::poll(
            &descriptor,
            1,
            poll_timeout(deadline, cancel, std::chrono::milliseconds(INT_MAX)));
        // POLLERR/POLLHUP also count as ready: the next I/O call reports
        // the precise error identically on both platforms.
        if (ready > 0)
            return Wait::ready;
        if (ready == 0)
            continue;

        const int code = os::last_error();
        if (os::is_interrupted(code))
            continue;
        error = code;
        return Wait::failed;
    }
}

std::string wait_failure(const char *operation, Wait result, int code)
{
    switch (result)
    {
    case Wait::timeout:
        return std::string(operation) + ": timed out";
    case Wait::cancelled:
        return std::string(operation) + ": cancelled";
    case Wait::failed:
        return failure("poll", code);
    case Wait::ready:
        break;
    }
    return std::string(operation) + ": unexpected wait result";
}

Wait wait_for_connect(
    socket_t socket,
    Deadline deadline,
    const std::atomic<bool> *cancel,
    int &error)
{
    while (true)
    {
        if (cancel && cancel->load())
            return Wait::cancelled;
        if (Clock::now() >= deadline)
            return Wait::timeout;

        const int timeout_ms =
            poll_timeout(deadline, cancel, std::chrono::milliseconds(INT_MAX));
#if defined(_WIN32)
        // WSAPoll on Windows before 10 version 2004 never reports a refused
        // connect (it just times out); select() reports it via exceptfds.
        fd_set writable;
        fd_set failed;
        FD_ZERO(&writable);
        FD_ZERO(&failed);
        FD_SET(socket, &writable);
        FD_SET(socket, &failed);
        timeval timeout{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
        const int ready = ::select(0, nullptr, &writable, &failed, &timeout);
#else
        pollfd descriptor{socket, POLLOUT, 0};
        const int ready = ::poll(&descriptor, 1, timeout_ms);
#endif
        if (ready == 0)
            continue;
        if (ready < 0)
        {
            const int code = os::last_error();
            if (os::is_interrupted(code))
                continue;
            error = code;
            return Wait::failed;
        }

        int connect_error = 0;
        os::socklen length = sizeof(connect_error);
        if (::getsockopt(
                socket,
                SOL_SOCKET,
                SO_ERROR,
                reinterpret_cast<char *>(&connect_error),
                &length)
            != 0)
        {
            error = os::last_error();
            return Wait::failed;
        }
        if (connect_error != 0)
        {
            error = connect_error;
            return Wait::failed;
        }
        return Wait::ready;
    }
}

void configure_no_sigpipe(socket_t socket)
{
#ifdef SO_NOSIGPIPE
    const int enabled = 1;
    os::set_option(socket, SOL_SOCKET, SO_NOSIGPIPE, enabled);
#else
    (void)socket;
#endif
}

Socket create_listener(const std::string &bind_address, std::uint16_t port)
{
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

    addrinfo *raw_addresses = nullptr;
    const std::string port_text = std::to_string(port);
    const char *host = bind_address.empty() ? nullptr : bind_address.c_str();
    const int lookup = ::getaddrinfo(host, port_text.c_str(), &hints, &raw_addresses);
    if (lookup != 0)
    {
        throw std::runtime_error(
            "解析监听地址失败: " + os::resolver_error_text(lookup));
    }
    const AddressList addresses(raw_addresses);

    std::string last_error = "没有可用监听地址";
    for (addrinfo *address = addresses.get(); address; address = address->ai_next)
    {
        Socket listener(::socket(
            address->ai_family,
            address->ai_socktype,
            address->ai_protocol));
        if (!listener.valid())
        {
            last_error = failure("socket", os::last_error());
            continue;
        }

        os::set_no_inherit(listener.get());
        configure_no_sigpipe(listener.get());
#if defined(_WIN32)
        // Windows SO_REUSEADDR would let any other socket bind the same port
        // (port hijacking). Exclusive use is the safe equivalent; Windows
        // already permits rebinding while old connections sit in TIME_WAIT.
        const BOOL exclusive = TRUE;
        os::set_option(listener.get(), SOL_SOCKET, SO_EXCLUSIVEADDRUSE, exclusive);
#else
        const int reuse = 1;
        os::set_option(listener.get(), SOL_SOCKET, SO_REUSEADDR, reuse);
#endif
        if (address->ai_family == AF_INET6)
        {
            // Linux defaults to dual-stack, Windows to IPv6-only: pin it.
            const int v6_only = 0;
            os::set_option(listener.get(), IPPROTO_IPV6, IPV6_V6ONLY, v6_only);
        }

        if (::bind(listener.get(), address->ai_addr, static_cast<os::socklen>(address->ai_addrlen)) != 0
            || ::listen(listener.get(), kListenBacklog) != 0)
        {
            last_error = failure("bind/listen", os::last_error());
            continue;
        }
        if (!os::set_non_blocking(listener.get(), true))
        {
            last_error = failure("ioctl", os::last_error());
            continue;
        }
        return listener;
    }

    throw std::runtime_error(last_error);
}

std::string remote_endpoint(const sockaddr_storage &address)
{
    if (address.ss_family == AF_INET)
    {
        sockaddr_in ipv4{};
        std::memcpy(&ipv4, &address, sizeof(ipv4));
        std::array<std::uint8_t, 4> bytes{};
        std::memcpy(bytes.data(), &ipv4.sin_addr, bytes.size());
        return format_ipv4(bytes) + ':' + std::to_string(ntohs(ipv4.sin_port));
    }
    if (address.ss_family == AF_INET6)
    {
        sockaddr_in6 ipv6{};
        std::memcpy(&ipv6, &address, sizeof(ipv6));
        std::array<std::uint8_t, 16> bytes{};
        std::memcpy(bytes.data(), &ipv6.sin6_addr, bytes.size());
        return '[' + format_ipv6(bytes) + "]:" + std::to_string(ntohs(ipv6.sin6_port));
    }
    return "unknown";
}

// glibc inet_pton4 rules: exactly four decimal octets, no leading zeros.
bool parse_ipv4(std::string_view text, std::uint8_t *output)
{
    std::array<std::uint8_t, 4> octets{};
    std::size_t index = 0;
    unsigned value = 0;
    bool saw_digit = false;
    for (const char character : text)
    {
        if (character >= '0' && character <= '9')
        {
            if (saw_digit && value == 0)
                return false;
            value = value * 10 + static_cast<unsigned>(character - '0');
            if (value > 255)
                return false;
            saw_digit = true;
        }
        else if (character == '.' && saw_digit)
        {
            if (index == 3)
                return false;
            octets[index++] = static_cast<std::uint8_t>(value);
            value = 0;
            saw_digit = false;
        }
        else
        {
            return false;
        }
    }
    if (!saw_digit || index != 3)
        return false;
    octets[3] = static_cast<std::uint8_t>(value);
    std::memcpy(output, octets.data(), octets.size());
    return true;
}

int hex_digit(char character)
{
    if (character >= '0' && character <= '9')
        return character - '0';
    if (character >= 'a' && character <= 'f')
        return character - 'a' + 10;
    if (character >= 'A' && character <= 'F')
        return character - 'A' + 10;
    return -1;
}

// glibc inet_pton6 rules, including one "::" and a trailing dotted quad.
bool parse_ipv6(std::string_view text, std::uint8_t *output)
{
    std::array<std::uint8_t, 16> bytes{};
    std::size_t position = 0;
    std::size_t length = 0;
    std::optional<std::size_t> gap;

    if (!text.empty() && text.front() == ':')
    {
        if (text.size() < 2 || text[1] != ':')
            return false;
        position = 1;
    }

    std::size_t token_start = position;
    unsigned value = 0;
    int digits = 0;
    while (position < text.size())
    {
        const char character = text[position++];
        const int digit = hex_digit(character);
        if (digit >= 0)
        {
            value = (value << 4) | static_cast<unsigned>(digit);
            if (++digits > 4)
                return false;
            continue;
        }
        if (character == ':')
        {
            token_start = position;
            if (digits == 0)
            {
                if (gap)
                    return false;
                gap = length;
                continue;
            }
            if (position == text.size())
                return false;
            if (length + 2 > bytes.size())
                return false;
            bytes[length++] = static_cast<std::uint8_t>(value >> 8);
            bytes[length++] = static_cast<std::uint8_t>(value & 0xff);
            value = 0;
            digits = 0;
            continue;
        }
        if (character == '.' && length + 4 <= bytes.size()
            && parse_ipv4(text.substr(token_start), bytes.data() + length))
        {
            length += 4;
            digits = 0;
            position = text.size();
            break;
        }
        return false;
    }

    if (digits > 0)
    {
        if (length + 2 > bytes.size())
            return false;
        bytes[length++] = static_cast<std::uint8_t>(value >> 8);
        bytes[length++] = static_cast<std::uint8_t>(value & 0xff);
    }
    if (gap)
    {
        if (length == bytes.size())
            return false;
        const std::size_t tail = length - *gap;
        std::memmove(bytes.data() + bytes.size() - tail, bytes.data() + *gap, tail);
        std::fill(bytes.data() + *gap, bytes.data() + bytes.size() - tail, std::uint8_t{0});
        length = bytes.size();
    }
    if (length != bytes.size())
        return false;
    std::memcpy(output, bytes.data(), bytes.size());
    return true;
}

} // namespace

NetworkRuntime::NetworkRuntime()
{
#if defined(_WIN32)
    WSADATA data{};
    const int result = ::WSAStartup(MAKEWORD(2, 2), &data);
    if (result != 0)
        throw std::runtime_error("WSAStartup 失败: " + os::error_text(result));
#endif
}

NetworkRuntime::~NetworkRuntime()
{
#if defined(_WIN32)
    ::WSACleanup();
#endif
}

Socket::Socket(socket_t socket) noexcept
    : socket_(socket)
{
}

Socket::~Socket()
{
    reset();
}

Socket::Socket(Socket &&other) noexcept
    : socket_(std::exchange(other.socket_, kInvalidSocket))
{
}

Socket &Socket::operator=(Socket &&other) noexcept
{
    if (this != &other)
        reset(std::exchange(other.socket_, kInvalidSocket));
    return *this;
}

void Socket::reset(socket_t socket) noexcept
{
    if (socket_ != kInvalidSocket)
        os::close(socket_);
    socket_ = socket;
}

bool write_all(
    socket_t socket,
    std::string_view data,
    Deadline deadline,
    std::string &error,
    const std::atomic<bool> *cancel)
{
    std::size_t written = 0;
    while (written < data.size())
    {
        const std::ptrdiff_t result =
            os::send_some(socket, data.data() + written, data.size() - written);
        if (result > 0)
        {
            written += static_cast<std::size_t>(result);
            continue;
        }
        if (result == 0)
        {
            error = "send: connection closed";
            return false;
        }

        const int code = os::last_error();
        if (os::is_interrupted(code))
            continue;
        if (os::is_would_block(code))
        {
            int wait_error = 0;
            const Wait waited = wait_socket(socket, POLLOUT, deadline, cancel, wait_error);
            if (waited == Wait::ready)
                continue;
            error = wait_failure("send", waited, wait_error);
            return false;
        }

        error = failure("send", code);
        return false;
    }
    return true;
}

bool read_until(
    socket_t socket,
    std::string &data,
    std::string_view delimiter,
    std::size_t max_size,
    Deadline deadline,
    std::string &error,
    const std::atomic<bool> *cancel)
{
    data.clear();
    char buffer[4096];
    while (data.size() < max_size)
    {
        const std::size_t remaining = max_size - data.size();
        const std::ptrdiff_t result =
            os::recv_some(socket, buffer, std::min(remaining, sizeof(buffer)));
        if (result > 0)
        {
            const std::size_t search_from =
                data.size() >= delimiter.size() ? data.size() - delimiter.size() + 1 : 0;
            data.append(buffer, static_cast<std::size_t>(result));
            if (data.find(delimiter, search_from) != std::string::npos)
                return true;
            continue;
        }
        if (result == 0)
        {
            error = "连接在消息完成前关闭";
            return false;
        }

        const int code = os::last_error();
        if (os::is_interrupted(code))
            continue;
        if (os::is_would_block(code))
        {
            int wait_error = 0;
            const Wait waited = wait_socket(socket, POLLIN, deadline, cancel, wait_error);
            if (waited == Wait::ready)
                continue;
            error = wait_failure("recv", waited, wait_error);
            return false;
        }

        error = failure("recv", code);
        return false;
    }

    error = "消息超过允许的最大长度";
    return false;
}

Socket connect_tcp(
    const std::string &host,
    std::uint16_t port,
    std::chrono::milliseconds timeout,
    std::string &error,
    const std::atomic<bool> *cancel)
{
    ensure_runtime();

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_NUMERICSERV;

    addrinfo *raw_addresses = nullptr;
    const std::string port_text = std::to_string(port);
    const int lookup = ::getaddrinfo(host.c_str(), port_text.c_str(), &hints, &raw_addresses);
    if (lookup != 0)
    {
        error = "解析地址失败: " + os::resolver_error_text(lookup);
        return Socket{};
    }
    const AddressList addresses(raw_addresses);

    const Deadline deadline = Clock::now() + timeout;
    for (addrinfo *address = addresses.get(); address; address = address->ai_next)
    {
        Socket socket(::socket(
            address->ai_family,
            address->ai_socktype,
            address->ai_protocol));
        if (!socket.valid())
        {
            error = failure("socket", os::last_error());
            continue;
        }

        os::set_no_inherit(socket.get());
        configure_no_sigpipe(socket.get());
        if (!os::set_non_blocking(socket.get(), true))
        {
            error = failure("ioctl", os::last_error());
            continue;
        }
        os::prefer_immediate_refusal(socket.get(), address->ai_addr);

        if (::connect(socket.get(), address->ai_addr, static_cast<os::socklen>(address->ai_addrlen)) != 0)
        {
            const int code = os::last_error();
            if (!os::is_connect_pending(code))
            {
                error = failure("connect", code);
                continue;
            }

            int connect_error = 0;
            const Wait waited = wait_for_connect(socket.get(), deadline, cancel, connect_error);
            if (waited != Wait::ready)
            {
                error = waited == Wait::failed
                    ? failure("connect", connect_error)
                    : wait_failure("connect", waited, 0);
                if (waited != Wait::failed)
                    return Socket{};
                continue;
            }
        }
        return socket;
    }
    return Socket{};
}

void graceful_close(Socket &socket, std::chrono::milliseconds linger)
{
    if (!socket.valid())
        return;

    os::set_non_blocking(socket.get(), true);
    ::shutdown(socket.get(), os::kShutdownSend);

    const Deadline deadline = Clock::now() + linger;
    char buffer[2048];
    std::size_t drained = 0;
    while (drained < 64 * 1024)
    {
        const std::ptrdiff_t result = os::recv_some(socket.get(), buffer, sizeof(buffer));
        if (result > 0)
        {
            drained += static_cast<std::size_t>(result);
            continue;
        }
        if (result == 0)
            break;

        const int code = os::last_error();
        if (os::is_interrupted(code))
            continue;
        int ignored = 0;
        if (!os::is_would_block(code)
            || wait_socket(socket.get(), POLLIN, deadline, nullptr, ignored) != Wait::ready)
        {
            break;
        }
    }
    socket.reset();
}

std::string format_ipv4(const std::array<std::uint8_t, 4> &address)
{
    char text[16];
    std::snprintf(
        text,
        sizeof(text),
        "%u.%u.%u.%u",
        static_cast<unsigned>(address[0]),
        static_cast<unsigned>(address[1]),
        static_cast<unsigned>(address[2]),
        static_cast<unsigned>(address[3]));
    return text;
}

std::string format_ipv6(const std::array<std::uint8_t, 16> &address)
{
    std::array<unsigned, 8> words{};
    for (std::size_t i = 0; i < words.size(); ++i)
        words[i] = (static_cast<unsigned>(address[i * 2]) << 8) | address[i * 2 + 1];

    // Longest run of zero words (first one wins a tie), only if >= 2 long.
    int best_base = -1;
    int best_length = 0;
    int current_base = -1;
    int current_length = 0;
    for (int i = 0; i < 8; ++i)
    {
        if (words[static_cast<std::size_t>(i)] == 0)
        {
            if (current_base < 0)
            {
                current_base = i;
                current_length = 1;
            }
            else
            {
                ++current_length;
            }
            continue;
        }
        if (current_base >= 0 && current_length > best_length)
        {
            best_base = current_base;
            best_length = current_length;
        }
        current_base = -1;
    }
    if (current_base >= 0 && current_length > best_length)
    {
        best_base = current_base;
        best_length = current_length;
    }
    if (best_length < 2)
        best_base = -1;

    std::string text;
    char word[8];
    for (int i = 0; i < 8; ++i)
    {
        if (best_base >= 0 && i >= best_base && i < best_base + best_length)
        {
            if (i == best_base)
                text += ':';
            continue;
        }
        if (i != 0)
            text += ':';
        if (i == 6 && best_base == 0
            && (best_length == 6 || (best_length == 5 && words[5] == 0xffff)))
        {
            text += format_ipv4({address[12], address[13], address[14], address[15]});
            return text;
        }
        std::snprintf(word, sizeof(word), "%x", words[static_cast<std::size_t>(i)]);
        text += word;
    }
    if (best_base >= 0 && best_base + best_length == 8)
        text += ':';
    return text;
}

std::optional<std::string> pack_ip_address(int family, const std::string &text)
{
    std::array<std::uint8_t, 16> bytes{};
    if (family == 4 && parse_ipv4(text, bytes.data()))
        return std::string(reinterpret_cast<const char *>(bytes.data()), 4);
    if (family == 6 && parse_ipv6(text, bytes.data()))
        return std::string(reinterpret_cast<const char *>(bytes.data()), 16);
    return std::nullopt;
}

TcpServer::~TcpServer()
{
    stop();
}

void TcpServer::start(ServerOptions options, Handler handler)
{
    if (running())
        throw std::runtime_error("TCP 服务已经启动");
    if (options.worker_count == 0
        || options.max_pending == 0
        || options.max_connections == 0
        || options.delimiter.empty()
        || options.max_request_size == 0
        || !handler)
    {
        throw std::runtime_error("无效的 TCP 服务配置");
    }

    stop();
    listener_ = create_listener(options.bind_address, options.port);
    options_ = std::move(options);
    handler_ = std::move(handler);
    stopping_.store(false);
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_ = {};
    }

    try
    {
        workers_.reserve(options_.worker_count);
        for (std::size_t i = 0; i < options_.worker_count; ++i)
            workers_.emplace_back(&TcpServer::worker_loop, this);
        io_thread_ = std::thread(&TcpServer::io_loop, this);
    }
    catch (...)
    {
        stop();
        throw;
    }
    running_.store(true);
}

void TcpServer::stop()
{
    stopping_.store(true);

    // The listener is closed only after the I/O thread has exited, so no
    // thread can poll or accept on a descriptor number the OS has reused.
    if (io_thread_.joinable())
        io_thread_.join();
    listener_.reset();

    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
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
    running_.store(false);
}

bool TcpServer::running() const
{
    return running_.load();
}

ServerStats TcpServer::stats() const
{
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void TcpServer::io_loop()
{
    std::vector<Reading> reading;
    std::vector<os::pollfd_t> descriptors;
    std::vector<bool> finished;
    Deadline accept_paused_until{};
    char buffer[4096];

    while (!stopping_.load())
    {
        Deadline now = Clock::now();
        std::uint64_t expired = 0;
        reading.erase(
            std::remove_if(reading.begin(), reading.end(), [&](const Reading &item) {
                const bool late = item.deadline <= now;
                expired += late ? 1 : 0;
                return late;
            }),
            reading.end());
        if (expired > 0)
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.timed_out += expired;
        }

        Deadline wake = now + kIoTick;
        for (const Reading &item : reading)
            wake = std::min(wake, item.deadline);

        const bool poll_listener =
            reading.size() < options_.max_connections && now >= accept_paused_until;
        if (!poll_listener && now < accept_paused_until)
            wake = std::min(wake, accept_paused_until);

        descriptors.clear();
        if (poll_listener)
        {
            os::pollfd_t descriptor{};
            descriptor.fd = listener_.get();
            descriptor.events = POLLIN;
            descriptors.push_back(descriptor);
        }
        for (const Reading &item : reading)
        {
            os::pollfd_t descriptor{};
            descriptor.fd = item.socket.get();
            descriptor.events = POLLIN;
            descriptors.push_back(descriptor);
        }

        const int timeout_ms = poll_timeout(wake, nullptr, kIoTick);
        if (descriptors.empty())
        {
            // WSAPoll rejects an empty set; sleep instead on every platform.
            std::this_thread::sleep_for(std::chrono::milliseconds(timeout_ms));
            continue;
        }

        const int ready = os::poll(descriptors.data(), descriptors.size(), timeout_ms);
        if (ready < 0)
        {
            if (!os::is_interrupted(os::last_error()))
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        if (ready == 0)
            continue;

        const std::size_t offset = poll_listener ? 1 : 0;
        finished.assign(reading.size(), false);
        for (std::size_t i = 0; i < reading.size(); ++i)
        {
            if (descriptors[offset + i].revents == 0)
                continue;

            Reading &item = reading[i];
            while (true)
            {
                const std::size_t room = options_.max_request_size - item.buffer.size();
                if (room == 0)
                {
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    ++stats_.oversized;
                    finished[i] = true;
                    break;
                }

                const std::ptrdiff_t result =
                    os::recv_some(item.socket.get(), buffer, std::min(room, sizeof(buffer)));
                if (result > 0)
                {
                    const std::size_t search_from = item.buffer.size() >= options_.delimiter.size()
                        ? item.buffer.size() - options_.delimiter.size() + 1
                        : 0;
                    item.buffer.append(buffer, static_cast<std::size_t>(result));
                    if (item.buffer.find(options_.delimiter, search_from) != std::string::npos)
                    {
                        dispatch(Connection{
                            std::move(item.socket),
                            std::move(item.remote),
                            std::move(item.buffer)});
                        finished[i] = true;
                        break;
                    }
                    continue;
                }

                const int code = result < 0 ? os::last_error() : 0;
                if (result < 0 && os::is_interrupted(code))
                    continue;
                if (result < 0 && os::is_would_block(code))
                    break;

                std::lock_guard<std::mutex> lock(stats_mutex_);
                ++stats_.closed_early;
                finished[i] = true;
                break;
            }
        }

        std::size_t kept = 0;
        for (std::size_t i = 0; i < reading.size(); ++i)
        {
            if (finished[i])
                continue;
            if (kept != i)
                reading[kept] = std::move(reading[i]);
            ++kept;
        }
        reading.erase(reading.begin() + static_cast<std::ptrdiff_t>(kept), reading.end());

        if (poll_listener && descriptors[0].revents != 0)
        {
            now = Clock::now();
            accept_ready(reading, now, accept_paused_until);
        }
    }
}

void TcpServer::accept_ready(
    std::vector<Reading> &reading,
    Deadline now,
    Deadline &accept_paused_until)
{
    for (int i = 0; i < kAcceptBurst && reading.size() < options_.max_connections; ++i)
    {
        sockaddr_storage address{};
        os::socklen address_length = sizeof(address);
        Socket socket(::accept(
            listener_.get(),
            reinterpret_cast<sockaddr *>(&address),
            &address_length));
        if (!socket.valid())
        {
            const int code = os::last_error();
            if (os::is_would_block(code) || os::is_interrupted(code))
                return;
            // Out of descriptors (or any other persistent accept failure):
            // back off instead of spinning on a listener that stays readable.
            accept_paused_until = now
                + (os::is_resource_exhausted(code) ? kAcceptBackoff : kAcceptBackoff / 10);
            return;
        }

        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            ++stats_.accepted;
        }
        // Linux accept() does not inherit O_NONBLOCK, Windows does: set it.
        if (!os::set_non_blocking(socket.get(), true))
            continue;
        os::set_no_inherit(socket.get());
        configure_no_sigpipe(socket.get());

        Reading item;
        item.socket = std::move(socket);
        item.remote = remote_endpoint(address);
        item.deadline = now + options_.request_timeout;
        reading.push_back(std::move(item));
    }
}

bool TcpServer::dispatch(Connection connection)
{
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        if (stopping_.load() || queue_.size() >= options_.max_pending)
        {
            std::lock_guard<std::mutex> stats_lock(stats_mutex_);
            ++stats_.rejected;
            return false;
        }
        queue_.push_back(std::move(connection));
    }
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        ++stats_.dispatched;
    }
    queue_condition_.notify_one();
    return true;
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
            handler_(connection);
        }
        catch (...)
        {
        }
        graceful_close(connection.socket, options_.close_linger);
    }
}

} // namespace simple_net
