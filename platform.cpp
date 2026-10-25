#include "platform.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <system_error>
#include <thread>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#else
#include <csignal>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace platform
{
namespace
{

constexpr int kForcedExitCode = 130;
constexpr auto kShutdownPollSlice = std::chrono::milliseconds(50);

std::atomic<bool> g_shutdown_requested{false};
std::atomic<int> g_shutdown_signals{0};
std::atomic<const char *> g_shutdown_reason{nullptr};

static_assert(std::atomic<bool>::is_always_lock_free, "signal handlers need lock-free atomics");
static_assert(std::atomic<int>::is_always_lock_free, "signal handlers need lock-free atomics");
static_assert(std::atomic<const char *>::is_always_lock_free, "signal handlers need lock-free atomics");

void record_shutdown(const char *reason) noexcept
{
    const char *expected = nullptr;
    g_shutdown_reason.compare_exchange_strong(expected, reason);
    g_shutdown_requested.store(true);
}

[[noreturn]] void force_exit() noexcept
{
#if defined(_WIN32)
    ::TerminateProcess(::GetCurrentProcess(), kForcedExitCode);
#endif
    ::_exit(kForcedExitCode);
}

// Async-signal-safe: only lock-free atomics and _exit().
void on_shutdown_signal(const char *reason) noexcept
{
    if (g_shutdown_signals.fetch_add(1) > 0)
        force_exit();
    record_shutdown(reason);
}

#if defined(_WIN32)

HANDLE g_cleanup_done = nullptr;

std::wstring utf8_to_wide(std::string_view text)
{
    if (text.empty())
        return {};
    const int size = ::MultiByteToWideChar(
        CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring wide(static_cast<std::size_t>(std::max(size, 0)), L'\0');
    if (size > 0)
    {
        ::MultiByteToWideChar(
            CP_UTF8, 0, text.data(), static_cast<int>(text.size()), wide.data(), size);
    }
    return wide;
}

std::string wide_to_utf8(std::wstring_view wide)
{
    if (wide.empty())
        return {};
    const int size = ::WideCharToMultiByte(
        CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    std::string text(static_cast<std::size_t>(std::max(size, 0)), '\0');
    if (size > 0)
    {
        ::WideCharToMultiByte(
            CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), text.data(), size, nullptr, nullptr);
    }
    return text;
}

BOOL WINAPI console_handler(DWORD event)
{
    switch (event)
    {
    case CTRL_C_EVENT:
        on_shutdown_signal("CTRL_C_EVENT");
        return TRUE;
    case CTRL_BREAK_EVENT:
        on_shutdown_signal("CTRL_BREAK_EVENT");
        return TRUE;
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        on_shutdown_signal(
            event == CTRL_CLOSE_EVENT ? "CTRL_CLOSE_EVENT"
            : event == CTRL_LOGOFF_EVENT ? "CTRL_LOGOFF_EVENT"
                                         : "CTRL_SHUTDOWN_EVENT");
        // Windows terminates the process as soon as this handler returns;
        // hold it until main() has flushed state (the OS still enforces its
        // own hard deadline).
        if (g_cleanup_done)
            ::WaitForSingleObject(g_cleanup_done, INFINITE);
        return TRUE;
    default:
        return FALSE;
    }
}

void write_handle(DWORD which, std::string_view text)
{
    const HANDLE handle = ::GetStdHandle(which);
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE || text.empty())
        return;

    DWORD mode = 0;
    if (::GetConsoleMode(handle, &mode))
    {
        const std::wstring wide = utf8_to_wide(text);
        std::size_t offset = 0;
        while (offset < wide.size())
        {
            const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(wide.size() - offset, 8192));
            DWORD written = 0;
            if (!::WriteConsoleW(handle, wide.data() + offset, chunk, &written, nullptr) || written == 0)
                return;
            offset += written;
        }
        return;
    }

    std::size_t offset = 0;
    while (offset < text.size())
    {
        const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(text.size() - offset, 1u << 20));
        DWORD written = 0;
        if (!::WriteFile(handle, text.data() + offset, chunk, &written, nullptr) || written == 0)
            return;
        offset += written;
    }
}

std::string file_error_text(DWORD code)
{
    switch (code)
    {
    case ERROR_ACCESS_DENIED:
        return "permission denied";
    case ERROR_SHARING_VIOLATION:
    case ERROR_LOCK_VIOLATION:
        return "file is in use";
    case ERROR_DISK_FULL:
    case ERROR_HANDLE_DISK_FULL:
        return "no space left on device";
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
        return "no such file or directory";
    case ERROR_FILE_EXISTS:
    case ERROR_ALREADY_EXISTS:
        return "file exists";
    case ERROR_WRITE_PROTECT:
        return "read-only file system";
    default:
        break;
    }
    return "os error " + std::to_string(code) + " ("
        + std::system_category().message(static_cast<int>(code)) + ")";
}

bool is_transient_lock(DWORD code)
{
    return code == ERROR_ACCESS_DENIED
        || code == ERROR_SHARING_VIOLATION
        || code == ERROR_LOCK_VIOLATION;
}

void write_new_file(const fs::path &path, std::string_view data, bool durable)
{
    const HANDLE file = ::CreateFileW(
        path.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        throw std::runtime_error(
            "无法创建临时文件 " + path_to_utf8(path) + ": " + file_error_text(::GetLastError()));
    }

    std::string error;
    std::size_t offset = 0;
    while (offset < data.size() && error.empty())
    {
        const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(data.size() - offset, 1u << 30));
        DWORD written = 0;
        if (!::WriteFile(file, data.data() + offset, chunk, &written, nullptr) || written == 0)
            error = file_error_text(::GetLastError());
        offset += written;
    }
    if (error.empty() && durable && !::FlushFileBuffers(file))
        error = file_error_text(::GetLastError());
    if (!::CloseHandle(file) && error.empty())
        error = file_error_text(::GetLastError());

    if (!error.empty())
    {
        ::DeleteFileW(path.c_str());
        throw std::runtime_error("写入临时文件失败 " + path_to_utf8(path) + ": " + error);
    }
}

bool replace_file(const fs::path &from, const fs::path &to, bool durable, std::string &error)
{
    // MoveFileExW with REPLACE_EXISTING is the atomic rename-over that POSIX
    // rename() provides; plain rename() fails on Windows when `to` exists.
    const DWORD flags = MOVEFILE_REPLACE_EXISTING | (durable ? MOVEFILE_WRITE_THROUGH : 0);
    DWORD code = ERROR_SUCCESS;
    for (int attempt = 0; attempt < 20; ++attempt)
    {
        if (::MoveFileExW(from.c_str(), to.c_str(), flags))
            return true;
        code = ::GetLastError();
        if (!is_transient_lock(code))
            break;
        ::Sleep(static_cast<DWORD>(std::min(10 * (attempt + 1), 100)));
    }
    error = file_error_text(code);
    return false;
}

void sync_parent_directory(const fs::path &)
{
    // MOVEFILE_WRITE_THROUGH already flushed the rename.
}

#else

void handle_signal(int signal_number)
{
    on_shutdown_signal(
        signal_number == SIGINT ? "SIGINT"
        : signal_number == SIGTERM ? "SIGTERM"
        : signal_number == SIGHUP ? "SIGHUP"
                                  : "signal");
}

void write_fd(int fd, std::string_view text)
{
    std::size_t offset = 0;
    while (offset < text.size())
    {
        const ssize_t written = ::write(fd, text.data() + offset, text.size() - offset);
        if (written > 0)
        {
            offset += static_cast<std::size_t>(written);
            continue;
        }
        if (written < 0 && errno == EINTR)
            continue;
        return;
    }
}

std::string file_error_text(int code)
{
    switch (code)
    {
    case EACCES:
    case EPERM:
        return "permission denied";
    case ETXTBSY:
        return "file is in use";
    case ENOSPC:
        return "no space left on device";
    case ENOENT:
        return "no such file or directory";
    case EEXIST:
        return "file exists";
    case EROFS:
        return "read-only file system";
    default:
        break;
    }
    return "os error " + std::to_string(code) + " (" + std::generic_category().message(code) + ")";
}

void write_new_file(const fs::path &path, std::string_view data, bool durable)
{
    const int file = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (file < 0)
    {
        throw std::runtime_error(
            "无法创建临时文件 " + path_to_utf8(path) + ": " + file_error_text(errno));
    }

    std::string error;
    std::size_t offset = 0;
    while (offset < data.size() && error.empty())
    {
        const ssize_t written = ::write(file, data.data() + offset, data.size() - offset);
        if (written > 0)
            offset += static_cast<std::size_t>(written);
        else if (written < 0 && errno == EINTR)
            continue;
        else
            error = file_error_text(written < 0 ? errno : ENOSPC);
    }
    if (error.empty() && durable && ::fsync(file) != 0)
        error = file_error_text(errno);
    if (::close(file) != 0 && error.empty())
        error = file_error_text(errno);

    if (!error.empty())
    {
        ::unlink(path.c_str());
        throw std::runtime_error("写入临时文件失败 " + path_to_utf8(path) + ": " + error);
    }
}

bool replace_file(const fs::path &from, const fs::path &to, bool, std::string &error)
{
    if (::rename(from.c_str(), to.c_str()) == 0)
        return true;
    error = file_error_text(errno);
    return false;
}

void sync_parent_directory(const fs::path &target)
{
    fs::path directory = target.parent_path();
    if (directory.empty())
        directory = ".";
    const int handle = ::open(directory.c_str(), O_RDONLY | O_CLOEXEC);
    if (handle < 0)
        return;
    ::fsync(handle);
    ::close(handle);
}

#endif

} // namespace

void install_shutdown_handlers()
{
#if defined(_WIN32)
    if (!g_cleanup_done)
        g_cleanup_done = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!::SetConsoleCtrlHandler(console_handler, TRUE))
        throw std::runtime_error("SetConsoleCtrlHandler 失败");
#else
    struct sigaction action{};
    action.sa_handler = handle_signal;
    sigemptyset(&action.sa_mask);
    // No SA_RESTART: blocking calls return EINTR, which every caller retries.
    action.sa_flags = 0;
    for (const int signal_number : {SIGINT, SIGTERM, SIGHUP})
    {
        if (::sigaction(signal_number, &action, nullptr) != 0)
            throw std::runtime_error("sigaction 失败");
    }

    struct sigaction ignore{};
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&ignore.sa_mask);
    ::sigaction(SIGPIPE, &ignore, nullptr);
#endif
}

bool shutdown_requested() noexcept
{
    return g_shutdown_requested.load();
}

void request_shutdown() noexcept
{
    record_shutdown("request");
}

bool wait_for_shutdown(std::chrono::milliseconds timeout)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!shutdown_requested())
    {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline)
            break;
        std::this_thread::sleep_for(std::min<std::chrono::steady_clock::duration>(
            deadline - now, kShutdownPollSlice));
    }
    return shutdown_requested();
}

const char *shutdown_reason() noexcept
{
    const char *reason = g_shutdown_reason.load();
    return reason ? reason : "none";
}

void notify_shutdown_complete() noexcept
{
#if defined(_WIN32)
    if (g_cleanup_done)
        ::SetEvent(g_cleanup_done);
#endif
}

std::vector<std::string> utf8_arguments(int argc, char **argv)
{
#if defined(_WIN32)
    int count = 0;
    LPWSTR *wide = ::CommandLineToArgvW(::GetCommandLineW(), &count);
    if (wide)
    {
        std::vector<std::string> arguments;
        arguments.reserve(static_cast<std::size_t>(count));
        for (int i = 0; i < count; ++i)
            arguments.push_back(wide_to_utf8(wide[i]));
        ::LocalFree(wide);
        if (count == argc)
            return arguments;
    }
#endif
    return std::vector<std::string>(argv, argv + argc);
}

std::string path_to_utf8(const fs::path &path)
{
#if defined(_WIN32)
    return wide_to_utf8(path.native());
#else
    return path.string();
#endif
}

fs::path path_from_utf8(std::string_view text)
{
#if defined(_WIN32)
    return fs::path(utf8_to_wide(text));
#else
    return fs::path(std::string(text));
#endif
}

void write_stdout(std::string_view text)
{
#if defined(_WIN32)
    write_handle(STD_OUTPUT_HANDLE, text);
#else
    write_fd(STDOUT_FILENO, text);
#endif
}

void write_stderr(std::string_view text)
{
#if defined(_WIN32)
    write_handle(STD_ERROR_HANDLE, text);
#else
    write_fd(STDERR_FILENO, text);
#endif
}

std::uint64_t raise_open_file_limit()
{
#if defined(_WIN32)
    return 0;
#else
    rlimit limit{};
    if (::getrlimit(RLIMIT_NOFILE, &limit) != 0)
        return 0;
    rlim_t target = limit.rlim_max;
    if (target == RLIM_INFINITY || target > (rlim_t{1} << 20))
        target = rlim_t{1} << 20;
    if (limit.rlim_cur != RLIM_INFINITY && limit.rlim_cur < target)
    {
        rlimit raised = limit;
        raised.rlim_cur = target;
        ::setrlimit(RLIMIT_NOFILE, &raised);
        ::getrlimit(RLIMIT_NOFILE, &limit);
    }
    return static_cast<std::uint64_t>(limit.rlim_cur);
#endif
}

std::uint32_t process_id() noexcept
{
#if defined(_WIN32)
    return static_cast<std::uint32_t>(::GetCurrentProcessId());
#else
    return static_cast<std::uint32_t>(::getpid());
#endif
}

void write_file_atomic(const fs::path &target, std::string_view data, bool durable)
{
    static std::atomic<std::uint64_t> counter{0};

    fs::path temporary = target;
    temporary += "." + std::to_string(process_id())
        + "." + std::to_string(counter.fetch_add(1)) + ".tmp";

    write_new_file(temporary, data, durable);

    std::string error;
    if (!replace_file(temporary, target, durable, error))
    {
        std::error_code ignored;
        fs::remove(temporary, ignored);
        throw std::runtime_error("发布文件失败 " + path_to_utf8(target) + ": " + error);
    }
    if (durable)
        sync_parent_directory(target);
}

std::size_t remove_stale_temp_files(const fs::path &directory)
{
    std::size_t removed = 0;
    std::error_code error;
    for (fs::directory_iterator iterator(directory, error), end; !error && iterator != end;
         iterator.increment(error))
    {
        std::error_code status_error;
        if (iterator->path().extension() != ".tmp" || !iterator->is_regular_file(status_error))
            continue;
        std::error_code remove_error;
        if (fs::remove(iterator->path(), remove_error))
            ++removed;
    }
    return removed;
}

} // namespace platform
