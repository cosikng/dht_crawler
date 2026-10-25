#pragma once

// Process-level services whose native APIs differ between Windows and POSIX:
// shutdown signals, UTF-8 command line/paths/console output and crash-safe
// file replacement. Callers get identical behaviour on both platforms.

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace platform
{

// Installs the graceful-shutdown handlers: SIGINT/SIGTERM on POSIX (SIGPIPE
// is ignored, as Windows has none), and a console control handler on
// Windows covering Ctrl+C, Ctrl+Break, console close, logoff and system
// shutdown. The first request starts a graceful shutdown; a second one
// terminates the process immediately with exit code 130.
void install_shutdown_handlers();
bool shutdown_requested() noexcept;
void request_shutdown() noexcept;
// Sleeps until a shutdown is requested or `timeout` elapses; returns
// shutdown_requested().
bool wait_for_shutdown(std::chrono::milliseconds timeout);
// Name of the event that requested shutdown ("SIGINT", "CTRL_CLOSE_EVENT"...).
const char *shutdown_reason() noexcept;
// Windows ends the process as soon as a close/logoff/shutdown handler
// returns, so that handler blocks until this is called after cleanup.
void notify_shutdown_complete() noexcept;

// Calls notify_shutdown_complete() on scope exit, whatever path main() takes.
class ShutdownCompletionGuard
{
public:
    ShutdownCompletionGuard() = default;
    ~ShutdownCompletionGuard()
    {
        notify_shutdown_complete();
    }
    ShutdownCompletionGuard(const ShutdownCompletionGuard &) = delete;
    ShutdownCompletionGuard &operator=(const ShutdownCompletionGuard &) = delete;
};

// Command line as UTF-8 (Windows argv is in the ANSI code page).
std::vector<std::string> utf8_arguments(int argc, char **argv);

std::string path_to_utf8(const std::filesystem::path &path);
std::filesystem::path path_from_utf8(std::string_view text);

// Writes complete UTF-8 text to stdout/stderr. On a Windows console this
// uses WriteConsoleW so the console code page does not matter; redirected
// output receives the raw bytes with "\n" line endings on both platforms.
void write_stdout(std::string_view text);
void write_stderr(std::string_view text);

// Raises the soft open-file limit to the hard limit on POSIX (the 1024
// default is far below what many libtorrent sessions need; Windows has no
// comparable per-process socket limit). Returns the resulting limit, or 0
// where not applicable.
std::uint64_t raise_open_file_limit();

std::uint32_t process_id() noexcept;

// Writes `data` to a uniquely named temporary file next to `target` and
// atomically replaces `target` with it, so readers only ever see the old or
// the new complete file. Replacing an existing file works on Windows too
// (MoveFileExW, retried while antivirus/indexers briefly hold the file).
// With `durable`, data is flushed to stable storage before the rename (and
// the directory entry afterwards on POSIX). Throws std::runtime_error.
void write_file_atomic(
    const std::filesystem::path &target,
    std::string_view data,
    bool durable);

// Removes leftover "*.tmp" files written by write_file_atomic() in `directory`
// (e.g. after a crash). Returns the number removed.
std::size_t remove_stale_temp_files(const std::filesystem::path &directory);

} // namespace platform
