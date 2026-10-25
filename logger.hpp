#pragma once

#include <cstddef>
#include <cstdint>
#include <sstream>
#include <string>
#include <string_view>

namespace logging
{

enum class Stream
{
    out,
    err
};

// Starts the background writer. Until then (and after stop()) lines are
// written synchronously. Lines are always emitted whole, so output from
// different threads never interleaves, and slow consoles (notably the
// Windows console) never block the threads that log: once `max_queued`
// lines are waiting, further lines are dropped and counted.
void start(std::size_t max_queued = 16384);
// Flushes everything queued and joins the writer.
void stop();
void write(Stream stream, std::string line);
std::uint64_t dropped();

class Line
{
public:
    explicit Line(Stream stream)
        : stream_(stream)
    {
    }

    ~Line()
    {
        write(stream_, buffer_.str());
    }

    Line(const Line &) = delete;
    Line &operator=(const Line &) = delete;

    template <typename Value>
    Line &operator<<(const Value &value)
    {
        buffer_ << value;
        return *this;
    }

private:
    Stream stream_;
    std::ostringstream buffer_;
};

inline Line info()
{
    return Line(Stream::out);
}

inline Line error()
{
    return Line(Stream::err);
}

// Escapes control characters and non-ASCII bytes so peer-supplied text
// cannot forge log lines or inject terminal escape sequences.
std::string sanitize(std::string_view text, std::size_t max_length = 128);

} // namespace logging
