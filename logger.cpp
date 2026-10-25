#include "logger.hpp"

#include "platform.hpp"

#include <algorithm>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

namespace logging
{
namespace
{

struct Entry
{
    Stream stream;
    std::string text;
};

struct State
{
    std::mutex mutex;
    std::condition_variable condition;
    std::vector<Entry> queue;
    std::thread writer;
    bool running = false;
    bool stopping = false;
    std::size_t max_queued = 16384;
    std::uint64_t dropped = 0;
    // Serialises the actual console/pipe writes of the writer thread and of
    // synchronous callers.
    std::mutex output_mutex;

    void stop_writer()
    {
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (!running)
                return;
            stopping = true;
        }
        condition.notify_all();
        if (writer.joinable())
            writer.join();

        std::lock_guard<std::mutex> lock(mutex);
        running = false;
        stopping = false;
    }

    ~State()
    {
        stop_writer();
    }
};

State &state()
{
    static State instance;
    return instance;
}

void emit(Stream stream, std::string_view text)
{
    if (stream == Stream::out)
        platform::write_stdout(text);
    else
        platform::write_stderr(text);
}

void writer_loop()
{
    State &log = state();
    std::vector<Entry> batch;
    std::uint64_t reported_dropped = 0;
    while (true)
    {
        std::uint64_t dropped = 0;
        {
            std::unique_lock<std::mutex> lock(log.mutex);
            log.condition.wait(lock, [&log] {
                return log.stopping || !log.queue.empty();
            });
            if (log.queue.empty() && log.stopping)
                return;
            batch.swap(log.queue);
            dropped = log.dropped;
        }

        // Consecutive lines for the same stream go out in one write.
        std::lock_guard<std::mutex> output(log.output_mutex);
        std::string chunk;
        Stream current = batch.front().stream;
        for (Entry &entry : batch)
        {
            if (entry.stream != current && !chunk.empty())
            {
                emit(current, chunk);
                chunk.clear();
            }
            current = entry.stream;
            chunk += entry.text;
            chunk += '\n';
        }
        if (!chunk.empty())
            emit(current, chunk);
        batch.clear();

        if (dropped != reported_dropped)
        {
            emit(
                Stream::err,
                "[Log] 日志队列已满，累计丢弃 " + std::to_string(dropped) + " 行\n");
            reported_dropped = dropped;
        }
    }
}

} // namespace

void start(std::size_t max_queued)
{
    State &log = state();
    std::lock_guard<std::mutex> lock(log.mutex);
    if (log.running)
        return;
    log.max_queued = max_queued == 0 ? 1 : max_queued;
    log.stopping = false;
    log.writer = std::thread(writer_loop);
    log.running = true;
}

void stop()
{
    state().stop_writer();
}

void write(Stream stream, std::string line)
{
    State &log = state();
    {
        std::unique_lock<std::mutex> lock(log.mutex);
        if (log.running && !log.stopping)
        {
            if (log.queue.size() >= log.max_queued)
            {
                ++log.dropped;
                return;
            }
            log.queue.push_back(Entry{stream, std::move(line)});
            lock.unlock();
            log.condition.notify_one();
            return;
        }
    }

    line += '\n';
    std::lock_guard<std::mutex> output(log.output_mutex);
    emit(stream, line);
}

std::uint64_t dropped()
{
    State &log = state();
    std::lock_guard<std::mutex> lock(log.mutex);
    return log.dropped;
}

std::string sanitize(std::string_view text, std::size_t max_length)
{
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(std::min(text.size(), max_length) + 8);
    for (const char character : text)
    {
        if (result.size() >= max_length)
        {
            result += "...";
            break;
        }
        const auto byte = static_cast<unsigned char>(character);
        if (byte >= 0x20 && byte < 0x7f && byte != '\\')
        {
            result.push_back(character);
            continue;
        }
        result += "\\x";
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 0x0f]);
    }
    return result;
}

} // namespace logging
