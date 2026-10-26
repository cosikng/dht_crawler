#pragma once

#include "file_index.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

struct sqlite3;
struct sqlite3_stmt;

// SQLite persistence for the crawler. All database work happens on two
// threads that each own a private connection and prepared statements: a
// reader that answers "is this info-hash already stored?" and a writer that
// optionally publishes .torrent files and inserts rows in batched
// transactions. Callers
// only enqueue (never block), both queues are bounded, and results come back
// through callbacks on the storage threads.
//
// The table layout is unchanged:
//   torrents(info_hash TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL,
//            discovered_peer TEXT NOT NULL,
//            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)
namespace storage
{

using InfoHash = std::array<std::uint8_t, 20>;

std::string to_hex(const InfoHash &hash);

enum class LookupResult
{
    absent,
    present,
    error
};

struct PersistJob
{
    InfoHash hash{};
    // Session that produced the job, for log messages.
    int origin = 0;
    std::string hash_hex;
    std::string name;
    std::string peer;
    // Bencoded .torrent; only used when Options::torrent_dir is set.
    std::vector<char> torrent_file;
    // Stored in the file index when Options::file_index_path is set.
    std::optional<file_index::Entry> file_list;
};

struct Options
{
    std::filesystem::path database_path;
    // Where <info_hash>.torrent files are written; empty: not written.
    std::filesystem::path torrent_dir;
    // File index database (see file_index.hpp); empty: disabled. Each
    // batch's file lists are committed before its crawler rows, so a hash
    // with a crawler row always has its file list.
    std::filesystem::path file_index_path;
    std::size_t max_lookups = 65536;
    std::size_t max_persist_jobs = 4096;
    std::size_t max_persist_bytes = std::size_t{256} << 20;
    std::size_t batch_size = 64;
    std::chrono::milliseconds batch_delay{100};
    std::chrono::milliseconds busy_timeout{5000};
    std::chrono::seconds checkpoint_interval{30};
    std::int64_t journal_size_limit = std::int64_t{64} << 20;
    std::uint64_t truncate_wal_above = std::uint64_t{64} << 20;
    // How long stop() keeps retrying a locked database before giving up on
    // the remaining queued rows.
    std::chrono::seconds drain_timeout{10};
};

struct Stats
{
    std::size_t queued_lookups = 0;
    std::size_t queued_jobs = 0;
    std::size_t queued_bytes = 0;
    std::uint64_t lookups = 0;
    std::uint64_t lookup_errors = 0;
    std::uint64_t persisted = 0;
    std::uint64_t persist_failures = 0;
    std::uint64_t rejected_lookups = 0;
    std::uint64_t rejected_jobs = 0;
    std::uint64_t busy_retries = 0;
    std::uint64_t checkpoints = 0;
    std::uint64_t wal_bytes = 0;
};

class Storage
{
public:
    // Called on the reader thread.
    using LookupHandler = std::function<void(int tag, const InfoHash &, LookupResult)>;
    // Called on the writer thread once the job is durable in SQLite (true)
    // or has definitely failed (false).
    using PersistHandler = std::function<void(const PersistJob &, bool persisted)>;

    // Opens the database (WAL, schema) synchronously; throws on failure.
    Storage(Options options, LookupHandler on_lookup, PersistHandler on_persist);
    ~Storage();

    Storage(const Storage &) = delete;
    Storage &operator=(const Storage &) = delete;

    // Non-blocking; false when the queue is full or storage is stopping.
    bool submit_lookup(int tag, const InfoHash &hash);
    // Moves from `job` only when accepted.
    bool submit_persist(PersistJob &job);
    // True while the write queue is above its high-water mark; producers
    // should stop starting work that ends in a write.
    bool under_pressure() const;

    // Discards queued lookups, writes every queued job (retrying a locked
    // database for up to drain_timeout), checkpoints and truncates the WAL,
    // then joins both threads. Idempotent.
    void stop();

    Stats stats() const;

private:
    class Connection;
    class Statement;

    struct Lookup
    {
        int tag;
        InfoHash hash;
    };

    void reader_loop();
    void writer_loop();
    void process_batch(std::vector<PersistJob> &batch);
    void report(const PersistJob &job, bool persisted) noexcept;
    bool write_file_lists(const std::vector<PersistJob *> &rows);
    // Runs `attempt` (returning an SQLite result code) until it succeeds,
    // retrying a locked database and up to 3 other failures.
    bool commit_with_retry(const char *label, const std::function<int(std::string &)> &attempt);
    int try_insert(const std::vector<PersistJob *> &rows, std::string &error);
    static std::size_t job_bytes(const PersistJob &job);
    void checkpoint(bool final_checkpoint);
    std::uint64_t wal_size() const;

    Options options_;
    LookupHandler on_lookup_;
    PersistHandler on_persist_;

    std::unique_ptr<Connection> writer_;
    std::unique_ptr<file_index::FileIndex> file_index_;
    std::unique_ptr<Connection> reader_;
    std::unique_ptr<Statement> insert_statement_;
    std::unique_ptr<Statement> contains_statement_;

    std::mutex read_mutex_;
    std::condition_variable read_condition_;
    std::deque<Lookup> lookups_;
    bool read_stopping_ = false;

    std::mutex write_mutex_;
    std::condition_variable write_condition_;
    std::deque<PersistJob> jobs_;
    std::size_t queued_bytes_ = 0;
    bool write_stopping_ = false;
    std::chrono::steady_clock::time_point drain_deadline_{};

    std::atomic<std::size_t> queued_lookup_count_{0};
    std::atomic<std::size_t> queued_job_count_{0};
    std::atomic<std::size_t> queued_byte_count_{0};
    std::atomic<std::uint64_t> lookups_done_{0};
    std::atomic<std::uint64_t> lookup_errors_{0};
    std::atomic<std::uint64_t> persisted_{0};
    std::atomic<std::uint64_t> persist_failures_{0};
    std::atomic<std::uint64_t> rejected_lookups_{0};
    std::atomic<std::uint64_t> rejected_jobs_{0};
    std::atomic<std::uint64_t> busy_retries_{0};
    std::atomic<std::uint64_t> checkpoints_{0};
    std::atomic<std::uint64_t> wal_bytes_{0};
    // Writer-thread state.
    int starved_checkpoints_ = 0;
    bool abandon_writes_ = false;

    std::mutex stop_mutex_;
    bool stopped_ = false;
    std::thread reader_thread_;
    std::thread writer_thread_;
};

} // namespace storage
