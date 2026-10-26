#include "crawler_storage.hpp"

#include "logger.hpp"
#include "platform.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <fstream>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <utility>

namespace fs = std::filesystem;

namespace storage
{
namespace
{

constexpr std::size_t kLookupBatch = 256;
constexpr auto kBusyBackoffMax = std::chrono::milliseconds(2000);
constexpr auto kBusyLogInterval = std::chrono::seconds(30);
constexpr int kStarvedCheckpointWarning = 4;

int primary_code(int code)
{
    return code & 0xff;
}

bool is_busy(int code)
{
    return primary_code(code) == SQLITE_BUSY || primary_code(code) == SQLITE_LOCKED;
}

} // namespace

std::string to_hex(const InfoHash &hash)
{
    static constexpr char digits[] = "0123456789abcdef";
    std::string text(hash.size() * 2, '0');
    for (std::size_t i = 0; i < hash.size(); ++i)
    {
        text[i * 2] = digits[hash[i] >> 4];
        text[i * 2 + 1] = digits[hash[i] & 0x0f];
    }
    return text;
}

class Storage::Connection
{
public:
    Connection(const fs::path &path, std::chrono::milliseconds busy_timeout)
    {
        // SQLite expects UTF-8 file names on every platform.
        const std::string filename = platform::path_to_utf8(path);
        const int result = sqlite3_open_v2(
            filename.c_str(),
            &database_,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX,
            nullptr);
        if (result != SQLITE_OK)
        {
            const std::string message =
                database_ ? sqlite3_errmsg(database_) : "无法分配 SQLite handle";
            if (database_)
                sqlite3_close(database_);
            database_ = nullptr;
            throw std::runtime_error("数据库打开失败: " + message);
        }
        sqlite3_busy_timeout(database_, static_cast<int>(busy_timeout.count()));
    }

    ~Connection()
    {
        if (database_)
            sqlite3_close(database_);
    }

    Connection(const Connection &) = delete;
    Connection &operator=(const Connection &) = delete;

    sqlite3 *get() const
    {
        return database_;
    }

    // Returns the SQLite result code; `error` receives the message on failure.
    int execute(const char *sql, std::string &error)
    {
        char *message = nullptr;
        const int result = sqlite3_exec(database_, sql, nullptr, nullptr, &message);
        if (result != SQLITE_OK)
            error = message ? message : sqlite3_errmsg(database_);
        sqlite3_free(message);
        return result;
    }

    void execute(const char *sql)
    {
        std::string error;
        if (execute(sql, error) != SQLITE_OK)
            throw std::runtime_error(error);
    }

private:
    sqlite3 *database_ = nullptr;
};

class Storage::Statement
{
public:
    Statement(sqlite3 *database, const char *sql)
        : database_(database)
    {
        if (sqlite3_prepare_v2(database, sql, -1, &statement_, nullptr) != SQLITE_OK)
            throw std::runtime_error(sqlite3_errmsg(database));
    }

    ~Statement()
    {
        sqlite3_finalize(statement_);
    }

    Statement(const Statement &) = delete;
    Statement &operator=(const Statement &) = delete;

    sqlite3_stmt *get() const
    {
        return statement_;
    }

    // Resets on scope exit. A statement left un-reset after SQLITE_ROW keeps
    // its read transaction (and WAL snapshot) open, which stops checkpoints
    // from ever recycling the WAL file.
    class Use
    {
    public:
        explicit Use(Statement &statement)
            : statement_(statement.statement_)
        {
        }

        ~Use()
        {
            sqlite3_reset(statement_);
            sqlite3_clear_bindings(statement_);
        }

        Use(const Use &) = delete;
        Use &operator=(const Use &) = delete;

    private:
        sqlite3_stmt *statement_;
    };

private:
    sqlite3 *database_;
    sqlite3_stmt *statement_ = nullptr;
};

Storage::Storage(Options options, LookupHandler on_lookup, PersistHandler on_persist)
    : options_(std::move(options)),
      on_lookup_(std::move(on_lookup)),
      on_persist_(std::move(on_persist))
{
    writer_ = std::make_unique<Connection>(options_.database_path, options_.busy_timeout);
    writer_->execute("PRAGMA journal_mode=WAL;");
    // NORMAL is crash-safe in WAL mode; it only defers the fsync to the
    // checkpoint instead of every commit.
    writer_->execute("PRAGMA synchronous=NORMAL;");
    writer_->execute("PRAGMA wal_autocheckpoint=1000;");
    const std::string size_limit =
        "PRAGMA journal_size_limit=" + std::to_string(options_.journal_size_limit) + ";";
    writer_->execute(size_limit.c_str());
    writer_->execute(
        "CREATE TABLE IF NOT EXISTS torrents ("
        "info_hash TEXT PRIMARY KEY NOT NULL,"
        "name TEXT NOT NULL,"
        "discovered_peer TEXT NOT NULL,"
        "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP"
        ");");
    insert_statement_ = std::make_unique<Statement>(
        writer_->get(),
        "INSERT OR IGNORE INTO torrents "
        "(info_hash, name, discovered_peer) VALUES (?, ?, ?);");

    if (!options_.file_index_path.empty())
    {
        file_index_ = std::make_unique<file_index::FileIndex>(
            options_.file_index_path,
            file_index::FileIndex::Mode::read_write,
            options_.busy_timeout);
    }

    reader_ = std::make_unique<Connection>(options_.database_path, options_.busy_timeout);
    reader_->execute("PRAGMA query_only=1;");
    contains_statement_ = std::make_unique<Statement>(
        reader_->get(),
        "SELECT 1 FROM torrents WHERE info_hash = ? LIMIT 1;");

    reader_thread_ = std::thread(&Storage::reader_loop, this);
    try
    {
        writer_thread_ = std::thread(&Storage::writer_loop, this);
    }
    catch (...)
    {
        stop();
        throw;
    }
}

Storage::~Storage()
{
    stop();
}

bool Storage::submit_lookup(int tag, const InfoHash &hash)
{
    {
        std::lock_guard<std::mutex> lock(read_mutex_);
        if (read_stopping_ || lookups_.size() >= options_.max_lookups)
        {
            ++rejected_lookups_;
            return false;
        }
        lookups_.push_back(Lookup{tag, hash});
        queued_lookup_count_.store(lookups_.size());
    }
    read_condition_.notify_one();
    return true;
}

bool Storage::submit_persist(PersistJob &job)
{
    {
        std::lock_guard<std::mutex> lock(write_mutex_);
        const std::size_t size = job_bytes(job);
        if (write_stopping_
            || jobs_.size() >= options_.max_persist_jobs
            || (queued_bytes_ > 0 && queued_bytes_ + size > options_.max_persist_bytes))
        {
            ++rejected_jobs_;
            return false;
        }
        queued_bytes_ += size;
        jobs_.push_back(std::move(job));
        queued_job_count_.store(jobs_.size());
        queued_byte_count_.store(queued_bytes_);
    }
    write_condition_.notify_one();
    return true;
}

bool Storage::under_pressure() const
{
    return queued_job_count_.load() * 4 >= options_.max_persist_jobs * 3
        || queued_byte_count_.load() * 4 >= options_.max_persist_bytes * 3;
}

void Storage::stop()
{
    std::lock_guard<std::mutex> stop_lock(stop_mutex_);
    if (stopped_)
        return;
    stopped_ = true;

    {
        std::lock_guard<std::mutex> lock(read_mutex_);
        read_stopping_ = true;
        lookups_.clear();
        queued_lookup_count_.store(0);
    }
    read_condition_.notify_all();
    if (reader_thread_.joinable())
        reader_thread_.join();

    {
        std::lock_guard<std::mutex> lock(write_mutex_);
        write_stopping_ = true;
        drain_deadline_ = std::chrono::steady_clock::now() + options_.drain_timeout;
    }
    write_condition_.notify_all();
    if (writer_thread_.joinable())
        writer_thread_.join();
}

Stats Storage::stats() const
{
    Stats result;
    result.queued_lookups = queued_lookup_count_.load();
    result.queued_jobs = queued_job_count_.load();
    result.queued_bytes = queued_byte_count_.load();
    result.lookups = lookups_done_.load();
    result.lookup_errors = lookup_errors_.load();
    result.persisted = persisted_.load();
    result.persist_failures = persist_failures_.load();
    result.rejected_lookups = rejected_lookups_.load();
    result.rejected_jobs = rejected_jobs_.load();
    result.busy_retries = busy_retries_.load();
    result.checkpoints = checkpoints_.load();
    result.wal_bytes = wal_bytes_.load();
    return result;
}

void Storage::reader_loop()
{
    std::vector<Lookup> batch;
    std::vector<LookupResult> results;
    while (true)
    {
        {
            std::unique_lock<std::mutex> lock(read_mutex_);
            read_condition_.wait(lock, [this] {
                return read_stopping_ || !lookups_.empty();
            });
            if (read_stopping_)
                return;
            const std::size_t count = std::min(lookups_.size(), kLookupBatch);
            batch.assign(lookups_.begin(), lookups_.begin() + static_cast<std::ptrdiff_t>(count));
            lookups_.erase(lookups_.begin(), lookups_.begin() + static_cast<std::ptrdiff_t>(count));
            queued_lookup_count_.store(lookups_.size());
        }

        results.assign(batch.size(), LookupResult::error);
        try
        {
            // One short read transaction per batch: a consistent snapshot,
            // released immediately so checkpoints are never starved.
            std::string error;
            const bool in_transaction = reader_->execute("BEGIN;", error) == SQLITE_OK;
            for (std::size_t i = 0; i < batch.size(); ++i)
            {
                const std::string hex = to_hex(batch[i].hash);
                Statement::Use use(*contains_statement_);
                sqlite3_stmt *statement = contains_statement_->get();
                if (sqlite3_bind_text(statement, 1, hex.c_str(), -1, SQLITE_STATIC) != SQLITE_OK)
                    continue;
                const int step = sqlite3_step(statement);
                if (step == SQLITE_ROW)
                    results[i] = LookupResult::present;
                else if (step == SQLITE_DONE)
                    results[i] = LookupResult::absent;
            }
            if (in_transaction)
                reader_->execute("COMMIT;", error);
        }
        catch (const std::exception &error)
        {
            logging::error() << "[DB] 查询失败: " << error.what();
        }

        for (std::size_t i = 0; i < batch.size(); ++i)
        {
            ++lookups_done_;
            if (results[i] == LookupResult::error)
                ++lookup_errors_;
            try
            {
                on_lookup_(batch[i].tag, batch[i].hash, results[i]);
            }
            catch (const std::exception &error)
            {
                logging::error() << "[DB] 查询回调失败: " << error.what();
            }
        }
    }
}

void Storage::writer_loop()
{
    std::vector<PersistJob> batch;
    auto next_checkpoint = std::chrono::steady_clock::now() + options_.checkpoint_interval;
    bool dirty = false;
    while (true)
    {
        bool stopping = false;
        {
            std::unique_lock<std::mutex> lock(write_mutex_);
            write_condition_.wait_until(lock, next_checkpoint, [this] {
                return write_stopping_ || !jobs_.empty();
            });
            stopping = write_stopping_;
            if (jobs_.empty() && stopping)
                break;

            if (!jobs_.empty())
            {
                if (!stopping && jobs_.size() < options_.batch_size)
                {
                    write_condition_.wait_for(lock, options_.batch_delay, [this] {
                        return write_stopping_ || jobs_.size() >= options_.batch_size;
                    });
                }
                const std::size_t count = std::min(jobs_.size(), options_.batch_size);
                batch.reserve(count);
                for (std::size_t i = 0; i < count; ++i)
                {
                    queued_bytes_ -= job_bytes(jobs_.front());
                    batch.push_back(std::move(jobs_.front()));
                    jobs_.pop_front();
                }
                queued_job_count_.store(jobs_.size());
                queued_byte_count_.store(queued_bytes_);
            }
        }

        if (!batch.empty() && abandon_writes_)
        {
            // Shutdown deadline passed while the database stayed locked:
            // fail the rest at once instead of waiting busy_timeout per batch.
            for (const PersistJob &job : batch)
                report(job, false);
            batch.clear();
        }
        if (!batch.empty())
        {
            try
            {
                process_batch(batch);
            }
            catch (const std::exception &error)
            {
                // Thrown before any job was reported: fail them all so no
                // claim is left in flight.
                logging::error() << "[DB] 写线程异常: " << error.what();
                for (const PersistJob &job : batch)
                    report(job, false);
            }
            batch.clear();
            dirty = true;
        }

        const auto now = std::chrono::steady_clock::now();
        if (now >= next_checkpoint)
        {
            if (dirty)
                checkpoint(false);
            dirty = false;
            next_checkpoint = now + options_.checkpoint_interval;
        }
    }

    checkpoint(true);
}

void Storage::report(const PersistJob &job, bool persisted) noexcept
{
    if (persisted)
        ++persisted_;
    else
        ++persist_failures_;
    try
    {
        on_persist_(job, persisted);
    }
    catch (...)
    {
    }
}

// Reports every job exactly once. Only the initial allocation can throw, and
// it does so before any job has been reported.
void Storage::process_batch(std::vector<PersistJob> &batch)
{
    std::vector<PersistJob *> rows;
    rows.reserve(batch.size());
    for (PersistJob &job : batch)
    {
        try
        {
            if (!options_.torrent_dir.empty())
            {
                const fs::path target = options_.torrent_dir / (job.hash_hex + ".torrent");
                std::error_code exists_error;
                if (!fs::exists(target, exists_error))
                {
                    platform::write_file_atomic(
                        target,
                        std::string_view(job.torrent_file.data(), job.torrent_file.size()),
                        false);
                }
            }
            rows.push_back(&job);
        }
        catch (const std::exception &error)
        {
            logging::error() << "[Session " << job.origin
                             << "][Fetcher] 保存 " << job.hash_hex
                             << " 失败: " << error.what();
            report(job, false);
        }
    }

    bool inserted = rows.empty();
    if (!inserted)
    {
        try
        {
            // File lists first: if they fail no crawler row is written, the
            // hashes are fetched again later and both stores stay in step.
            inserted = write_file_lists(rows)
                && commit_with_retry("[DB]", [&](std::string &error) {
                       return try_insert(rows, error);
                   });
        }
        catch (const std::exception &error)
        {
            logging::error() << "[DB] 批量写入失败: " << error.what();
        }
    }
    for (const PersistJob *job : rows)
        report(*job, inserted);
    batch.clear();
}

bool Storage::write_file_lists(const std::vector<PersistJob *> &rows)
{
    if (!file_index_)
        return true;

    std::vector<file_index::Entry> entries;
    for (PersistJob *job : rows)
    {
        if (job->file_list)
            entries.push_back(std::move(*job->file_list));
    }
    if (entries.empty())
        return true;

    return commit_with_retry("[FileIndex]", [&](std::string &error) {
        const file_index::Result result = file_index_->put(entries);
        error = result.message;
        if (result.status == file_index::Status::ok)
            return SQLITE_OK;
        return result.status == file_index::Status::busy ? SQLITE_BUSY : SQLITE_ERROR;
    });
}

std::size_t Storage::job_bytes(const PersistJob &job)
{
    std::size_t bytes = job.torrent_file.size();
    if (job.file_list)
    {
        bytes += job.file_list->name.size();
        for (const file_index::File &file : job.file_list->files)
            bytes += file.path.size() + sizeof(file_index::File);
    }
    return bytes;
}

bool Storage::commit_with_retry(const char *label, const std::function<int(std::string &)> &attempt)
{
    auto backoff = std::chrono::milliseconds(50);
    auto last_busy_log = std::chrono::steady_clock::time_point{};
    int failures = 0;
    while (true)
    {
        std::string error;
        const int result = attempt(error);
        if (result == SQLITE_OK)
            return true;

        const auto now = std::chrono::steady_clock::now();
        if (is_busy(result))
        {
            // Another process (a DB browser, a backup tool, Windows file
            // locks held by AV) owns the lock. Keep the rows and retry: the
            // bounded queue pushes back on producers meanwhile.
            ++busy_retries_;
            bool give_up = false;
            {
                std::lock_guard<std::mutex> lock(write_mutex_);
                give_up = write_stopping_ && now >= drain_deadline_;
            }
            if (give_up)
            {
                logging::error() << label << " 退出时数据库仍被占用，放弃剩余记录: " << error;
                abandon_writes_ = true;
                return false;
            }
            if (now - last_busy_log >= kBusyLogInterval)
            {
                logging::error() << label << " 数据库被占用，稍后重试: " << error;
                last_busy_log = now;
            }
            std::this_thread::sleep_for(backoff);
            backoff = std::min(backoff * 2, kBusyBackoffMax);
            continue;
        }

        if (++failures >= 3)
        {
            logging::error() << label << " 批量写入失败: "
                             << (error.empty() ? "未知 SQLite 错误" : error);
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50 * failures));
    }
}

int Storage::try_insert(const std::vector<PersistJob *> &rows, std::string &error)
{
    int result = writer_->execute("BEGIN IMMEDIATE;", error);
    if (result != SQLITE_OK)
        return result;

    sqlite3_stmt *statement = insert_statement_->get();
    for (const PersistJob *job : rows)
    {
        Statement::Use use(*insert_statement_);
        if (sqlite3_bind_text(statement, 1, job->hash_hex.c_str(), -1, SQLITE_STATIC) != SQLITE_OK
            || sqlite3_bind_text(statement, 2, job->name.c_str(), -1, SQLITE_STATIC) != SQLITE_OK
            || sqlite3_bind_text(statement, 3, job->peer.c_str(), -1, SQLITE_STATIC) != SQLITE_OK
            || (result = sqlite3_step(statement)) != SQLITE_DONE)
        {
            if (result == SQLITE_OK || result == SQLITE_DONE)
                result = sqlite3_errcode(writer_->get());
            error = sqlite3_errmsg(writer_->get());
            std::string ignored;
            writer_->execute("ROLLBACK;", ignored);
            return result == SQLITE_OK ? SQLITE_ERROR : result;
        }
    }

    result = writer_->execute("COMMIT;", error);
    if (result != SQLITE_OK)
    {
        std::string ignored;
        writer_->execute("ROLLBACK;", ignored);
    }
    return result;
}

void Storage::checkpoint(bool final_checkpoint)
{
    int log_frames = 0;
    int checkpointed = 0;
    const int mode = final_checkpoint ? SQLITE_CHECKPOINT_TRUNCATE : SQLITE_CHECKPOINT_PASSIVE;
    const int result = sqlite3_wal_checkpoint_v2(
        writer_->get(), nullptr, mode, &log_frames, &checkpointed);
    ++checkpoints_;

    if (!final_checkpoint && result == SQLITE_OK)
    {
        if (checkpointed < log_frames)
        {
            if (++starved_checkpoints_ == kStarvedCheckpointWarning)
            {
                logging::error() << "[DB] WAL 检查点持续被其他连接的长事务阻塞 (frames="
                                 << log_frames << " checkpointed=" << checkpointed << ")";
            }
        }
        else
        {
            starved_checkpoints_ = 0;
            // Fully checkpointed: shrink an oversized WAL file now rather
            // than waiting for the next writer to reset it.
            if (wal_size() > options_.truncate_wal_above)
            {
                sqlite3_wal_checkpoint_v2(
                    writer_->get(), nullptr, SQLITE_CHECKPOINT_TRUNCATE, &log_frames, &checkpointed);
            }
        }
    }
    wal_bytes_.store(wal_size());

    if (file_index_)
    {
        const file_index::Result result = file_index_->checkpoint(final_checkpoint);
        if (!result && final_checkpoint)
            logging::error() << "[FileIndex] 检查点失败: " << result.message;
    }
}

// Measured through an open handle: on Windows the size in the directory
// entry (what std::filesystem::file_size reads) lags behind while SQLite
// keeps the file open.
std::uint64_t Storage::wal_size() const
{
    fs::path wal = options_.database_path;
    wal += "-wal";
    std::ifstream file(wal, std::ios::binary | std::ios::ate);
    if (!file)
        return 0;
    const std::streamoff size = file.tellg();
    return size > 0 ? static_cast<std::uint64_t>(size) : 0;
}

} // namespace storage
