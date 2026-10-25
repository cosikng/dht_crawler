// Self-contained unit and stress tests (no test framework dependency).
// Run: unit_tests [name-filter]

#include "crawler_storage.hpp"
#include "hash_registry.hpp"
#include "logger.hpp"
#include "platform.hpp"
#include "simple_network.hpp"
#include "tracker_protocol.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;
using namespace std::chrono_literals;

namespace
{

struct TestCase
{
    const char *name;
    void (*function)();
};

std::vector<TestCase> &tests()
{
    static std::vector<TestCase> registry;
    return registry;
}

struct Registrar
{
    Registrar(const char *name, void (*function)())
    {
        tests().push_back({name, function});
    }
};

struct Failure : std::exception
{
    explicit Failure(std::string text)
        : message(std::move(text))
    {
    }
    const char *what() const noexcept override
    {
        return message.c_str();
    }
    std::string message;
};

#define TEST(name)                                     \
    void name();                                       \
    const Registrar name##_registrar(#name, name);     \
    void name()

#define CHECK(condition)                                                              \
    do                                                                                \
    {                                                                                 \
        if (!(condition))                                                             \
        {                                                                             \
            std::ostringstream failure_text;                                          \
            failure_text << __FILE__ << ':' << __LINE__ << ": CHECK(" #condition ")"; \
            throw Failure(failure_text.str());                                        \
        }                                                                             \
    } while (false)

#define CHECK_EQ(actual, expected)                                                  \
    do                                                                              \
    {                                                                               \
        const auto actual_value = (actual);                                         \
        const auto expected_value = (expected);                                     \
        if (!(actual_value == expected_value))                                      \
        {                                                                           \
            std::ostringstream failure_text;                                        \
            failure_text << __FILE__ << ':' << __LINE__ << ": " #actual " == " #expected \
                         << " (got \"" << actual_value << "\", expected \""         \
                         << expected_value << "\")";                                 \
            throw Failure(failure_text.str());                                      \
        }                                                                           \
    } while (false)

// A fresh directory under the system temp dir, removed on destruction.
class TempDir
{
public:
    explicit TempDir(const std::string &label)
    {
        static std::atomic<int> counter{0};
        path_ = fs::temp_directory_path()
            / ("dht_crawler_test_" + std::to_string(platform::process_id()) + "_"
                + std::to_string(counter.fetch_add(1)) + "_" + label);
        fs::remove_all(path_);
        fs::create_directories(path_);
    }
    ~TempDir()
    {
        std::error_code ignored;
        fs::remove_all(path_, ignored);
    }
    const fs::path &path() const
    {
        return path_;
    }

private:
    fs::path path_;
};

storage::InfoHash make_hash(std::uint64_t seed)
{
    storage::InfoHash hash{};
    std::mt19937_64 random(seed * 0x9e3779b97f4a7c15ULL + 1);
    for (std::size_t i = 0; i < hash.size(); i += 8)
    {
        const std::uint64_t value = random();
        std::memcpy(hash.data() + i, &value, std::min<std::size_t>(8, hash.size() - i));
    }
    return hash;
}

std::string read_file(const fs::path &path)
{
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

std::string bytes_of(const std::string &address, int family)
{
    const auto packed = simple_net::pack_ip_address(family, address);
    return packed ? *packed : std::string("<invalid>");
}

std::string ipv6_text(const std::string &address)
{
    const auto packed = simple_net::pack_ip_address(6, address);
    if (!packed)
        return "<invalid>";
    std::array<std::uint8_t, 16> bytes{};
    std::memcpy(bytes.data(), packed->data(), bytes.size());
    return simple_net::format_ipv6(bytes);
}

// ---------------------------------------------------------------------------
// Tracker protocol

TEST(url_decode_accepts_valid_and_rejects_broken_encoding)
{
    CHECK_EQ(*tracker::url_decode("%41%62c"), std::string("Abc"));
    CHECK_EQ(*tracker::url_decode("a+b"), std::string("a b"));
    CHECK_EQ(*tracker::url_decode(""), std::string());
    CHECK_EQ(tracker::url_decode("%00")->size(), std::size_t{1});
    CHECK(!tracker::url_decode("%"));
    CHECK(!tracker::url_decode("%4"));
    CHECK(!tracker::url_decode("abc%"));
    CHECK(!tracker::url_decode("%G1"));
    CHECK(!tracker::url_decode("%1G"));
    CHECK(!tracker::url_decode("%%41"));
}

TEST(parse_query_keeps_first_value_and_drops_malformed_pairs)
{
    const auto values = tracker::parse_query("a=1&a=2&=x&bad=%zz&flag&b=%20");
    CHECK_EQ(values.at("a"), std::string("1"));
    CHECK(values.count("bad") == 0);
    CHECK(values.count("") == 0);
    CHECK_EQ(values.at("flag"), std::string());
    CHECK_EQ(values.at("b"), std::string(" "));
    CHECK(tracker::parse_query("").empty());
    CHECK(tracker::parse_query("&&&").empty());
}

TEST(parse_info_hash_requires_exactly_20_bytes_or_40_hex)
{
    std::string raw(20, '\0');
    raw[19] = '\xff';
    const auto hash = tracker::parse_info_hash(raw);
    CHECK(hash.has_value());
    CHECK_EQ(tracker::hash_to_hex(*hash), std::string("00000000000000000000000000000000000000ff"));

    const auto hex = tracker::parse_info_hash("0123456789ABCDEF0123456789abcdef01234567");
    CHECK(hex.has_value());
    CHECK_EQ(tracker::hash_to_hex(*hex), std::string("0123456789abcdef0123456789abcdef01234567"));

    for (const std::size_t size : {0, 1, 19, 21, 39, 41, 1000})
        CHECK(!tracker::parse_info_hash(std::string(size, 'a')).has_value());
    CHECK(!tracker::parse_info_hash("0123456789abcdef0123456789abcdef0123456g"));
}

TEST(parse_request_line_reports_missing_line_and_extra_tokens)
{
    CHECK(!tracker::parse_request_line("GET / HTTP/1.1"));
    const auto line = tracker::parse_request_line("GET /announce?x HTTP/1.1\r\nHost: a\r\n\r\n");
    CHECK(line && line->method == "GET" && line->target == "/announce?x" && !line->extra_tokens);
    const auto extra = tracker::parse_request_line("GET / HTTP/1.1 junk\r\n\r\n");
    CHECK(extra && extra->extra_tokens);
    const auto short_line = tracker::parse_request_line("GET\r\n\r\n");
    CHECK(short_line && short_line->version.empty());
}

TEST(bencoded_replies_are_exact)
{
    CHECK_EQ(tracker::failure_body("x"), std::string("d14:failure reason1:xe"));
    // Lengths are byte counts, also for multi-byte UTF-8.
    CHECK_EQ(tracker::failure_body("\xe8\xb6\x85"), std::string("d14:failure reason3:\xe8\xb6\x85" "e"));

    const std::vector<tracker::PeerEndpoint> peers = {
        {4, "1.2.3.4", 0x1ae1},
        {6, "::1", 80},
        {4, "999.1.1.1", 1},
        {6, "not-an-address", 1},
    };
    const std::string body = tracker::success_body(peers, 60);
    const std::string expected =
        std::string("d8:intervali60e12:min intervali60e5:peers6:")
        + std::string("\x01\x02\x03\x04\x1a\xe1", 6)
        + "6:peers618:" + std::string(15, '\0') + std::string("\x01\x00\x50", 3) + "e";
    CHECK(body == expected);

    const std::string empty = tracker::success_body({}, 30);
    CHECK_EQ(empty, std::string("d8:intervali30e12:min intervali30e5:peers0:e"));
}

TEST(rpc_response_parser_rejects_poisoned_replies)
{
    const auto ok = tracker::parse_rpc_response("DHTP/1 OK 2\nPEER 4 1.2.3.4 80\nPEER 6 ::1 443\nEND\n");
    CHECK(ok.status == tracker::LookupStatus::ok && ok.peers.size() == 2);
    CHECK(ok.peers[1].family == 6 && ok.peers[1].port == 443);

    CHECK(tracker::parse_rpc_response("DHTP/1 TIMEOUT\nEND\n").status == tracker::LookupStatus::timeout);
    CHECK(tracker::parse_rpc_response("DHTP/1 ERROR x\nEND\n").status == tracker::LookupStatus::error);
    for (const char *poisoned : {
             "",
             "HTTP/1.1 200 OK\nEND\n",
             "DHTP/1 OK\nEND\n",
             "DHTP/1 OK -1\nEND\n",
             "DHTP/1 OK 513\nEND\n",
             "DHTP/1 OK 2\nPEER 4 1.2.3.4 80\nEND\n",
             "DHTP/1 OK 1\nPEER 5 1.2.3.4 80\nEND\n",
             "DHTP/1 OK 1\nPEER 4 1.2.3.4 0\nEND\n",
             "DHTP/1 OK 1\nPEER 4 1.2.3.4 65536\nEND\n",
             "DHTP/1 OK 1\nPEER 4 1.2.3.4 80 extra\nEND\n",
             "DHTP/1 OK 1\nNODE 4 1.2.3.4 80\nEND\n",
         })
    {
        CHECK(tracker::parse_rpc_response(poisoned).status == tracker::LookupStatus::error);
    }
}

// ---------------------------------------------------------------------------
// Portable address handling

TEST(ipv4_parser_matches_glibc_inet_pton)
{
    CHECK_EQ(bytes_of("1.2.3.4", 4), std::string("\x01\x02\x03\x04", 4));
    CHECK_EQ(bytes_of("0.0.0.0", 4), std::string(4, '\0'));
    CHECK_EQ(bytes_of("255.255.255.255", 4), std::string(4, '\xff'));
    for (const char *invalid : {"", "1.2.3", "1.2.3.4.", ".1.2.3", "1..2.3", "01.2.3.4",
                                "256.1.1.1", "1.2.3.4 ", " 1.2.3.4", "1.2.3.a", "1.2.3.4.5", "0x1.2.3.4"})
    {
        CHECK(!simple_net::pack_ip_address(4, invalid));
    }
}

TEST(ipv6_parser_matches_glibc_inet_pton)
{
    for (const char *valid : {"::", "::1", "1::", "1:2:3:4:5:6:7:8", "::ffff:1.2.3.4",
                              "1:2:3:4:5:6:1.2.3.4", "fe80::1", "FFFF::abcd", "1::2:3"})
    {
        CHECK(simple_net::pack_ip_address(6, valid).has_value());
    }
    for (const char *invalid : {"", ":", ":::", "1:::2", "1::2::3", "12345::", "1:2:3:4:5:6:7:8:9",
                                "1:2:3:4:5:6:7:8::", "::1.2.3", "1.2.3.4", "1:2:3:4:5:6:7:1.2.3.4",
                                "g::1", " ::1", "::1 ", "1:", ":1", "fe80::1%eth0", "::01.2.3.4"})
    {
        CHECK(!simple_net::pack_ip_address(6, invalid));
    }
}

TEST(ipv6_formatting_is_rfc5952_like_glibc)
{
    CHECK_EQ(ipv6_text("::"), std::string("::"));
    CHECK_EQ(ipv6_text("::1"), std::string("::1"));
    CHECK_EQ(ipv6_text("1::"), std::string("1::"));
    CHECK_EQ(ipv6_text("0:0:0:0:0:ffff:7f00:1"), std::string("::ffff:127.0.0.1"));
    CHECK_EQ(ipv6_text("::1.2.3.4"), std::string("::1.2.3.4"));
    CHECK_EQ(ipv6_text("0:0:0:0:ffff:0:102:304"), std::string("::ffff:0:102:304"));
    CHECK_EQ(ipv6_text("2001:0DB8:0000:0000:0000:0000:0000:0001"), std::string("2001:db8::1"));
    // First of two equal runs wins; a single zero group is never compressed.
    CHECK_EQ(ipv6_text("2001:db8:0:0:1:0:0:1"), std::string("2001:db8::1:0:0:1"));
    CHECK_EQ(ipv6_text("2001:0:0:1:0:0:0:1"), std::string("2001:0:0:1::1"));
    CHECK_EQ(ipv6_text("2001:db8:0:1:1:1:1:1"), std::string("2001:db8:0:1:1:1:1:1"));
    CHECK_EQ(ipv6_text("0:2:3:4:5:6:7:8"), std::string("0:2:3:4:5:6:7:8"));
    CHECK_EQ(ipv6_text("1:2:3:4:5:6:7:8"), std::string("1:2:3:4:5:6:7:8"));
    CHECK_EQ(simple_net::format_ipv4({10, 0, 0, 255}), std::string("10.0.0.255"));
}

// ---------------------------------------------------------------------------
// Logger

TEST(log_sanitizer_neutralises_control_characters)
{
    CHECK_EQ(logging::sanitize("started"), std::string("started"));
    CHECK_EQ(logging::sanitize("a\nb\r\x1b[31m"), std::string("a\\x0ab\\x0d\\x1b[31m"));
    CHECK_EQ(logging::sanitize("back\\slash"), std::string("back\\x5cslash"));
    CHECK_EQ(logging::sanitize(std::string(200, 'x'), 8), std::string("xxxxxxxx..."));
}

// ---------------------------------------------------------------------------
// Hash registry (dedup cache bounds and claim semantics)

TEST(registry_claim_state_machine)
{
    HashRegistry registry(1000);
    const auto now = HashRegistry::Clock::now();
    const auto hash = make_hash(1);

    CHECK(registry.try_claim(hash, now) == HashRegistry::Claim::claimed);
    CHECK(registry.try_claim(hash, now) == HashRegistry::Claim::in_flight);
    registry.settle_failed(hash, now + 60s);
    CHECK(registry.try_claim(hash, now + 59s) == HashRegistry::Claim::backoff);
    CHECK(registry.try_claim(hash, now + 61s) == HashRegistry::Claim::claimed);
    registry.settle_completed(hash, now + 600s);
    CHECK(registry.try_claim(hash, now + 70s) == HashRegistry::Claim::completed);
    CHECK(registry.try_claim(hash, now + 601s) == HashRegistry::Claim::claimed);
    registry.release(hash);
    CHECK(registry.stats().in_flight == 0);
    CHECK(registry.try_claim(hash, now + 601s) == HashRegistry::Claim::claimed);
}

TEST(registry_settled_entries_are_size_bounded)
{
    constexpr std::size_t kCap = 10000;
    HashRegistry registry(kCap);
    const auto now = HashRegistry::Clock::now();
    for (std::uint64_t i = 0; i < 1000000; ++i)
    {
        const auto hash = make_hash(i + 100);
        CHECK(registry.try_claim(hash, now) == HashRegistry::Claim::claimed);
        registry.settle_completed(hash, now + 1h);
    }
    const HashRegistry::Stats stats = registry.stats();
    CHECK(stats.settled <= kCap);
    CHECK(stats.settled >= kCap - 16);
    CHECK(stats.in_flight == 0);
    CHECK(stats.evicted >= 1000000 - kCap);
}

TEST(registry_expired_entries_are_reclaimed)
{
    HashRegistry registry(1000000);
    const auto now = HashRegistry::Clock::now();
    for (std::uint64_t i = 0; i < 50000; ++i)
    {
        const auto hash = make_hash(i + 5000000);
        registry.try_claim(hash, now);
        registry.settle_failed(hash, now + 1s);
    }
    CHECK(registry.stats().settled == 50000);
    registry.purge(now + 2s);
    CHECK(registry.stats().settled == 0);
}

TEST(registry_never_evicts_in_flight_claims)
{
    HashRegistry registry(100);
    const auto now = HashRegistry::Clock::now();
    for (std::uint64_t i = 0; i < 20000; ++i)
        CHECK(registry.try_claim(make_hash(i + 9000000), now) == HashRegistry::Claim::claimed);
    for (std::uint64_t i = 0; i < 2000; ++i)
    {
        const auto hash = make_hash(i + 12000000);
        registry.try_claim(hash, now);
        registry.settle_completed(hash, now + 1h);
    }
    CHECK(registry.stats().in_flight == 20000);
    for (std::uint64_t i = 0; i < 20000; ++i)
        CHECK(registry.try_claim(make_hash(i + 9000000), now) == HashRegistry::Claim::in_flight);
}

TEST(registry_concurrent_claims_are_exclusive)
{
    HashRegistry registry(100000);
    constexpr int kThreads = 8;
    constexpr std::uint64_t kHashes = 20000;
    std::atomic<std::uint64_t> wins{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t)
    {
        threads.emplace_back([&, t] {
            const auto now = HashRegistry::Clock::now();
            for (std::uint64_t i = 0; i < kHashes; ++i)
            {
                // Different visiting orders maximise contention.
                const std::uint64_t index = (i * static_cast<std::uint64_t>(t + 1)) % kHashes;
                if (registry.try_claim(make_hash(index + 20000000), now) == HashRegistry::Claim::claimed)
                    ++wins;
            }
        });
    }
    for (std::thread &thread : threads)
        thread.join();
    CHECK(wins.load() == kHashes);
    CHECK(registry.stats().in_flight == kHashes);
}

// ---------------------------------------------------------------------------
// Atomic files (Windows rename-over-existing semantics)

TEST(atomic_write_replaces_existing_file)
{
    TempDir directory("atomic");
    const fs::path target = directory.path() / "state.bin";
    platform::write_file_atomic(target, "first", true);
    platform::write_file_atomic(target, "second-version", true);
    CHECK_EQ(read_file(target), std::string("second-version"));
    platform::write_file_atomic(target, "", false);
    CHECK_EQ(read_file(target), std::string());
}

TEST(atomic_write_concurrent_writers_never_tear)
{
    TempDir directory("atomic_race");
    const fs::path target = directory.path() / "shared.torrent";
    std::vector<std::thread> threads;
    std::atomic<int> errors{0};
    for (int t = 0; t < 8; ++t)
    {
        threads.emplace_back([&, t] {
            const std::string content(4096 + t, static_cast<char>('a' + t));
            for (int i = 0; i < 100; ++i)
            {
                try
                {
                    platform::write_file_atomic(target, content, false);
                }
                catch (const std::exception &)
                {
                    ++errors;
                }
            }
        });
    }
    for (std::thread &thread : threads)
        thread.join();

    CHECK(errors.load() == 0);
    const std::string final_content = read_file(target);
    CHECK(final_content.size() >= 4096 && final_content.size() < 4096 + 8);
    CHECK(std::all_of(final_content.begin(), final_content.end(), [&](char c) {
        return c == final_content.front();
    }));
    CHECK(static_cast<std::size_t>(final_content.front() - 'a') == final_content.size() - 4096);
    for (const auto &entry : fs::directory_iterator(directory.path()))
        CHECK(entry.path().extension() != ".tmp");
}

TEST(atomic_write_waits_out_a_reader_holding_the_target)
{
    TempDir directory("atomic_open");
    const fs::path target = directory.path() / "busy.state";
    platform::write_file_atomic(target, "old", true);

    // An open handle without FILE_SHARE_DELETE (what most Windows programs
    // use) makes MoveFileEx fail with ERROR_ACCESS_DENIED until it closes.
    auto reader = std::make_unique<std::ifstream>(target, std::ios::binary);
    CHECK(reader->is_open());
    std::thread closer([&] {
        std::this_thread::sleep_for(200ms);
        reader.reset();
    });
    platform::write_file_atomic(target, "new", true);
    closer.join();
    CHECK_EQ(read_file(target), std::string("new"));
}

TEST(stale_temp_files_are_removed)
{
    TempDir directory("stale");
    std::ofstream(directory.path() / "a.torrent.123.4.tmp") << "x";
    std::ofstream(directory.path() / "legacy.torrent.tmp") << "x";
    std::ofstream(directory.path() / "keep.torrent") << "x";
    CHECK(platform::remove_stale_temp_files(directory.path()) == 2);
    CHECK(fs::exists(directory.path() / "keep.torrent"));
}

TEST(utf8_paths_round_trip)
{
    const std::string name = "\xe7\x9b\xae\xe5\xbd\x95-\xc3\xbc";  // "目录-ü"
    TempDir directory("utf8");
    const fs::path nested = directory.path() / platform::path_from_utf8(name);
    fs::create_directories(nested);
    CHECK(fs::exists(nested));
    const std::string utf8 = platform::path_to_utf8(nested);
    CHECK(utf8.find(name) != std::string::npos);
    CHECK(platform::path_from_utf8(utf8) == nested);
}

// ---------------------------------------------------------------------------
// SQLite storage

struct Collector
{
    std::mutex mutex;
    std::condition_variable condition;
    std::size_t persisted = 0;
    std::size_t failed = 0;
    std::size_t present = 0;
    std::size_t absent = 0;
    std::size_t lookup_errors = 0;

    storage::Storage::LookupHandler lookup_handler()
    {
        return [this](int, const storage::InfoHash &, storage::LookupResult result) {
            std::lock_guard<std::mutex> lock(mutex);
            if (result == storage::LookupResult::present)
                ++present;
            else if (result == storage::LookupResult::absent)
                ++absent;
            else
                ++lookup_errors;
            condition.notify_all();
        };
    }

    storage::Storage::PersistHandler persist_handler()
    {
        return [this](const storage::PersistJob &, bool ok) {
            std::lock_guard<std::mutex> lock(mutex);
            (ok ? persisted : failed) += 1;
            condition.notify_all();
        };
    }

    std::size_t finished()
    {
        std::lock_guard<std::mutex> lock(mutex);
        return persisted + failed;
    }

    template <typename Predicate>
    bool wait(Predicate predicate, std::chrono::seconds timeout = 120s)
    {
        std::unique_lock<std::mutex> lock(mutex);
        return condition.wait_for(lock, timeout, [&] { return predicate(*this); });
    }
};

storage::PersistJob make_job(std::uint64_t index)
{
    storage::PersistJob job;
    job.hash = make_hash(index);
    job.hash_hex = storage::to_hex(job.hash);
    job.name = "torrent-" + std::to_string(index) + "-\xe5\x90\x8d";
    job.peer = "[2001:db8::1]:" + std::to_string(1000 + index % 50000);
    job.torrent_file.assign(64, static_cast<char>('A' + index % 26));
    return job;
}

void submit_with_backpressure(storage::Storage &store, storage::PersistJob job)
{
    while (!store.submit_persist(job))
        std::this_thread::sleep_for(1ms);
}

std::int64_t count_rows(const fs::path &database)
{
    sqlite3 *db = nullptr;
    sqlite3_open_v2(platform::path_to_utf8(database).c_str(), &db, SQLITE_OPEN_READONLY, nullptr);
    sqlite3_stmt *statement = nullptr;
    sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM torrents;", -1, &statement, nullptr);
    std::int64_t rows = -1;
    if (sqlite3_step(statement) == SQLITE_ROW)
        rows = sqlite3_column_int64(statement, 0);
    sqlite3_finalize(statement);
    sqlite3_close(db);
    return rows;
}

// Through a handle: Windows directory metadata lags while SQLite holds the
// file open.
std::uint64_t file_size_or_zero(const fs::path &path)
{
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file)
        return 0;
    const std::streamoff size = file.tellg();
    return size > 0 ? static_cast<std::uint64_t>(size) : 0;
}

TEST(storage_schema_is_unchanged)
{
    TempDir directory("schema");
    storage::Options options;
    options.database_path = directory.path() / "crawler.db";
    options.torrent_dir = directory.path();
    Collector collector;
    {
        storage::Storage store(options, collector.lookup_handler(), collector.persist_handler());
    }

    sqlite3 *db = nullptr;
    CHECK(sqlite3_open(platform::path_to_utf8(options.database_path).c_str(), &db) == SQLITE_OK);
    sqlite3_stmt *statement = nullptr;
    CHECK(sqlite3_prepare_v2(db, "SELECT sql FROM sqlite_master WHERE name='torrents';", -1, &statement, nullptr) == SQLITE_OK);
    CHECK(sqlite3_step(statement) == SQLITE_ROW);
    const std::string sql = reinterpret_cast<const char *>(sqlite3_column_text(statement, 0));
    sqlite3_finalize(statement);

    CHECK(sqlite3_prepare_v2(db, "PRAGMA journal_mode;", -1, &statement, nullptr) == SQLITE_OK);
    CHECK(sqlite3_step(statement) == SQLITE_ROW);
    const std::string journal = reinterpret_cast<const char *>(sqlite3_column_text(statement, 0));
    sqlite3_finalize(statement);
    sqlite3_close(db);

    CHECK_EQ(sql, std::string(
        "CREATE TABLE torrents ("
        "info_hash TEXT PRIMARY KEY NOT NULL,"
        "name TEXT NOT NULL,"
        "discovered_peer TEXT NOT NULL,"
        "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP"
        ")"));
    CHECK_EQ(journal, std::string("wal"));
}

TEST(storage_concurrent_burst_writes_and_reads)
{
    TempDir directory("burst");
    storage::Options options;
    // Non-ASCII directory: SQLite must receive a UTF-8 path on Windows too.
    const fs::path data_dir = directory.path() / platform::path_from_utf8("\xe6\x95\xb0\xe6\x8d\xae");
    fs::create_directories(data_dir);
    options.database_path = data_dir / "crawler.db";
    options.torrent_dir = data_dir;
    options.max_persist_jobs = 512;
    options.checkpoint_interval = 1s;

    Collector collector;
    storage::Storage store(options, collector.lookup_handler(), collector.persist_handler());

    constexpr int kProducers = 16;
    constexpr int kJobsPerProducer = 500;
    constexpr std::size_t kTotal = kProducers * kJobsPerProducer;

    // An external connection reading continuously, like a DB browser.
    std::atomic<bool> reading{true};
    std::atomic<int> reader_errors{0};
    std::thread external_reader([&] {
        while (reading.load())
        {
            if (count_rows(options.database_path) < 0)
                ++reader_errors;
            std::this_thread::sleep_for(5ms);
        }
    });

    std::vector<std::thread> producers;
    for (int p = 0; p < kProducers; ++p)
    {
        producers.emplace_back([&, p] {
            for (int i = 0; i < kJobsPerProducer; ++i)
            {
                const std::uint64_t index = static_cast<std::uint64_t>(p) * kJobsPerProducer + i;
                submit_with_backpressure(store, make_job(index));
                while (!store.submit_lookup(p, make_hash(index + 1000000)))
                    std::this_thread::sleep_for(1ms);
            }
        });
    }
    for (std::thread &producer : producers)
        producer.join();

    CHECK(collector.wait([](Collector &c) { return c.persisted + c.failed == kTotal; }));
    CHECK(collector.wait([](Collector &c) { return c.present + c.absent + c.lookup_errors == kTotal; }));
    reading.store(false);
    external_reader.join();

    CHECK_EQ(collector.failed, std::size_t{0});
    CHECK_EQ(collector.lookup_errors, std::size_t{0});
    CHECK_EQ(reader_errors.load(), 0);
    CHECK_EQ(count_rows(options.database_path), static_cast<std::int64_t>(kTotal));

    // Every stored hash is now reported present.
    for (std::uint64_t i = 0; i < 100; ++i)
        CHECK(store.submit_lookup(0, make_hash(i)));
    CHECK(collector.wait([](Collector &c) { return c.present >= 100; }));

    store.stop();
    CHECK(fs::exists(data_dir / (storage::to_hex(make_hash(7)) + ".torrent")));
    CHECK_EQ(read_file(data_dir / (storage::to_hex(make_hash(7)) + ".torrent")), std::string(64, 'H'));

    // Clean shutdown truncates the WAL: no unbounded growth.
    fs::path wal = options.database_path;
    wal += "-wal";
    CHECK_EQ(file_size_or_zero(wal), std::uint64_t{0});
}

TEST(storage_reader_never_pins_a_wal_snapshot)
{
    TempDir directory("snapshot");
    storage::Options options;
    options.database_path = directory.path() / "crawler.db";
    options.torrent_dir = directory.path();
    Collector collector;
    storage::Storage store(options, collector.lookup_handler(), collector.persist_handler());

    for (std::uint64_t i = 0; i < 200; ++i)
        submit_with_backpressure(store, make_job(i));
    CHECK(collector.wait([](Collector &c) { return c.persisted == 200; }));
    // Lookups that hit (SQLITE_ROW) are exactly what used to leave the
    // shared statement un-reset and its read transaction open.
    for (std::uint64_t i = 0; i < 200; ++i)
        CHECK(store.submit_lookup(0, make_hash(i)));
    CHECK(collector.wait([](Collector &c) { return c.present == 200; }));

    sqlite3 *db = nullptr;
    CHECK(sqlite3_open(platform::path_to_utf8(options.database_path).c_str(), &db) == SQLITE_OK);
    sqlite3_busy_timeout(db, 2000);
    // A connection only discovers WAL mode on its first read.
    CHECK(sqlite3_exec(db, "SELECT COUNT(*) FROM torrents;", nullptr, nullptr, nullptr) == SQLITE_OK);
    int log_frames = -1;
    int checkpointed = -1;
    // SQLITE_BUSY here would mean some connection still holds a snapshot.
    const int result = sqlite3_wal_checkpoint_v2(db, nullptr, SQLITE_CHECKPOINT_TRUNCATE, &log_frames, &checkpointed);
    sqlite3_close(db);
    CHECK_EQ(result, SQLITE_OK);
    CHECK_EQ(log_frames, 0);
    fs::path wal = options.database_path;
    wal += "-wal";
    CHECK_EQ(file_size_or_zero(wal), std::uint64_t{0});
}

TEST(storage_survives_an_external_write_lock)
{
    TempDir directory("locked");
    storage::Options options;
    options.database_path = directory.path() / "crawler.db";
    options.torrent_dir = directory.path();
    options.busy_timeout = 100ms;
    Collector collector;
    storage::Storage store(options, collector.lookup_handler(), collector.persist_handler());

    sqlite3 *blocker = nullptr;
    CHECK(sqlite3_open(platform::path_to_utf8(options.database_path).c_str(), &blocker) == SQLITE_OK);
    CHECK(sqlite3_exec(blocker, "BEGIN EXCLUSIVE;", nullptr, nullptr, nullptr) == SQLITE_OK);

    for (std::uint64_t i = 0; i < 300; ++i)
        submit_with_backpressure(store, make_job(i + 50000));
    std::this_thread::sleep_for(1500ms);
    CHECK_EQ(collector.finished(), std::size_t{0});
    CHECK(store.stats().busy_retries > 0);

    CHECK(sqlite3_exec(blocker, "COMMIT;", nullptr, nullptr, nullptr) == SQLITE_OK);
    sqlite3_close(blocker);

    CHECK(collector.wait([](Collector &c) { return c.persisted == 300; }, 30s));
    CHECK_EQ(collector.failed, std::size_t{0});
}

TEST(storage_stop_flushes_every_queued_job)
{
    TempDir directory("drain");
    storage::Options options;
    options.database_path = directory.path() / "crawler.db";
    options.torrent_dir = directory.path();
    options.batch_delay = 1000ms;
    Collector collector;
    {
        storage::Storage store(options, collector.lookup_handler(), collector.persist_handler());
        for (std::uint64_t i = 0; i < 2000; ++i)
            submit_with_backpressure(store, make_job(i + 70000));
        store.stop();
        CHECK(!store.submit_lookup(0, make_hash(1)));
        storage::PersistJob late = make_job(1);
        CHECK(!store.submit_persist(late));
    }
    CHECK_EQ(collector.persisted, std::size_t{2000});
    CHECK_EQ(count_rows(options.database_path), std::int64_t{2000});
}

TEST(storage_queues_are_bounded)
{
    TempDir directory("bounded");
    storage::Options options;
    options.database_path = directory.path() / "crawler.db";
    options.torrent_dir = directory.path();
    options.max_persist_jobs = 4;
    options.max_persist_bytes = 1000;
    options.busy_timeout = 50ms;
    Collector collector;
    storage::Storage store(options, collector.lookup_handler(), collector.persist_handler());

    sqlite3 *blocker = nullptr;
    sqlite3_open(platform::path_to_utf8(options.database_path).c_str(), &blocker);
    sqlite3_exec(blocker, "BEGIN EXCLUSIVE;", nullptr, nullptr, nullptr);

    int accepted = 0;
    for (std::uint64_t i = 0; i < 100; ++i)
    {
        storage::PersistJob job = make_job(i + 90000);
        if (store.submit_persist(job))
            ++accepted;
    }
    // At most the batch already taken by the blocked writer plus the queue.
    CHECK(accepted <= 8);
    CHECK(store.under_pressure());
    CHECK(store.stats().rejected_jobs >= 92);

    sqlite3_exec(blocker, "COMMIT;", nullptr, nullptr, nullptr);
    sqlite3_close(blocker);
    CHECK(collector.wait([&](Collector &c) { return c.persisted == static_cast<std::size_t>(accepted); }, 30s));
    CHECK(!store.under_pressure());
}

} // namespace

int main(int argc, char **argv)
{
    const std::string filter = argc > 1 ? argv[1] : "";
    int failures = 0;
    int executed = 0;
    for (const TestCase &test : tests())
    {
        if (!filter.empty() && std::string(test.name).find(filter) == std::string::npos)
            continue;
        ++executed;
        const auto start = std::chrono::steady_clock::now();
        try
        {
            test.function();
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start);
            std::printf("[PASS] %s (%lld ms)\n", test.name, static_cast<long long>(elapsed.count()));
        }
        catch (const std::exception &error)
        {
            ++failures;
            std::printf("[FAIL] %s: %s\n", test.name, error.what());
        }
        std::fflush(stdout);
    }
    std::printf("%d/%d tests passed\n", executed - failures, executed);
    logging::stop();
    return failures == 0 && executed > 0 ? 0 : 1;
}
