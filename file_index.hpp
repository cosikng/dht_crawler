#pragma once

// File index: the file lists recorded in fetched torrents, keyed by
// info-hash, in a standalone SQLite database ("dht_files.db" by default),
// separate from the crawler database. The table is WITHOUT ROWID with the
// 20-byte info-hash as primary key, i.e. the table itself is a B-tree
// clustered on the hash and a lookup is a single B-tree descent.
//
// Schema, format version 1:
//
//   CREATE TABLE file_lists (
//       info_hash  BLOB PRIMARY KEY NOT NULL,  -- 20 raw bytes (v1 info-hash)
//       name       TEXT NOT NULL,              -- torrent name
//       file_count INTEGER NOT NULL,
//       total_size INTEGER NOT NULL,           -- bytes
//       files      BLOB NOT NULL               -- see below
//   ) WITHOUT ROWID;
//   CREATE TABLE index_meta (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL);
//   -- index_meta('format_version') = '1'
//
// `files` is a sequence of unsigned LEB128 varints and bytes:
//
//   varint count
//   count times: varint shared, varint suffix_length, suffix bytes, varint size
//
// with path = the previous file's path truncated to `shared` bytes, followed
// by `suffix` (front coding; the first file follows an empty path). Paths are
// '/'-separated and start with the torrent name for multi-file torrents; a
// single-file torrent's only path is its name. Files keep the torrent's
// order; BEP 47 padding files are not stored.
//
// The database uses WAL, so readers (other processes included) can look up
// entries while the crawler writes. A FileIndex object must only be used by
// one thread at a time; open one per thread.

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace file_index
{

using InfoHash = std::array<std::uint8_t, 20>;

struct File
{
    std::string path;
    std::uint64_t size = 0;
};

struct Entry
{
    InfoHash info_hash{};
    std::string name;
    std::vector<File> files;

    std::uint64_t total_size() const;
};

enum class Status
{
    ok,
    // Another connection holds the write lock; retrying later can succeed.
    busy,
    error
};

struct Result
{
    Status status = Status::ok;
    std::string message;

    explicit operator bool() const
    {
        return status == Status::ok;
    }
};

class FileIndex
{
public:
    enum class Mode
    {
        read_only,
        // Creates the database and schema if needed.
        read_write
    };

    // Throws std::runtime_error if the file cannot be opened or is not a
    // file index of a supported format version.
    explicit FileIndex(
        const std::filesystem::path &path,
        Mode mode = Mode::read_only,
        std::chrono::milliseconds busy_timeout = std::chrono::milliseconds(5000));
    ~FileIndex();

    FileIndex(FileIndex &&) noexcept;
    FileIndex &operator=(FileIndex &&) noexcept;
    FileIndex(const FileIndex &) = delete;
    FileIndex &operator=(const FileIndex &) = delete;

    // Stores the entries in one transaction; an existing entry with the
    // same info-hash is replaced. read_write only.
    Result put(const std::vector<Entry> &entries);

    // nullopt when the hash is not in the index. Throws std::runtime_error on
    // database errors or a corrupt entry.
    std::optional<Entry> get(const InfoHash &info_hash);
    bool contains(const InfoHash &info_hash);
    // Number of torrents in the index.
    std::uint64_t size();

    // Copies WAL content into the database; `truncate` also empties the WAL
    // file (waits for readers, up to the busy timeout).
    Result checkpoint(bool truncate);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

std::string encode_files(const std::vector<File> &files);
// nullopt for malformed input (truncated, inconsistent or trailing bytes).
std::optional<std::vector<File>> decode_files(std::string_view encoded);

std::string to_hex(const InfoHash &info_hash);
// 40 hex digits, either case.
std::optional<InfoHash> parse_hash(std::string_view hex);

struct TreeOptions
{
    // "|-- " instead of box-drawing characters.
    bool ascii = false;
    // Exact byte counts instead of KiB/MiB/...
    bool exact_sizes = false;
};

// Human-readable listing: a header with hash, name, file count and total
// size, then the directory tree with per-file and per-directory sizes.
// Names are passed through printable().
std::string render_tree(const Entry &entry, const TreeOptions &options = {});

// "0 B", "1023 B", "1.5 KiB", "2.4 MiB", ...
std::string format_size(std::uint64_t bytes);

// Torrent names are untrusted bytes: keeps valid UTF-8 and escapes control
// characters, invalid UTF-8 (\xHH) and bidirectional-override characters
// (\u{202E}), which could otherwise disguise a name in a terminal.
std::string printable(std::string_view text);

} // namespace file_index
