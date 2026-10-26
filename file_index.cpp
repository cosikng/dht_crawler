#include "file_index.hpp"

#include "platform.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <climits>
#include <cstdio>
#include <limits>
#include <stdexcept>
#include <unordered_map>
#include <utility>

namespace fs = std::filesystem;

namespace file_index
{
namespace
{

constexpr const char *kFormatVersion = "1";
constexpr std::int64_t kJournalSizeLimit = std::int64_t{64} << 20;
// Deeper paths are shown with their remaining components on one line: a
// hostile torrent could otherwise nest thousands of levels, and the indented
// output grows with the square of the depth.
constexpr std::size_t kMaxTreeDepth = 32;

std::uint64_t saturating_add(std::uint64_t left, std::uint64_t right)
{
    return right > std::numeric_limits<std::uint64_t>::max() - left
        ? std::numeric_limits<std::uint64_t>::max()
        : left + right;
}

bool is_busy(int code)
{
    const int primary = code & 0xff;
    return primary == SQLITE_BUSY || primary == SQLITE_LOCKED;
}

Result failure(int code, std::string message)
{
    return Result{is_busy(code) ? Status::busy : Status::error, std::move(message)};
}

void put_varint(std::string &output, std::uint64_t value)
{
    while (value >= 0x80)
    {
        output.push_back(static_cast<char>((value & 0x7f) | 0x80));
        value >>= 7;
    }
    output.push_back(static_cast<char>(value));
}

bool get_varint(std::string_view input, std::size_t &offset, std::uint64_t &value)
{
    value = 0;
    for (int shift = 0; shift < 64; shift += 7)
    {
        if (offset >= input.size())
            return false;
        const auto byte = static_cast<unsigned char>(input[offset++]);
        // The tenth byte may only carry bit 63.
        if (shift == 63 && byte > 1)
            return false;
        value |= static_cast<std::uint64_t>(byte & 0x7f) << shift;
        if ((byte & 0x80) == 0)
            return true;
    }
    return false;
}

class Statement
{
public:
    Statement(sqlite3 *database, const char *sql)
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

    // Resets on scope exit so no statement keeps a read transaction open.
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
    sqlite3_stmt *statement_ = nullptr;
};

std::string_view column_bytes(sqlite3_stmt *statement, int column)
{
    const void *data = sqlite3_column_blob(statement, column);
    const int size = sqlite3_column_bytes(statement, column);
    if (!data || size <= 0)
        return {};
    return std::string_view(static_cast<const char *>(data), static_cast<std::size_t>(size));
}

void append_hex_escape(std::string &output, unsigned char byte)
{
    static constexpr char digits[] = "0123456789abcdef";
    output += "\\x";
    output.push_back(digits[byte >> 4]);
    output.push_back(digits[byte & 0x0f]);
}

bool is_hidden_control(std::uint32_t code_point)
{
    return (code_point >= 0x80 && code_point <= 0x9f)
        || code_point == 0x200e || code_point == 0x200f
        || (code_point >= 0x202a && code_point <= 0x202e)
        || (code_point >= 0x2066 && code_point <= 0x2069);
}

} // namespace

std::uint64_t Entry::total_size() const
{
    std::uint64_t total = 0;
    for (const File &file : files)
        total = saturating_add(total, file.size);
    return total;
}

struct FileIndex::Impl
{
    sqlite3 *database = nullptr;
    std::unique_ptr<Statement> insert;
    std::unique_ptr<Statement> select;
    std::unique_ptr<Statement> exists;
    std::unique_ptr<Statement> count;

    ~Impl()
    {
        // Statements must be finalized before the connection closes.
        insert.reset();
        select.reset();
        exists.reset();
        count.reset();
        if (database)
            sqlite3_close(database);
    }

    int execute(const char *sql, std::string &error)
    {
        char *message = nullptr;
        const int result = sqlite3_exec(database, sql, nullptr, nullptr, &message);
        if (result != SQLITE_OK)
            error = message ? message : sqlite3_errmsg(database);
        sqlite3_free(message);
        return result;
    }

    void execute(const char *sql)
    {
        std::string error;
        if (execute(sql, error) != SQLITE_OK)
            throw std::runtime_error(error);
    }
};

FileIndex::FileIndex(const fs::path &path, Mode mode, std::chrono::milliseconds busy_timeout)
    : impl_(std::make_unique<Impl>())
{
    // SQLite expects UTF-8 file names on every platform.
    const std::string filename = platform::path_to_utf8(path);
    const int flags = (mode == Mode::read_only
                              ? SQLITE_OPEN_READONLY
                              : SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE)
        | SQLITE_OPEN_NOMUTEX;
    if (sqlite3_open_v2(filename.c_str(), &impl_->database, flags, nullptr) != SQLITE_OK)
    {
        const std::string message =
            impl_->database ? sqlite3_errmsg(impl_->database) : "无法分配 SQLite handle";
        throw std::runtime_error("文件索引打开失败 " + filename + ": " + message);
    }
    sqlite3_busy_timeout(impl_->database, static_cast<int>(busy_timeout.count()));

    try
    {
        if (mode == Mode::read_write)
        {
            impl_->execute("PRAGMA journal_mode=WAL;");
            impl_->execute("PRAGMA synchronous=NORMAL;");
            const std::string size_limit =
                "PRAGMA journal_size_limit=" + std::to_string(kJournalSizeLimit) + ";";
            impl_->execute(size_limit.c_str());
            impl_->execute(
                "CREATE TABLE IF NOT EXISTS file_lists ("
                "info_hash BLOB PRIMARY KEY NOT NULL,"
                "name TEXT NOT NULL,"
                "file_count INTEGER NOT NULL,"
                "total_size INTEGER NOT NULL,"
                "files BLOB NOT NULL"
                ") WITHOUT ROWID;");
            impl_->execute(
                "CREATE TABLE IF NOT EXISTS index_meta ("
                "key TEXT PRIMARY KEY NOT NULL,"
                "value TEXT NOT NULL);");
            impl_->execute(
                "INSERT OR IGNORE INTO index_meta (key, value) VALUES ('format_version', '1');");
        }

        Statement version(
            impl_->database,
            "SELECT value FROM index_meta WHERE key = 'format_version';");
        Statement::Use use(version);
        if (sqlite3_step(version.get()) != SQLITE_ROW)
            throw std::runtime_error("缺少格式版本");
        const std::string_view value = column_bytes(version.get(), 0);
        if (value != kFormatVersion)
            throw std::runtime_error("不支持的格式版本 " + std::string(value));

        impl_->select = std::make_unique<Statement>(
            impl_->database,
            "SELECT name, files FROM file_lists WHERE info_hash = ?;");
        impl_->exists = std::make_unique<Statement>(
            impl_->database,
            "SELECT 1 FROM file_lists WHERE info_hash = ? LIMIT 1;");
        impl_->count = std::make_unique<Statement>(
            impl_->database,
            "SELECT COUNT(*) FROM file_lists;");
        if (mode == Mode::read_write)
        {
            impl_->insert = std::make_unique<Statement>(
                impl_->database,
                "INSERT OR REPLACE INTO file_lists "
                "(info_hash, name, file_count, total_size, files) VALUES (?, ?, ?, ?, ?);");
        }
    }
    catch (const std::exception &error)
    {
        throw std::runtime_error("不是可用的文件索引 " + filename + ": " + error.what());
    }
}

FileIndex::~FileIndex() = default;
FileIndex::FileIndex(FileIndex &&) noexcept = default;
FileIndex &FileIndex::operator=(FileIndex &&) noexcept = default;

Result FileIndex::put(const std::vector<Entry> &entries)
{
    if (!impl_->insert)
        return Result{Status::error, "文件索引以只读方式打开"};

    std::string error;
    int result = impl_->execute("BEGIN IMMEDIATE;", error);
    if (result != SQLITE_OK)
        return failure(result, error);

    sqlite3_stmt *statement = impl_->insert->get();
    for (const Entry &entry : entries)
    {
        const std::string files = encode_files(entry.files);
        const std::uint64_t total = std::min<std::uint64_t>(
            entry.total_size(), static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()));
        if (files.size() > static_cast<std::size_t>(INT_MAX) || entry.name.size() > static_cast<std::size_t>(INT_MAX))
        {
            impl_->execute("ROLLBACK;", error);
            return Result{Status::error, "文件列表过大: " + to_hex(entry.info_hash)};
        }

        Statement::Use use(*impl_->insert);
        sqlite3_bind_blob(statement, 1, entry.info_hash.data(), static_cast<int>(entry.info_hash.size()), SQLITE_STATIC);
        sqlite3_bind_text(statement, 2, entry.name.data(), static_cast<int>(entry.name.size()), SQLITE_STATIC);
        sqlite3_bind_int64(statement, 3, static_cast<sqlite3_int64>(entry.files.size()));
        sqlite3_bind_int64(statement, 4, static_cast<sqlite3_int64>(total));
        sqlite3_bind_blob(statement, 5, files.data(), static_cast<int>(files.size()), SQLITE_STATIC);
        result = sqlite3_step(statement);
        if (result != SQLITE_DONE)
        {
            const std::string message = sqlite3_errmsg(impl_->database);
            std::string ignored;
            impl_->execute("ROLLBACK;", ignored);
            return failure(result, message);
        }
    }

    result = impl_->execute("COMMIT;", error);
    if (result != SQLITE_OK)
    {
        std::string ignored;
        impl_->execute("ROLLBACK;", ignored);
        return failure(result, error);
    }
    return Result{};
}

std::optional<Entry> FileIndex::get(const InfoHash &info_hash)
{
    Statement::Use use(*impl_->select);
    sqlite3_stmt *statement = impl_->select->get();
    sqlite3_bind_blob(statement, 1, info_hash.data(), static_cast<int>(info_hash.size()), SQLITE_STATIC);
    const int result = sqlite3_step(statement);
    if (result == SQLITE_DONE)
        return std::nullopt;
    if (result != SQLITE_ROW)
        throw std::runtime_error(std::string("文件索引查询失败: ") + sqlite3_errmsg(impl_->database));

    std::optional<std::vector<File>> files = decode_files(column_bytes(statement, 1));
    if (!files)
        throw std::runtime_error("文件索引条目损坏: " + to_hex(info_hash));
    Entry entry;
    entry.info_hash = info_hash;
    entry.name = std::string(column_bytes(statement, 0));
    entry.files = std::move(*files);
    return entry;
}

bool FileIndex::contains(const InfoHash &info_hash)
{
    Statement::Use use(*impl_->exists);
    sqlite3_stmt *statement = impl_->exists->get();
    sqlite3_bind_blob(statement, 1, info_hash.data(), static_cast<int>(info_hash.size()), SQLITE_STATIC);
    const int result = sqlite3_step(statement);
    if (result == SQLITE_ROW)
        return true;
    if (result == SQLITE_DONE)
        return false;
    throw std::runtime_error(std::string("文件索引查询失败: ") + sqlite3_errmsg(impl_->database));
}

std::uint64_t FileIndex::size()
{
    Statement::Use use(*impl_->count);
    sqlite3_stmt *statement = impl_->count->get();
    if (sqlite3_step(statement) != SQLITE_ROW)
        throw std::runtime_error(std::string("文件索引查询失败: ") + sqlite3_errmsg(impl_->database));
    return static_cast<std::uint64_t>(sqlite3_column_int64(statement, 0));
}

Result FileIndex::checkpoint(bool truncate)
{
    const int result = sqlite3_wal_checkpoint_v2(
        impl_->database,
        nullptr,
        truncate ? SQLITE_CHECKPOINT_TRUNCATE : SQLITE_CHECKPOINT_PASSIVE,
        nullptr,
        nullptr);
    if (result != SQLITE_OK)
        return failure(result, sqlite3_errmsg(impl_->database));
    return Result{};
}

std::string encode_files(const std::vector<File> &files)
{
    std::string output;
    put_varint(output, files.size());
    std::string_view previous;
    for (const File &file : files)
    {
        const std::string_view path(file.path);
        const std::size_t limit = std::min(previous.size(), path.size());
        std::size_t shared = 0;
        while (shared < limit && previous[shared] == path[shared])
            ++shared;
        put_varint(output, shared);
        put_varint(output, path.size() - shared);
        output.append(path.substr(shared));
        put_varint(output, file.size);
        previous = path;
    }
    return output;
}

std::optional<std::vector<File>> decode_files(std::string_view encoded)
{
    std::size_t offset = 0;
    std::uint64_t count = 0;
    // Every file takes at least three bytes, which also bounds the reserve.
    if (!get_varint(encoded, offset, count) || count > encoded.size() / 3)
        return std::nullopt;

    std::vector<File> files;
    files.reserve(static_cast<std::size_t>(count));
    std::string previous;
    for (std::uint64_t i = 0; i < count; ++i)
    {
        std::uint64_t shared = 0;
        std::uint64_t length = 0;
        if (!get_varint(encoded, offset, shared) || shared > previous.size())
            return std::nullopt;
        if (!get_varint(encoded, offset, length) || length > encoded.size() - offset)
            return std::nullopt;

        File file;
        file.path.reserve(static_cast<std::size_t>(shared + length));
        file.path.assign(previous, 0, static_cast<std::size_t>(shared));
        file.path.append(encoded.substr(offset, static_cast<std::size_t>(length)));
        offset += static_cast<std::size_t>(length);
        if (!get_varint(encoded, offset, file.size))
            return std::nullopt;

        previous = file.path;
        files.push_back(std::move(file));
    }
    if (offset != encoded.size())
        return std::nullopt;
    return files;
}

std::string to_hex(const InfoHash &info_hash)
{
    static constexpr char digits[] = "0123456789abcdef";
    std::string text(info_hash.size() * 2, '0');
    for (std::size_t i = 0; i < info_hash.size(); ++i)
    {
        text[i * 2] = digits[info_hash[i] >> 4];
        text[i * 2 + 1] = digits[info_hash[i] & 0x0f];
    }
    return text;
}

std::optional<InfoHash> parse_hash(std::string_view hex)
{
    auto value = [](char character) -> int {
        if (character >= '0' && character <= '9')
            return character - '0';
        if (character >= 'a' && character <= 'f')
            return character - 'a' + 10;
        if (character >= 'A' && character <= 'F')
            return character - 'A' + 10;
        return -1;
    };

    InfoHash info_hash{};
    if (hex.size() != info_hash.size() * 2)
        return std::nullopt;
    for (std::size_t i = 0; i < info_hash.size(); ++i)
    {
        const int high = value(hex[i * 2]);
        const int low = value(hex[i * 2 + 1]);
        if (high < 0 || low < 0)
            return std::nullopt;
        info_hash[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return info_hash;
}

std::string format_size(std::uint64_t bytes)
{
    if (bytes < 1024)
        return std::to_string(bytes) + " B";

    static constexpr const char *units[] = {"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"};
    double value = static_cast<double>(bytes) / 1024.0;
    std::size_t unit = 0;
    // 1023.95 would print as "1024.0"; move to the next unit instead.
    while (value >= 1023.95 && unit + 1 < std::size(units))
    {
        value /= 1024.0;
        ++unit;
    }
    char text[32];
    std::snprintf(text, sizeof(text), "%.1f %s", value, units[unit]);
    return text;
}

std::string printable(std::string_view text)
{
    std::string output;
    output.reserve(text.size());
    std::size_t i = 0;
    while (i < text.size())
    {
        const auto lead = static_cast<unsigned char>(text[i]);
        if (lead < 0x80)
        {
            if (lead < 0x20 || lead == 0x7f)
                append_hex_escape(output, lead);
            else
                output.push_back(static_cast<char>(lead));
            ++i;
            continue;
        }

        std::size_t length = 0;
        std::uint32_t code_point = 0;
        if (lead >= 0xc2 && lead <= 0xdf)
        {
            length = 2;
            code_point = lead & 0x1f;
        }
        else if (lead >= 0xe0 && lead <= 0xef)
        {
            length = 3;
            code_point = lead & 0x0f;
        }
        else if (lead >= 0xf0 && lead <= 0xf4)
        {
            length = 4;
            code_point = lead & 0x07;
        }

        bool valid = length > 0 && i + length <= text.size();
        for (std::size_t k = 1; valid && k < length; ++k)
        {
            const auto byte = static_cast<unsigned char>(text[i + k]);
            if ((byte & 0xc0) != 0x80)
                valid = false;
            code_point = (code_point << 6) | (byte & 0x3f);
        }
        // Reject overlong forms, surrogates and values beyond U+10FFFF.
        if (valid
            && ((length == 3 && code_point < 0x800)
                || (length == 4 && (code_point < 0x10000 || code_point > 0x10ffff))
                || (code_point >= 0xd800 && code_point <= 0xdfff)))
        {
            valid = false;
        }

        if (!valid)
        {
            append_hex_escape(output, lead);
            ++i;
            continue;
        }
        if (is_hidden_control(code_point))
        {
            char escape[16];
            std::snprintf(escape, sizeof(escape), "\\u{%X}", static_cast<unsigned>(code_point));
            output += escape;
        }
        else
        {
            output.append(text.substr(i, length));
        }
        i += length;
    }
    return output;
}

std::string render_tree(const Entry &entry, const TreeOptions &options)
{
    struct Node
    {
        std::string name;
        bool directory = false;
        std::uint64_t size = 0;
        std::vector<std::size_t> children;
    };

    // Node 0 is the unnamed root; children keep first-appearance order.
    std::vector<Node> nodes(1);
    nodes[0].directory = true;
    std::unordered_map<std::string, std::size_t> directories;

    for (const File &file : entry.files)
    {
        std::vector<std::string_view> components;
        std::string_view rest(file.path);
        while (!rest.empty())
        {
            if (components.size() + 1 == kMaxTreeDepth)
            {
                components.push_back(rest);
                break;
            }
            const std::size_t slash = rest.find('/');
            const std::string_view component = rest.substr(0, slash);
            if (!component.empty())
                components.push_back(component);
            if (slash == std::string_view::npos)
                break;
            rest.remove_prefix(slash + 1);
        }
        if (components.empty())
            components.push_back({});

        std::size_t parent = 0;
        nodes[0].size = saturating_add(nodes[0].size, file.size);
        for (std::size_t c = 0; c + 1 < components.size(); ++c)
        {
            std::string key = std::to_string(parent);
            key.push_back('/');
            key.append(components[c]);
            auto found = directories.find(key);
            if (found == directories.end())
            {
                Node directory;
                directory.name = std::string(components[c]);
                directory.directory = true;
                nodes.push_back(std::move(directory));
                nodes[parent].children.push_back(nodes.size() - 1);
                found = directories.emplace(std::move(key), nodes.size() - 1).first;
            }
            parent = found->second;
            nodes[parent].size = saturating_add(nodes[parent].size, file.size);
        }

        Node leaf;
        leaf.name = std::string(components.back());
        leaf.size = file.size;
        nodes.push_back(std::move(leaf));
        nodes[parent].children.push_back(nodes.size() - 1);
    }

    auto size_text = [&options](std::uint64_t bytes) {
        return options.exact_sizes ? std::to_string(bytes) + " B" : format_size(bytes);
    };
    const char *branch = options.ascii ? "|-- " : "\xe2\x94\x9c\xe2\x94\x80\xe2\x94\x80 ";
    const char *last_branch = options.ascii ? "`-- " : "\xe2\x94\x94\xe2\x94\x80\xe2\x94\x80 ";
    const char *vertical = options.ascii ? "|   " : "\xe2\x94\x82   ";
    const char *blank = "    ";

    std::string output = to_hex(entry.info_hash) + "  " + printable(entry.name) + '\n';
    output += std::to_string(entry.files.size())
        + (entry.files.size() == 1 ? " file, " : " files, ")
        + size_text(entry.total_size()) + '\n';

    // Iterative depth-first walk: recursion depth would follow the
    // (untrusted) nesting depth.
    struct Frame
    {
        std::size_t node;
        std::string prefix;
        bool last;
        bool top;
    };
    std::vector<Frame> stack;
    const std::vector<std::size_t> &top = nodes[0].children;
    for (std::size_t i = top.size(); i-- > 0;)
        stack.push_back(Frame{top[i], {}, i + 1 == top.size(), true});

    while (!stack.empty())
    {
        Frame frame = std::move(stack.back());
        stack.pop_back();
        const Node &node = nodes[frame.node];

        output += frame.prefix;
        if (!frame.top)
            output += frame.last ? last_branch : branch;
        output += printable(node.name);
        if (node.directory)
            output += '/';
        output += "  [" + size_text(node.size) + "]\n";

        std::string child_prefix = frame.prefix;
        if (!frame.top)
            child_prefix += frame.last ? blank : vertical;
        for (std::size_t i = node.children.size(); i-- > 0;)
            stack.push_back(Frame{node.children[i], child_prefix, i + 1 == node.children.size(), false});
    }
    return output;
}

} // namespace file_index
