#pragma once

// HTTP announce parsing, bencoded tracker replies and the DHTP/1 crawler RPC
// codec shared by tracker_server and the tests.

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <vector>

namespace tracker
{

constexpr int kMaxPort = 65535;
constexpr std::size_t kMaxPeers = 512;

using InfoHash = std::array<std::uint8_t, 20>;

template <typename Integer>
bool parse_integer(std::string_view text, Integer &value)
{
    if (text.empty())
        return false;

    Integer parsed{};
    const char *begin = text.data();
    const char *end = begin + text.size();
    const auto result = std::from_chars(begin, end, parsed);
    if (result.ec != std::errc{} || result.ptr != end)
        return false;
    value = parsed;
    return true;
}

struct PeerEndpoint
{
    int family = 0;
    std::string address;
    std::uint16_t port = 0;
};

enum class LookupStatus
{
    ok,
    timeout,
    error
};

struct LookupReply
{
    LookupStatus status = LookupStatus::error;
    std::vector<PeerEndpoint> peers;
    std::string error;
};

struct RequestLine
{
    std::string method;
    std::string target;
    std::string version;
    bool extra_tokens = false;
};

int hex_value(char character);
std::optional<std::string> url_decode(std::string_view encoded);
std::unordered_map<std::string, std::string> parse_query(std::string_view query);
// Accepts the 20 raw bytes of a BEP 3 info_hash or 40 hex digits.
std::optional<InfoHash> parse_info_hash(const std::string &value);
std::string hash_to_hex(const InfoHash &hash);

// Splits the first request line; nullopt when no CRLF-terminated line exists.
std::optional<RequestLine> parse_request_line(const std::string &request);

std::string bencode_string(std::string_view value);
std::string failure_body(std::string_view reason);
// Compact BEP 23 (IPv4) / BEP 7 (IPv6) peer string; unparsable addresses
// are skipped.
std::string compact_peers(const std::vector<PeerEndpoint> &peers, int family);
std::string success_body(const std::vector<PeerEndpoint> &peers, int interval_seconds);
std::string http_response(
    int status,
    std::string_view status_text,
    std::string_view content_type,
    const std::string &body);

std::string rpc_request(const std::string &hash_hex);
// Parses a complete "DHTP/1 ..." reply terminated by "END\n".
LookupReply parse_rpc_response(const std::string &response);

} // namespace tracker
