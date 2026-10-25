#include "tracker_protocol.hpp"

#include "simple_network.hpp"

#include <sstream>
#include <utility>

namespace tracker
{

int hex_value(char character)
{
    if (character >= '0' && character <= '9')
        return character - '0';
    if (character >= 'a' && character <= 'f')
        return character - 'a' + 10;
    if (character >= 'A' && character <= 'F')
        return character - 'A' + 10;
    return -1;
}

std::optional<std::string> url_decode(std::string_view encoded)
{
    std::string decoded;
    decoded.reserve(encoded.size());
    for (std::size_t i = 0; i < encoded.size(); ++i)
    {
        if (encoded[i] == '%')
        {
            if (i + 2 >= encoded.size())
                return std::nullopt;
            const int high = hex_value(encoded[i + 1]);
            const int low = hex_value(encoded[i + 2]);
            if (high < 0 || low < 0)
                return std::nullopt;
            decoded.push_back(static_cast<char>((high << 4) | low));
            i += 2;
        }
        else if (encoded[i] == '+')
        {
            decoded.push_back(' ');
        }
        else
        {
            decoded.push_back(encoded[i]);
        }
    }
    return decoded;
}

std::unordered_map<std::string, std::string> parse_query(std::string_view query)
{
    std::unordered_map<std::string, std::string> values;
    std::size_t offset = 0;
    while (offset <= query.size())
    {
        const std::size_t separator = query.find('&', offset);
        const std::string_view item = query.substr(
            offset,
            separator == std::string_view::npos
                ? query.size() - offset
                : separator - offset);
        const std::size_t equals = item.find('=');
        const std::string_view key = item.substr(0, equals);
        const std::string_view encoded_value =
            equals == std::string_view::npos
                ? std::string_view{}
                : item.substr(equals + 1);

        const std::optional<std::string> decoded_key = url_decode(key);
        const std::optional<std::string> decoded_value = url_decode(encoded_value);
        if (decoded_key && decoded_value && !decoded_key->empty())
            values.emplace(*decoded_key, *decoded_value);

        if (separator == std::string_view::npos)
            break;
        offset = separator + 1;
    }
    return values;
}

std::optional<InfoHash> parse_info_hash(const std::string &value)
{
    InfoHash hash{};
    if (value.size() == hash.size())
    {
        for (std::size_t i = 0; i < hash.size(); ++i)
            hash[i] = static_cast<std::uint8_t>(value[i]);
        return hash;
    }

    if (value.size() == hash.size() * 2)
    {
        for (std::size_t i = 0; i < hash.size(); ++i)
        {
            const int high = hex_value(value[i * 2]);
            const int low = hex_value(value[i * 2 + 1]);
            if (high < 0 || low < 0)
                return std::nullopt;
            hash[i] = static_cast<std::uint8_t>((high << 4) | low);
        }
        return hash;
    }
    return std::nullopt;
}

std::string hash_to_hex(const InfoHash &hash)
{
    static constexpr char digits[] = "0123456789abcdef";
    std::string result(hash.size() * 2, '0');
    for (std::size_t i = 0; i < hash.size(); ++i)
    {
        result[i * 2] = digits[hash[i] >> 4];
        result[i * 2 + 1] = digits[hash[i] & 0x0f];
    }
    return result;
}

std::optional<RequestLine> parse_request_line(const std::string &request)
{
    const std::size_t line_end = request.find("\r\n");
    if (line_end == std::string::npos)
        return std::nullopt;

    std::istringstream parser(request.substr(0, line_end));
    RequestLine line;
    std::string extra;
    parser >> line.method >> line.target >> line.version;
    parser >> extra;
    line.extra_tokens = !extra.empty();
    return line;
}

std::string bencode_string(std::string_view value)
{
    return std::to_string(value.size()) + ':' + std::string(value);
}

std::string failure_body(std::string_view reason)
{
    return "d14:failure reason" + bencode_string(reason) + 'e';
}

std::string compact_peers(const std::vector<PeerEndpoint> &peers, int family)
{
    std::string compact;
    for (const PeerEndpoint &peer : peers)
    {
        if (peer.family != family)
            continue;

        const std::optional<std::string> address =
            simple_net::pack_ip_address(family, peer.address);
        if (!address)
            continue;

        compact += *address;
        compact.push_back(static_cast<char>((peer.port >> 8) & 0xff));
        compact.push_back(static_cast<char>(peer.port & 0xff));
    }
    return compact;
}

std::string success_body(const std::vector<PeerEndpoint> &peers, int interval_seconds)
{
    const std::string peers4 = compact_peers(peers, 4);
    const std::string peers6 = compact_peers(peers, 6);

    std::string body =
        "d8:intervali" + std::to_string(interval_seconds)
        + "e12:min intervali" + std::to_string(interval_seconds)
        + "e5:peers" + bencode_string(peers4);
    if (!peers6.empty())
        body += "6:peers6" + bencode_string(peers6);
    body += 'e';
    return body;
}

std::string http_response(
    int status,
    std::string_view status_text,
    std::string_view content_type,
    const std::string &body)
{
    std::ostringstream response;
    response << "HTTP/1.1 " << status << ' ' << status_text << "\r\n"
             << "Content-Type: " << content_type << "\r\n"
             << "Content-Length: " << body.size() << "\r\n"
             << "Connection: close\r\n"
             << "Cache-Control: no-store\r\n\r\n"
             << body;
    return response.str();
}

std::string rpc_request(const std::string &hash_hex)
{
    return "DHTP/1 GET_PEERS " + hash_hex + '\n';
}

LookupReply parse_rpc_response(const std::string &response)
{
    std::istringstream lines(response);
    std::string header;
    if (!std::getline(lines, header))
        return {LookupStatus::error, {}, "空 RPC 响应"};
    if (!header.empty() && header.back() == '\r')
        header.pop_back();

    std::istringstream header_parser(header);
    std::string protocol;
    std::string status;
    header_parser >> protocol >> status;
    if (protocol != "DHTP/1")
        return {LookupStatus::error, {}, "无效 RPC 协议"};
    if (status == "TIMEOUT")
        return {LookupStatus::timeout, {}, "DHT 查询超时"};
    if (status != "OK")
        return {LookupStatus::error, {}, "DHT 爬虫查询失败"};

    std::size_t peer_count = 0;
    if (!(header_parser >> peer_count) || peer_count > kMaxPeers)
        return {LookupStatus::error, {}, "无效 peer 数量"};

    std::vector<PeerEndpoint> peers;
    peers.reserve(peer_count);
    for (std::size_t i = 0; i < peer_count; ++i)
    {
        std::string line;
        if (!std::getline(lines, line))
            return {LookupStatus::error, {}, "RPC peer 列表不完整"};
        if (!line.empty() && line.back() == '\r')
            line.pop_back();

        std::istringstream peer_parser(line);
        std::string type;
        PeerEndpoint peer;
        int port = 0;
        std::string extra;
        peer_parser >> type >> peer.family >> peer.address >> port;
        peer_parser >> extra;
        if (type != "PEER"
            || (peer.family != 4 && peer.family != 6)
            || port <= 0
            || port > kMaxPort
            || !extra.empty())
        {
            return {LookupStatus::error, {}, "无效 RPC peer"};
        }
        peer.port = static_cast<std::uint16_t>(port);
        peers.push_back(std::move(peer));
    }
    return {LookupStatus::ok, std::move(peers), {}};
}

} // namespace tracker
