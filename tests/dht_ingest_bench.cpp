// Measures the CPU cost of ingesting DHT traffic for each way of capturing
// announce_peer messages. Build with -DDHT_CRAWLER_BUILD_BENCHMARKS=ON and
// run tests/dht_ingest_bench.py, or the two roles by hand:
//
//   dht_ingest_bench receive --mode MODE --port P --seconds T [--upload-limit BYTES]
//   dht_ingest_bench send --port P --rate PACKETS_PER_SECOND --seconds T
//
// --upload-limit sets dht_upload_rate_limit (libtorrent default 8000 B/s).
// Once that quota is spent libtorrent drops incoming queries *before* its
// request handling (and before AnnouncePlugin), but after dht_pkt_alert has
// been posted, so the modes differ in what they see as well as in cost.
//
// Modes:
//   sniff      alert_category::dht_log; bdecode every incoming dht_pkt_alert
//              (the crawler before AnnouncePlugin)
//   prefilter  as sniff, but bdecode only packets containing "13:announce_peer"
//   alerts     dht_log enabled, alerts popped and discarded (libtorrent's share)
//   plugin     session plugin (on_dht_request), dht_log disabled
//   none       no capture at all (cost of the DHT itself)
//
// The crawler uses "prefilter". "plugin" avoids the alerts entirely but only
// sees queries libtorrent actually handles: beyond the DHT upload quota it
// drops queries before plugins run, and with them most announces.
//
// The receiver reports its own process CPU and libtorrent's
// dht.dht_messages_in counter, so the sender's CPU is not included.

#include <libtorrent/alert_types.hpp>
#include <libtorrent/bdecode.hpp>
#include <libtorrent/extensions.hpp>
#include <libtorrent/session.hpp>
#include <libtorrent/session_params.hpp>
#include <libtorrent/session_stats.hpp>
#include <libtorrent/settings_pack.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#include <random>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <time.h>
#endif

namespace lt = libtorrent;
using Clock = std::chrono::steady_clock;

namespace
{

// Counts announce_peer requests libtorrent's DHT node handles. The hook runs
// on the network thread after the request shape is verified and before the
// token check.
class AnnouncePlugin final : public lt::plugin
{
public:
    explicit AnnouncePlugin(std::atomic<std::uint64_t> &announces)
        : announces_(announces)
    {
    }

    lt::feature_flags_t implemented_features() override
    {
        return dht_request_feature;
    }

    bool on_dht_request(
        lt::string_view query,
        const lt::udp::endpoint &,
        const lt::bdecode_node &message,
        lt::entry &) override
    {
        if (query != "announce_peer")
            return false;
        const lt::bdecode_node arguments = message.dict_find_dict("a");
        const lt::bdecode_node hash = arguments ? arguments.dict_find_string("info_hash") : lt::bdecode_node();
        if (hash && hash.string_length() == lt::sha1_hash::size())
            announces_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

private:
    std::atomic<std::uint64_t> &announces_;
};

// Exact process CPU consumption. GetProcessTimes/getrusage charge whole
// scheduler ticks, which grossly mis-measures threads that run in short
// bursts (exactly what a DHT node does). Windows: CPU cycles of all threads
// (unit "Mcycles"); POSIX: CPU nanoseconds (unit "ms").
double process_cpu()
{
#if defined(_WIN32)
    ULONG64 cycles = 0;
    ::QueryProcessCycleTime(::GetCurrentProcess(), &cycles);
    return static_cast<double>(cycles) / 1e6;
#else
    timespec time{};
    ::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time);
    return static_cast<double>(time.tv_sec) * 1e3 + static_cast<double>(time.tv_nsec) / 1e6;
#endif
}

const char *process_cpu_unit()
{
#if defined(_WIN32)
    return "Mcycles";
#else
    return "ms";
#endif
}

std::string option(int argc, char **argv, const char *name, const char *fallback)
{
    for (int i = 2; i + 1 < argc; ++i)
    {
        if (std::string_view(argv[i]) == name)
            return argv[i + 1];
    }
    return fallback;
}

std::string random_bytes(std::mt19937_64 &random, std::size_t size)
{
    std::string bytes(size, '\0');
    for (char &byte : bytes)
        byte = static_cast<char>(random() & 0xff);
    return bytes;
}

std::string bstr(const std::string &value)
{
    return std::to_string(value.size()) + ':' + value;
}

// KRPC queries with sorted keys, in roughly the mix a crawler node receives.
std::vector<std::string> make_packets(std::size_t count)
{
    std::mt19937_64 random(12345);
    std::vector<std::string> packets;
    packets.reserve(count);
    for (std::size_t i = 0; i < count; ++i)
    {
        const std::string id = bstr(random_bytes(random, 20));
        const std::string tail = "1:t" + bstr(random_bytes(random, 2)) + "1:y1:qe";
        const unsigned kind = static_cast<unsigned>(random() % 100);
        if (kind < 25)
        {
            const auto port = 1024 + random() % 60000;
            packets.push_back(
                "d1:ad2:id" + id + "12:implied_porti0e9:info_hash" + bstr(random_bytes(random, 20))
                + "4:porti" + std::to_string(port) + "e5:token" + bstr(random_bytes(random, 8))
                + "e1:q13:announce_peer" + tail);
        }
        else if (kind < 65)
        {
            packets.push_back(
                "d1:ad2:id" + id + "9:info_hash" + bstr(random_bytes(random, 20))
                + "e1:q9:get_peers" + tail);
        }
        else if (kind < 85)
        {
            packets.push_back(
                "d1:ad2:id" + id + "6:target" + bstr(random_bytes(random, 20))
                + "e1:q9:find_node" + tail);
        }
        else
        {
            packets.push_back("d1:ad2:id" + id + "e1:q4:ping" + tail);
        }
    }
    return packets;
}

int send(int argc, char **argv)
{
    const auto port = static_cast<unsigned short>(std::stoi(option(argc, argv, "--port", "0")));
    const long rate = std::stol(option(argc, argv, "--rate", "10000"));
    const double seconds = std::stod(option(argc, argv, "--seconds", "10"));
    const std::vector<std::string> packets = make_packets(8192);

    boost::asio::io_context context;
    std::vector<std::unique_ptr<boost::asio::ip::udp::socket>> sockets;
    // One source address per simulated node; all of 127/8 is loopback.
    for (int host = 1; host < 255; ++host)
    {
        auto socket = std::make_unique<boost::asio::ip::udp::socket>(context);
        boost::system::error_code error;
        socket->open(boost::asio::ip::udp::v4(), error);
        socket->bind({boost::asio::ip::make_address_v4("127.0.0." + std::to_string(host)), 0}, error);
        if (!error)
            sockets.push_back(std::move(socket));
    }
    if (sockets.empty())
        return 1;

    const boost::asio::ip::udp::endpoint target(boost::asio::ip::make_address_v4("127.0.0.1"), port);
    const auto start = Clock::now();
    const auto end = start + std::chrono::duration<double>(seconds);
    std::uint64_t sent = 0;
    while (Clock::now() < end)
    {
        const double elapsed = std::chrono::duration<double>(Clock::now() - start).count();
        const auto due = static_cast<std::uint64_t>(elapsed * static_cast<double>(rate));
        for (; sent < due; ++sent)
        {
            const std::string &packet = packets[sent % packets.size()];
            boost::system::error_code error;
            sockets[sent % sockets.size()]->send_to(boost::asio::buffer(packet), target, 0, error);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    std::printf("sent %llu packets from %zu source addresses\n",
                static_cast<unsigned long long>(sent), sockets.size());
    return 0;
}

int receive(int argc, char **argv)
{
    const std::string mode = option(argc, argv, "--mode", "plugin");
    const std::string port = option(argc, argv, "--port", "0");
    const double seconds = std::stod(option(argc, argv, "--seconds", "10"));
    const bool dht_log = mode == "sniff" || mode == "prefilter" || mode == "alerts";

    lt::settings_pack settings;
    lt::alert_category_t mask = lt::alert_category::status
        | lt::alert_category::error
        | lt::alert_category::dht_operation;
    if (dht_log)
        mask |= lt::alert_category::dht_log;
    settings.set_int(lt::settings_pack::alert_mask, mask);
    settings.set_int(lt::settings_pack::alert_queue_size, 10000);
    settings.set_bool(lt::settings_pack::enable_dht, true);
    settings.set_bool(lt::settings_pack::enable_lsd, false);
    settings.set_bool(lt::settings_pack::enable_upnp, false);
    settings.set_bool(lt::settings_pack::enable_natpmp, false);
    settings.set_str(lt::settings_pack::dht_bootstrap_nodes, "");
    settings.set_str(lt::settings_pack::listen_interfaces, "127.0.0.1:" + port);
    // The flood comes from 254 loopback addresses; lift the per-IP limit so
    // libtorrent processes all of it instead of blocking the senders.
    settings.set_int(lt::settings_pack::dht_block_ratelimit, 100000000);
    const std::string upload_limit = option(argc, argv, "--upload-limit", "");
    if (!upload_limit.empty())
        settings.set_int(lt::settings_pack::dht_upload_rate_limit, std::stoi(upload_limit));

    std::atomic<std::uint64_t> plugin_announces{0};
    lt::session_params parameters(std::move(settings));
    if (mode == "plugin")
        parameters.extensions.push_back(std::make_shared<AnnouncePlugin>(plugin_announces));
    lt::session session(std::move(parameters));

    // Let startup work (interface enumeration, crypto init) finish first.
    std::this_thread::sleep_for(std::chrono::seconds(2));
    std::cout << "READY" << std::endl;

    const double cpu_start = process_cpu();
    const auto end = Clock::now() + std::chrono::duration<double>(seconds);
    std::vector<lt::alert *> alerts;
    lt::bdecode_node decoded;
    std::uint64_t log_alerts = 0;
    std::uint64_t packet_alerts = 0;
    std::uint64_t other_alerts = 0;
    std::uint64_t dropped_notices = 0;
    std::uint64_t sniffed_announces = 0;
    std::uint64_t decoded_packets = 0;

    auto handle = [&](lt::alert *alert) {
        if (auto *packet = lt::alert_cast<lt::dht_pkt_alert>(alert))
        {
            ++packet_alerts;
            if (packet->direction != lt::dht_pkt_alert::incoming
                || (mode != "sniff" && mode != "prefilter"))
            {
                return;
            }
            const lt::span<char const> buffer = packet->pkt_buf();
            if (mode == "prefilter"
                && std::string_view(buffer.data(), static_cast<std::size_t>(buffer.size()))
                           .find("13:announce_peer")
                    == std::string_view::npos)
            {
                return;
            }
            lt::error_code error;
            ++decoded_packets;
            if (lt::bdecode(buffer.data(), buffer.data() + buffer.size(), decoded, error, nullptr, 10, 500) != 0
                || decoded.type() != lt::bdecode_node::dict_t
                || decoded.dict_find_string_value("y") != "q"
                || decoded.dict_find_string_value("q") != "announce_peer")
            {
                return;
            }
            const lt::bdecode_node arguments = decoded.dict_find_dict("a");
            if (arguments && arguments.dict_find_string_value("info_hash").size() == 20)
                ++sniffed_announces;
        }
        else if (lt::alert_cast<lt::dht_log_alert>(alert))
            ++log_alerts;
        else if (lt::alert_cast<lt::alerts_dropped_alert>(alert))
            ++dropped_notices;
        else
            ++other_alerts;
    };

    while (Clock::now() < end)
    {
        session.wait_for_alert(std::chrono::milliseconds(100));
        session.pop_alerts(&alerts);
        for (lt::alert *alert : alerts)
            handle(alert);
    }
    const double cpu_used = process_cpu() - cpu_start;

    std::int64_t messages_in = -1;
    std::int64_t messages_dropped = -1;
    const int in_index = lt::find_metric_idx("dht.dht_messages_in");
    const int dropped_index = lt::find_metric_idx("dht.dht_messages_in_dropped");
    session.post_session_stats();
    const auto stats_deadline = Clock::now() + std::chrono::seconds(5);
    while (messages_in < 0 && Clock::now() < stats_deadline)
    {
        session.wait_for_alert(std::chrono::milliseconds(200));
        session.pop_alerts(&alerts);
        for (lt::alert *alert : alerts)
        {
            if (auto *stats = lt::alert_cast<lt::session_stats_alert>(alert))
            {
                messages_in = stats->counters()[in_index];
                messages_dropped = stats->counters()[dropped_index];
            }
        }
    }

    const std::uint64_t announces = mode == "plugin" ? plugin_announces.load() : sniffed_announces;
    // Per-message cost in thousandths of the CPU unit (kcycles or us).
    const double per_message =
        messages_in > 0 ? cpu_used * 1e3 / static_cast<double>(messages_in) : 0.0;
    std::printf(
        "RESULT mode=%s cpu=%.1f cpu_unit=%s messages_in=%lld messages_dropped=%lld "
        "per_message=%.2f announces=%llu dht_log_alerts=%llu dht_pkt_alerts=%llu "
        "other_alerts=%llu alerts_dropped_notices=%llu bdecoded=%llu\n",
        mode.c_str(),
        cpu_used,
        process_cpu_unit(),
        static_cast<long long>(messages_in),
        static_cast<long long>(messages_dropped),
        per_message,
        static_cast<unsigned long long>(announces),
        static_cast<unsigned long long>(log_alerts),
        static_cast<unsigned long long>(packet_alerts),
        static_cast<unsigned long long>(other_alerts),
        static_cast<unsigned long long>(dropped_notices),
        static_cast<unsigned long long>(decoded_packets));
    std::fflush(stdout);
    return 0;
}

} // namespace

int main(int argc, char **argv)
{
    const std::string role = argc > 1 ? argv[1] : "";
    if (role == "send")
        return send(argc, argv);
    if (role == "receive")
        return receive(argc, argv);
    std::fprintf(stderr, "usage: %s receive|send [options]\n", argv[0]);
    return 2;
}
