#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <list>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

// Process-wide claim table for info-hashes, shared by every libtorrent
// session so each hash is worked on by at most one task at a time.
//
//   unknown --try_claim--> in flight --settle_completed--> completed (TTL)
//                              |      --settle_failed----> failed (backoff)
//                              +------release-----------> unknown
//
// In-flight entries are bounded by the callers' task limits and are never
// evicted. Settled entries are only a cache in front of the database: they
// expire by time and, beyond `max_settled`, the oldest are evicted, so memory
// stays bounded however long the crawler runs. Bucket placement uses a
// per-process random seed, so peers announcing crafted info-hashes cannot
// force hash-table collisions.
class HashRegistry
{
public:
    using InfoHash = std::array<std::uint8_t, 20>;
    using Clock = std::chrono::steady_clock;

    enum class Claim
    {
        claimed,
        in_flight,
        completed,
        backoff
    };

    struct Stats
    {
        std::size_t in_flight = 0;
        std::size_t settled = 0;
        std::uint64_t expired = 0;
        std::uint64_t evicted = 0;
    };

    explicit HashRegistry(std::size_t max_settled, std::size_t shard_count = 16);

    HashRegistry(const HashRegistry &) = delete;
    HashRegistry &operator=(const HashRegistry &) = delete;

    Claim try_claim(const InfoHash &hash, Clock::time_point now);
    // Moves a hash to the completed cache until `expires` (inserting it if
    // it was not in flight).
    void settle_completed(const InfoHash &hash, Clock::time_point expires);
    void settle_failed(const InfoHash &hash, Clock::time_point retry_after);
    // Drops an in-flight claim without penalty.
    void release(const InfoHash &hash);
    // Reclaims expired settled entries; also done incrementally by the
    // other calls.
    void purge(Clock::time_point now);

    Stats stats() const;

private:
    enum class State : std::uint8_t
    {
        in_flight,
        completed,
        failed
    };

    struct Hasher
    {
        std::uint64_t seed;
        std::size_t operator()(const InfoHash &hash) const noexcept;
    };

    struct Entry
    {
        State state = State::in_flight;
        Clock::time_point until{};
        std::list<InfoHash>::iterator order;
    };

    struct Shard
    {
        explicit Shard(Hasher hasher)
            : entries(0, hasher)
        {
        }

        mutable std::mutex mutex;
        std::unordered_map<InfoHash, Entry, Hasher> entries;
        // Settled hashes, oldest first.
        std::list<InfoHash> settled;
        std::size_t in_flight = 0;
        std::uint64_t expired = 0;
        std::uint64_t evicted = 0;
    };

    Shard &shard_for(const InfoHash &hash);
    void settle(const InfoHash &hash, State state, Clock::time_point until);
    void trim(Shard &shard, Clock::time_point now);

    std::uint64_t shard_seed_;
    std::size_t max_settled_per_shard_;
    std::vector<std::unique_ptr<Shard>> shards_;
};
