#include "hash_registry.hpp"

#include <algorithm>
#include <cstring>
#include <random>

namespace
{

std::uint64_t random_seed()
{
    std::random_device device;
    std::uint64_t seed = (static_cast<std::uint64_t>(device()) << 32) ^ device();
    seed ^= static_cast<std::uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    return seed;
}

std::uint64_t load64(const std::uint8_t *bytes)
{
    std::uint64_t value = 0;
    std::memcpy(&value, bytes, sizeof(value));
    return value;
}

// splitmix64 finaliser.
std::uint64_t mix(std::uint64_t value)
{
    value ^= value >> 30;
    value *= 0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27;
    value *= 0x94d049bb133111ebULL;
    value ^= value >> 31;
    return value;
}

} // namespace

std::size_t HashRegistry::Hasher::operator()(const InfoHash &hash) const noexcept
{
    std::uint32_t tail = 0;
    std::memcpy(&tail, hash.data() + 16, sizeof(tail));
    std::uint64_t value = mix(load64(hash.data()) ^ seed);
    value = mix(value ^ load64(hash.data() + 8));
    value = mix(value ^ tail);
    return static_cast<std::size_t>(value);
}

HashRegistry::HashRegistry(std::size_t max_settled, std::size_t shard_count)
    : shard_seed_(random_seed())
{
    shard_count = std::max<std::size_t>(shard_count, 1);
    max_settled_per_shard_ =
        std::max<std::size_t>((max_settled + shard_count - 1) / shard_count, 1);

    const Hasher hasher{random_seed()};
    shards_.reserve(shard_count);
    for (std::size_t i = 0; i < shard_count; ++i)
        shards_.push_back(std::make_unique<Shard>(hasher));
}

HashRegistry::Shard &HashRegistry::shard_for(const InfoHash &hash)
{
    const std::uint64_t value = mix(load64(hash.data() + 12) ^ shard_seed_);
    return *shards_[static_cast<std::size_t>(value % shards_.size())];
}

HashRegistry::Claim HashRegistry::try_claim(const InfoHash &hash, Clock::time_point now)
{
    Shard &shard = shard_for(hash);
    std::lock_guard<std::mutex> lock(shard.mutex);
    trim(shard, now);

    const auto [iterator, inserted] = shard.entries.try_emplace(hash);
    Entry &entry = iterator->second;
    if (inserted)
    {
        entry.state = State::in_flight;
        ++shard.in_flight;
        return Claim::claimed;
    }
    if (entry.state == State::in_flight)
        return Claim::in_flight;
    if (entry.until > now)
        return entry.state == State::completed ? Claim::completed : Claim::backoff;

    shard.settled.erase(entry.order);
    entry.state = State::in_flight;
    entry.until = {};
    ++shard.in_flight;
    ++shard.expired;
    return Claim::claimed;
}

void HashRegistry::settle_completed(const InfoHash &hash, Clock::time_point expires)
{
    settle(hash, State::completed, expires);
}

void HashRegistry::settle_failed(const InfoHash &hash, Clock::time_point retry_after)
{
    settle(hash, State::failed, retry_after);
}

void HashRegistry::settle(const InfoHash &hash, State state, Clock::time_point until)
{
    Shard &shard = shard_for(hash);
    std::lock_guard<std::mutex> lock(shard.mutex);

    // Allocate the order node first so a bad_alloc leaves the shard intact.
    const auto order = shard.settled.insert(shard.settled.end(), hash);
    Entry *entry = nullptr;
    try
    {
        const auto [iterator, inserted] = shard.entries.try_emplace(hash);
        entry = &iterator->second;
        if (!inserted)
        {
            if (entry->state == State::in_flight)
                --shard.in_flight;
            else
                shard.settled.erase(entry->order);
        }
    }
    catch (...)
    {
        shard.settled.erase(order);
        throw;
    }

    entry->state = state;
    entry->until = until;
    entry->order = order;
    trim(shard, Clock::now());
}

void HashRegistry::release(const InfoHash &hash)
{
    Shard &shard = shard_for(hash);
    std::lock_guard<std::mutex> lock(shard.mutex);
    const auto iterator = shard.entries.find(hash);
    if (iterator == shard.entries.end() || iterator->second.state != State::in_flight)
        return;
    shard.entries.erase(iterator);
    --shard.in_flight;
}

void HashRegistry::purge(Clock::time_point now)
{
    for (const auto &shard : shards_)
    {
        std::lock_guard<std::mutex> lock(shard->mutex);
        trim(*shard, now);
    }
}

void HashRegistry::trim(Shard &shard, Clock::time_point now)
{
    // Oldest settled entries first. Entries behind a younger-but-longer-lived
    // front entry may linger past their expiry; lookups still honour their
    // own deadline, and the size cap bounds the memory.
    while (!shard.settled.empty())
    {
        const auto iterator = shard.entries.find(shard.settled.front());
        const bool over_capacity = shard.settled.size() > max_settled_per_shard_;
        const bool expired = iterator == shard.entries.end() || iterator->second.until <= now;
        if (!over_capacity && !expired)
            break;

        if (expired)
            ++shard.expired;
        else
            ++shard.evicted;
        if (iterator != shard.entries.end())
            shard.entries.erase(iterator);
        shard.settled.pop_front();
    }
}

HashRegistry::Stats HashRegistry::stats() const
{
    Stats result;
    for (const auto &shard : shards_)
    {
        std::lock_guard<std::mutex> lock(shard->mutex);
        result.in_flight += shard->in_flight;
        result.settled += shard->settled.size();
        result.expired += shard->expired;
        result.evicted += shard->evicted;
    }
    return result;
}
