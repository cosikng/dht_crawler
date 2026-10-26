#pragma once

#include "file_index.hpp"

#include <optional>

#include <libtorrent/span.hpp>

// Builds the file-index entry for a fetched torrent from its raw (verified)
// info dictionary. Names come exactly as recorded, preferring the
// "name.utf-8"/"path.utf-8" variants like libtorrent does, but without the
// per-platform sanitising libtorrent applies to its own file_storage
// (Windows turns ':' into '_', paths use '\\'), so the result is identical
// on every platform. A '/' inside a recorded component becomes '_', empty
// components are dropped and BEP 47 padding files are skipped.
//
// Uses the v1 file list ("length" or "files"), which every torrent this
// crawler can fetch has: it looks torrents up by v1 info-hash, so it fetches
// v1 and hybrid torrents only. nullopt if the dictionary is malformed.
std::optional<file_index::Entry> file_list_from_info(
    const file_index::InfoHash &info_hash,
    libtorrent::span<char const> info_section);
