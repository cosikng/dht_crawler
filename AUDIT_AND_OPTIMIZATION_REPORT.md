# DHT Crawler — Cross-Platform Port, Audit and Optimization Report

Scope: `dht_crawler-main` (C++17: `dht_db`, `tracker_server`, `simple_network`), per `TASKS.txt`.
Date: 2026-10-24. Host: Windows 11 Pro 10.0.26300, w64devkit GCC 16.2.0 (MinGW-w64, msvcrt),
CMake 4.5.0-rc1, Ninja 1.13.2, vcpkg `x64-mingw-static` (libtorrent-rasterbar **2.1.2**, ABI 100;
SQLite 3.54.1), Python 3.15.1 (test harness only).

## 0. Summary

| | Before | After |
|---|---|---|
| Windows build | fails: `arpa/inet.h` (simple_network.cpp, tracker_server.cpp) and `create_torrent(torrent_info)` removed in libtorrent 2.1 (dht_db.cpp) | all targets build, **0 warnings** with `-Wall -Wextra -Wpedantic -Werror`, Release and Debug |
| Windows binaries | — | self-contained (only system DLLs: KERNEL32, WS2_32, MSWSOCK, IPHLPAPI, bcrypt, CRYPT32, ADVAPI32, USER32, SHELL32, msvcrt) |
| Tests | none | 33 C++ unit/stress tests + 29 Python integration/stress tests, **100 % passing** (Release; Debug with libtorrent asserts as of §10) |
| Address families per process | one (`--bind` takes a single address) | IPv4 + IPv6 dual-stack in one process (`--bind 0.0.0.0,::`), see §10 |
| Metadata concurrency per session | effectively **3** (libtorrent auto-manager) regardless of `--max-active` | `--max-active` (default 200); verified 5/5 concurrent in a test that yields 3/5 on the old code |
| Cross-session duplicate fetches | possible (per-session state) | impossible (process-wide claim table) |
| SQLite | shared statement raced across threads; un-reset statement pinned a WAL snapshot forever | one connection per storage thread; statements always reset; WAL checkpointed/truncated |
| Unbounded memory | DB queue, pending futures, per-session hash state | every queue and cache bounded (count and bytes) |
| Windows shutdown | console close / logoff / shutdown killed the process without flushing; SIGTERM never delivered | console control handler; DB flushed first, DHT state saved, sessions torn down in parallel |

No Python or libtorrent-Python components exist in this repository (TASKS.txt mentions them);
the only Python file is the new stdlib-only test harness.

The historic `TODO.md` (all items done) and `CRASH_AND_CONCURRENCY.md` (open items) were read first;
every open item of the latter is resolved here (§3, IDs marked *CRASH-DOC*), except the deployment
steps that must be performed on the production Linux host (§9).

Line references `file:N` in §1–§3 point at the code **as found** (pre-port revision). The
"Resolution" columns point at the new code.

---

## 1. Linux-specific dependencies found (Phase 0)

| ID | Location (original) | Dependency | Effect on Windows | Resolution |
|---|---|---|---|---|
| L1 | simple_network.cpp:9-16 | `<arpa/inet.h> <fcntl.h> <netdb.h> <netinet/in.h> <poll.h> <sys/socket.h> <sys/time.h> <unistd.h>` | fatal compile error | `socket_platform.hpp`: guarded Winsock/POSIX includes, `WIN32_LEAN_AND_MEAN`, `NOMINMAX`, `_WIN32_WINNT>=0x0600` before any Windows header |
| L2 | tracker_server.cpp:21, 289 | `<arpa/inet.h>`, `inet_pton` | fatal compile error (the reported one) | removed; `simple_net::pack_ip_address()` (own glibc-compatible parser, simple_network.cpp:449-579) |
| L3 | simple_network.hpp:18-38,58,66 | sockets typed `int`, invalid = `-1`, `listener < 0` checks | `SOCKET` is `UINT_PTR`; `< 0` is never true; truncation | `simple_net::socket_t` (`std::uintptr_t` ≡ `SOCKET` / `int`), `kInvalidSocket`, RAII `Socket`; `static_assert`s in socket_platform.hpp:48-49 |
| L4 | simple_network.cpp:114-118 | `::close(fd)` on sockets | closes a CRT descriptor, not the socket: leak / wrong handle | `os::close()` → `closesocket()` / `close()` (socket_platform.hpp:111) |
| L5 | simple_network.cpp:23-26,149,187,245,266,272,380,395 | `errno`, `strerror`, `EINTR`, `EINPROGRESS`, `ETIMEDOUT` | Winsock reports via `WSAGetLastError()`, `WSAEWOULDBLOCK` for a pending connect; `strerror` not thread-safe | `os::last_error / is_would_block / is_interrupted / is_connect_pending / is_resource_exhausted`; portable error wording `os::error_text()` (simple_network.cpp:64) |
| L6 | simple_network.cpp:235-242,279 | `fcntl(O_NONBLOCK)` | n/a on Windows | `os::set_non_blocking()` → `ioctlsocket(FIONBIO)` / `fcntl` |
| L7 | simple_network.cpp:120-127; tracker_server.cpp:461-463; dht_db.cpp:1016-1018 | `SO_RCVTIMEO/SO_SNDTIMEO` with `struct timeval` | Winsock reads a `DWORD` of **milliseconds**: the 13 s HTTP timeout becomes 13 ms, the 10 s RPC timeout 10 ms → every tracker request fails | socket timeouts removed entirely; all I/O is non-blocking + `poll` with a **total** deadline (`write_all`/`read_until`/`connect_tcp`, simple_network.cpp:627-792) |
| L8 | simple_network.cpp:247-248,376-377 | `poll()` | `WSAPoll`; before Windows 10 2004 it never reports a refused connect; rejects an empty set | `os::poll()` wrapper; connect wait uses `select()` on Windows (simple_network.cpp:286); empty set → sleep |
| L9 | simple_network.cpp:70-71 | `SO_REUSEADDR` | on Windows lets **another socket bind the same port** (hijack) | Windows: `SO_EXCLUSIVEADDRUSE`; POSIX: `SO_REUSEADDR` (simple_network.cpp:398). Verified: hijack refused, immediate restart with TIME_WAIT works |
| L10 | simple_network.cpp:339,447 | `SHUT_RDWR`; `shutdown()` on the listener to wake `accept` | `SD_BOTH`; on Windows `shutdown()` of a listener fails and wakes nothing | `os::kShutdownSend/Both`; listener closed only after the I/O thread joined (simple_network.cpp:964) |
| L11 | simple_network.cpp:139,170 | `ssize_t`, `size_t` lengths for `send/recv` | MSVC has no `ssize_t`; Winsock takes `int` | `os::send_some/recv_some` return `ptrdiff_t`, clamp to `INT_MAX` |
| L12 | simple_network.cpp:30-37,134-138 | `MSG_NOSIGNAL` / `SO_NOSIGPIPE` | guarded already; Windows has no SIGPIPE | kept; POSIX additionally ignores `SIGPIPE` process-wide |
| L13 | simple_network.cpp:52,217 | `gai_strerror` | `gai_strerrorA` is not thread-safe and returns ANSI-code-page text | `os::resolver_error_text()` |
| L14 | simple_network.cpp:90-110; dht_db.cpp:301-307,1070 | `getnameinfo` / asio `address::to_string()` for IPv6 text | OS formatter differs in edge cases and scope-id suffix (`%eth0` vs `%12`) — this text is stored in SQLite (`discovered_peer`) | own RFC 5952 formatter identical to glibc `inet_ntop` (`format_ipv4/format_ipv6`, simple_network.cpp:843), used for DB, RPC and logs |
| L15 | (whole tracker) | no `WSAStartup` | every Winsock call fails with `WSANOTINITIALISED` | RAII `simple_net::NetworkRuntime` (simple_network.cpp:581) held by every `TcpServer` and a function-local static for free functions — transparent to callers |
| L16 | tracker_server.cpp:630-631; dht_db.cpp:1621-1622 | `std::signal(SIGINT/SIGTERM)` | SIGTERM is never raised; console close/logoff/shutdown terminate the process with no cleanup; Ctrl+Break unhandled | `platform::install_shutdown_handlers()` (platform.cpp:369): `SetConsoleCtrlHandler` for CTRL_C/BREAK/CLOSE/LOGOFF/SHUTDOWN (handler blocks until cleanup finished); POSIX `sigaction` SIGINT/SIGTERM/SIGHUP |
| L17 | tracker_server.cpp:33; dht_db.cpp:59 | `volatile sig_atomic_t` read by many threads | data race (UB) on both platforms; on Windows the CRT runs the handler on another thread | lock-free `std::atomic` with `static_assert(is_always_lock_free)` |
| L18 | dht_db.cpp:850,1472 | `std::filesystem::rename` over an existing file | CRT `rename` fails if the target exists; transient `ERROR_ACCESS_DENIED/SHARING_VIOLATION` while AV/indexer/readers hold the file | `platform::write_file_atomic()` (platform.cpp:519): unique temp name, `MoveFileExW(REPLACE_EXISTING[\|WRITE_THROUGH])` with bounded retry; POSIX `rename` + `fsync(file, dir)` |
| L19 | dht_db.cpp:394 | `path.string()` → `sqlite3_open_v2` | ANSI code page instead of UTF-8: non-ASCII paths fail or open another file | `platform::path_to_utf8()` (crawler_storage.cpp `Connection`) — tested with a Chinese directory |
| L20 | dht_db.cpp:1368 | `temp_dir.string()` as libtorrent `save_path` | same (libtorrent expects UTF-8) | UTF-8 path |
| L21 | dht_db.cpp:928,972 | `std::cout << fs::path` | ANSI conversion; can throw for unrepresentable names | UTF-8 path text |
| L22 | all sources | UTF-8 Chinese log literals | console code page 437/936 shows mojibake; MSVC without `/utf-8` re-encodes literals | `platform::write_stdout/err()` use `WriteConsoleW` on a console, raw bytes otherwise; CMake adds `/utf-8` for MSVC |
| L23 | main() argv | narrow `argv` | ANSI code page: non-ASCII `--database` etc. paths are lossy | `platform::utf8_arguments()` via `CommandLineToArgvW` (platform.cpp:433); paths built with `path_from_utf8` |
| L24 | stdout/stderr | CRT text mode | `\n` → `\r\n` in redirected logs (log files differ from Linux) | output written as raw bytes (`WriteFile`), `\n` only |
| L25 | simple_network.cpp:57-82 | `IPV6_V6ONLY` default | Linux 0 (dual-stack), Windows 1 | pinned to 0 on both (simple_network.cpp:407) |
| L26 | simple_network.cpp:389 | `accept()` non-blocking inheritance | Windows inherits `FIONBIO`, Linux does not | set explicitly on every accepted socket |
| L27 | Windows TCP stack (found by tests) | SYN after RST | Windows retries the SYN for **~2.05 s** before reporting `WSAECONNREFUSED`; Linux fails at once | on loopback destinations `SIO_TCP_INITIAL_RTO` with `TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS` (socket_platform.hpp:187) — measured 0.0 s |
| L28 | POSIX `RLIMIT_NOFILE` | 1024 descriptors by default | Windows has no comparable socket cap → Linux-only `EMFILE` with many sessions | `platform::raise_open_file_limit()` raises soft to hard limit |
| L29 | CMakeLists.txt:33-36,50-52,54-59 | no `ws2_32`, no Windows defines, no `/utf-8` | link errors / mojibake | `crawler_platform` links `ws2_32 shell32` and defines `WIN32_LEAN_AND_MEAN NOMINMAX` PUBLIC on WIN32; MSVC `/W4 /permissive- /utf-8`; optional `-Werror` / `/WX` |
| L30 | CMakeLists.txt:11,26; dht_db.cpp:1445 | libtorrent ≥ 2.0; `create_torrent(torrent_info)` | not available with ABI ≥ 4 (vcpkg 2.1.2) → compile error | minimum raised to **2.0.9** (both `find_package` and pkg-config paths, plus `#error`); `write_torrent_file_buf()` |
| L31 | `.vscode/c_cpp_properties.json`, README | Linux-only config and instructions | — | Windows configuration (C++17), Windows build docs, `CMakePresets.json` |

---

## 2. Architecture after the refactor

```
                    ┌──────────── per libtorrent session (N threads, N ≤ 64) ────────────┐
UDP announce_peer ─►│ dht_pkt_alert → bdecode (reused node, depth 10 / 500 tokens)        │
                    │   capacity? (session max_active, global max_active_total,          │
                    │              storage back-pressure)                                │
                    │   HashRegistry::try_claim  (process-wide, 16 shards, seeded hash)  │
                    │   └─► Storage::submit_lookup (bounded)                              │
                    │ mailbox ◄── lookup result (absent/present/error)                    │
                    │   absent → async_add_torrent (upload_mode, NOT paused/auto_managed)│
                    │ add_torrent_alert → connect_peer, deadline heap                    │
                    │ metadata_received_alert → write_torrent_file_buf → submit_persist  │
                    │ metadata_failed / torrent_error / deadline → settle_failed + remove│
                    │ every 30 s or on alerts_dropped: reconcile() vs get_torrent_status │
                    └───────────────────────────────────────────────────────────────────┘
                          │ lookups                                   │ jobs (≤4096, ≤256 MiB)
                          ▼                                           ▼
             storage reader thread (own conn,              storage writer thread (own conn)
             short read txns, never pins WAL)              [--save-torrents: atomic .torrent
                                                           publish] → batched
                                                           INSERT OR IGNORE, BUSY-retry,
                                                           checkpoint/TRUNCATE
                                                           └─► HashRegistry::settle_*

tracker_server ──DHTP/1 TCP──► TcpServer (poll reactor + 8 workers) ─► session.dht_get_peers()
main thread: signals, periodic DHT state save (900 s), stats; ordered parallel shutdown
logger thread: whole-line async output, bounded queue
```

New/changed files: `platform.{hpp,cpp}`, `socket_platform.hpp`, `simple_network.{hpp,cpp}`,
`logger.{hpp,cpp}`, `tracker_protocol.{hpp,cpp}`, `hash_registry.{hpp,cpp}`,
`crawler_storage.{hpp,cpp}`, `dht_db.cpp`, `tracker_server.cpp`, `CMakeLists.txt`,
`CMakePresets.json`, `tests/unit_tests.cpp`, `tests/integration_test.py`.

### Cross-platform abstraction summary

| Concern | Windows | POSIX | Where |
|---|---|---|---|
| Init/teardown | `WSAStartup/WSACleanup` (RAII, ref-counted) | no-op | `NetworkRuntime` |
| Socket type / invalid / close | `SOCKET`, `INVALID_SOCKET`, `closesocket` | `int`, `-1`, `close` | `socket_t`, `Socket`, `os::close` |
| Non-blocking | `ioctlsocket(FIONBIO)` | `fcntl(O_NONBLOCK)` | `os::set_non_blocking` |
| Errors | `WSAGetLastError`, `WSAEWOULDBLOCK`, `WSAEINTR` | `errno`, `EAGAIN/EWOULDBLOCK`, `EINTR` | `os::*` predicates, `os::error_text` (same wording on both) |
| Multiplexing | `WSAPoll`; `select` for connect | `poll` | `os::poll`, `wait_for_connect`, `TcpServer::io_loop` |
| Timeouts | total deadlines via poll (no `SO_RCVTIMEO`) | same | `write_all`, `read_until`, `connect_tcp` |
| Address reuse | `SO_EXCLUSIVEADDRUSE` | `SO_REUSEADDR` | `create_listener` |
| Dual stack | `IPV6_V6ONLY=0` | `IPV6_V6ONLY=0` | `create_listener` |
| Refused connect | loopback: no SYN retransmission | immediate | `os::prefer_immediate_refusal` |
| Handle inheritance | `SetHandleInformation` | `FD_CLOEXEC` | `os::set_no_inherit` |
| Address text | own RFC 5952 / glibc-compatible formatter and parser | same | `format_ipv4/6`, `pack_ip_address` |
| Signals | `SetConsoleCtrlHandler` (C, Break, Close, Logoff, Shutdown) | `sigaction` (INT, TERM, HUP), `SIGPIPE` ignored | `platform::install_shutdown_handlers` |
| 2nd signal | `TerminateProcess(130)` | `_exit(130)` | `force_exit` |
| Atomic replace | `MoveFileExW(REPLACE_EXISTING)` + retry, `FlushFileBuffers` | `rename`, `fsync` file + dir | `platform::write_file_atomic` |
| Paths / argv | UTF-16 ⇄ UTF-8 (`CommandLineToArgvW`) | native UTF-8 | `utf8_arguments`, `path_to/from_utf8` |
| Console | `WriteConsoleW` / raw `WriteFile` | `write(2)` | `write_stdout/err` |
| fd limit | n/a | raise `RLIMIT_NOFILE` | `raise_open_file_limit` |

---

## 3. Architectural and concurrency findings (Phase 1), ranked by severity

Areas: **(1)** libtorrent multi-session mechanics, **(2)** concurrency/backpressure, **(3)** SQLite,
**(4)** HTTP tracker, **(5)** shutdown/signals.

### Critical

| ID | Area | Location (original) | Finding | Fix (new code) | Verified by |
|---|---|---|---|---|---|
| C1 | 2,3 | dht_db.cpp:492-505, 639-640 | *CRASH-DOC P0.* All session threads share one `sqlite3*` and one `sqlite3_stmt` in `DatabaseManager::contains()`. `FULLMUTEX` serialises single calls, not the `reset/bind/step` sequence: results interleave, `SQLITE_MISUSE`, possible memory corruption. | Database access only on two storage threads, each with a private connection and statements (`storage::Storage`, crawler_storage.cpp:163); sessions only enqueue. | `storage_concurrent_burst_writes_and_reads` (16 producers + external reader) |
| C2 | 3 | dht_db.cpp:499-501, 464 | **WAL checkpoint starvation.** `contains()` returns on `SQLITE_ROW` without `sqlite3_reset`, so the reader connection almost always holds an open read transaction; checkpoints can never recycle the WAL → unbounded `-wal` growth. Demonstrated: with a statement left at `SQLITE_ROW`, `wal_checkpoint(TRUNCATE)` returns busy with 5104 frames / 524 checkpointed; after reset 0/0. No `synchronous`, `journal_size_limit` or explicit checkpoints. | RAII `Statement::Use` resets every statement (crawler_storage.cpp:137); reader uses one short transaction per batch; `synchronous=NORMAL`, `wal_autocheckpoint=1000`, `journal_size_limit=64 MiB`, periodic PASSIVE checkpoint, TRUNCATE when oversized and at shutdown, starvation warning (crawler_storage.cpp:586). | `storage_reader_never_pins_a_wal_snapshot`; `-wal` is 0 bytes after every shutdown |
| C3 | 2 | dht_db.cpp:579-624, 1509 | *CRASH-DOC P0.* An exception in `writer_loop` after a batch is dequeued destroys its `std::promise`s; `future::get()` in the session loop then throws `future_error` outside any `try` → `std::terminate`. | No promises/futures: the writer reports each job exactly once through a callback (`Storage::report`, `process_batch` contract, crawler_storage.cpp:458). | `storage_stop_flushes_every_queued_job`, `storage_survives_an_external_write_lock` |
| C4 | 1,5 | dht_db.cpp:1211-1230 | *CRASH-DOC P1.* Session thread entry has no exception boundary: `wait_for_alert`, `expire_tasks`, `poll_database_writes`, `post_dht_stats` exceptions terminate the process. | `run_session` catch-all + per-iteration boundary with back-off; per-alert boundary kept (dht_db.cpp:1199, 1247). | code review; Debug run with libtorrent asserts |
| C5 | 1 | dht_db.cpp:1445 | *CRASH-DOC.* `create_torrent(torrent_info)` re-hashes v2 piece layers (`set_hash2`) — the production SIGSEGV on libtorrent 2.0.5; removed entirely in 2.1 (ABI 100). | `write_torrent_file_buf(atp, allow_missing_piece_layer)` copies the verified info dictionary verbatim and never rebuilds piece layers (dht_db.cpp:1595); libtorrent ≥ 2.0.9 enforced. | `test_3_metadata_pipeline…` checks `sha1(info) == info_hash` of the written file |
| C6 | 4 | simple_network.cpp:335-344 vs 372-392 | `TcpServer::stop()` closes the listening descriptor while the accept thread may still `poll`/`accept` on that number; in `dht_db` libtorrent can reuse the number immediately → accept on a foreign socket. | Listener is closed only after the I/O thread has joined (simple_network.cpp:964). | `test_restart_on_same_port…`, repeated start/stop in tests |

### High

| ID | Area | Location (original) | Finding | Fix (new code) | Verified by |
|---|---|---|---|---|---|
| H1 | 1 | dht_db.cpp:1366-1369 | **Metadata concurrency silently capped at 3 per session.** Default `add_torrent_params` flags include `auto_managed\|paused`; libtorrent queues `downloading_metadata` torrents behind `active_downloads=3`, and they only count as "inactive" after `auto_manage_startup=60 s` — longer than the 30 s metadata timeout (libtorrent torrent.cpp `update_state_list`, session_impl.cpp `auto_manage_torrents`). ~197 of 200 "active" tasks just time out. | Clear `auto_managed\|paused` (dht_db.cpp:1546). | `test_4_metadata_fetches_run_concurrently`: 5/5 concurrent; the same test against a build with the original flags fails with `3 != 5` |
| H2 | 1,2 | dht_db.cpp:765-766, 1336-1386 | *CRASH-DOC P0/P1.* Hash state is per session and the DB check + registration is not atomic: the same hash is fetched by several sessions at once (duplicate connections, DHT queries, CPU, file writes). | Process-wide `HashRegistry` claim state machine (in-flight → completed TTL / failed back-off), hash_registry.cpp:68. | `registry_concurrent_claims_are_exclusive`; `test_3…cross_session_dedup` (two sessions announce, exactly one handshake, one row) |
| H3 | 2 | dht_db.cpp:1442-1478 | *CRASH-DOC P0.* Exists-check then write to a fixed `<hash>.torrent.tmp`: concurrent writers truncate each other's temp file, rename/remove each other's file; `fs::remove` (throwing overload) inside the error path. | Claim prevents concurrent tasks; `write_file_atomic` uses unique temp names and atomic replace; leftovers removed at start. | `atomic_write_concurrent_writers_never_tear`, `stale_temp_files_are_removed` |
| H4 | 1 | dht_db.cpp:1358, 1371, 1406-1413, 864-869, many `std::cout` | **Blocking work inside the alert loop**: SQLite query per announce (up to the 5 s busy timeout), synchronous `add_torrent`, `.torrent` file write + rename, synchronous console logging. `dht_log` (needed for `dht_pkt_alert`) floods the default 2000-entry queue, and `metadata_received_alert` has the same *normal* priority as `dht_pkt_alert`, so stalls drop it. | Alert loop only parses and enqueues: async DB lookup, `async_add_torrent`, file+DB on the writer thread, async logger; `alert_queue_size=10000`; wake-up via `set_alert_notify` + mailbox instead of 250 ms polling (dht_db.cpp:1231-1350). | integration tests; `[Stats] … AlertDrops` counter |
| H5 | 1 | dht_db.cpp:1255-1282 | **No recovery from dropped alerts / zombie handles.** A lost `metadata_received_alert` wastes the fetched metadata until timeout; a lost or late `add_torrent_alert` (with async adds) would leave an untracked torrent forever. | `alerts_dropped_alert` triggers `reconcile()`, which also runs every 30 s: untracked torrents are removed, tasks whose metadata arrived are persisted; late add alerts for expired hashes are removed immediately. Every torrent is gone within `metadata_timeout + 30 s` (dht_db.cpp:1351, 1556, 1678). | end-to-end tests; `Orphans` counter |
| H6 | 2 | dht_db.cpp:643, 767, 765, 1349-1352 | **Unbounded memory growth**: DB request queue and per-session `pending_writes` futures unbounded; `hash_states` grows with announce rate × TTL (every announce of a new hash while saturated creates a 60 s "failed" entry); no size cap. | Bounded lookup queue (65 536), persist queue (4096 jobs / 256 MiB) with 75 % back-pressure; registry settled entries capped (`--dedup-cache-size`, default 262 144 ≈ 36 MB) with TTL + oldest-first eviction, in-flight claims never evicted; saturation drops announces without creating state. | `registry_settled_entries_are_size_bounded` (1 M inserts → exactly 10 000 kept), `registry_never_evicts_in_flight_claims`, `storage_queues_are_bounded` |
| H7 | 4 | simple_network.cpp:120-127,158-196; tracker_server.cpp:461-463 | **Slowloris / idle-connection starvation.** Timeouts are per `recv`, so a client sending one byte every 12 s holds one of the 8 HTTP workers for hours; 8 idle connections stall the tracker; queued requests wait behind them. | Poll reactor reads every request (≤1024 concurrent) with a total deadline (`lookup_timeout + 3 s`), only complete requests reach workers; oversize (16 KiB) dropped (simple_network.cpp:1001). | `test_slow_and_idle_clients_do_not_starve_workers` (80 idle + 40 real clients, all < 2 s), `test_incomplete_request_times_out`, `test_oversized_request_is_dropped` |
| H8 | 5 | tracker_server.cpp:630-631; dht_db.cpp:1621-1622 | **Windows shutdown not graceful** (see L16): closing the console, logoff or shutdown loses the DB queue and DHT state. | Console control handler + ordered shutdown: stop RPC → join sessions → flush SQLite → save DHT state → remove torrents → `abort()` all sessions in parallel (dht_db.cpp:808). | `test_5_graceful_shutdown_persists_everything`, `test_shutdown_interrupts_in_flight_lookups` (CTRL_BREAK on Windows, SIGINT on POSIX) |
| H9 | 3 | dht_db.cpp:525-577 | **Fetched metadata discarded on lock contention.** After 3 attempts the batch fails and is re-fetched later. Windows file locks are mandatory: a DB browser, backup tool or AV scanner makes `SQLITE_BUSY` far more likely than on Linux. | `SQLITE_BUSY/LOCKED` keeps the rows and retries with exponential back-off (2 s cap) while back-pressure pauses producers; other errors fail after 3 attempts; at shutdown a 10 s drain deadline (crawler_storage.cpp:503). | `storage_survives_an_external_write_lock` (external `BEGIN EXCLUSIVE` for 1.5 s → 300/300 rows, 0 failures) |
| H10 | 4 | simple_network.cpp:393-400 | `accept()` failing with `EMFILE/ENFILE` while the listener stays readable → 100 % CPU spin. | Back-off 100 ms on resource exhaustion, 10 ms on other errors (simple_network.cpp:1140). | code review |

### Medium

| ID | Area | Location (original) | Finding | Fix |
|---|---|---|---|---|
| M1 | 4,5 | dht_db.cpp:1089, 706-707 | `lookup_stopping_` checked outside `lookup_mutex_`: a lookup registered right after `cancel_pending_lookups()` delays shutdown by the full lookup timeout. | flag set and checked under the same mutex (dht_db.cpp:1025, 1129) |
| M2 | 1 | dht_db.cpp:1255-1282 | *CRASH-DOC P2.* `metadata_failed_alert` ignored: slot held until timeout. | `fail_task` on `metadata_failed_alert` |
| M3 | 1 | dht_db.cpp:716 | DHT state saved only at a clean exit: a crash loses node IDs/routing progress. | periodic save (`--dht-save-interval`, 900 s), durable atomic write |
| M4 | 1 | dht_db.cpp:684-686 | All sessions created in the same instant: N simultaneous bootstrap bursts from one IP to the same 4 routers (rate limiting / bans). | staggered start (`--bootstrap-stagger-ms`, 200 ms) |
| M5 | 2 | dht_db.cpp many `std::cout/cerr` | *CRASH-DOC P2.* Multi-`<<` lines interleave between threads; synchronous console I/O (very slow on the Windows console) on hot paths. | async logger, whole lines, bounded queue with drop counter (logger.cpp) |
| M6 | 4 | tracker_server.cpp:546-549 | Client-controlled `event` logged raw: `%0A` forges log lines, `%1B` injects terminal escape sequences. | `logging::sanitize()` (tested by `test_log_lines_cannot_be_forged`) |
| M7 | 1 | dht_db.cpp:1481-1542 | Full scans of `active_tasks`, `pending_writes` and the whole `hash_states` map on every loop iteration (≤ 250 ms). | deadline min-heaps; FIFO-trimmed registry (amortised O(1)) |
| M8 | 2 | dht_db.cpp:765, 1594 | `std::hash<sha1_hash>` is the raw first 8 bytes: peers can announce crafted info-hashes that all land in one bucket (hash flooding). | registry uses a per-process random seed (splitmix-mixed) for buckets and shards |
| M9 | 1 | dht_db.cpp:1290 | New `bdecode_node` (token vector allocation) per DHT packet, default limits depth 100 / 2 000 000 tokens for ≤1.5 KB UDP payloads. | reused node, libtorrent's own DHT limits (depth 10, 500 tokens) |
| M10 | 2 | dht_db.cpp:107-114, 185-189 | Durations unbounded (`now + seconds(LLONG_MAX)` overflows steady_clock: UB); `--max-active` unbounded. | ≤ 1 year durations, `--max-active ≤ 100 000`, validated new options |
| M11 | 4 | simple_network.cpp:447-448 | `shutdown(RDWR)+close` with unread input sends RST, which can destroy a response the client has not read yet. | `graceful_close`: FIN, drain ≤ 250 ms, close |
| M12 | 4 | simple_network.cpp:402-415 | Socket leaks if `remote_endpoint()`/`push_back` throw between `accept` and enqueue. | RAII `Socket` everywhere | 
| M13 | 5 | dht_db.cpp:710-725 + destructor order | Sessions destroyed one after another (each blocks), the DB is flushed last — risky under Windows' ~5 s close deadline. | DB flushed first; `session::abort()` proxies destroyed together |
| M14 | 4 | simple_network.cpp:23-26, 52, 217 | OS-specific error text (localised on Windows) leaks into bencoded tracker failure reasons; `strerror` is not thread-safe. | fixed portable wording (`connect: connection refused`, `recv: timed out`, …) |
| M15 | 4 | dht_db.cpp:55 | 4 RPC workers behind 8 HTTP workers: queued RPCs consume the tracker's lookup timeout. | 8 RPC workers |

### Low / observations (not changed)

| ID | Area | Observation |
|---|---|---|
| O1 | 1 | **BEP 42 node-ID clustering.** libtorrent regenerates node IDs from the external IP (`node::update_node_id`), leaving ≤ 8 21-bit prefixes per IPv4 address. Many sessions behind one IP therefore cluster in the keyspace; real coverage gains need several public IPs. Saved states with duplicate node IDs are now detected and regenerated. |
| O2 | 1 | `dht_get_peers_reply_alert` is posted once per responding node; the tracker answers with the first batch only. Preserved (protocol contract). With a dual-stack crawler (§10) the lookup runs on both DHTs, so a reply may contain only `peers` or only `peers6`, whichever family answers first. |
| O3 | 1 | `max_metadata_size` (3 MiB) bounds memory per active task; worst case scales with `--max-active-total`. |
| O4 | 1 | libtorrent 2.1.2 tries uTP first. When a peer silently drops UDP (no reply, ICMP rate-limited), the TCP fallback of some tasks was observed to stall past the metadata timeout. Reproduce by disabling `FakePeer._refuse_utp` in the test harness. Consider evaluating `enable_outgoing_utp=false` in production. |
| O5 | 4 | `RPC peer 列表不完整` is unreachable (the `END` line is read as the missing peer line); behaviour preserved. |

---

## 4. Implemented changes by area (index)

- **Area 1:** H1, H4, H5, C4, C5, M2, M3, M4, M7, M9; alert mask kept (needed for `dht_pkt_alert`),
  `alert_queue_size=10000`, async add, reconcile, deadline heaps, duplicate-node-ID check;
  dual-stack sessions (§10).
- **Area 2:** C1, C3, H2, H3, H6, M5, M8, M10; global slot budget `--max-active-total`; storage
  back-pressure; registry stats in a 60 s `[Stats]` line.
- **Area 3:** C1, C2, H9; PRAGMAs (`journal_mode=WAL`, `synchronous=NORMAL`, `wal_autocheckpoint`,
  `journal_size_limit`, `busy_timeout=5000`, `query_only` on the reader), `NOMUTEX` connections
  (one thread each), batched transactions with static binds, UTF-8 path. Schema text unchanged.
- **Area 4:** C6, H7, H10, M6, M11, M12, M14, M15; protocol code moved into `tracker_protocol.cpp`
  unchanged in behaviour (parsing, bencoding, failure strings, compact peers).
- **Area 5:** H8, M1, M13; second signal forces exit (130); SIGHUP graceful on POSIX for parity
  with console close.

## 5. Intentional behaviour changes

All CLI options and positional arguments keep their meaning; new ones are `--max-active-total`,
`--dedup-cache-size`, `--dht-save-interval`, `--bootstrap-stagger-ms`, `--save-torrents`,
`--file-index`, `--disable-file-index` (§12). `--bind` (and the
positional `bind_addr`) additionally accept a comma-separated list and `--bind` may be repeated
(§10); a single address behaves exactly as before.

- SQLite: schema, column types and value formats unchanged (`info_hash` lowercase hex,
  `discovered_peer` `a.b.c.d:port` / `[v6]:port`, `CURRENT_TIMESTAMP` UTC). `synchronous=NORMAL`
  (WAL-safe; the last commits before a power loss may be rolled back).
- `.torrent` files are **no longer written by default**; `--save-torrents` turns it on
  (into `--torrent-dir`, default `torrents`). Without it the crawler neither serialises the
  torrent (`write_torrent_file_buf` is not called) nor creates the directory; the database row,
  deduplication and retry behaviour are unchanged. When enabled, files contain the verified
  `info` dictionary verbatim (same info-hash); optional top-level keys produced by the old
  `create_torrent::generate()` may differ.
- Torrents are added unpaused and not auto-managed (H1); `metadata_failed_alert` fails a task
  immediately.
- An announce dropped because of saturation no longer blacklists the hash for `retry_delay`.
- HTTP/RPC: the timeout is now a total deadline per request instead of per `recv`.
- Logs: whole lines, the per-session stats line has extra counters, client text is escaped.

## 6. Build

```
cmake -S . -B build/mingw-release -G Ninja -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake ^
      -DVCPKG_TARGET_TRIPLET=x64-mingw-static -DCMAKE_BUILD_TYPE=Release -DDHT_CRAWLER_WERROR=ON
cmake --build build/mingw-release
```

(or `cmake --preset mingw-release`). Results on this machine:

- Release and Debug: all 6 targets (`crawler_platform`, `tracker_protocol`, `crawler_core`,
  `dht_db`, `tracker_server`, `unit_tests`) compile with **0 warnings** under
  `-Wall -Wextra -Wpedantic -Werror` (GCC 16.2.0). `tracker_server.cpp` specifically: 0 warnings.
- `dht_db.exe` 30.5 MB, `tracker_server.exe` 3.2 MB, statically linked, system DLLs only.
- CMake configure is warning-free too: `CMP0167` is now set before `project()`, so vcpkg's
  toolchain-defined `find_package` wrapper (which records policies at definition time) no longer
  emits the FindBoost developer warning.
- `cmake --preset mingw-release`, `cmake --build --preset mingw-release` and
  `ctest --preset mingw-release` verified end to end.

## 7. Tests and results

`ctest --test-dir build/<dir> --output-on-failure` runs both suites.

**`unit_tests` (26, C++):** URL decoding / query parsing / info-hash validation; exact bencoded
replies; poisoned DHTP/1 replies; IPv4/IPv6 parsing and formatting vs glibc rules; log sanitiser;
registry state machine, 1 M-entry memory bound, TTL expiry, in-flight protection, 8-thread claim
exclusivity; atomic replace over an existing file, 8 concurrent writers to one target (no torn
file, no leftover temp), replace while another handle holds the file (Windows `MoveFileEx`
retry), stale temp cleanup, UTF-8 paths; SQLite schema unchanged; 16-producer burst (8 000 rows
+ 8 000 lookups) in a non-ASCII NTFS directory with an external reader polling, then WAL = 0 bytes;
reader never pins a snapshot (external TRUNCATE checkpoint succeeds with 0 frames); external
`BEGIN EXCLUSIVE` survived without loss; `stop()` flushes 2 000 queued jobs; bounded queues and
back-pressure.

**`integration_tests` (28, Python, real binaries):**
- tracker: health; compact IPv4/IPv6 peers byte-exact; hex info-hash; 14 malformed `info_hash`
  variants (wrong lengths, broken `%`-encoding, NULs, duplicates); bad methods/paths/request lines
  /binary garbage; oversized requests; incomplete request deadline; 80 idle + 40 live clients;
  200 concurrent announces; 8 kinds of poisoned RPC replies plus a crawler slower than the
  lookup timeout; unreachable crawler refused in < 1 s;
  **no handle leaks** after 660 abusive connections (connect-close, RST, close-without-read,
  idle) measured with `GetProcessHandleCount`; graceful stop during 30 s in-flight lookups
  (< 3 s, exit 0); restart on the same port + no port hijacking; log forging.
- crawler (2 sessions, loopback only, fake bootstrap): RPC protocol and coalescing; tracker →
  crawler end to end; **full metadata pipeline** with a fake DHT node and a fake BEP 9 peer
  (UTF-8 torrent name, BEP 5 `implied_port`, cross-session dedup, row and `.torrent` verified);
  5 concurrent fetches in one session; graceful shutdown (exit 0, both state files, no `.tmp`,
  empty WAL, schema via `PRAGMA table_info`); restart restores both DHT states.
- `--bind` lists (§10): 10 invalid forms rejected with exit 1 before any file is created;
  repeated `--bind` accumulates.
- dual-stack crawler (2 sessions on `127.0.0.1` + `::1`): every session accepts TCP on both
  families; metadata fetched from an IPv6 peer (`[::1]:port` stored) and an IPv4 peer; one hash
  announced over both families is fetched exactly once; shutdown saves 2 node IDs per session
  and a restart restores both. Skipped automatically where IPv6 loopback is unavailable.

| Run | Result |
|---|---|
| Release, `ctest` | unit_tests passed (11.8 s), integration_tests passed (38.8 s) — 100 % |
| Debug (libtorrent `TORRENT_USE_ASSERTS`), `ctest` | unit_tests passed (19.7 s), integration_tests passed (67.3 s) — 100 % |
| Release, 5 consecutive `ctest` runs (flakiness check) | 5/5 runs: 100 % tests passed |
| After the dual-stack change: Release `ctest` (28 integration tests) | 100 % passed (57.3 s total) |
| After the dual-stack change: Debug `ctest` | 100 % passed (93.6 s total) |
| After the dual-stack change: 3 more consecutive Release runs | 3/3 runs: 100 % tests passed |
| H1 regression proof | `test_4` against a build with the original add flags: `AssertionError: 3 != 5` |

### Windows quirks found by the tests (and handled)

1. Winsock `SO_RCVTIMEO` takes milliseconds (L7).
2. ~2.05 s SYN retries after RST on a closed port (L27): measured with Python, fixed with
   `SIO_TCP_INITIAL_RTO`, measured 0.0 s afterwards.
3. `std::filesystem::file_size` reads NTFS directory metadata that lags while SQLite keeps the
   file open (a WAL truncated to 0 still reported 115 392 bytes); WAL size is now measured through
   a handle.
4. A connection only learns the database is in WAL mode on its first read; checkpoints issued
   before that are silent no-ops (`log = -1`).
5. `MoveFileExW` fails with `ERROR_ACCESS_DENIED` while another handle (without
   `FILE_SHARE_DELETE`) is open; bounded retry.
6. `SO_EXCLUSIVEADDRUSE` refuses a same-address bind, allows a wildcard bind that receives none of
   the specific listener's traffic, and does not block an immediate restart with TIME_WAIT.
7. Git Bash `kill` does not deliver console control events to native processes; the harness
   uses `CREATE_NEW_PROCESS_GROUP` + `CTRL_BREAK_EVENT`.
8. libtorrent's uTP-first connects depend on ICMP port-unreachable replies, which Windows
   rate-limits; the fake peer answers the uTP SYN with `ST_RESET` like a TCP-only peer (O4).

## 8. Remaining risks and items not verified here

- **Linux was not compiled or run on this machine** (no WSL or Linux toolchain available). All
  POSIX branches were reviewed against glibc headers (one missing `<cstdio>` was found and
  fixed). Run `cmake --preset linux-release && cmake --build --preset linux-release && ctest
  --preset linux-release` on a Linux host with libtorrent ≥ 2.0.9 before deploying.
- **MSVC** was not available; the `msvc-release` preset (`x64-windows-static`, `/utf-8 /W4
  /permissive-`) is provided but untested.
- `CTRL_CLOSE_EVENT`/`LOGOFF`/`SHUTDOWN` cannot be triggered from an automated test; they share
  the tested Ctrl+Break path plus a blocking wait that is released by `ShutdownCompletionGuard`.
  Windows still enforces its own hard limit (~5 s for console close).
- O1 (BEP 42 clustering) and O4 (uTP fallback) are libtorrent behaviours, documented not changed.

## 9. CRASH_AND_CONCURRENCY.md status

| Item | Status |
|---|---|
| Raise CMake minimum to 2.0.9 (both paths) | done |
| Handle `metadata_failed_alert` | done (M2) |
| Avoid `create_torrent(torrent_info)`; use `write_torrent_file_buf()` | done (C5) |
| App-level v2 piece-layer validation | not needed: piece layers are never rebuilt |
| Shared SQLite reader/statement | done (C1) |
| Cross-session claim | done (H2) |
| Temp-file race | done (H3) |
| Broken promises | done (C3) |
| Duplicate work despite unique constraint | done (H2) |
| Write queue unbounded / no timeout | done (H6, H9) |
| Per-session vs global concurrency | done (`--max-active-total`) |
| Session exception boundary | done (C4) |
| Log interleaving | done (M5) |
| Upgrade production libtorrent 2.0.5 → ≥ 2.0.9, clean rebuild, verify with `pkg-config`/`ldd` | **operator action on the Linux host** (CMake now refuses older versions) |

## 10. Dual-stack binding (follow-up change)

**Before:** `--bind` accepted one address, so one process served one address family; covering
IPv4 and IPv6 needed two processes with separate DHT state directories and RPC ports, duplicate
detection per process only, and two writers on the database.

**Now:** `Config::bind_addresses` (dht_db.cpp:86) holds up to 16 addresses (dht_db.cpp:61).
`--bind` and the positional `bind_addr` take a comma-separated list (`append_bind_addresses`,
dht_db.cpp:146; spaces trimmed, IPv6 may be bracketed); the first `--bind` replaces the default
`0.0.0.0` and repeats append (dht_db.cpp:239). Every entry is parsed with `lt::make_address`, and
duplicates are rejected after normalisation, so `::` and `0:0::0` collide (dht_db.cpp:363).
Invalid lists exit with the usage text before any directory, socket or database is created.

`build_listen_interface` (dht_db.cpp:449) gives each session every address on its own port,
e.g. `0.0.0.0:6881,[::]:6881`. This needs nothing else from the crawler because libtorrent
already handles it (checked in the 2.1.2 source):

- IPv6 listen sockets are opened `v6_only` (TCP and UDP), so `0.0.0.0` and `::` share a port on
  Linux and Windows alike;
- unspecified addresses expand to one listen socket per up interface of that family, with
  overlapping explicit addresses de-duplicated;
- one DHT node runs per listen socket (IPv6 DHT per BEP 32); the session's single state file
  stores one node ID per listen address in `dht_state.nids`, and on start each socket takes the
  ID saved for its exact local address (`dht_tracker::new_socket`). An existing single-stack
  state file therefore keeps its IPv4 IDs and new IPv6 IDs are generated.

All address families share the process-wide `HashRegistry`, the storage threads and the RPC
port, so a hash announced over IPv4 and IPv6 is fetched once. `discovered_peer` keeps the
existing `[v6]:port` format. Tracker side: `tracker_server --bind ::` was already dual-stack
(`IPV6_V6ONLY=0`, L25); the tracker's lookup now spans both DHTs but still returns the first
reply batch (O2).

Verified by `CrawlerBindArgumentTests` (2 tests) and `DualStackCrawlerTests` (5 tests) in §7.
A manual run showed `节点 ID 2` saved and restored per session with `--bind 127.0.0.1,[::1]`.

## 11. DHT ingest CPU under heavy traffic (follow-up)

Two community suggestions were checked against the libtorrent 2.1.2 source and measured.

**Claim 1 — `dht_log` string formatting.** Confirmed mechanism. `dht_pkt_alert` exists only in
`alert_category::dht_log`, and that category also gates `dht_log_alert`: libtorrent's DHT logger
`should_log()` is just `should_post<dht_log_alert>()`, and every `log()` call `vsnprintf`s an
alert (session_impl.cpp:7262-7276; ~110 log sites in `src/kademlia/`). `log_packet` copies every
incoming **and** outgoing DHT packet into a `dht_pkt_alert` (session_impl.cpp:7279-7288). The two
cannot be separated through the alert mask.

**Claim 2 — `bdecode` of every packet.** Confirmed: the crawler decoded every incoming packet a
second time (libtorrent already decodes each one), partly just to count requests/responses.

**Why a session plugin is not the answer.** libtorrent's `plugin::on_dht_request` hands plugins
each request already decoded, without any alerts, and runs before the announce token check
(node.cpp:833 vs 940). But libtorrent drops queries *before* that hook once the DHT upload quota
(`dht_upload_rate_limit`, default 8000 B/s with 3 s burst; dht_tracker.cpp:630) is spent
(node.cpp:307-311), whereas `dht_pkt_alert` is posted earlier, for every packet. Under heavy
traffic the packet sniffer therefore harvests announces from queries libtorrent itself
discards; a plugin would miss them, or would need an unlimited quota, which makes libtorrent
answer every query and costs more CPU (and upload bandwidth) than everything saved.

**Benchmark** (`tests/dht_ingest_bench.cpp`, `tests/dht_ingest_bench.py`, opt-in target
`-DDHT_CRAWLER_BUILD_BENCHMARKS=ON`): a libtorrent session on loopback receives a KRPC mix
(25 % announce_peer, 40 % get_peers, 20 % find_node, 15 % ping) from 254 source addresses at
10 000 messages/s for 10 s, with libtorrent's per-IP rate limit lifted. CPU is counted exactly
(`QueryProcessCycleTime` / `CLOCK_PROCESS_CPUTIME_ID`) because tick-based `GetProcessTimes`
produced contradictory numbers and was discarded. Windows 11 loopback; absolute numbers will
differ on Linux, the comparison is what matters.

Default quota (production setting), modes interleaved, median of 7 runs:

| mode | kcycles/message (min..max) | announces seen | dht_log alerts | dht_pkt alerts |
|---|---|---|---|---|
| sniff (previous crawler) | 98.4 (80.3..104.6) | 24 140 | 1 240 | 100 903 |
| prefilter (crawler now) | 92.1 (89.1..99.7) | 24 140 | 1 241 | 100 911 |
| alerts only, no parsing | 90.6 (82.7..96.9) | — | 1 239 | 100 901 |
| plugin, no `dht_log` | 76.9 (68.1..88.6) | **234** | 0 | 0 |
| no capture at all | 80.0 (69.2..87.7) | — | 0 | 0 |

libtorrent dropped 98.9 % of the queries at this rate (`dht_messages_in_dropped`), so it logged
little: ~1 `dht_log_alert` per 80 messages, but one packet copy per message.

Unlimited quota (`--upload-limit 100000000`, libtorrent answers everything), median of 3 runs:

| mode | kcycles/message | announces seen | dht_log alerts | dht_pkt alerts |
|---|---|---|---|---|
| sniff | 142.9 | 24 133 | 123 650 | 199 799 |
| prefilter | 132.3 | 24 141 | 123 680 | 199 843 |
| alerts only | 133.3 | — | 123 641 | 199 785 |
| plugin | 130.4 | 24 144 | 0 | 0 |
| no capture | 126.6 | — | 0 | 0 |

Here libtorrent formats ~1.24 log alerts and copies 2 packets per message.

**Reading:** both overheads are real but modest. Alert generation costs ~5-13 % of ingest
CPU and our second `bdecode` ~7-8 %. The dominant cost is libtorrent's own DHT handling, and it
grows ~50 % once libtorrent answers every query. Run-to-run spread is ±15 %, so differences of a
few percent are within noise.

**Changes made (dht_db.cpp):**
- `handle_dht_packet` skips any packet that does not contain `13:announce_peer` (the bencoded
  query name every announce_peer must carry) before decoding; the full `y`/`q` checks still run
  on the rest. No false negatives: the benchmark saw identical announce counts.
- Req/Resp in the per-session stats line now come from libtorrent's session counters
  (`post_session_stats()`, posted regardless of the alert mask): Req = requests libtorrent
  handled (sum of the disjoint `dht_*_in` / `dht_invalid_*` counters), new Dropped =
  `dht_messages_in_dropped`, Resp = the remainder. The old Req (all queries seen) ≈ new
  Req + Dropped.
- `alert_category::dht_log` stays enabled: it is the only way to see quota-dropped announces.

**Not verified here:** Windows Smart App Control switched to enforcement during this work and
blocks newly built unsigned executables (Code Integrity events 3033/3077). The new `dht_db.exe`
and benchmark compile warning-free, but neither could be executed, so the integration tests did
not run against this change. The measurements above come from a benchmark built before the
block, whose `prefilter` mode implements the same check. Run `ctest` (and optionally the
benchmark) on the Linux host to confirm.

**Further lead (not measured):** every metadata task's torrent also does its own DHT lookup and
announces the crawler as a peer (libtorrent default for magnet torrents), which produces the
crawler's own RPC traffic, logging and packet alerts. Profiling production (`perf top`) or
trialling `torrent_flags::disable_dht` would show whether that matters; it trades away extra
metadata sources.

## 12. File-list index (follow-up feature)

On by default (`--disable-file-index` turns it off, `--file-index PATH` moves it from
`dht_files.db`): every fetched torrent's directory structure, file names and sizes go into a
standalone SQLite database next to, not inside, the crawler database (whose schema is unchanged).

**Format.** Table `file_lists(info_hash BLOB PRIMARY KEY, name, file_count, total_size, files)`
declared `WITHOUT ROWID`, so the table is itself a B-tree clustered on the 20-byte hash and a
lookup is one descent. SQLite was chosen because it is already a dependency, is B-tree based,
gives crash-safe writes and lets other processes read while the crawler writes (WAL). Each file
list is one front-coded varint blob (paths sharing a directory prefix store only the
difference), so a torrent costs one row rather than one row per file. `index_meta` records
format version 1. The full byte-level spec is at the top of `file_index.hpp`.

**API (`file_index.hpp`, CMake target `file_index`, SQLite only, no libtorrent).**
`FileIndex(path, Mode)` with `get / contains / size / put / checkpoint`, plus
`encode_files / decode_files`, `render_tree`, `format_size`, `printable`, `parse_hash`,
`to_hex`. The decoder validates every length against the remaining input, so a corrupt row
raises instead of reading out of bounds. Tree rendering is iterative and caps nesting at 32
levels, deeper remainders shown on one line, so hostile metadata can neither overflow the
stack nor blow output up quadratically. `printable()` escapes control characters, invalid
UTF-8 and bidi overrides (a "txt‮exe" trick) while keeping valid UTF-8.

**Extraction (`torrent_file_list.cpp`).** Parsed from the verified raw info dictionary with
libtorrent's bounded `bdecode`, not from libtorrent's `file_storage`, which sanitises names per
platform (Windows rewrites `:` and uses `\`); names therefore match the torrent exactly and are
identical on both platforms. `name.utf-8`/`path.utf-8` are preferred as libtorrent does; BEP 47
padding files (attr `p`, legacy `_____padding_file`) are skipped; `/` inside a component
becomes `_`. The v1 file list is used: the crawler looks torrents up by v1 info-hash, so it only
ever fetches v1 or hybrid torrents, both of which carry it.

**Write path.** The storage writer thread commits a batch's file lists **before** its crawler
rows, with the same BUSY retry / shutdown drain logic (`commit_with_retry`). If the index write
fails the batch is failed and refetched later, so with the index on every crawler row has its
file list. Index WAL is checkpointed with the crawler database and truncated at shutdown. Queue
memory accounting includes the file lists.

**Lookup tool `dht_files`.** `dht_files [--index PATH] [--ascii] [--bytes] HASH...` opens the
index read-only (safe while the crawler runs) and prints the tree; exit 0 all found, 1 some
invalid/not found, 2 usage or index error.

**Tests.** Unit: exact encoded bytes, round trip incl. 2^64-1 sizes, every truncation and
malformed form rejected, put/get/replace/read-only/foreign-database, exact Unicode and ASCII
tree output, 20 000-level nesting bounded, size formatting, hostile-name escaping, storage
writing file lists with rows. Integration (`test_4b`): a real libtorrent session fetches a
multi-file torrent with a padding file from the fake peer; `dht_files` output is compared byte
for byte, and the unknown-hash exit code is checked. Full suite green on Windows Release;
Debug and Linux were not run for this change.
