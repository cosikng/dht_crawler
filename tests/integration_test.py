#!/usr/bin/env python3
"""Cross-platform integration and stress tests for tracker_server and dht_db.

Standard library only. Runs identically on Windows and Linux:

    python -I tests/integration_test.py --tracker build/.../tracker_server --crawler build/.../dht_db

Nothing here talks to the public internet: the crawler binds to loopback and
is given an unreachable bootstrap node; DHT announces and metadata come from
a fake DHT node and a fake BitTorrent peer implemented below.
"""

import argparse
import collections
import contextlib
import hashlib
import os
import re
import signal
import socket
import socketserver
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

IS_WINDOWS = os.name == "nt"
TRACKER = None
CRAWLER = None


# --------------------------------------------------------------------------
# bencode

def bencode(value):
    if isinstance(value, int):
        return b"i%de" % value
    if isinstance(value, str):
        value = value.encode()
    if isinstance(value, bytes):
        return b"%d:%s" % (len(value), value)
    if isinstance(value, list):
        return b"l" + b"".join(bencode(item) for item in value) + b"e"
    if isinstance(value, dict):
        items = sorted((k.encode() if isinstance(k, str) else k, v) for k, v in value.items())
        return b"d" + b"".join(bencode(k) + bencode(v) for k, v in items) + b"e"
    raise TypeError(type(value))


def bdecode(data):
    def parse(index):
        token = data[index:index + 1]
        if token == b"i":
            end = data.index(b"e", index)
            return int(data[index + 1:end]), end + 1
        if token in (b"l", b"d"):
            index += 1
            items = []
            while data[index:index + 1] != b"e":
                item, index = parse(index)
                items.append(item)
            if token == b"l":
                return items, index + 1
            if len(items) % 2:
                raise ValueError("odd dictionary")
            return dict(zip(items[::2], items[1::2])), index + 1
        colon = data.index(b":", index)
        length = int(data[index:colon])
        start = colon + 1
        if start + length > len(data):
            raise ValueError("truncated string")
        return data[start:start + length], start + length

    value, end = parse(0)
    if end != len(data):
        raise ValueError("trailing data")
    return value


# --------------------------------------------------------------------------
# processes and sockets

def free_port(udp_too=False):
    """A port free for TCP (and UDP when asked) on 127.0.0.1."""
    for _ in range(200):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        if not udp_too:
            return port
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
    raise RuntimeError("no free port")


def family_of(host):
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def free_port_pair(hosts=("127.0.0.1",)):
    """Two consecutive ports free for TCP and UDP on every host (one per
    crawler session)."""
    for _ in range(200):
        port = free_port(udp_too=True)
        try:
            for host in hosts:
                for candidate in (port, port + 1):
                    with socket.socket(family_of(host)) as tcp, \
                            socket.socket(family_of(host), socket.SOCK_DGRAM) as udp:
                        tcp.bind((host, candidate))
                        udp.bind((host, candidate))
            return port
        except OSError:
            continue
    raise RuntimeError("no free port pair")


def ipv6_loopback_available():
    if not socket.has_ipv6:
        return False
    try:
        with socket.socket(socket.AF_INET6) as probe:
            probe.bind(("::1", 0))
        return True
    except OSError:
        return False


def handle_count(pid):
    """Open handles (Windows) or descriptors (Linux) of a process."""
    if IS_WINDOWS:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel32.GetProcessHandleCount.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return None
        try:
            count = wintypes.DWORD()
            if not kernel32.GetProcessHandleCount(handle, ctypes.byref(count)):
                return None
            return count.value
        finally:
            kernel32.CloseHandle(handle)
    fd_dir = "/proc/%d/fd" % pid
    if os.path.isdir(fd_dir):
        return len(os.listdir(fd_dir))
    return None


class Process:
    def __init__(self, args, cwd=None):
        self.args = [str(a) for a in args]
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if IS_WINDOWS else 0
        self.popen = subprocess.Popen(
            self.args, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, creationflags=flags)
        self.lines = []
        self.condition = threading.Condition()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        for raw in self.popen.stdout:
            line = raw.decode("utf-8", "replace").rstrip("\n")
            with self.condition:
                self.lines.append(line)
                self.condition.notify_all()

    def output(self):
        with self.condition:
            return "\n".join(self.lines)

    def wait_for_output(self, text, timeout=30, count=1):
        deadline = time.monotonic() + timeout
        with self.condition:
            while sum(text in line for line in self.lines) < count:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or self.popen.poll() is not None:
                    return sum(text in line for line in self.lines) >= count
                self.condition.wait(min(remaining, 0.2))
            return True

    @property
    def pid(self):
        return self.popen.pid

    def signal_stop(self):
        """The console event / signal a user's Ctrl+C or Ctrl+Break sends."""
        if IS_WINDOWS:
            os.kill(self.popen.pid, signal.CTRL_BREAK_EVENT)
        else:
            self.popen.send_signal(signal.SIGINT)

    def stop(self, timeout=30):
        """Graceful stop; returns (exit code, seconds taken)."""
        if self.popen.poll() is not None:
            self.reader.join(5)
            return self.popen.returncode, 0.0
        start = time.monotonic()
        self.signal_stop()
        try:
            code = self.popen.wait(timeout)
        except subprocess.TimeoutExpired:
            self.popen.kill()
            self.popen.wait()
            raise AssertionError("process did not stop within %ss:\n%s" % (timeout, self.output()))
        self.reader.join(5)
        return code, time.monotonic() - start

    def kill(self):
        if self.popen.poll() is None:
            self.popen.kill()
            self.popen.wait()


def raw_request(port, payload, timeout=15.0, read=True):
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as connection:
        connection.sendall(payload)
        if not read:
            return b""
        chunks = []
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)


def http_get(port, target, timeout=15.0):
    if isinstance(target, str):
        target = target.encode()
    data = raw_request(port, b"GET " + target + b" HTTP/1.1\r\nHost: test\r\n\r\n", timeout)
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = int(lines[0].split()[1]) if lines and lines[0] else None
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        headers[name.strip().lower()] = value.strip()
    if status is not None:
        assert int(headers[b"content-length"]) == len(body), data
    return status, headers, body


def pct(data):
    return "".join("%%%02X" % b for b in data)


# --------------------------------------------------------------------------
# fake crawler RPC (DHTP/1) for tracker tests

class FakeCrawler(socketserver.ThreadingTCPServer):
    allow_reuse_address = not IS_WINDOWS
    daemon_threads = True

    def __init__(self):
        self.behaviour = lambda hash_hex: b"DHTP/1 OK 0\nEND\n"
        self.delay = 0.0
        self.requests = []
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), FakeCrawler.Handler)
        self.thread = threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    @property
    def port(self):
        return self.server_address[1]

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            line = self.rfile.readline(512)
            match = re.match(rb"DHTP/1 GET_PEERS ([0-9a-f]{40})\n$", line)
            hash_hex = match.group(1).decode() if match else None
            with self.server.lock:
                self.server.requests.append(hash_hex)
            if self.server.delay:
                time.sleep(self.server.delay)
            with contextlib.suppress(OSError):
                self.wfile.write(self.server.behaviour(hash_hex))


# --------------------------------------------------------------------------
# fake DHT node and BitTorrent peer for crawler tests

def make_torrent(name, length):
    info = {b"length": length, b"name": name.encode("utf-8"), b"piece length": 16384,
            b"pieces": hashlib.sha1(name.encode("utf-8")).digest() * ((length + 16383) // 16384)}
    encoded = bencode(info)
    return hashlib.sha1(encoded).digest(), encoded


def send_announce(session_port, info_hash, peer_port, implied_port=False, via=None, host="127.0.0.1"):
    """KRPC announce_peer to the crawler session listening on host:session_port.
    With implied_port the crawler must use the UDP source port, so pass the
    peer's own UDP socket as `via`."""
    message = bencode({
        "a": {"id": os.urandom(20), "implied_port": 1 if implied_port else 0,
              "info_hash": info_hash, "port": peer_port, "token": b"token"},
        "q": "announce_peer", "t": b"aa", "y": "q"})
    if via is not None:
        via.sendto(message, (host, session_port))
        return
    with socket.socket(family_of(host), socket.SOCK_DGRAM) as udp:
        udp.sendto(message, (host, session_port))


class FakePeer:
    """Serves BEP 9 ut_metadata for known info-hashes over plaintext TCP.

    libtorrent tries uTP first, then an MSE-encrypted TCP handshake, then
    plaintext TCP. Like a TCP-only peer we answer the uTP SYN with ST_RESET
    and close encrypted handshakes, so each fallback happens at once (a
    silently dropped SYN depends on rate-limited ICMP replies instead).
    """

    UT_METADATA_ID = 3
    UTP_SYN = 0x41    # type ST_SYN (4), version 1
    UTP_RESET = 0x31  # type ST_RESET (3), version 1

    def __init__(self, torrents, host="127.0.0.1"):
        self.host = host
        self.torrents = dict(torrents)
        self.handshakes = collections.Counter()
        self.lock = threading.Lock()
        self.active = set()
        self.max_concurrent = 0
        self.release = threading.Event()
        self.release.set()
        self.hold_until = 0
        family = family_of(host)
        for _ in range(100):
            self.listener = socket.socket(family)
            self.listener.bind((host, 0))
            self.port = self.listener.getsockname()[1]
            self.udp = socket.socket(family, socket.SOCK_DGRAM)
            try:
                self.udp.bind((host, self.port))
                break
            except OSError:
                self.listener.close()
                self.udp.close()
        self.listener.listen(64)
        self.udp.settimeout(0.2)
        self.running = True
        threading.Thread(target=self._accept, daemon=True).start()
        threading.Thread(target=self._refuse_utp, daemon=True).start()

    def close(self):
        self.running = False
        self.release.set()
        with contextlib.suppress(OSError):
            self.listener.close()
        with contextlib.suppress(OSError):
            self.udp.close()

    def _refuse_utp(self):
        while self.running:
            try:
                packet, address = self.udp.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                if not self.running:
                    return
                continue
            if len(packet) >= 20 and packet[0] == self.UTP_SYN:
                connection_id, = struct.unpack(">H", packet[2:4])
                sequence, = struct.unpack(">H", packet[16:18])
                reset = struct.pack(">BBHIIIHH", self.UTP_RESET, 0, connection_id,
                                    int(time.monotonic() * 1e6) & 0xffffffff, 0, 0, 1, sequence)
                with contextlib.suppress(OSError):
                    self.udp.sendto(reset, address)

    def hold(self, until_concurrent, timeout):
        """Withhold metadata until `until_concurrent` torrents are connected."""
        self.hold_until = until_concurrent
        self.hold_deadline = time.monotonic() + timeout
        self.release.clear()

    def _accept(self):
        while self.running:
            try:
                connection, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(connection,), daemon=True).start()

    @staticmethod
    def _exact(connection, size):
        data = b""
        while len(data) < size:
            chunk = connection.recv(size - len(data))
            if not chunk:
                raise ConnectionError("closed")
            data += chunk
        return data

    def _send_extended(self, connection, extended_id, payload):
        body = bytes([20, extended_id]) + payload
        connection.sendall(struct.pack(">I", len(body)) + body)

    def _serve(self, connection):
        info_hash = None
        connection.settimeout(30)
        try:
            handshake = self._exact(connection, 68)
            if handshake[:20] != b"\x13BitTorrent protocol":
                return
            info_hash = handshake[28:48]
            if info_hash not in self.torrents:
                return
            info = self.torrents[info_hash]
            with self.lock:
                self.handshakes[info_hash] += 1
                self.active.add(info_hash)
                self.max_concurrent = max(self.max_concurrent, len(self.active))
                if self.hold_until and len(self.active) >= self.hold_until:
                    self.release.set()
            reserved = bytearray(8)
            reserved[5] |= 0x10
            connection.sendall(b"\x13BitTorrent protocol" + bytes(reserved) + info_hash + b"-PY0001-" + os.urandom(12))
            self._send_extended(connection, 0, bencode({"m": {"ut_metadata": self.UT_METADATA_ID},
                                                       "metadata_size": len(info)}))
            their_id = None
            while self.running:
                length = struct.unpack(">I", self._exact(connection, 4))[0]
                if length == 0:
                    continue
                message = self._exact(connection, length)
                if message[0] != 20:
                    continue
                if message[1] == 0:
                    their_id = bdecode(message[2:]).get(b"m", {}).get(b"ut_metadata")
                    continue
                if message[1] != self.UT_METADATA_ID or their_id is None:
                    continue
                request = bdecode(message[2:])
                if request.get(b"msg_type") != 0:
                    continue
                if not self.release.is_set():
                    self.release.wait(max(0.0, self.hold_deadline - time.monotonic()))
                piece = request[b"piece"]
                data = info[piece * 16384:(piece + 1) * 16384]
                header = bencode({"msg_type": 1, "piece": piece, "total_size": len(info)})
                self._send_extended(connection, their_id, header + data)
        except (OSError, ConnectionError, ValueError, KeyError, struct.error):
            pass
        finally:
            with self.lock:
                if info_hash is not None:
                    self.active.discard(info_hash)
            with contextlib.suppress(OSError):
                connection.close()


# --------------------------------------------------------------------------
# tracker_server

class TrackerTests(unittest.TestCase):
    LOOKUP_TIMEOUT = 2  # request deadline = lookup timeout + 3 s

    @classmethod
    def setUpClass(cls):
        cls.crawler = FakeCrawler()
        cls.port = free_port()
        cls.tracker = Process([TRACKER, "--bind", "127.0.0.1", "--port", cls.port,
                               "--crawler-host", "127.0.0.1", "--crawler-port", cls.crawler.port,
                               "--lookup-timeout", cls.LOOKUP_TIMEOUT, "--interval", 90])
        if not cls.tracker.wait_for_output("HTTP 监听", 15):
            raise AssertionError("tracker did not start:\n" + cls.tracker.output())

    @classmethod
    def tearDownClass(cls):
        code, _ = cls.tracker.stop()
        cls.crawler.shutdown()
        cls.crawler.server_close()
        assert code == 0, cls.tracker.output()

    def setUp(self):
        self.crawler.delay = 0.0
        self.crawler.behaviour = lambda hash_hex: b"DHTP/1 OK 0\nEND\n"

    def assertAlive(self):
        self.assertIsNone(self.tracker.popen.poll(), self.tracker.output())
        status, _, body = http_get(self.port, "/health")
        self.assertEqual((status, body), (200, b"ok\n"))

    def failure_reason(self, target):
        status, _, body = http_get(self.port, target)
        self.assertEqual(status, 200)
        reply = bdecode(body)
        return reply.get(b"failure reason", b"").decode("utf-8")

    def test_health(self):
        self.assertAlive()

    def test_announce_returns_compact_ipv4_and_ipv6_peers(self):
        self.crawler.behaviour = lambda hash_hex: (
            b"DHTP/1 OK 5\nPEER 4 1.2.3.4 6881\nPEER 4 10.0.0.1 1\nPEER 4 255.255.255.255 65535\n"
            b"PEER 6 2001:db8::1 51413\nPEER 6 ::ffff:1.2.3.4 80\nEND\n")
        info_hash = bytes(range(20))
        status, headers, body = http_get(self.port, "/announce?info_hash=%s&port=6881&event=started" % pct(info_hash))
        self.assertEqual(status, 200)
        self.assertEqual(headers[b"content-type"], b"text/plain")
        reply = bdecode(body)
        self.assertEqual(reply[b"interval"], 90)
        self.assertEqual(reply[b"min interval"], 90)
        self.assertEqual(reply[b"peers"],
                         socket.inet_aton("1.2.3.4") + struct.pack(">H", 6881)
                         + socket.inet_aton("10.0.0.1") + struct.pack(">H", 1)
                         + socket.inet_aton("255.255.255.255") + struct.pack(">H", 65535))
        self.assertEqual(reply[b"peers6"],
                         socket.inet_pton(socket.AF_INET6, "2001:db8::1") + struct.pack(">H", 51413)
                         + socket.inet_pton(socket.AF_INET6, "::ffff:1.2.3.4") + struct.pack(">H", 80))
        # Keys come out sorted, as bencode requires.
        self.assertTrue(body.startswith(b"d8:interval"))
        self.assertIn(info_hash.hex(), self.crawler.requests)

    def test_announce_accepts_hex_info_hash(self):
        reply = bdecode(http_get(self.port, "/announce?info_hash=" + "AB" * 20)[2])
        self.assertEqual(reply[b"peers"], b"")
        self.assertIn("ab" * 20, self.crawler.requests)

    def test_malformed_info_hash_is_rejected_without_crashing(self):
        wrong_length = "info_hash 必须是 20 字节"
        missing = "缺少 info_hash"
        cases = {
            "/announce": missing,
            "/announce?port=1": missing,
            "/announce?info_hash=": wrong_length,
            "/announce?info_hash=%01": wrong_length,
            "/announce?info_hash=" + pct(b"x" * 19): wrong_length,
            "/announce?info_hash=" + pct(b"x" * 21): wrong_length,
            "/announce?info_hash=" + "a" * 39: wrong_length,
            "/announce?info_hash=" + "a" * 41: wrong_length,
            "/announce?info_hash=" + "g" * 40: wrong_length,
            "/announce?info_hash=" + pct(b"x" * 1000): wrong_length,
            "/announce?info_hash=%": missing,
            "/announce?info_hash=%4": missing,
            "/announce?info_hash=%zz" + pct(b"x" * 19): missing,
            "/announce?info_hash=%%41": missing,
        }
        for target, expected in cases.items():
            with self.subTest(target=target[:60]):
                self.assertEqual(self.failure_reason(target), expected)
        # A NUL inside a binary hash is fine; the first duplicate wins.
        info_hash = b"\x00" * 19 + b"\x01"
        self.assertEqual(self.failure_reason("/announce?info_hash=%s&info_hash=bad" % pct(info_hash)), "")
        self.assertAlive()

    def test_bad_requests(self):
        def status_of(payload):
            data = raw_request(self.port, payload)
            return int(data.split(b" ")[1]) if data else None

        self.assertEqual(status_of(b"POST /announce HTTP/1.1\r\n\r\n"), 400)
        self.assertEqual(status_of(b"GET /nope HTTP/1.1\r\n\r\n"), 404)
        self.assertEqual(status_of(b"GET / HTTP/1.1 extra\r\n\r\n"), 400)
        self.assertEqual(status_of(b"GET /announce\r\n\r\n"), 400)
        self.assertEqual(status_of(b"\r\n\r\n"), 400)
        self.assertEqual(status_of(b"\x00\xff\x13binary\r\n\r\n"), 400)
        self.assertAlive()

    def test_oversized_request_is_dropped(self):
        # Dropped without a reply. Unread input makes both TCP stacks answer
        # the close with RST, so the client sees EOF or a reset.
        for payload in (b"GET /announce?" + b"a" * (20 * 1024),
                        b"GET /health HTTP/1.1\r\nX: " + b"b" * (17 * 1024) + b"\r\n\r\n"):
            start = time.monotonic()
            try:
                data = raw_request(self.port, payload)
            except ConnectionResetError:
                data = b""
            self.assertEqual(data, b"")
            self.assertLess(time.monotonic() - start, 3)
        self.assertAlive()

    def test_incomplete_request_times_out(self):
        start = time.monotonic()
        data = raw_request(self.port, b"GET /health HTTP/1.1\r\n")
        elapsed = time.monotonic() - start
        self.assertEqual(data, b"")
        self.assertGreater(elapsed, self.LOOKUP_TIMEOUT + 3 - 1)
        self.assertLess(elapsed, self.LOOKUP_TIMEOUT + 3 + 3)

    def test_slow_and_idle_clients_do_not_starve_workers(self):
        idle = []
        try:
            for _ in range(80):
                connection = socket.create_connection(("127.0.0.1", self.port), timeout=10)
                connection.sendall(b"GET /health HTTP/1.1\r\nHost: slow")
                idle.append(connection)
            time.sleep(0.3)
            durations = []
            errors = []

            def client():
                start = time.monotonic()
                try:
                    status, _, body = http_get(self.port, "/health", timeout=10)
                    if (status, body) != (200, b"ok\n"):
                        errors.append(status)
                except OSError as error:
                    errors.append(error)
                durations.append(time.monotonic() - start)

            threads = [threading.Thread(target=client) for _ in range(40)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(errors, [])
            self.assertLess(max(durations), 2.0, durations)
        finally:
            for connection in idle:
                connection.close()

    def test_concurrent_announces(self):
        self.crawler.delay = 0.02
        self.crawler.behaviour = lambda hash_hex: (
            b"DHTP/1 OK 1\nPEER 4 %d.%d.%d.%d 1000\nEND\n" % tuple(bytes.fromhex(hash_hex)[:4]))
        results = {}
        lock = threading.Lock()

        def client(index):
            info_hash = hashlib.sha1(b"concurrent-%d" % index).digest()
            try:
                reply = bdecode(http_get(self.port, "/announce?info_hash=" + pct(info_hash), timeout=30)[2])
                ok = reply.get(b"peers") == info_hash[:4] + struct.pack(">H", 1000)
            except (OSError, ValueError) as error:
                ok = error
            with lock:
                results[index] = ok

        threads = [threading.Thread(target=client, args=(i,)) for i in range(200)]
        start = time.monotonic()
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        failures = {k: v for k, v in results.items() if v is not True}
        self.assertEqual(failures, {})
        self.assertLess(time.monotonic() - start, 20)

    def test_poisoned_rpc_replies(self):
        info_hash = "/announce?info_hash=" + "cd" * 20
        cases = [
            (b"HTTP/1.1 200 OK\r\n\r\nEND\n", "无效 RPC 协议"),
            (b"DHTP/1 OK 513\nEND\n", "无效 peer 数量"),
            # The END line is read as the missing peer line (as before the port).
            (b"DHTP/1 OK 2\nPEER 4 1.2.3.4 1\nEND\n", "无效 RPC peer"),
            (b"DHTP/1 OK 1\nPEER 4 1.2.3.4 99999\nEND\n", "无效 RPC peer"),
            (b"DHTP/1 TIMEOUT\nEND\n", "DHT 查询超时"),
            (b"DHTP/1 ERROR lookup-failed\nEND\n", "DHT 爬虫查询失败"),
            (b"DHTP/1 OK 1\n", "连接在消息完成前关闭"),
            (b"x" * (70 * 1024), "消息超过允许的最大长度"),
        ]
        for response, expected in cases:
            with self.subTest(expected=expected):
                self.crawler.behaviour = lambda hash_hex, response=response: response
                self.assertEqual(self.failure_reason(info_hash), expected)
        self.crawler.delay = self.LOOKUP_TIMEOUT + 1
        self.assertEqual(self.failure_reason(info_hash), "recv: timed out")
        self.assertAlive()

    def test_unreachable_crawler_is_refused_immediately(self):
        http_port = free_port()
        tracker = Process([TRACKER, "--bind", "127.0.0.1", "--port", http_port,
                           "--crawler-port", free_port(), "--lookup-timeout", 10])
        try:
            self.assertTrue(tracker.wait_for_output("HTTP 监听", 15), tracker.output())
            start = time.monotonic()
            status, _, body = http_get(http_port, "/announce?info_hash=" + "ef" * 20)
            elapsed = time.monotonic() - start
            # Windows would otherwise retry the SYN for ~2 s after the RST.
            self.assertEqual(bdecode(body)[b"failure reason"].decode(), "connect: connection refused")
            self.assertLess(elapsed, 1.0)
        finally:
            self.assertEqual(tracker.stop()[0], 0)

    def test_no_socket_leaks_under_abuse(self):
        if handle_count(self.tracker.pid) is None:
            self.skipTest("handle counting not supported on this platform")
        for _ in range(30):
            http_get(self.port, "/announce?info_hash=" + "aa" * 20)
        time.sleep(0.5)
        baseline = handle_count(self.tracker.pid)

        def abuse(kind, count):
            for _ in range(count):
                with contextlib.suppress(OSError):
                    connection = socket.create_connection(("127.0.0.1", self.port), timeout=5)
                    if kind == "reset":
                        connection.sendall(b"GET /announce?info_hash=")
                        connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                    elif kind == "no-read":
                        connection.sendall(b"GET /announce?info_hash=" + b"bb" * 20 + b" HTTP/1.1\r\n\r\n")
                    elif kind == "idle":
                        held.append(connection)
                        continue
                    connection.close()

        held = []
        threads = [threading.Thread(target=abuse, args=(kind, count))
                   for kind, count in (("close", 300), ("reset", 150), ("no-read", 150), ("idle", 60))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        for connection in held:
            connection.close()
        # Everything is closed by the peer or has hit the request deadline.
        time.sleep(self.LOOKUP_TIMEOUT + 3 + 2)
        self.assertAlive()
        after = handle_count(self.tracker.pid)
        self.assertLessEqual(after, baseline + 10, "handles before=%s after=%s" % (baseline, after))

    def test_shutdown_interrupts_in_flight_lookups(self):
        crawler = FakeCrawler()
        crawler.delay = 30
        port = free_port()
        tracker = Process([TRACKER, "--bind", "127.0.0.1", "--port", port,
                           "--crawler-port", crawler.port, "--lookup-timeout", 60])
        try:
            self.assertTrue(tracker.wait_for_output("HTTP 监听", 15), tracker.output())
            clients = [threading.Thread(target=self._quiet_get, args=(port,)) for _ in range(5)]
            for client in clients:
                client.start()
            time.sleep(1.0)
            code, seconds = tracker.stop()
            self.assertEqual(code, 0, tracker.output())
            self.assertLess(seconds, 3.0)
            self.assertIn("收到退出信号", tracker.output())
            for client in clients:
                client.join(10)
        finally:
            tracker.kill()
            crawler.shutdown()
            crawler.server_close()

    @staticmethod
    def _quiet_get(port):
        with contextlib.suppress(OSError, ValueError, IndexError):
            http_get(port, "/announce?info_hash=" + "12" * 20, timeout=40)

    def test_restart_on_same_port_and_no_port_hijacking(self):
        port = free_port()
        args = [TRACKER, "--bind", "127.0.0.1", "--port", port, "--crawler-port", self.crawler.port]
        tracker = Process(args)
        try:
            self.assertTrue(tracker.wait_for_output("HTTP 监听", 15), tracker.output())
            # Another socket must not be able to take over the listening
            # address (Windows SO_REUSEADDR would allow exactly that).
            with socket.socket() as intruder:
                intruder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                with self.assertRaises(OSError):
                    intruder.bind(("127.0.0.1", port))
            # A wildcard bind is refused on Linux; Windows may allow it, but
            # the more specific listener keeps receiving its connections.
            with socket.socket() as intruder:
                intruder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    intruder.bind(("0.0.0.0", port))
                    intruder.listen(16)
                except OSError:
                    pass
                intruder.settimeout(0.5)
                for _ in range(10):
                    self.assertEqual(http_get(port, "/health")[2], b"ok\n")
                with self.assertRaises(OSError):
                    intruder.accept()
            for _ in range(20):
                http_get(port, "/health")
            self.assertEqual(tracker.stop()[0], 0)

            # Server-side TIME_WAIT connections must not block a restart.
            tracker = Process(args)
            self.assertTrue(tracker.wait_for_output("HTTP 监听", 15), tracker.output())
            self.assertEqual(http_get(port, "/health")[2], b"ok\n")
        finally:
            self.assertEqual(tracker.stop()[0], 0)

    def test_log_lines_cannot_be_forged(self):
        http_get(self.port, "/announce?info_hash=" + "34" * 20 + "&event=started%0A[Tracker][回复]%20forged%1B[2J")
        time.sleep(0.3)
        output = self.tracker.output()
        self.assertIn("event=started\\x0a[Tracker]", output)
        self.assertNotIn("\x1b", output)
        self.assertFalse(any(line.startswith("[Tracker][回复] forged") for line in output.splitlines()))


# --------------------------------------------------------------------------
# dht_db

def database_row(database, info_hash):
    with contextlib.closing(sqlite3.connect(database, timeout=5)) as db:
        return db.execute("SELECT info_hash, name, discovered_peer, timestamp FROM torrents "
                          "WHERE info_hash = ?", (info_hash.hex(),)).fetchone()


def wait_for_database_row(database, info_hash, timeout=40):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = database_row(database, info_hash)
        if row:
            return row
        time.sleep(0.2)
    return None


def crawler_storage_args(root):
    return ["--database", os.path.join(root, "db", "crawler.db"),
            "--temp-dir", os.path.join(root, "tmp"),
            "--torrent-dir", os.path.join(root, "torrents"),
            "--dht-state-dir", os.path.join(root, "state")]


class CrawlerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="dht_crawler_it_")
        root = os.path.join(cls.directory.name, "数据")  # non-ASCII on purpose
        os.makedirs(root)
        cls.root = root
        cls.database = os.path.join(root, "db", "crawler.db")
        cls.first_port = free_port_pair()
        cls.rpc_port = free_port()
        cls.args = [CRAWLER, "--bind", "127.0.0.1", "--listeners", 2, "--first-port", cls.first_port,
                    "--bootstrap-nodes", "127.0.0.1:%d" % free_port(udp_too=True),
                    "--bootstrap-stagger-ms", 50, "--metadata-timeout", 20, "--retry-delay", 5,
                    "--tracker-rpc-bind", "127.0.0.1", "--tracker-rpc-port", cls.rpc_port,
                    "--tracker-timeout", 2,
                    "--database", cls.database,
                    "--temp-dir", os.path.join(root, "tmp"),
                    "--torrent-dir", os.path.join(root, "torrents"),
                    "--dht-state-dir", os.path.join(root, "state")]
        cls.crawler = Process(cls.args)
        if not cls.crawler.wait_for_output("[Tracker RPC] 监听", 60):
            cls.crawler.kill()
            raise AssertionError("crawler did not start:\n" + cls.crawler.output())

    @classmethod
    def tearDownClass(cls):
        cls.crawler.kill()
        cls.directory.cleanup()

    def rpc(self, payload, timeout=15):
        return raw_request(self.rpc_port, payload, timeout)

    def row(self, info_hash):
        return database_row(self.database, info_hash)

    def wait_for_row(self, info_hash, timeout=40):
        return wait_for_database_row(self.database, info_hash, timeout)

    def test_1_rpc_protocol(self):
        self.assertEqual(self.rpc(b"garbage\n"), b"DHTP/1 ERROR invalid-request\nEND\n")
        self.assertEqual(self.rpc(b"DHTP/1 GET_PEERS " + b"z" * 40 + b"\n"), b"DHTP/1 ERROR invalid-request\nEND\n")
        self.assertEqual(self.rpc(b"DHTP/1 GET_PEERS " + b"a" * 40 + b" extra\n"), b"DHTP/1 ERROR invalid-request\nEND\n")
        try:  # oversized: dropped without a reply (EOF or RST)
            self.assertEqual(self.rpc(b"x" * 300), b"")
        except ConnectionResetError:
            pass

        # Concurrent lookups of one hash are coalesced and all time out.
        replies = []

        def lookup():
            replies.append(self.rpc(b"DHTP/1 GET_PEERS " + b"5a" * 20 + b"\n"))

        threads = [threading.Thread(target=lookup) for _ in range(6)]
        start = time.monotonic()
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(replies, [b"DHTP/1 TIMEOUT\nEND\n"] * 6)
        self.assertLess(time.monotonic() - start, 6)

    def test_2_tracker_end_to_end(self):
        port = free_port()
        tracker = Process([TRACKER, "--bind", "127.0.0.1", "--port", port,
                           "--crawler-port", self.rpc_port, "--lookup-timeout", 5])
        try:
            self.assertTrue(tracker.wait_for_output("HTTP 监听", 15), tracker.output())
            body = http_get(port, "/announce?info_hash=" + pct(os.urandom(20)))[2]
            self.assertEqual(bdecode(body)[b"failure reason"].decode(), "DHT 查询超时")
        finally:
            self.assertEqual(tracker.stop()[0], 0)

    def test_3_metadata_pipeline_and_cross_session_dedup(self):
        info_hash, info = make_torrent("测试-文件 ✓.bin", 40000)
        peer = FakePeer({info_hash: info})
        try:
            # Both sessions hear about the same hash; session 1 via BEP 5
            # implied_port (the UDP source port is the peer's port).
            send_announce(self.first_port, info_hash, peer.port)
            send_announce(self.first_port + 1, info_hash, 1, implied_port=True, via=peer.udp)
            row = self.wait_for_row(info_hash)
            self.assertIsNotNone(row, self.crawler.output())
            self.assertEqual(row[0], info_hash.hex())
            self.assertEqual(row[1], "测试-文件 ✓.bin")
            self.assertEqual(row[2], "127.0.0.1:%d" % peer.port)
            self.assertRegex(row[3], r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$")

            torrent_path = os.path.join(self.root, "torrents", info_hash.hex() + ".torrent")
            with open(torrent_path, "rb") as torrent_file:
                torrent = bdecode(torrent_file.read())
            self.assertEqual(hashlib.sha1(bencode(torrent[b"info"])).digest(), info_hash)

            # Announce again: already stored, so no second fetch.
            send_announce(self.first_port, info_hash, peer.port)
            time.sleep(2)
            self.assertEqual(peer.handshakes[info_hash], 1, self.crawler.output())
            with contextlib.closing(sqlite3.connect(self.database)) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM torrents WHERE info_hash = ?",
                                            (info_hash.hex(),)).fetchone()[0], 1)
        finally:
            peer.close()

    def test_4_metadata_fetches_run_concurrently(self):
        torrents = dict(make_torrent("concurrent-%d.bin" % i, 20000 + i) for i in range(5))
        peer = FakePeer(torrents)
        peer.hold(until_concurrent=len(torrents), timeout=15)
        try:
            for info_hash in torrents:
                send_announce(self.first_port, info_hash, peer.port)
                time.sleep(0.3)  # stays under libtorrent's 5 packets/s DHT rate limit
            for info_hash in torrents:
                self.assertIsNotNone(self.wait_for_row(info_hash), self.crawler.output())
            # With libtorrent's default auto-managed queueing only 3 metadata
            # downloads per session would ever run at once.
            self.assertEqual(peer.max_concurrent, len(torrents))
        finally:
            peer.close()

    def test_5_graceful_shutdown_persists_everything(self):
        code, seconds = self.crawler.stop(timeout=60)
        output = self.crawler.output()
        self.assertEqual(code, 0, output)
        self.assertLess(seconds, 30)
        self.assertIn("收到退出信号", output)
        self.assertEqual(output.count("已保存状态"), 2, output)
        self.assertIn("[DB] 已写入", output)
        for session, port in ((0, self.first_port), (1, self.first_port + 1)):
            state = os.path.join(self.root, "state", "session-%d-port-%d.state" % (session, port))
            self.assertGreater(os.path.getsize(state), 0)
        for directory in ("state", "torrents"):
            leftovers = [n for n in os.listdir(os.path.join(self.root, directory)) if n.endswith(".tmp")]
            self.assertEqual(leftovers, [])
        wal = self.database + "-wal"
        self.assertTrue(not os.path.exists(wal) or os.path.getsize(wal) == 0)

        with contextlib.closing(sqlite3.connect(self.database)) as db:
            columns = db.execute("PRAGMA table_info(torrents)").fetchall()
            self.assertEqual([(c[1], c[2], c[3], c[4], c[5]) for c in columns], [
                ("info_hash", "TEXT", 1, None, 1),
                ("name", "TEXT", 1, None, 0),
                ("discovered_peer", "TEXT", 1, None, 0),
                ("timestamp", "DATETIME", 0, "CURRENT_TIMESTAMP", 0),
            ])
            self.assertEqual(db.execute("PRAGMA journal_mode").fetchone()[0], "wal")

    def test_6_restart_restores_dht_state(self):
        crawler = Process(self.args)
        try:
            self.assertTrue(crawler.wait_for_output("已加载状态", 60, count=2), crawler.output())
            self.assertTrue(crawler.wait_for_output("[Tracker RPC] 监听", 60), crawler.output())
        finally:
            code, _ = crawler.stop(timeout=60)
        self.assertEqual(code, 0, crawler.output())


class CrawlerBindArgumentTests(unittest.TestCase):
    """--bind list validation happens before anything is created or bound."""

    def run_crawler(self, *arguments):
        with tempfile.TemporaryDirectory(prefix="dht_crawler_args_") as root:
            result = subprocess.run(
                [CRAWLER, *[str(a) for a in arguments]], cwd=root, stdin=subprocess.DEVNULL,
                capture_output=True, timeout=30)
            created = os.listdir(root)
        return result.returncode, result.stderr.decode("utf-8", "replace"), created

    def test_invalid_bind_lists_are_rejected(self):
        many = ",".join("127.0.0.%d" % i for i in range(1, 18))
        cases = [
            (["--bind", ""], None),
            (["--bind", "0.0.0.0,"], None),
            (["--bind", ",::"], None),
            (["--bind", "0.0.0.0,,::"], None),
            (["--bind", "[]"], None),
            (["--bind", many], None),
            (["--bind", "0.0.0.0,bogus"], "无效绑定地址: bogus"),
            (["--bind", "0.0.0.0, 0.0.0.0"], "重复的绑定地址: 0.0.0.0"),
            (["--bind", "::", "--bind", "0:0::0"], "重复的绑定地址: 0:0::0"),
            (["127.0.0.1,", "1"], None),
        ]
        for arguments, message in cases:
            with self.subTest(arguments=arguments):
                code, stderr, created = self.run_crawler(*arguments)
                self.assertEqual(code, 1, stderr)
                self.assertIn("--bind ADDRESS[,ADDRESS]", stderr)
                if message:
                    self.assertIn(message, stderr)
                self.assertEqual(created, [])

    @unittest.skipUnless(ipv6_loopback_available(), "IPv6 loopback not available")
    def test_repeated_bind_options_accumulate(self):
        with tempfile.TemporaryDirectory(prefix="dht_crawler_args_") as root:
            port = free_port_pair(("127.0.0.1", "::1"))
            crawler = Process([CRAWLER, "--bind", "127.0.0.1", "--bind", "[::1]", "--first-port", port,
                               "--bootstrap-nodes", "127.0.0.1:%d" % free_port(udp_too=True),
                               "--disable-tracker-rpc", *crawler_storage_args(root)])
            try:
                self.assertTrue(crawler.wait_for_output("[Tracker RPC] 已禁用", 60), crawler.output())
                self.assertIn("监听 127.0.0.1:%d,[::1]:%d，" % (port, port), crawler.output())
            finally:
                code, _ = crawler.stop(timeout=60)
            self.assertEqual(code, 0, crawler.output())


@unittest.skipUnless(ipv6_loopback_available(), "IPv6 loopback not available")
class DualStackCrawlerTests(unittest.TestCase):
    """One crawler, two sessions, each listening on 127.0.0.1 and ::1."""

    HOSTS = ("127.0.0.1", "::1")

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="dht_crawler_dual_")
        cls.root = cls.directory.name
        cls.database = os.path.join(cls.root, "db", "crawler.db")
        cls.first_port = free_port_pair(cls.HOSTS)
        cls.args = [CRAWLER, "--bind", "127.0.0.1,[::1]", "--listeners", 2, "--first-port", cls.first_port,
                    "--bootstrap-nodes", "127.0.0.1:%d" % free_port(udp_too=True),
                    "--bootstrap-stagger-ms", 50, "--metadata-timeout", 20, "--retry-delay", 5,
                    "--tracker-rpc-bind", "127.0.0.1", "--tracker-rpc-port", free_port(),
                    "--tracker-timeout", 2, *crawler_storage_args(cls.root)]
        cls.crawler = Process(cls.args)
        if not cls.crawler.wait_for_output("[Tracker RPC] 监听", 60):
            cls.crawler.kill()
            raise AssertionError("crawler did not start:\n" + cls.crawler.output())

    @classmethod
    def tearDownClass(cls):
        cls.crawler.kill()
        cls.directory.cleanup()

    def test_1_every_session_listens_on_both_families(self):
        expected = ",".join("127.0.0.1:%d,[::1]:%d" % (port, port)
                            for port in (self.first_port, self.first_port + 1))
        self.assertIn("监听 " + expected + "，", self.crawler.output())
        for host in self.HOSTS:
            for port in (self.first_port, self.first_port + 1):
                with socket.socket(family_of(host)) as probe:
                    probe.settimeout(5)
                    self.assertEqual(probe.connect_ex((host, port)), 0, (host, port))

    def test_2_metadata_is_fetched_over_each_family(self):
        hash6, info6 = make_torrent("ipv6-peer.bin", 30000)
        hash4, info4 = make_torrent("ipv4-peer.bin", 30001)
        peer6 = FakePeer({hash6: info6}, host="::1")
        peer4 = FakePeer({hash4: info4})
        try:
            send_announce(self.first_port, hash6, peer6.port, host="::1")
            send_announce(self.first_port + 1, hash4, peer4.port)
            row6 = wait_for_database_row(self.database, hash6)
            row4 = wait_for_database_row(self.database, hash4)
            self.assertIsNotNone(row6, self.crawler.output())
            self.assertIsNotNone(row4, self.crawler.output())
            self.assertEqual(row6[2], "[::1]:%d" % peer6.port)
            self.assertEqual(row4[2], "127.0.0.1:%d" % peer4.port)
        finally:
            peer6.close()
            peer4.close()

    def test_3_a_hash_is_fetched_once_across_families(self):
        info_hash, info = make_torrent("both-families.bin", 30002)
        peer6 = FakePeer({info_hash: info}, host="::1")
        peer4 = FakePeer({info_hash: info})
        try:
            send_announce(self.first_port, info_hash, peer6.port, host="::1")
            send_announce(self.first_port, info_hash, peer4.port)
            send_announce(self.first_port + 1, info_hash, peer4.port)
            row = wait_for_database_row(self.database, info_hash)
            self.assertIsNotNone(row, self.crawler.output())
            time.sleep(2)
            self.assertEqual(peer6.handshakes[info_hash] + peer4.handshakes[info_hash], 1)
            self.assertIn(row[2], ("[::1]:%d" % peer6.port, "127.0.0.1:%d" % peer4.port))
        finally:
            peer6.close()
            peer4.close()

    def test_4_shutdown_saves_a_node_id_per_family(self):
        code, _ = self.crawler.stop(timeout=60)
        output = self.crawler.output()
        self.assertEqual(code, 0, output)
        saved = [line for line in output.splitlines() if "已保存状态" in line]
        self.assertEqual(len(saved), 2, output)
        for line in saved:
            self.assertIn("节点 ID 2", line)

    def test_5_restart_restores_both_node_ids(self):
        crawler = Process(self.args)
        try:
            self.assertTrue(crawler.wait_for_output("已加载状态", 60, count=2), crawler.output())
            for line in crawler.output().splitlines():
                if "已加载状态" in line:
                    self.assertIn("节点 ID 2", line)
            self.assertTrue(crawler.wait_for_output("[Tracker RPC] 监听", 60), crawler.output())
        finally:
            code, _ = crawler.stop(timeout=60)
        self.assertEqual(code, 0, crawler.output())


def main():
    global TRACKER, CRAWLER
    parser = argparse.ArgumentParser()
    parser.add_argument("--tracker", required=True)
    parser.add_argument("--crawler")
    options, remaining = parser.parse_known_args()
    TRACKER = os.path.abspath(options.tracker)
    CRAWLER = os.path.abspath(options.crawler) if options.crawler else None
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    suite.addTests(loader.loadTestsFromTestCase(TrackerTests))
    if CRAWLER:
        for case in (CrawlerBindArgumentTests, CrawlerTests, DualStackCrawlerTests):
            suite.addTests(loader.loadTestsFromTestCase(case))
    names = [n for n in remaining if not n.startswith("-")]
    if names:
        suite = unittest.TestSuite(t for t in _flatten(suite) if any(n in t.id() for n in names))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


def _flatten(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from _flatten(test)
        else:
            yield test


if __name__ == "__main__":
    main()
