#!/usr/bin/env python3
"""Runs dht_ingest_bench once per capture mode and prints a comparison.

    python -I tests/dht_ingest_bench.py --bench build/.../dht_ingest_bench \
        [--rate 20000] [--seconds 10] [--runs 2] [--modes sniff,prefilter,alerts,plugin,none]

Loopback only; nothing is sent to the public DHT.
"""

import argparse
import os
import re
import socket
import statistics
import subprocess


def free_port():
    for _ in range(100):
        with socket.socket() as tcp:
            tcp.bind(("127.0.0.1", 0))
            port = tcp.getsockname()[1]
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
    raise RuntimeError("no free port")


def run(bench, mode, rate, seconds, upload_limit):
    port = free_port()
    command = [bench, "receive", "--mode", mode, "--port", str(port), "--seconds", str(seconds + 1)]
    if upload_limit:
        command += ["--upload-limit", str(upload_limit)]
    receiver = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in receiver.stdout:
        if line.strip() == "READY":
            break
    subprocess.run([bench, "send", "--port", str(port), "--rate", str(rate), "--seconds", str(seconds)],
                   check=True, capture_output=True, text=True)
    output, _ = receiver.communicate(timeout=60)
    match = re.search(r"^RESULT (.*)$", output, re.M)
    if not match:
        raise RuntimeError("no result from %s:\n%s" % (mode, output))
    fields = dict(item.split("=", 1) for item in match.group(1).split())
    return {key: (value if key in ("mode", "cpu_unit") else float(value))
            for key, value in fields.items()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bench", required=True)
    parser.add_argument("--rate", type=int, default=20000)
    parser.add_argument("--seconds", type=float, default=10)
    parser.add_argument("--runs", type=int, default=2)
    parser.add_argument("--modes", default="sniff,prefilter,alerts,plugin,none")
    parser.add_argument("--upload-limit", type=int, default=0,
                        help="dht_upload_rate_limit in bytes/s (default: libtorrent's 8000)")
    options = parser.parse_args()
    options.bench = os.path.abspath(options.bench)

    print("rate %d packets/s for %gs, median of %d run(s), dht_upload_rate_limit %s" % (
        options.rate, options.seconds, options.runs, options.upload_limit or "default"))
    modes = options.modes.split(",")
    # Interleaved (A B C A B C ...) so slow drift in machine load affects every
    # mode alike.
    results = {mode: [] for mode in modes}
    for _ in range(options.runs):
        for mode in modes:
            results[mode].append(run(options.bench, mode, options.rate, options.seconds,
                                     options.upload_limit))

    unit = results[modes[0]][0]["cpu_unit"]
    per = "kcyc/msg" if unit == "Mcycles" else "us/msg"
    header = "%-10s %9s %19s %11s %11s %10s %9s %9s %7s" % (
        "mode", per, "(min..max)", "messages_in", "lt_dropped", "announces", "dht_log",
        "dht_pkt", "q_drops")
    print(header)
    print("-" * len(header))
    for mode in modes:
        values = results[mode]
        median = lambda key: statistics.median(result[key] for result in values)
        per_message = [result["per_message"] for result in values]
        print("%-10s %9.2f %19s %11.0f %11.0f %10.0f %9.0f %9.0f %7.0f" % (
            mode, median("per_message"), "(%.1f..%.1f)" % (min(per_message), max(per_message)),
            median("messages_in"), median("messages_dropped"), median("announces"),
            median("dht_log_alerts"), median("dht_pkt_alerts"), median("alerts_dropped_notices")))


if __name__ == "__main__":
    main()
