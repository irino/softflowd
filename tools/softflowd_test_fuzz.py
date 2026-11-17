#!/usr/bin/env python3
"""
softflowd_test_fuzz.py -- fuzz testing suite for softflowd (C vs Rust).
"""

import argparse
import concurrent.futures
import os
import random
import socket
import struct
import subprocess
import sys
import tempfile
from typing import List, Tuple

import softflowd_test_helper as helper
from softflowd_collector import UdpSink, Decoder, datagrams_to_csv


def parse_pcap(path: str) -> Tuple[bytes, List[Tuple[int, int, int, int, bytes]]]:
    with open(path, "rb") as f:
        data = f.read()
    global_hdr = data[:24]
    off = 24
    packets = []
    while off < len(data):
        ts, us, caplen, origlen = struct.unpack("<IIII", data[off:off + 16])
        pkt_data = data[off + 16:off + 16 + caplen]
        packets.append((ts, us, caplen, origlen, bytearray(pkt_data)))
        off += 16 + caplen
    return global_hdr, packets


def write_pcap(path: str, global_hdr: bytes, packets: List[Tuple[int, int, int, int, bytes]]):
    out = bytearray(global_hdr)
    for ts, us, caplen, origlen, pkt in packets:
        out += struct.pack("<IIII", ts, us, len(pkt), origlen) + bytes(pkt)
    with open(path, "wb") as f:
        f.write(out)


def run_single_fuzz(args_tuple):
    pcap_path, version, a_bin, b_bin = args_tuple
    results = {}
    for daemon_type, daemon_bin in [("A", a_bin), ("B", b_bin)]:
        sink = UdpSink(host="127.0.0.1", port=0)
        try:
            res = subprocess.run(
                [daemon_bin, "-d", "-r", pcap_path, "-n", f"127.0.0.1:{sink.port}", "-v", version],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10
            )
            sink.close(quiet=0.05, timeout=0.5)
            retcode = res.returncode
            stdout_text = res.stdout
            datagrams = list(sink.datagrams)
        except subprocess.TimeoutExpired:
            sink.close(quiet=0.05, timeout=0.1)
            retcode = -999
            stdout_text = "TIMEOUT"
            datagrams = []
        except Exception as e:
            sink.close(quiet=0.05, timeout=0.1)
            retcode = -998
            stdout_text = str(e)
            datagrams = []
        results[daemon_type] = (retcode, stdout_text, datagrams)

    b_ret, b_out, b_dgram = results["B"]
    a_ret, a_out, a_dgram = results["A"]

    failed = False
    fail_reason = ""

    if b_ret == 101 or b_ret < 0:
        failed = True
        fail_reason = f"B exited with status {b_ret} (panic 101 or signal)"
    else:
        if a_out.strip() != b_out.strip():
            failed = True
            fail_reason = f"statistics (stdout) differ (A: {repr(a_out.strip())}, B: {repr(b_out.strip())})"
        else:
            csv_a = datagrams_to_csv(a_dgram)
            csv_b = datagrams_to_csv(b_dgram)
            rows_a = sorted(",".join(r.split(",")[2:]) for r in csv_a.splitlines()[1:] if r.strip())
            rows_b = sorted(",".join(r.split(",")[2:]) for r in csv_b.splitlines()[1:] if r.strip())
            if rows_a != rows_b:
                failed = True
                fail_reason = "exported flow records differ"

    return pcap_path, version, failed, fail_reason, b_bin


def fuzz_main() -> int:
    ap = argparse.ArgumentParser(description="softflowd fuzz test suite (garbage corpus)")
    ap.add_argument("--a", default="./softflowd", help="C softflowd binary (default: ./softflowd)")
    ap.add_argument("--b", default="rust/target/release/rsoftflowd", help="Rust softflowd binary")
    ap.add_argument("--pcap-dir", default="pcaps", help="Directory with http.cap and v6-http.cap")
    args = ap.parse_args()

    a_bin = os.path.abspath(args.a)
    b_bin = os.path.abspath(args.b)
    pcap_dir = os.path.abspath(args.pcap_dir)

    for name in ("http.cap", "v6-http.cap"):
        p = os.path.join(pcap_dir, name)
        if not os.path.exists(p):
            helper.ensure_sample_pcap(p, is_v6=("v6" in name))

    tmp_dir = tempfile.mkdtemp(prefix="softflowd_fuzz_")
    mutated_pcaps = []

    for name in ("http.cap", "v6-http.cap"):
        src_pcap = os.path.join(pcap_dir, name)
        global_hdr, pkts = parse_pcap(src_pcap)

        # (a) each packet cut to every length 0..len
        for i, (ts, us, caplen, origlen, pkt) in enumerate(pkts):
            for l in range(len(pkt) + 1):
                mut_pkts = list(pkts)
                mut_pkts[i] = (ts, us, l, origlen, pkt[:l])
                out_path = os.path.join(tmp_dir, f"{name.split('.')[0]}_cut_{i}_{l}.pcap")
                write_pcap(out_path, global_hdr, mut_pkts)
                mutated_pcaps.append(out_path)

        # (b) 200 files with 1 to 8 bit flips, random.Random(12345)
        with open(src_pcap, "rb") as f:
            raw_pcap = f.read()
        rng = random.Random(12345)
        for k in range(200):
            num_flips = rng.randint(1, 8)
            mutated = bytearray(raw_pcap)
            for _ in range(num_flips):
                pos = rng.randint(24, len(mutated) - 1)
                bit = rng.randint(0, 7)
                mutated[pos] ^= (1 << bit)
            out_path = os.path.join(tmp_dir, f"{name.split('.')[0]}_flip_{k}.pcap")
            with open(out_path, "wb") as f_out:
                f_out.write(mutated)
            mutated_pcaps.append(out_path)

    versions = ["5", "9", "10"]
    tasks = [(pcap, ver, a_bin, b_bin) for pcap in mutated_pcaps for ver in versions]
    total_runs = len(tasks)

    print(f"Running fuzzing on {len(mutated_pcaps)} mutated pcap files ({total_runs} total runs)...")

    failures = 0
    with concurrent.futures.ProcessPoolExecutor() as executor:
        futures = [executor.submit(run_single_fuzz, task) for task in tasks]
        for future in concurrent.futures.as_completed(futures):
            pcap_path, version, failed, fail_reason, bin_b = future.result()
            if failed:
                failures += 1
                cmd_str = f"{bin_b} -d -r {pcap_path} -n 127.0.0.1:PORT -v {version}"
                print(f"FAIL: {cmd_str}: {fail_reason}")

    if failures == 0:
        print(f"FUZZ: PASS {total_runs} files")
        return 0
    else:
        print(f"FUZZ: FAIL {failures} of {total_runs}")
        return 1


if __name__ == "__main__":
    sys.exit(fuzz_main())
