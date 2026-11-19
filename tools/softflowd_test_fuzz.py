#!/usr/bin/env python3
"""
softflowd_test_fuzz.py -- garbage packet corpus: softflowd C (A) against Rust (B).

Mutated copies of a pcap are read with -r by both versions; the exported flow
records, the statistics on standard output and the exit status must agree, and B
must neither panic (exit status 101) nor die of a signal nor hang.

  tools/softflowd_test_suite.py fuzz [--a ./softflowd] [--b rust/target/release/rsoftflowd]
                                     [--pcap-dir pcaps] [--full] [--jobs N]
                                     [--keep-failing DIR] [--seed N]

Default (quick, under a minute on one CPU):
  - cut: the first packet of each IP protocol (TCP, UDP, ICMP; at most 3) of http.cap and
    v6-http.cap is cut to every length from 0 up to 130 octets (the other packets stay whole);
  - flips: 100 files for each pcap with 1 to 8 bit flips in the bytes of the packets;
  - each of these runs with `-v 5` and with `-6 -v 9`;
  - damaged: 30 files for each pcap with bit flips in the file header and in the
    record headers; only "B does not crash and has the exit status of A" is checked,
    because a damaged caplen makes C stop early and Rust flush, which is not a finding.

--full: every packet cut to every length, 200 flip files and 100 damaged files for each
pcap, and the NetFlow versions 5, 9 and 10, each with and without -6 (some minutes on one CPU).

The flips hit only the bytes of the packets in "flips": a flip in a record header or in
the file header changes what the file means and is tested in "damaged" instead.

Output: one line for each failing run with the command; the last line is
`FUZZ: PASS n files` or `FUZZ: FAIL k of n` (k files fail of n files).
"""

import argparse
import concurrent.futures
import os
import random
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
from typing import Callable, Iterator, List, Optional, Tuple

from softflowd_collector import datagrams_to_csv

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
RUN_TIMEOUT = 20
PCAP_HEADER_LEN = 24
RECORD_HEADER_LEN = 16

# (extra options, NetFlow version)
QUICK_OPTION_SETS = [([], "5"), (["-6"], "9")]
FULL_OPTION_SETS = [(extra, ver) for ver in ("5", "9", "10") for extra in ([], ["-6"])]
DAMAGED_OPTION_SETS = [(["-6"], "9")]


# --------------------------------------------------------------------------
# pcap files
# --------------------------------------------------------------------------

def read_pcap(path: str) -> Tuple[bytes, List[Tuple[bytes, bytes]]]:
    """Return the file header and the list of (record header, packet bytes)."""
    with open(path, "rb") as f:
        data = f.read()
    records = []
    off = PCAP_HEADER_LEN
    while off + RECORD_HEADER_LEN <= len(data):
        caplen = struct.unpack("<I", data[off + 8:off + 12])[0]
        records.append((data[off:off + RECORD_HEADER_LEN],
                        data[off + RECORD_HEADER_LEN:off + RECORD_HEADER_LEN + caplen]))
        off += RECORD_HEADER_LEN + caplen
    return data[:PCAP_HEADER_LEN], records


def build_pcap(header: bytes, records: List[Tuple[bytes, bytes]]) -> bytes:
    out = bytearray(header)
    for rec_header, packet in records:
        out += rec_header + packet
    return bytes(out)


def first_packet_of_each_protocol(records: List[Tuple[bytes, bytes]], limit: int) -> List[int]:
    """The index of the first packet of each IP protocol (an Ethernet frame is assumed).

    The first packets of a pcap are all of one flow, so cutting "the first 3 packets" would
    never reach the ICMP packets that come later.  Without a recognized packet the first
    `limit` packets are taken.
    """
    seen = {}
    for i, (_, packet) in enumerate(records):
        if len(packet) >= 24 and packet[12:14] == b"\x08\x00":
            seen.setdefault(packet[23], i)  # IPv4: the protocol field
        elif len(packet) >= 21 and packet[12:14] == b"\x86\xdd":
            seen.setdefault(packet[20], i)  # IPv6: the next header
    indexes = sorted(seen.values())[:limit]
    return indexes if indexes else list(range(min(limit, len(records))))


def with_cut_packet(header: bytes, records: List[Tuple[bytes, bytes]], index: int,
                    length: int) -> bytes:
    """The pcap with the packet `index` cut to `length` octets (caplen follows, origlen stays)."""
    rec_header, packet = records[index]
    cut = (rec_header[:8] + struct.pack("<I", length) + rec_header[12:], packet[:length])
    return build_pcap(header, records[:index] + [cut] + records[index + 1:])


def flip_bits_in_packets(header: bytes, records: List[Tuple[bytes, bytes]],
                         rng: random.Random) -> bytes:
    """1 to 8 bit flips, only in the bytes of the packets."""
    packets = [bytearray(p) for _, p in records]
    candidates = [i for i, p in enumerate(packets) if p]
    for _ in range(rng.randint(1, 8)):
        i = rng.choice(candidates)
        packets[i][rng.randrange(len(packets[i]))] ^= 1 << rng.randint(0, 7)
    return build_pcap(header, [(rh, bytes(p)) for (rh, _), p in zip(records, packets)])


def flip_bits_in_headers(raw: bytes, records: List[Tuple[bytes, bytes]],
                         rng: random.Random) -> bytes:
    """1 to 4 bit flips, only in the file header and in the record headers."""
    positions = list(range(PCAP_HEADER_LEN))
    off = PCAP_HEADER_LEN
    for _, packet in records:
        positions.extend(range(off, off + RECORD_HEADER_LEN))
        off += RECORD_HEADER_LEN + len(packet)
    damaged = bytearray(raw)
    for _ in range(rng.randint(1, 4)):
        damaged[rng.choice(positions)] ^= 1 << rng.randint(0, 7)
    return bytes(damaged)


def ensure_sample_pcap(pcap_dir: str, name: str) -> str:
    """pcaps/http.cap and pcaps/v6-http.cap; made with tools/gen_ci_smoke_pcap.py if missing."""
    path = os.path.join(pcap_dir, name)
    if not os.path.exists(path):
        os.makedirs(pcap_dir, exist_ok=True)
        cmd = [sys.executable, os.path.join(TOOLS_DIR, "gen_ci_smoke_pcap.py")]
        if name.startswith("v6"):
            cmd.append("-6")
        subprocess.run(cmd + ["-n", "20", path], check=True, stdout=subprocess.DEVNULL)
    return path


# --------------------------------------------------------------------------
# One run
# --------------------------------------------------------------------------

class Run:
    """The result of one program on one file."""

    def __init__(self, status: int, stdout: str, rows: List[str]) -> None:
        self.status = status
        self.stdout = stdout
        self.rows = rows


def run_program(binary: str, pcap_path: str, extra: List[str], version: str) -> Run:
    """Run `binary -r FILE` and collect the datagrams that it sent to a local socket.

    The program has exited when subprocess.run() returns, and a datagram that it sent
    to the loopback is in the receive buffer by then, so the buffer is read at once
    without waiting for a quiet period.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        try:
            res = subprocess.run(
                [binary, "-r", pcap_path, "-n", f"127.0.0.1:{port}", "-v", version] + extra,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=RUN_TIMEOUT)
            status, stdout = res.returncode, res.stdout.decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            status, stdout = -999, "TIMEOUT"
        sock.setblocking(False)
        datagrams = []
        while True:
            try:
                datagrams.append((sock.recv(65535), "127.0.0.1"))
            except BlockingIOError:
                break
    finally:
        sock.close()
    # The first two columns are the times; the multiset of the other columns is compared.
    csv = datagrams_to_csv(datagrams).splitlines()[1:]
    rows = sorted(",".join(r.split(",")[2:]) for r in csv if r.strip())
    return Run(status, stdout, rows)


def crashed(status: int) -> bool:
    """A panic (101), a signal (negative) or a timeout (-999)."""
    return status == 101 or status < 0


def check_packets(a: Run, b: Run) -> str:
    """Why B differs from A on a file whose headers are whole; "" if it does not."""
    if crashed(b.status):
        return f"B exited with status {b.status} (panic 101, signal or timeout)"
    if a.status != b.status:
        return f"exit status differs (A {a.status}, B {b.status})"
    if a.stdout.strip() != b.stdout.strip():
        return "statistics on standard output differ"
    if a.rows != b.rows:
        return f"exported flow records differ (A {len(a.rows)}, B {len(b.rows)})"
    return ""


def check_damaged(a: Run, b: Run) -> str:
    """A damaged file: B must not crash and must exit as A does; nothing else is compared."""
    if crashed(b.status):
        return f"B exited with status {b.status} (panic 101, signal or timeout)"
    if a.status != b.status:
        return f"exit status differs (A {a.status}, B {b.status})"
    return ""


# --------------------------------------------------------------------------
# The corpus
# --------------------------------------------------------------------------

class Case:
    """A mutated file: its name, its bytes, how it is checked and with which options."""

    def __init__(self, name: str, data: bytes, check: Callable[[Run, Run], str],
                 option_sets: List[Tuple[List[str], str]]) -> None:
        self.name = name
        self.data = data
        self.check = check
        self.option_sets = option_sets


def corpus(pcap_dir: str, full: bool, seed: int) -> Iterator[Case]:
    cut_packets = None if full else 3  # quick: the first packet of up to 3 IP protocols
    cut_max = None if full else 130
    n_flips = 200 if full else 100
    n_damaged = 100 if full else 30
    option_sets = FULL_OPTION_SETS if full else QUICK_OPTION_SETS
    for name in ("http.cap", "v6-http.cap"):
        path = ensure_sample_pcap(pcap_dir, name)
        stem = name.split(".")[0]
        header, records = read_pcap(path)
        with open(path, "rb") as f:
            raw = f.read()

        cut_indexes = (range(len(records)) if cut_packets is None
                       else first_packet_of_each_protocol(records, cut_packets))
        for i in cut_indexes:
            packet_len = len(records[i][1])
            top = packet_len if cut_max is None else min(packet_len, cut_max)
            for length in range(top + 1):
                yield Case(f"{stem}_cut_{i}_{length}", with_cut_packet(header, records, i, length),
                           check_packets, option_sets)

        rng = random.Random(seed)
        for k in range(n_flips):
            yield Case(f"{stem}_flip_{k}", flip_bits_in_packets(header, records, rng),
                       check_packets, option_sets)

        rng = random.Random(seed + 1)
        for k in range(n_damaged):
            yield Case(f"{stem}_damaged_{k}", flip_bits_in_headers(raw, records, rng),
                       check_damaged, DAMAGED_OPTION_SETS)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def run_case(case: Case, tmp_dir: str, a_bin: str, b_bin: str, b_name: str,
             keep_dir: Optional[str]) -> List[str]:
    """Run one case with each option set; return the failure lines (none if it passes)."""
    path = os.path.join(tmp_dir, f"{case.name}.pcap")
    with open(path, "wb") as f:
        f.write(case.data)
    failures = []
    for extra, version in case.option_sets:
        a = run_program(a_bin, path, extra, version)
        b = run_program(b_bin, path, extra, version)
        why = case.check(a, b)
        if why:
            shown = path
            if keep_dir:
                shown = os.path.join(keep_dir, f"{case.name}.pcap")
                shutil.copy(path, shown)
            options = " ".join(extra + ["-v", version])
            failures.append(f"FAIL: {b_name} -r {shown} -n 127.0.0.1:PORT {options}: {why}")
    os.remove(path)
    return failures


def fuzz_main() -> int:
    ap = argparse.ArgumentParser(description="softflowd fuzz test (garbage packet corpus)")
    ap.add_argument("--a", default="./softflowd", help="C softflowd (default: ./softflowd)")
    ap.add_argument("--b", default="rust/target/release/rsoftflowd", help="Rust softflowd")
    ap.add_argument("--pcap-dir", default="pcaps", help="directory of http.cap and v6-http.cap")
    ap.add_argument("--full", action="store_true", help="the whole corpus (some minutes on one CPU)")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 1, help="parallel runs")
    ap.add_argument("--seed", type=int, default=12345, help="seed of the random flips")
    ap.add_argument("--keep-failing", metavar="DIR", help="copy the failing pcaps to DIR")
    args = ap.parse_args()

    a_bin, b_bin = os.path.abspath(args.a), os.path.abspath(args.b)
    pcap_dir = os.path.abspath(args.pcap_dir)
    keep_dir = os.path.abspath(args.keep_failing) if args.keep_failing else None
    if keep_dir:
        os.makedirs(keep_dir, exist_ok=True)

    cases = list(corpus(pcap_dir, args.full, args.seed))
    mode = "full" if args.full else "quick"
    print(f"Fuzzing ({mode}): {len(cases)} mutated pcap files ...", flush=True)

    failing_files = 0
    lock = threading.Lock()
    # The temporary files are removed when the block ends, also after an error.
    with tempfile.TemporaryDirectory(prefix="softflowd_fuzz_") as tmp_dir:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
            futures = [pool.submit(run_case, case, tmp_dir, a_bin, b_bin, args.b, keep_dir)
                       for case in cases]
            for future in concurrent.futures.as_completed(futures):
                failed = future.result()
                if failed:
                    with lock:
                        failing_files += 1
                        for line in failed:
                            print(line, flush=True)

    if failing_files:
        print(f"FUZZ: FAIL {failing_files} of {len(cases)}")
        return 1
    print(f"FUZZ: PASS {len(cases)} files")
    return 0


if __name__ == "__main__":
    sys.exit(fuzz_main())
