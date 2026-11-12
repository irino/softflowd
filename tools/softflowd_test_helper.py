"""
Shared helpers of the softflowd test scripts: build and measurement helpers (also used by
the bench), the settings of the compat suite that compat_main() sets, and the sample pcaps.
"""

import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import urllib.request
from typing import List, Optional, Sequence, Tuple


# Project root directory (this script lives in tools/)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ==========================================================================
# Build and measurement helpers
# ==========================================================================

def _red(text: str) -> str:
    return f"\033[91m{text}\033[0m" if sys.stderr.isatty() else text


def run_command(cmd: List[str], cwd: Optional[str] = None,
                env: Optional[dict] = None) -> subprocess.CompletedProcess:
    """Run a command, capturing output; print it if the command fails."""
    res = subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        print(_red(f"Command failed: {' '.join(cmd)} (cwd={cwd})"),
              file=sys.stderr)
        if res.stdout:
            print(f"Stdout:\n{res.stdout}", file=sys.stderr)
        if res.stderr:
            print(f"Stderr:\n{res.stderr}", file=sys.stderr)
    return res


def build_c(src_dir: str, configure_args: Sequence[str] = (),
            jobs: Optional[int] = None, autoreconf: bool = True,
            autoreconf_force: bool = False) -> bool:
    """Configure and build the C sources in src_dir (in place).

    Runs [autoreconf], ./configure ARGS, make clean and make.  jobs=None
    runs an unlimited `make -j`.  Returns True on success.  The built
    softflowd and softflowctl are left in src_dir; use copy_binaries().
    """
    if autoreconf:
        run_command(["autoreconf", "-fi" if autoreconf_force else "-i"],
                    cwd=src_dir)
    run_command(["./configure", *configure_args], cwd=src_dir)
    run_command(["make", "clean"], cwd=src_dir)
    make = ["make", "-j" if jobs is None else f"-j{jobs}"]
    return run_command(make, cwd=src_dir).returncode == 0


def copy_binaries(src_dir: str, daemon_dest: str,
                  ctl_dest: Optional[str] = None) -> None:
    """Copy the built softflowd (and optionally softflowctl) out of src_dir."""
    shutil.copy2(os.path.join(src_dir, "softflowd"), daemon_dest)
    if ctl_dest is not None:
        shutil.copy2(os.path.join(src_dir, "softflowctl"), ctl_dest)


EXPORTER_SRC = re.compile(r"(export|export_common|ipfix|netflow[0-9]+|psamp)\.c:")


def warm_page_cache(path: str) -> None:
    """Read a file once so that timed runs do not pay for cold disk reads."""
    with open(path, "rb") as f:
        while f.read(1 << 20):
            pass


def perf_stat(cmd: Sequence[str], log_path: str, title: str = "") -> None:
    """Append `perf stat` (5 runs) of cmd to log_path."""
    with open(log_path, "a") as perf_log:
        if title:
            perf_log.write(f"== {title} ==\n")
            perf_log.flush()
        subprocess.run(["perf", "stat", "-r", "5", "-e",
                        "instructions,branches,branch-misses,cycles", *cmd],
                       stdout=subprocess.DEVNULL, stderr=perf_log)


def callgrind_profile(cmd: Sequence[str], cg_dir: str, tag: str,
                      topn: int) -> Optional[Tuple[int, int, List[str]]]:
    """Profile cmd with callgrind; files are written to cg_dir as tag.*.

    Returns (total Ir, self Ir in the exporter sources export*.c / ipfix.c /
    netflow*.c / psamp.c, the first topn lines of the profile) or None if callgrind
    produced no output.
    """
    out = os.path.join(cg_dir, tag + ".out")
    txt = os.path.join(cg_dir, tag + ".txt")
    with open(os.path.join(cg_dir, tag + ".log"), "w") as lg:
        subprocess.run(["valgrind", "--tool=callgrind",
                        f"--callgrind-out-file={out}", *cmd],
                       stdout=subprocess.DEVNULL, stderr=lg)
    if not os.path.exists(out) or os.path.getsize(out) == 0:
        return None
    with open(txt, "w") as t:
        subprocess.run(["callgrind_annotate", "--auto=no", "--threshold=100",
                        out], stdout=t, stderr=subprocess.DEVNULL)
    total = 0
    with open(out) as f:
        for line in f:
            if line.startswith("totals:"):
                total = int(line.split()[1])
                break
    # Self Ir per "file:function" line: "1,234 (12.3%)  path/file.c:func".
    exporter_ir = 0
    top: List[str] = []
    in_table = False
    with open(txt) as f:
        for line in f:
            if "file:function" in line:
                in_table = True
                continue
            if in_table and "%)" in line:
                if len(top) < topn:
                    top.append(line.rstrip("\n"))
                if EXPORTER_SRC.search(line):
                    exporter_ir += int(line.split()[0].replace(",", ""))
    return total, exporter_ir, top


def parse_gauge(stderr_text: str
                ) -> Optional[Tuple[int, Optional[int], Optional[int]]]:
    """Parse the "cpu clocks" lines softflowd prints on exit with -g.

    Returns (total_clocks, export_clocks, export_calls).  export_clocks and
    export_calls are None if the daemon predates the export-clock counter or
    ran with threaded export (-M), which reports "n/a".  Returns None if there
    is no "cpu clocks" line at all (the daemon does not support -g).
    """
    total = export = calls = None
    for line in stderr_text.splitlines():
        m = re.search(r"cpu clocks:\s*(\d+)", line)
        if m:
            total = int(m.group(1))
        m = re.search(r"cpu clocks \(export\):\s*(\d+)\s*\((\d+) calls\)", line)
        if m:
            export, calls = int(m.group(1)), int(m.group(2))
    if total is None:
        return None
    return total, export, calls


# ==========================================================================
# compat: backward compatibility suite
# ==========================================================================

# Global test work directory for artifacts; created by compat_main().
SUITE_TMP_DIR = ""

# Flow collector backend ("nfdump" or "python"); resolved in main().
COLLECTOR_BACKEND = "nfdump"

# Optional directory holding http.cap / v6-http.cap (set by --pcap-dir).
PCAP_DIR: Optional[str] = None

# Pcap files given on the command line; compared in addition to the samples.
COMPAT_PCAPS: List[str] = []

# Persistent cache for the stable binaries and the sample pcaps (set by
# --cache-dir; None disables it).  It lives outside SUITE_TMP_DIR, which is
# removed at exit.
CACHE_DIR: Optional[str] = None
REBUILD_STABLE = False
REBUILD_DEV = False
REFRESH_PCAP = False

# Magic numbers of libpcap (both byte orders, micro/nanosecond) and pcapng.
PCAP_MAGICS = (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",
               b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1",
               b"\x0a\x0d\x0d\x0a")

# Sample PCAP URLs for testing
HTTP_PCAP_URL = "https://wiki.wireshark.org/uploads/27707187aeb30df68e70c8fb9d614981/http.cap"
V6_HTTP_PCAP_URL = "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/v6-http.cap"

# nfdump `-o csv` appends collector-side metadata columns to NetFlow v9/IPFIX
# output describing when/where nfcapd received the record (see nfdump(1),
# OUTPUT FORMAT: %ra, %eng, %exid, %tr) -- not anything the exporter under
# test produced. Because this suite always runs the captures of A and B
# as two separate, sequential nfcapd sessions, these columns legitimately
# differ between runs even when the exported flow data is byte-identical.
# Masked out by default; see --include-collector-metadata.
COLLECTOR_METADATA_COLUMNS = {"ra", "eng", "exid", "tr"}

# Protocol numbers softflowd's C stable reference (<= 1.1.1) can misreport for
# ICMPv6 due to a pointer-arithmetic bug in ipv6_to_flowrec() (fixed upstream
# in commit 262225e): affected rows show protocol 0 instead of 58, with a
# correspondingly wrong ICMP type/code overlaid in nfdump's 'dp' column.
# ICMPv4 ("1" / "ICMP") is deliberately not listed: the bug is IPv6-specific,
# so ICMPv4 rows are compared like any other row.
# nfdump 1.7.3 prints the protocol of an ICMPv6 row by name ("ICMP6") and only
# protocol 0 as a number; other builds print numbers.  The values are compared
# upper-cased, so both spellings are listed.
ICMP_RECLASSIFICATION_PROTOCOLS = {"0", "58", "ICMP6"}

# Known aliases nfdump's `-o csv` uses for the protocol / destination-port
# columns across versions and builds (e.g. terse 'pr'/'dp' vs the more
# descriptive 'proto'/'dstPort' seen on some builds). Compared case-
# insensitively. The header row itself is located purely positionally (see
# normalize_nfdump_csv) since no single name is safe to assume there either;
# these sets are only consulted to find the two specific columns the ICMP
# tolerance needs, once the header row is already known. If a build uses
# names outside both sets, the ICMP tolerance simply does not activate for
# that capture (see the [WARN] it prints) rather than guessing.
PROTOCOL_COLUMN_NAMES = {"pr", "proto", "protocol"}
DST_PORT_COLUMN_NAMES = {"dp", "dstport", "destport", "destinationport"}


def print_green(text: str) -> None:
    print(f"\033[92m{text}\033[0m")


def print_red(text: str) -> None:
    print(f"\033[91m{text}\033[0m")


def print_yellow(text: str) -> None:
    print(f"\033[93m{text}\033[0m")


def print_cyan(text: str) -> None:
    print(f"\033[96m{text}\033[0m")


def check_required_tool(cmd: str, apt_pkg: str, url: str) -> str:
    """Ensure required system tool exists or report installation instructions."""
    path = shutil.which(cmd)
    if path:
        return path
    print_red(f"Error: Required tool '{cmd}' was not found in PATH.")
    print("Please install it:")
    print(f"  Ubuntu/Debian: sudo apt update && sudo apt install -y {apt_pkg}")
    print(f"  Source: {url}")
    sys.exit(1)


def default_cache_dir() -> str:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "softflowd-test")


def is_pcap_file(path: str) -> bool:
    """True if path is non-empty and starts with a pcap or pcapng magic number."""
    try:
        with open(path, "rb") as f:
            return f.read(4) in PCAP_MAGICS
    except OSError:
        return False


def ensure_sample_pcap(name: str, url: str) -> str:
    """Return the sample PCAP: --pcap-dir, then the cache, otherwise download it."""
    if PCAP_DIR is not None:
        local = os.path.join(PCAP_DIR, name)
        if os.path.exists(local):
            return local
    pcap_dir = os.path.join(CACHE_DIR, "pcap") if CACHE_DIR else SUITE_TMP_DIR
    path = os.path.join(pcap_dir, name)
    if os.path.exists(path) and not (REFRESH_PCAP and CACHE_DIR):
        if is_pcap_file(path):
            return path
        print_yellow(f"Cached sample PCAP {path} is not a pcap file; downloading it again")
    print(f"Downloading test sample PCAP: {name} ...")
    # Download to a temporary name so an interrupted or failed download never
    # leaves a broken file behind.
    part = f"{path}.part.{os.getpid()}"
    try:
        os.makedirs(pcap_dir, exist_ok=True)
        urllib.request.urlretrieve(url, part)
        if not is_pcap_file(part):
            raise ValueError("the downloaded file is not a pcap file")
        os.replace(part, path)
    except Exception as e:
        if os.path.exists(part):
            os.remove(part)
        print_red(f"Failed to download PCAP file ({name}): {e}")
        sys.exit(1)
    return path


def parity_loopback_pcap(header: bytes) -> bytes:
    """Conversations in which both ends have the same address (IPv4 and IPv6, as on a loopback interface): UDP
    that starts from the higher or the lower port, TCP, ICMP, the same port at both ends, and, for the
    comparison, two addresses that differ. RFC 5103: the packets of both directions are one Biflow."""
    def eth(v6: bool) -> bytes:
        return bytes([2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2]) + (b"\x86\xdd" if v6 else b"\x08\x00")

    def frame(v6: bool, src: str, dst: str, proto: int, payload: bytes) -> bytes:
        if v6:
            return eth(True) + struct.pack(">IHBB16s16s", 0x60000000, len(payload), proto, 64,
                                           socket.inet_pton(socket.AF_INET6, src),
                                           socket.inet_pton(socket.AF_INET6, dst)) + payload
        return eth(False) + struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                                        socket.inet_aton(src), socket.inet_aton(dst)) + payload

    def udp(sport: int, dport: int, size: int = 20) -> bytes:
        return struct.pack(">HHHH", sport, dport, 8 + size, 0) + b"x" * size

    def tcp(sport: int, dport: int, flags: int) -> bytes:
        return struct.pack(">HHIIBBHHH", sport, dport, 1, 1, 0x50, flags, 8192, 0, 0)

    def icmp(kind: int) -> bytes:
        return struct.pack(">BBHHH", kind, 0, 0, 1, 1) + b"y" * 8

    frames = []
    for v6, same, other in ((False, "127.0.0.1", "127.0.0.2"), (True, "::1", "::2")):
        def add(proto: int, payload: bytes, src: str = same, dst: str = same) -> None:
            frames.append(frame(v6, src, dst, proto, payload))
        for high, low in ((40000, 53), (53, 40000)):    # the first packet is from the higher or the lower port
            add(17, udp(high, low))
            add(17, udp(low, high))
            add(17, udp(high, low))
            add(17, udp(low, high, 5))
        add(6, tcp(50000, 80, 0x02))
        add(6, tcp(80, 50000, 0x12))
        add(6, tcp(50000, 80, 0x10))
        add(6, tcp(81, 50001, 0x02))
        add(6, tcp(50001, 81, 0x12))
        add(6, tcp(81, 50001, 0x10))
        add(6, tcp(7000, 7000, 0x02))                   # the same port at both ends
        add(6, tcp(7000, 7000, 0x10))
        add(58 if v6 else 1, icmp(128 if v6 else 8))
        add(58 if v6 else 1, icmp(129 if v6 else 0))
        add(17, udp(40001, 53), other, same)            # two addresses
        add(17, udp(53, 40001), same, other)
    out = bytearray(header)
    for n, f in enumerate(frames):
        out += struct.pack("<IIII", 1000000 + n // 10, (n % 10) * 1000 + 10, len(f), len(f)) + f
    return bytes(out)


def parity_can_capture_lo() -> bool:
    """A live capture needs a privilege (root or CAP_NET_RAW) and a loopback device."""
    if os.geteuid() != 0 or not os.path.exists("/sys/class/net/lo"):
        return False
    return True
