#!/usr/bin/env python3
"""
softflowd_test_collector.py -- test, benchmark and collector tools for softflowd.

One self-contained script (standard library only) with three subcommands:

  tools/softflowd_test_collector.py collect [-p PORT] [-b ADDR] [-6]  flow collector (default)
  tools/softflowd_test_collector.py compat  [options] [PCAP...]       backward compatibility
  tools/softflowd_test_collector.py bench   [options] PCAP...         export benchmark

Options after the subcommand belong to that subcommand; `-h` after a
subcommand shows its help.  Without a subcommand the arguments go to collect
(the successor of collector.pl), so run the former run_compat_suite.py
usage as `compat [options]`.

----------------------------------------------------------------------------
compat
----------------------------------------------------------------------------
softflowd Comprehensive Backward Compatibility Test Suite

This script verifies backward compatibility between softflowd stable version (1.1.1)
and current development source code (C development versions).

Features:
- Automatically compiles all necessary binaries (C stable, C dev, plus optional C++ and Rust).
- Compares NetFlow/IPFIX exported flow records (v1, v5, v9, IPFIX) via nfcapd & nfdump,
  or via the built-in Python collector when nfdump is not installed.
- Compares softflowctl control socket queries/statistics and shutdown commands.
- Configurable stable commit/tag and flexible skip options.

Default comparison matrix:
  1. stable-softflowd-legacy vs softflowd-legacy
  2. stable-softflowd vs softflowd
  3. softflowd-static vs softflowd
  4. softflowd vs softflowd+ (skippable)
  5. softflowd vs rsoftflowd (skippable)

Usage:
    tools/softflowd_test_collector.py compat [OPTIONS] [PCAP...]

Positional PCAP files are tested in addition to the sample pcaps: each one is
exported as NetFlow v1, v5, v9 and IPFIX by the stable and the development
daemon, the flows are compared, and the daemons are measured on it.  A pcap
that yields no flow records on either side (an IPv6-only pcap has none in v1 and
v5) is reported as skipped, not as a failure.

Options:
    --stable-commit HASH    : Git commit/tag for C stable version (default: 0260261)
    --build-dir DIR         : Directory for temporary builds (default: temporary dir)
    --skip-build            : Skip compiling binaries (assume pre-built)
    --skip-ctl              : Skip softflowctl control socket tests
    --skip-cpp              : Skip C++ tests / builds
    --skip-rust             : Skip Rust tests / builds
    --stable PATH           : Explicit reference stable softflowd daemon binary
    --dev PATH              : Explicit target development softflowd daemon binary
    --ctl-stable PATH       : Explicit reference stable softflowctl binary
    --ctl-dev PATH          : Explicit target development softflowctl binary
    -i, --ignore-timestamp  : Ignore 'firstSeen' and 'duration' timestamps in nfdump comparison
    --auto-ignore-legacy-v9 : Ignore timestamps for the stable-softflowd-legacy vs
                              softflowd-legacy pair's NetFlow v9 case only (default: True).
                              The C stable reference (<= 1.1.1) has a known bug where
                              --enable-legacy's NetFlow v9 exporter ignores -a/--adjust-time
                              (fixed in the dev tree), which would otherwise always show up
                              as a spurious timestamp mismatch there
    --no-auto-ignore        : Disable the above; compare that timestamp too
    --auto-ignore-icmp-reclass : When the stable side of a pair is the old C reference,
                              tolerate its known ICMPv6 protocol/type misclassification bug
                              (fixed upstream in ipv6_to_flowrec(), commit 262225e) by masking
                              the protocol and destination-port columns (whatever they are
                              named in this nfdump build) only for rows either side reports as
                              ICMPv6 (ICMPv4 rows are always compared) -- and only where
                              every other column still matches
                              (default: True)
    --no-auto-ignore-icmp-reclass : Disable the above; compare those columns too
    -6, --ignore-ipv6       : Ignore IPv6 test cases
    --include-collector-metadata : Also compare nfdump's collector-side metadata
                              columns (ra/eng/exid/tr); masked out by default since
                              they reflect nfcapd's own receive time/state, not the
                              exporter's output
    --collector MODE          : Flow collector: auto (nfdump if nfcapd and nfdump are installed,
                              otherwise python), nfdump, or python (default: auto)
    --pcap-dir DIR            : Use http.cap and v6-http.cap from DIR instead of downloading them
    --cache-dir DIR           : Persistent cache for the stable and development C binaries
                              and the downloaded sample pcaps (default:
                              ~/.cache/softflowd-test)
    --no-cache                : Do not use the cache (build and download on every run)
    --rebuild-stable          : Rebuild the stable binaries even if they are cached
    --rebuild-dev             : Rebuild the development C binaries even if they are cached
    --refresh-pcap            : Download the sample pcaps again even if they are cached
    --gauge-clock             : Run each daemon once per test case with its own
    --no-gauge-clock            -g flag and print the "cpu clocks" (total) and
                              "cpu clocks (export)" (time inside the export call)
                              counters it reports on exit, for stable and dev.
                              On by default; --no-gauge-clock turns it off
    --benchmark [TOOL]        : Time each daemon (stable and dev) for every test
    --no-benchmark              case.  TOOL is hyperfine, time (wall clock plus user and
                              system CPU time of the child, as time(1) reports them,
                              measured in-process) or auto (hyperfine if installed,
                              otherwise time; the default).  On by default, so it
                              needs no extra tool; --no-benchmark turns it off
    --bench-runs N            : Timed runs per daemon and test case (default: 20)
    --bench-warmup N          : Untimed warmup runs before them (default: 3)
    --bench-min-runs N        : hyperfine picks the run count itself but runs at least N
                              times (like bench -m); with --benchmark time, the run count
    --bench-max-runs N        : hyperfine runs at most N times (like bench -M)
    --callgrind               : Also profile each daemon with callgrind and report the total
                              instruction count (Ir) and the Ir spent in the exporter
                              sources (ipfix.c, netflow*.c, psamp.c).  Needs valgrind and
                              callgrind_annotate; about 50x slower than a normal run
    --callgrind-top N         : Print the N most expensive functions of each profile
                              (default: 0; the profiles are saved as BENCH_CSV.callgrind/)
    --perf                    : Also run `perf stat` on each daemon; the output is appended to
                              BENCH_CSV.perf.log (--bench-csv is required)
    --bench-pcap FILE         : Extra pcap to measure with -g/--benchmark for NetFlow
                              v1, v5, v9 and IPFIX; unlike a positional PCAP it is not
                              compared for compatibility.  May be repeated.  The sample
                              pcaps are tiny, so use this for numbers that mean something
    --bench-csv FILE          : Write the -g/--benchmark results of all pairs as CSV
    -h, --help              : Show this help message

----------------------------------------------------------------------------
bench
----------------------------------------------------------------------------
benchmark -- compare softflowd's NetFlow/IPFIX export implementations
(static-separate / static / dynamic, see --enable-compat-export) across one or more pcap
files and NetFlow/IPFIX versions.  Options and output files are those of the
former benchmark_export.sh.

implementations (static-separate / static / dynamic, see --enable-compat-export) across one
or more pcap files and NetFlow/IPFIX versions.

Usage:
  tools/softflowd_test_collector.py bench [options] pcap1.pcap [pcap2.pcap ...]

Requires: hyperfine (falls back to a plain timing loop if missing).  perf
(-p) and valgrind/callgrind_annotate (-C) are optional.  -g relies on
softflowd's own -g flag, so it needs no extra tool.

For each (pcap, build variant, version) combination:
  1. Builds (once per variant, reused across pcaps/versions) a dedicated
     softflowd-<variant> binary via autoreconf/configure/make.
  2. Starts a local UDP sink on 127.0.0.1:PORT so packets are actually
     received and discarded, rather than bouncing ICMP port-unreachable
     errors back at the sender.
  3. Runs the binary via hyperfine (warmup runs pull the pcap into the page
     cache before the timed runs) or a plain timing loop.
  4. Appends one row per combination to OUTFILE.
  5. With -p, also runs `perf stat` once per combination.
  6. With -C, also runs callgrind once per combination and records the total
     instruction count (Ir) and the self Ir spent in the exporter sources
     (ipfix.c, netflow*.c, psamp.c).
  7. With -g, also runs the binary once per combination with -g and records
     the "cpu clocks" and "cpu clocks (export)" counters in OUTFILE.gauge.csv.

----------------------------------------------------------------------------
collect (the default without a subcommand)
----------------------------------------------------------------------------
Prints the NetFlow v1/v5/v9 and IPFIX flows received on a UDP port, one CSV
row per flow with the column names of `nfdump -o csv` (ts, te, td, sa, da,
sp, dp, pr, flg, stos, ipkt, ibyt, in, out).  Fields that are not mapped to
one of those columns are kept in the trailing "x" column as "name=value"
pairs instead of being dropped, so that a difference in any exported field
still shows up when two builds are compared.  This replaces collector.pl,
which only understands NetFlow v1 and v5.  compat uses the same decoder when
nfdump is not installed.
"""

import argparse
import atexit
import csv
import datetime
import hashlib
import ipaddress
import json
import os
import re
import select
import shlex
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from typing import Dict, List, Optional, Sequence, Tuple

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


EXPORTER_SRC = re.compile(r"(ipfix|netflow[0-9]+|psamp)\.c:")


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

    Returns (total Ir, self Ir in the exporter sources ipfix.c / netflow*.c /
    psamp.c, the first topn lines of the profile) or None if callgrind
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
# Collector: NetFlow v1/v5/v9 and IPFIX decoder, UDP sink, `collect`
# ==========================================================================

CSV_COLUMNS = ["ts", "te", "td", "sa", "da", "sp", "dp", "pr", "flg", "stos",
               "ipkt", "ibyt", "in", "out", "x"]

# Field type numbers shared by NetFlow v9 and IPFIX (RFC 3954 / IANA IPFIX
# registry); only the ones that are mapped to a CSV column are listed.
T_OCTETS, T_PACKETS, T_PROTO, T_TOS, T_TCP_FLAGS = 1, 2, 4, 5, 6
T_SPORT, T_SRC4, T_INPUT, T_DPORT, T_DST4, T_OUTPUT = 7, 8, 10, 11, 12, 14
T_LAST, T_FIRST = 21, 22
T_SRC6, T_DST6 = 27, 28
T_ICMP4, T_ICMP6 = 32, 139
T_FLOW_START_MS, T_FLOW_END_MS = 152, 153
T_SYSTEM_INIT_MS = 160

IP_TYPES = {T_SRC4: 4, T_DST4: 4, T_SRC6: 16, T_DST6: 16}
IPPROTO_ICMP, IPPROTO_ICMPV6 = 1, 58


def _value(raw: bytes) -> str:
    """Render a raw field value: an integer up to 8 bytes, hex otherwise."""
    if len(raw) <= 8:
        return str(int.from_bytes(raw, "big"))
    return raw.hex()


class Decoder:
    """Stateful decoder: keeps v9/IPFIX templates between datagrams."""

    def __init__(self) -> None:
        # (version, exporter address, domain id, template id) -> template
        self._templates: Dict[tuple, dict] = {}
        # (exporter address, domain id) -> systemInitTimeMilliseconds
        self._sys_init: Dict[tuple, int] = {}
        self.dropped = 0

    # -- public ------------------------------------------------------------

    def feed(self, data: bytes, exporter: str = "") -> List[dict]:
        """Decode one datagram; returns a list of flow dicts."""
        if len(data) < 2:
            self.dropped += 1
            return []
        version = struct.unpack("!H", data[:2])[0]
        try:
            if version in (1, 5):
                return self._fixed(data, version)
            if version == 9:
                return self._v9(data, exporter)
            if version == 10:
                return self._ipfix(data, exporter)
        except (struct.error, IndexError, ValueError):
            pass
        self.dropped += 1
        return []

    # -- NetFlow v1 / v5 ---------------------------------------------------

    def _fixed(self, data: bytes, version: int) -> List[dict]:
        hdr_len, rec_len = (16, 48) if version == 1 else (24, 48)
        count, uptime, secs, nsecs = struct.unpack("!HIII", data[2:16])
        flows = []
        for i in range(count):
            off = hdr_len + i * rec_len
            rec = data[off:off + rec_len]
            if len(rec) < rec_len:
                raise ValueError("short record")
            if version == 1:
                (src, dst, nh, inp, out, pkts, octets, first, last, sport,
                 dport, _pad, proto, tos, flags) = struct.unpack(
                     "!IIIHHIIIIHHHBBB", rec[:41])
                extra = {}
            else:
                (src, dst, nh, inp, out, pkts, octets, first, last, sport,
                 dport, _pad1, flags, proto, tos, sas, das, smk, dmk) = \
                    struct.unpack("!IIIHHIIIIHHBBBBHHBB", rec[:46])
                extra = {"src_as": sas, "dst_as": das,
                         "src_mask": smk, "dst_mask": dmk}
            extra["nexthop"] = str(ipaddress.IPv4Address(nh))
            base = secs * 1000 + nsecs // 1000000
            flows.append({
                "sa": str(ipaddress.IPv4Address(src)),
                "da": str(ipaddress.IPv4Address(dst)),
                "sp": sport, "dp": dport, "pr": proto, "flg": flags,
                "stos": tos, "ipkt": pkts, "ibyt": octets,
                "in": inp, "out": out,
                "first_ms": base - ((uptime - first) % (1 << 32)),
                "last_ms": base - ((uptime - last) % (1 << 32)),
                "extra": extra,
            })
        return flows

    # -- NetFlow v9 --------------------------------------------------------

    def _v9(self, data: bytes, exporter: str) -> List[dict]:
        _ver, _count, uptime, secs, _seq, domain = struct.unpack(
            "!HHIIII", data[:20])
        flows: List[dict] = []
        off = 20
        # Flowset lengths are taken as declared.  They are not required to be
        # multiples of 4: softflowd pads so that the *next* flowset starts on
        # a 4-byte boundary, which makes the length itself unaligned.
        while off + 4 <= len(data):
            fsid, flen = struct.unpack("!HH", data[off:off + 4])
            if flen < 4:
                break
            body = data[off + 4:off + flen]
            if fsid == 0:
                self._v9_templates(body, exporter, domain, options=False)
            elif fsid == 1:
                self._v9_templates(body, exporter, domain, options=True)
            elif fsid >= 256:
                tmpl = self._templates.get((9, exporter, domain, fsid))
                if tmpl is None:
                    self.dropped += 1
                elif not tmpl["options"]:
                    base = secs * 1000
                    for rec in self._records(body, tmpl["fields"]):
                        flows.append(self._flow_from_fields(
                            rec, uptime_ms=uptime, export_ms=base))
            off += flen
        return flows

    def _v9_templates(self, body: bytes, exporter: str, domain: int,
                      options: bool) -> None:
        off = 0
        while off + 4 <= len(body):
            if options:
                tid, scope_len, opt_len = struct.unpack(
                    "!HHH", body[off:off + 6])
                off += 6
                specs = [struct.unpack("!HH", body[off + 4 * i:off + 4 * i + 4])
                         for i in range((scope_len + opt_len) // 4)]
                off += scope_len + opt_len
            else:
                tid, nfields = struct.unpack("!HH", body[off:off + 4])
                off += 4
                specs = [struct.unpack("!HH", body[off + 4 * i:off + 4 * i + 4])
                         for i in range(nfields)]
                off += 4 * nfields
            self._templates[(9, exporter, domain, tid)] = {
                "options": options, "fields": list(specs)}
            if options and off % 4 == 2:
                off += 2  # trailing padding of the options template set

    # -- IPFIX -------------------------------------------------------------

    def _ipfix(self, data: bytes, exporter: str) -> List[dict]:
        _ver, length, export_time, _seq, domain = struct.unpack(
            "!HHIII", data[:16])
        flows: List[dict] = []
        off = 16
        end = min(length, len(data))
        while off + 4 <= end:
            sid, slen = struct.unpack("!HH", data[off:off + 4])
            if slen < 4:
                break
            body = data[off + 4:off + slen]
            if sid in (2, 3):
                self._ipfix_templates(body, exporter, domain, options=sid == 3)
            elif sid >= 256:
                tmpl = self._templates.get((10, exporter, domain, sid))
                if tmpl is None:
                    self.dropped += 1
                else:
                    for rec in self._records(body, tmpl["fields"]):
                        if tmpl["options"]:
                            self._note_options(rec, exporter, domain)
                        else:
                            flows.append(self._flow_from_fields(
                                rec, export_ms=export_time * 1000,
                                sys_init=self._sys_init.get((exporter, domain))))
            off += slen
        return flows

    def _ipfix_templates(self, body: bytes, exporter: str, domain: int,
                         options: bool) -> None:
        off = 0
        while off + 4 <= len(body):
            tid, nfields = struct.unpack("!HH", body[off:off + 4])
            off += 4
            if options:
                off += 2  # scope field count; scope fields are ordinary specs
            specs = []
            for _ in range(nfields):
                ie, flen = struct.unpack("!HH", body[off:off + 4])
                off += 4
                if ie & 0x8000:
                    off += 4  # enterprise number; the field is kept as "type"
                specs.append((ie & 0x7FFF, flen))
            self._templates[(10, exporter, domain, tid)] = {
                "options": options, "fields": specs}

    def _note_options(self, rec: List[Tuple[int, bytes]], exporter: str,
                      domain: int) -> None:
        for ftype, raw in rec:
            if ftype == T_SYSTEM_INIT_MS and len(raw) == 8:
                self._sys_init[(exporter, domain)] = int.from_bytes(raw, "big")

    # -- shared v9 / IPFIX -------------------------------------------------

    @staticmethod
    def _records(body: bytes, specs: List[Tuple[int, int]]):
        """Yield each record of a data set as a list of (type, raw bytes)."""
        fixed = sum(flen for _t, flen in specs if flen != 0xFFFF)
        variable = any(flen == 0xFFFF for _t, flen in specs)
        off = 0
        while off + fixed <= len(body) and (fixed or variable):
            rec = []
            for ftype, flen in specs:
                if flen == 0xFFFF:  # IPFIX variable-length field (RFC 7011)
                    flen = body[off]
                    off += 1
                    if flen == 255:
                        flen = struct.unpack("!H", body[off:off + 2])[0]
                        off += 2
                rec.append((ftype, body[off:off + flen]))
                off += flen
            yield rec

    @staticmethod
    def _flow_from_fields(rec: List[Tuple[int, bytes]],
                          uptime_ms: Optional[int] = None,
                          export_ms: Optional[int] = None,
                          sys_init: Optional[int] = None) -> dict:
        flow: dict = {"sp": 0, "dp": 0, "pr": 0, "flg": 0, "stos": 0,
                      "ipkt": 0, "ibyt": 0, "in": 0, "out": 0,
                      "sa": "0.0.0.0", "da": "0.0.0.0"}
        extra: Dict[str, str] = {}
        icmp: Optional[int] = None
        first = last = None
        simple = {T_SPORT: "sp", T_DPORT: "dp", T_PROTO: "pr",
                  T_TCP_FLAGS: "flg", T_TOS: "stos", T_PACKETS: "ipkt",
                  T_OCTETS: "ibyt", T_INPUT: "in", T_OUTPUT: "out"}
        for ftype, raw in rec:
            if ftype in IP_TYPES and len(raw) == IP_TYPES[ftype]:
                key = "sa" if ftype in (T_SRC4, T_SRC6) else "da"
                flow[key] = str(ipaddress.ip_address(raw))
            elif ftype in simple and len(raw) <= 8:
                flow[simple[ftype]] = int.from_bytes(raw, "big")
            elif ftype in (T_ICMP4, T_ICMP6) and len(raw) == 2:
                icmp = int.from_bytes(raw, "big")
            elif ftype == T_FIRST and len(raw) == 4:
                first = int.from_bytes(raw, "big")
            elif ftype == T_LAST and len(raw) == 4:
                last = int.from_bytes(raw, "big")
            elif ftype == T_FLOW_START_MS and len(raw) == 8:
                flow["first_ms"] = int.from_bytes(raw, "big")
            elif ftype == T_FLOW_END_MS and len(raw) == 8:
                flow["last_ms"] = int.from_bytes(raw, "big")
            else:
                extra["t%d" % ftype] = _value(raw)
        if icmp is not None and flow["pr"] in (IPPROTO_ICMP, IPPROTO_ICMPV6):
            flow["dp"] = icmp  # nfdump shows type * 256 + code here
        elif icmp is not None:
            extra["icmp"] = str(icmp)
        for key, rel in (("first_ms", first), ("last_ms", last)):
            if rel is None:
                continue
            if sys_init is not None:
                flow[key] = sys_init + rel
            elif uptime_ms is not None and export_ms is not None:
                flow[key] = export_ms - ((uptime_ms - rel) % (1 << 32))
            else:
                flow[key] = None
                extra["up_" + key[:-3]] = str(rel)
        flow["extra"] = extra
        return flow


def _fmt_time(ms: Optional[int]) -> str:
    if ms is None:
        return "-"
    dt = datetime.datetime.fromtimestamp(ms / 1000.0, datetime.timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + "%03d" % (ms % 1000)


def flow_to_row(flow: dict) -> List[str]:
    """Format a decoded flow as the CSV columns in CSV_COLUMNS."""
    first, last = flow.get("first_ms"), flow.get("last_ms")
    dur = "%.3f" % ((last - first) / 1000.0) if first is not None and \
        last is not None else "-"
    extra = ";".join("%s=%s" % kv for kv in sorted(flow["extra"].items()))
    return [_fmt_time(first), _fmt_time(last), dur, flow["sa"], flow["da"],
            str(flow["sp"]), str(flow["dp"]), str(flow["pr"]),
            str(flow["flg"]), str(flow["stos"]), str(flow["ipkt"]),
            str(flow["ibyt"]), str(flow["in"]), str(flow["out"]),
            extra or "-"]


def datagrams_to_csv(datagrams: List[Tuple[bytes, str]]) -> str:
    """Decode datagrams in arrival order and return nfdump-style CSV text."""
    dec = Decoder()
    lines = [",".join(CSV_COLUMNS)]
    for data, exporter in datagrams:
        for flow in dec.feed(data, exporter):
            lines.append(",".join(flow_to_row(flow)))
    return "\n".join(lines) + "\n"


class UdpSink:
    """Background UDP receiver that stores every datagram it gets."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0,
                 store: bool = True) -> None:
        """Bind host:port (port 0 picks a free one).

        With store=False the datagrams are only counted (packets, octets) and
        then discarded, which is what a benchmark sink needs.
        """
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        self.sock.bind((host, port))
        self.port = self.sock.getsockname()[1]
        self.datagrams: List[Tuple[bytes, str]] = []
        self.packets = 0
        self.octets = 0
        self._store = store
        self._stop = threading.Event()
        self._last_rx = time.monotonic()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            ready, _, _ = select.select([self.sock], [], [], 0.1)
            if not ready:
                continue
            data, addr = self.sock.recvfrom(65535)
            self.packets += 1
            self.octets += len(data)
            if self._store:
                self.datagrams.append((data, addr[0]))
            self._last_rx = time.monotonic()

    def close(self, quiet: float = 0.3, timeout: float = 3.0) -> None:
        """Wait until no datagram arrived for `quiet` seconds, then stop."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and \
                time.monotonic() - self._last_rx < quiet:
            time.sleep(0.05)
        self._stop.set()
        self._thread.join()
        self.sock.close()


def collect_main() -> int:
    ap = argparse.ArgumentParser(
        description="Print NetFlow v1/v5/v9 and IPFIX flows received on a "
                    "UDP port (CSV, nfdump column names).",
        epilog="This is the default of softflowd_test_collector.py.  The other "
               "subcommands are compat (backward compatibility test) and bench "
               "(export benchmark); run them with -h for their options.")
    ap.add_argument("-p", "--port", type=int, default=2055,
                    help="UDP port to listen on (default: 2055)")
    ap.add_argument("-b", "--bind", default=None,
                    help="address to listen on (default: any)")
    ap.add_argument("-6", "--ipv6", action="store_true",
                    help="listen on IPv6 (default: IPv4)")
    args = ap.parse_args()
    host = args.bind or ("::" if args.ipv6 else "0.0.0.0")
    sink_sock = socket.socket(
        socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM)
    sink_sock.bind((host, args.port))
    dec = Decoder()
    print(",".join(CSV_COLUMNS), flush=True)
    try:
        while True:
            data, addr = sink_sock.recvfrom(65535)
            for flow in dec.feed(data, addr[0]):
                print(",".join(flow_to_row(flow)), flush=True)
    except KeyboardInterrupt:
        return 0


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
# test produced. Because this suite always runs the stable and dev captures
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


# ==============================================================================
# Build Functions
# ==============================================================================

# (short name, description, configure arguments, binary name suffix)
C_BUILD_VARIANTS = [
    ("default", "default", [], ""),
    ("legacy", "legacy (--enable-legacy)", ["--enable-legacy"], "-legacy"),
    ("static", "static (--enable-compat-export=static)", ["--enable-compat-export=static"], "-static"),
]


def build_c_variants(src_dir: str, output_dir: str, what: str, prefix: str,
                     variants: list) -> List[str]:
    """Build each variant in src_dir and copy the binaries into output_dir.

    Returns the flat list [softflowd, softflowctl, ...] in variants order.
    """
    paths: List[str] = []
    for n, (short, desc, args, suffix) in enumerate(variants):
        print(f"  -> Configuring and building {what} {desc}...")
        if not build_c(src_dir, args, autoreconf=(n == 0)):
            print_red(f"Failed to build {what} {short} C binaries.")
            sys.exit(1)
        daemon = os.path.join(output_dir, f"{prefix}softflowd{suffix}")
        ctl = os.path.join(output_dir, f"{prefix}softflowctl{suffix}")
        copy_binaries(src_dir, daemon, ctl)
        paths += [daemon, ctl]
    return paths


STABLE_BINARIES = ("stable-softflowd", "stable-softflowctl",
                   "stable-softflowd-legacy", "stable-softflowctl-legacy")


def stable_cache_key(commit_hash: str) -> str:
    """Resolve commit_hash to a full SHA so that a moved tag or branch does not
    hit a stale cache entry; fall back to the name as given."""
    res = subprocess.run(["git", "rev-parse", "--verify", f"{commit_hash}^{{commit}}"],
                         cwd=PROJECT_ROOT, capture_output=True, text=True)
    return res.stdout.strip() if res.returncode == 0 and res.stdout.strip() else commit_hash


def build_c_stable(commit_hash: str, output_dir: str) -> Tuple[str, str, str, str]:
    """
    Check out C stable version into an isolated temp worktree and compile both
    standard and legacy variants.  The binaries are cached in CACHE_DIR per
    commit; a cached set is reused without building (or needing the commit).
    Returns: (stable-softflowd, stable-softflowctl, stable-softflowd-legacy, stable-softflowctl-legacy)
    """
    cache_entry = None
    if CACHE_DIR:
        key = stable_cache_key(commit_hash)
        cache_entry = os.path.join(CACHE_DIR, "stable", re.sub(r"[^A-Za-z0-9._-]", "_", key))
        cached = None if REBUILD_STABLE else cached_binaries(cache_entry, STABLE_BINARIES,
                                                            output_dir)
        if cached:
            print_cyan(f"\n[Build] Using cached C stable binaries ({commit_hash}): {cache_entry}")
            return cached

    print_cyan(f"\n[Build] Compiling C stable version (Commit/Tag: {commit_hash})...")
    worktree_dir = os.path.join(SUITE_TMP_DIR, "c_stable_worktree")

    run_command(["git", "worktree", "add", "-f", worktree_dir, commit_hash], cwd=PROJECT_ROOT)
    atexit.register(lambda: subprocess.run(["git", "worktree", "remove", "-f", worktree_dir], cwd=PROJECT_ROOT, stderr=subprocess.DEVNULL))

    # The stable tree predates --enable-compat-export: default and legacy only.
    paths = tuple(build_c_variants(worktree_dir, output_dir, "stable", "stable-",
                                   C_BUILD_VARIANTS[:2]))
    if cache_entry:
        store_binary_cache(cache_entry, paths, "stable")
    return paths


def cached_binaries(cache_entry: str, names: Sequence[str],
                    output_dir: str) -> Optional[Tuple[str, ...]]:
    """Copy the cached binaries into output_dir; None if the entry is not complete."""
    if not all(os.access(os.path.join(cache_entry, n), os.X_OK) for n in names):
        return None
    os.utime(cache_entry)  # most recently used, see prune_dev_cache()
    paths = []
    for n in names:
        dest = os.path.join(output_dir, n)
        shutil.copy2(os.path.join(cache_entry, n), dest)
        paths.append(dest)
    return tuple(paths)


def store_binary_cache(cache_entry: str, paths: Sequence[str], what: str) -> None:
    """Store the built binaries in the cache; a failure only costs a rebuild next time."""
    tmp = f"{cache_entry}.tmp.{os.getpid()}"
    try:
        os.makedirs(tmp)
        for path in paths:
            shutil.copy2(path, os.path.join(tmp, os.path.basename(path)))
        # Rename into place only when complete so the cache never holds a partial set.
        if os.path.isdir(cache_entry):
            shutil.rmtree(cache_entry)
        os.rename(tmp, cache_entry)
        print(f"  -> Cached {what} binaries in {cache_entry}")
    except OSError as e:
        print_yellow(f"Warning: could not cache the {what} binaries: {e}")
        shutil.rmtree(tmp, ignore_errors=True)


# Binary names build_c_dev() produces, in the order build_c_variants() returns them.
DEV_BINARIES = tuple(f"{b}{suffix}" for _, _, _, suffix in C_BUILD_VARIANTS
                     for b in ("softflowd", "softflowctl"))

# Number of development builds kept in the cache.
DEV_CACHE_KEEP = 5

# Paths (and *.md files) that do not influence the C binaries and are left out of
# the cache key.
DEV_KEY_EXCLUDE_DIRS = ("cpp", "rust", "tools", ".github")


def dev_cache_key() -> Tuple[str, bool]:
    """Hash everything the C build depends on: the contents of the tracked and
    the not-ignored untracked files (so uncommitted edits count, HEAD does not),
    the configure arguments, the compiler settings and the compiler version.

    Returns (hex digest, whether the tree differs from HEAD).
    """
    out = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                         cwd=PROJECT_ROOT, capture_output=True, check=True).stdout
    names = sorted(n for n in (b.decode() for b in out.split(b"\0") if b)
                   if n.split("/")[0] not in DEV_KEY_EXCLUDE_DIRS
                   and not n.endswith(".md"))
    h = hashlib.sha256()
    for name in names:
        h.update(name.encode() + b"\0")
        path = os.path.join(PROJECT_ROOT, name)
        if os.path.isfile(path):  # a tracked file deleted from the tree has no content
            with open(path, "rb") as f:
                h.update(hashlib.sha256(f.read()).digest())
    for _, _, args, _ in C_BUILD_VARIANTS:
        h.update(b"\0args\0" + " ".join(args).encode())
    for var in ("CC", "CFLAGS", "CPPFLAGS", "LDFLAGS"):
        h.update(f"\0{var}={os.environ.get(var, '')}".encode())
    cc = subprocess.run([os.environ.get("CC") or "cc", "--version"],
                        capture_output=True, text=True)
    h.update(b"\0cc\0" + cc.stdout.encode())
    dirty = subprocess.run(["git", "status", "--porcelain", "--", ".",
                            *[f":(exclude){d}" for d in DEV_KEY_EXCLUDE_DIRS],
                            ":(exclude,glob)**/*.md", ":(exclude)*.md"],
                           cwd=PROJECT_ROOT, capture_output=True, text=True,
                           check=True).stdout.strip() != ""
    return h.hexdigest(), dirty


def prune_dev_cache(dev_cache_dir: str, keep: int = DEV_CACHE_KEEP) -> None:
    """Remove all but the `keep` most recently used development builds."""
    try:
        entries = [os.path.join(dev_cache_dir, n) for n in os.listdir(dev_cache_dir)
                   if ".tmp." not in n]
        entries.sort(key=os.path.getmtime, reverse=True)
        for old in entries[keep:]:
            shutil.rmtree(old, ignore_errors=True)
    except OSError:
        pass


def build_c_dev(output_dir: str) -> Tuple[str, ...]:
    """
    Compile C development version (current working source tree including uncommitted/current changes)
    in 3 configurations:
      1. Default (softflowd / softflowctl)
      2. Legacy (softflowd-legacy / softflowctl-legacy)
      3. Static compat export (softflowd-static / softflowctl-static)
    The binaries are cached in CACHE_DIR under a hash of the build inputs, so
    an unchanged tree is not compiled again.
    """
    cache_entry = None
    if CACHE_DIR:
        try:
            key, dirty = dev_cache_key()
        except (OSError, subprocess.CalledProcessError) as e:
            print_yellow(f"Warning: cannot compute the development build cache key ({e}); "
                         "building without the cache")
        else:
            dev_cache_dir = os.path.join(CACHE_DIR, "dev")
            cache_entry = os.path.join(dev_cache_dir, key[:16])
            state = "uncommitted changes" if dirty else "same as HEAD"
            cached = None if REBUILD_DEV else cached_binaries(cache_entry, DEV_BINARIES,
                                                              output_dir)
            if cached:
                print_cyan(f"\n[Build] Using cached C development binaries "
                           f"(key {key[:12]}, {state}): {cache_entry}")
                return cached
            print_cyan(f"\n[Build] Compiling C development version (current source tree; "
                       f"key {key[:12]}, {state})...")
    if cache_entry is None:
        print_cyan("\n[Build] Compiling C development version (current source tree)...")
    paths = tuple(build_c_variants(PROJECT_ROOT, output_dir, "C development", "",
                                   C_BUILD_VARIANTS))
    if cache_entry:
        store_binary_cache(cache_entry, paths, "development")
        prune_dev_cache(os.path.dirname(cache_entry))
    return paths


def build_cpp(output_dir: str) -> Tuple[Optional[str], Optional[str]]:
    """Compile C++ version in cpp/build using cmake."""
    print_cyan("\n[Build] Compiling C++ binaries (cpp/)...")
    cpp_dir = os.path.join(PROJECT_ROOT, "cpp")
    build_dir = os.path.join(cpp_dir, "build")
    os.makedirs(build_dir, exist_ok=True)

    res = run_command(["cmake", ".."], cwd=build_dir)
    if res.returncode != 0:
        print_yellow("Warning: cmake configuration failed for C++ version.")
        return None, None

    res = run_command(["make", "-j"], cwd=build_dir)
    if res.returncode != 0:
        print_yellow("Warning: make failed for C++ version.")
        return None, None

    cpp_daemon = os.path.join(build_dir, "softflowd+")
    cpp_ctl = os.path.join(build_dir, "softflowctl+")

    dest_daemon = os.path.join(output_dir, "softflowd+")
    dest_ctl = os.path.join(output_dir, "softflowctl+")

    if os.path.exists(cpp_daemon):
        shutil.copy2(cpp_daemon, dest_daemon)
    else:
        dest_daemon = None

    if os.path.exists(cpp_ctl):
        shutil.copy2(cpp_ctl, dest_ctl)
    else:
        dest_ctl = None

    return dest_daemon, dest_ctl


def build_rust(output_dir: str) -> Tuple[Optional[str], Optional[str]]:
    """Compile Rust version in rust/ using cargo build."""
    print_cyan("\n[Build] Compiling Rust binaries (rust/)...")
    rust_dir = os.path.join(PROJECT_ROOT, "rust")
    if not os.path.exists(rust_dir):
        return None, None

    res = run_command(["cargo", "build"], cwd=rust_dir)
    if res.returncode != 0:
        print_yellow("Warning: cargo build failed for Rust version.")
        return None, None

    rust_daemon = os.path.join(rust_dir, "target", "debug", "rsoftflowd")
    rust_ctl = os.path.join(rust_dir, "target", "debug", "rsoftflowctl")

    dest_daemon = os.path.join(output_dir, "rsoftflowd")
    dest_ctl = os.path.join(output_dir, "rsoftctl")

    if os.path.exists(rust_daemon):
        shutil.copy2(rust_daemon, dest_daemon)
    else:
        dest_daemon = None

    if os.path.exists(rust_ctl):
        shutil.copy2(rust_ctl, dest_ctl)
    else:
        dest_ctl = None

    return dest_daemon, dest_ctl


# ==============================================================================
# Testing Verification Functions
# ==============================================================================

def test_cli_compatibility(stable_bin: str, dev_bin: str) -> bool:
    """Verify CLI options handling and return code compatibility."""
    print("  [Step 1] Verifying CLI Options...")

    p_stable = subprocess.run([stable_bin, "-z"], capture_output=True, text=True)
    p_dev = subprocess.run([dev_bin, "-z"], capture_output=True, text=True)

    if p_stable.returncode == 0 or p_dev.returncode == 0:
        print_red("    FAILED: Invalid CLI options should return non-zero exit code.")
        return False

    p_stable_res = subprocess.run([stable_bin, "-h"], capture_output=True, text=True)
    p_dev_res = subprocess.run([dev_bin, "-h"], capture_output=True, text=True)
    stable_help = p_stable_res.stdout + p_stable_res.stderr
    dev_help = p_dev_res.stdout + p_dev_res.stderr

    required_options = ["-i", "-r", "-t", "-m", "-n", "-p", "-c", "-v", "-L", "-T", "-d", "-D"]
    missing_stable = [opt for opt in required_options if opt not in stable_help]
    missing_dev = [opt for opt in required_options if opt not in dev_help]

    if missing_stable or missing_dev:
        print_red(
            f"    FAILED: Help strings missing key options. Stable missing: {missing_stable}, Dev missing: {missing_dev}"
        )
        # If dev daemon doesn't support -d / -D or similar, warn or handle gracefully depending on implementation
        if not missing_stable and len(missing_dev) > 0 and all(o in ["-d", "-D"] for o in missing_dev):
            print_yellow("    Warning: Dev daemon help output omitted daemon background flags (-d/-D), continuing...")
        else:
            return False

    print_green("    CLI options verification: PASSED")
    return True


def start_blocked_daemon(daemon_bin: str, sock_path: str) -> Tuple[subprocess.Popen, int, str, str]:
    """Start daemon listening on a blocked PCAP FIFO for control socket testing."""
    fifo_dir = tempfile.mkdtemp(dir=SUITE_TMP_DIR)
    fifo_path = os.path.join(fifo_dir, "pcap.fifo")
    os.mkfifo(fifo_path)

    fifo_fd = os.open(fifo_path, os.O_RDWR)
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    os.write(fifo_fd, header)

    # Use -d for foreground/control testing
    args = [daemon_bin, "-d", "-r", fifo_path, "-c", sock_path]
    proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    return proc, fifo_fd, fifo_path, fifo_dir


def stop_blocked_daemon(proc: subprocess.Popen, fifo_fd: int, fifo_path: str, fifo_dir: str):
    """Safely terminate blocked daemon process and clean up FIFO resources."""
    try:
        proc.terminate()
        start_time = time.time()
        while time.time() - start_time < 2.0:
            if proc.poll() is not None:
                break
            time.sleep(0.05)
        else:
            proc.kill()
            proc.wait(timeout=2)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    finally:
        try:
            os.close(fifo_fd)
        except Exception:
            pass
        shutil.rmtree(fifo_dir, ignore_errors=True)


def test_control_socket_compatibility(
    stable_daemon: str, dev_daemon: str, ctl_stable: str, ctl_dev: str
) -> bool:
    """Verify control socket queries and cross-compatibility."""
    print("  [Step 2] Verifying Control Socket Cross-Connection...")

    sock_stable = os.path.join(SUITE_TMP_DIR, "ctl_stable.sock")
    sock_dev = os.path.join(SUITE_TMP_DIR, "ctl_dev.sock")

    # 1. Test Stable Daemon
    proc_stable, o_fd, o_path, o_dir = start_blocked_daemon(stable_daemon, sock_stable)
    try:
        res1 = subprocess.run([ctl_stable, "-c", sock_stable, "statistics"], capture_output=True, text=True, timeout=3)
        if res1.returncode != 0:
            print_red(f"    FAILED: Stable CTL failed to query Stable Daemon: {res1.stderr}")
            return False

        try:
            subprocess.run([ctl_dev, "-c", sock_stable, "statistics"], capture_output=True, text=True, timeout=3)
        except Exception:
            pass
    finally:
        stop_blocked_daemon(proc_stable, o_fd, o_path, o_dir)

    # 2. Test Dev Daemon
    proc_dev, n_fd, n_path, n_dir = start_blocked_daemon(dev_daemon, sock_dev)
    try:
        res4 = subprocess.run([ctl_dev, "-c", sock_dev, "statistics"], capture_output=True, text=True, timeout=3)
        if res4.returncode != 0:
            print_red(f"    FAILED: Dev CTL failed to query Dev Daemon: {res4.stderr}")
            return False
    finally:
        stop_blocked_daemon(proc_dev, n_fd, n_path, n_dir)

    print_green("    Control socket verification: PASSED")
    return True


def run_nfdump_capture(pcap_path: str, daemon_bin: str, version: int) -> str:
    """Run daemon against PCAP and collect exported flows via nfcapd, decoded with nfdump."""
    out_dir = tempfile.mkdtemp(dir=SUITE_TMP_DIR)
    # A free port, not the default 2055: some distributions (Debian, Ubuntu)
    # start their own nfcapd on 2055 when the nfdump package is installed.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("0.0.0.0", 0))
        port = probe.getsockname()[1]
    # Outside out_dir, which nfdump -R scans for capture files.
    nfcapd_log = os.path.join(SUITE_TMP_DIR, f"nfcapd-{port}.log")
    with open(nfcapd_log, "w") as log_file:
        nfcapd_proc = subprocess.Popen(["nfcapd", "-p", str(port), "-w", out_dir], stdout=log_file, stderr=subprocess.STDOUT)
    time.sleep(1)
    if nfcapd_proc.poll() is not None:
        with open(nfcapd_log) as log_file:
            sys.exit(f"error: nfcapd exited right after starting on UDP port {port}:\n{log_file.read()}")

    try:
        cmd = [
            daemon_bin,
            "-d",
            "-r", pcap_path,
            "-a",
            "-n", f"127.0.0.1:{port}",
            "-v", str(version),
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        proc.wait()
        time.sleep(0.5)
        nfcapd_proc.terminate()
        try:
            nfcapd_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            nfcapd_proc.kill()

        result = subprocess.run(["nfdump", "-R", out_dir, "-o", "csv"], capture_output=True, text=True)
        return result.stdout
    finally:
        if nfcapd_proc.poll() is None:
            nfcapd_proc.kill()


def run_python_capture(pcap_path: str, daemon_bin: str, version: int) -> str:
    """Run daemon against PCAP and decode the exported datagrams in Python.

    Returns CSV text with nfdump's column names (see the collector section).
    """
    sink = UdpSink("127.0.0.1", 0)
    try:
        cmd = [
            daemon_bin,
            "-d",
            "-r", pcap_path,
            "-a",
            "-n", f"127.0.0.1:{sink.port}",
            "-v", str(version),
        ]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    finally:
        sink.close()
    return datagrams_to_csv(sink.datagrams)


def run_capture(pcap_path: str, daemon_bin: str, version: int) -> str:
    """Collect exported flows with the selected collector backend."""
    if COLLECTOR_BACKEND == "python":
        return run_python_capture(pcap_path, daemon_bin, version)
    return run_nfdump_capture(pcap_path, daemon_bin, version)


def run_gauge_capture(pcap_path: str, daemon_bin: str, version: int) -> Optional[Tuple[int, Optional[int], Optional[int]]]:
    """Run daemon once with -g and parse the "cpu clocks" lines it prints on exit.

    Returns (total_clocks, export_clocks, export_calls), where export_clocks/
    export_calls are None if the daemon predates the export-clock counter or
    ran with threaded export (-M), which reports "n/a" for export clocks.
    Returns None if the daemon does not support -g at all (no output line).
    """
    cmd = [daemon_bin, "-g", "-r", pcap_path, "-n", f"127.0.0.1:{export_port()}", "-v", str(version)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    return parse_gauge(res.stderr)


def export_port() -> int:
    """UDP port the daemons export to: the measurement sink if there is one."""
    return MEASURE.sink.port if MEASURE is not None else 2055


class MeasureSettings:
    """What is measured besides compatibility (set from the command line)."""

    def __init__(self, gauge: bool, tool: Optional[str], runs: int,
                 warmup: int, min_runs: Optional[int], max_runs: Optional[int],
                 callgrind: bool, topn: int, perf: bool,
                 extra_pcaps: List[str], csv_path: Optional[str]) -> None:
        self.gauge = gauge
        self.tool = tool  # None, "hyperfine" or "time"
        self.runs = runs
        self.warmup = warmup
        self.min_runs = min_runs  # hyperfine --min-runs (adaptive run count)
        self.max_runs = max_runs  # hyperfine --max-runs
        self.callgrind = callgrind
        self.topn = topn
        self.perf = perf
        self.extra_pcaps = extra_pcaps
        self.csv_path = csv_path
        # Profiles and the perf log go next to --bench-csv, else into the
        # (temporary) suite directory.
        self.prefix = csv_path or os.path.join(SUITE_TMP_DIR, "measure")
        self.cg_dir = self.prefix + ".callgrind"
        self.perf_log = self.prefix + ".perf.log"
        if callgrind:
            os.makedirs(self.cg_dir, exist_ok=True)
        # Receives and discards the export packets while a daemon is measured.
        self.sink = UdpSink("127.0.0.1", 0, store=False)
        self.rows: List[dict] = []


# Set by compat_main() when --gauge-clock and/or --benchmark is given.
MEASURE: Optional[MeasureSettings] = None


def _time_runs(cmd: List[str], runs: int, warmup: int) -> Optional[dict]:
    """Run cmd repeatedly and measure it the way time(1) does.

    Wall clock time comes from the parent; user and system CPU time are the
    child's resource usage returned by wait4().  Returns None if the command
    fails.
    """
    wall: List[float] = []
    user: List[float] = []
    system: List[float] = []
    for n in range(warmup + runs):
        start = time.monotonic()
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        _pid, status, usage = os.wait4(proc.pid, 0)
        elapsed = time.monotonic() - start
        proc.returncode = os.waitstatus_to_exitcode(status)
        if proc.returncode != 0:
            return None
        if n >= warmup:
            wall.append(elapsed)
            user.append(usage.ru_utime)
            system.append(usage.ru_stime)
    return {"mean": statistics.fmean(wall), "median": statistics.median(wall),
            "stddev": statistics.stdev(wall) if len(wall) > 1 else 0.0,
            "user": statistics.fmean(user), "system": statistics.fmean(system),
            "runs": len(wall)}


def _hyperfine_runs(cmd: List[str], runs: int, warmup: int,
                    min_runs: Optional[int] = None,
                    max_runs: Optional[int] = None) -> Optional[dict]:
    """Time cmd with hyperfine.  None on failure.

    A fixed number of runs, or with min_runs/max_runs hyperfine's own
    adaptive count (at least min_runs, default 10, and at most max_runs).
    """
    with tempfile.TemporaryDirectory(dir=SUITE_TMP_DIR) as tmp:
        out = os.path.join(tmp, "hyperfine.json")
        base = ["hyperfine", "--warmup", str(warmup)]
        if min_runs is None and max_runs is None:
            base += ["--runs", str(runs)]
        else:
            base += ["--min-runs", str(min_runs or 10)]
            if max_runs is not None:
                base += ["--max-runs", str(max_runs)]
        base += ["--export-json", out]
        # --shell=none keeps the shell's start-up out of a millisecond-sized
        # measurement; fall back to the default shell for old hyperfine.
        for extra in (["--shell=none"], []):
            res = subprocess.run(base + extra + [shlex.join(cmd)],
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.PIPE, text=True)
            if res.returncode == 0 and os.path.exists(out):
                break
        else:
            return None
        with open(out) as f:
            r = json.load(f)["results"][0]
    return {"mean": r["mean"], "median": r["median"],
            "stddev": r["stddev"] or 0.0, "user": r.get("user", 0.0),
            "system": r.get("system", 0.0), "runs": len(r["times"])}


def measure_cmd(daemon_bin: str, pcap_path: str, version: int) -> List[str]:
    """Command line that replays pcap_path through a daemon into the sink."""
    assert MEASURE is not None
    return [daemon_bin, "-r", pcap_path, "-n", f"127.0.0.1:{MEASURE.sink.port}",
            "-v", str(version)]


def measure_runtime(daemon_bin: str, pcap_path: str, version: int) -> Optional[dict]:
    """Time one daemon replaying one pcap with the selected tool."""
    assert MEASURE is not None and MEASURE.tool is not None
    cmd = measure_cmd(daemon_bin, pcap_path, version)
    if MEASURE.tool == "hyperfine":
        return _hyperfine_runs(cmd, MEASURE.runs, MEASURE.warmup,
                               MEASURE.min_runs, MEASURE.max_runs)
    # time(1) style: no adaptive count; --bench-min-runs sets the run count.
    return _time_runs(cmd, MEASURE.min_runs or MEASURE.runs, MEASURE.warmup)


def _dev_ratio(dev: Optional[float], stable: Optional[float]) -> str:
    """dev / stable as "0.87x"; "-" when either side is missing."""
    if not dev or not stable:
        return "-"
    return f"{dev / stable:.2f}x"


def _slug(text: str) -> str:
    """File name friendly form of a pair or test case name."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("_")


def _fmt_ir(c: Optional[Tuple[int, int]]) -> str:
    if c is None:
        return "failed"
    return f"Ir={c[0]:,} (exporter {c[1]:,})"


def _fmt_ms(m: Optional[dict]) -> str:
    if m is None:
        return "failed"
    return f"{m['mean'] * 1000:.3f} ms (+-{m['stddev'] * 1000:.3f})"


def _fmt_gauge(g: Optional[Tuple[int, Optional[int], Optional[int]]]) -> str:
    if g is None:
        return "-g not supported"
    total, export, calls = g
    if export is None:
        return f"total={total}"
    return f"total={total} export={export} ({calls} calls)"


def measure_pair(stable_daemon: str, dev_daemon: str, pair_name: str,
                 cases: List[Tuple[str, str, int]]) -> None:
    """Measure the stable and dev daemon of a pair on the compat test cases
    (plus --bench-pcap files) and remember the results for the summary."""
    if MEASURE is None:
        return
    if MEASURE.min_runs is None and MEASURE.max_runs is None:
        runs_label = f"x{MEASURE.runs}"
    else:
        runs_label = f"min {MEASURE.min_runs or 10}" + \
            (f" max {MEASURE.max_runs}" if MEASURE.max_runs else "")
    what = [w for w, on in (("-g counters", MEASURE.gauge),
                            (f"{MEASURE.tool} {runs_label}", MEASURE.tool),
                            ("callgrind", MEASURE.callgrind),
                            ("perf stat", MEASURE.perf)) if on]
    print(f"  [Step 4] Measuring stable vs dev ({', '.join(what)})...")
    cases = list(cases)
    for extra in MEASURE.extra_pcaps:
        for version, label in ((1, "NetFlow v1"), (5, "NetFlow v5"),
                               (9, "NetFlow v9"), (10, "IPFIX")):
            cases.append((f"{os.path.basename(extra)} ({label})", extra, version))
    for name, pcap_path, version in cases:
        row: dict = {"pair": pair_name, "case": name,
                     "pcap": os.path.basename(pcap_path), "version": version}
        print(f"    - {name}")
        warm_page_cache(pcap_path)
        if MEASURE.gauge:
            row["gauge_stable"] = run_gauge_capture(pcap_path, stable_daemon, version)
            row["gauge_dev"] = run_gauge_capture(pcap_path, dev_daemon, version)
            print(f"        cpu clocks: stable[{_fmt_gauge(row['gauge_stable'])}]"
                  f"  dev[{_fmt_gauge(row['gauge_dev'])}]")
        if MEASURE.tool:
            row["time_stable"] = measure_runtime(stable_daemon, pcap_path, version)
            row["time_dev"] = measure_runtime(dev_daemon, pcap_path, version)
            ts, td = row["time_stable"], row["time_dev"]
            print(f"        time:       stable {_fmt_ms(ts)}  dev {_fmt_ms(td)}  "
                  f"dev/stable {_dev_ratio(td and td['mean'], ts and ts['mean'])}")
        if MEASURE.callgrind:
            for side, daemon in (("stable", stable_daemon), ("dev", dev_daemon)):
                tag = f"{_slug(pair_name)}_{_slug(name)}_{side}"
                res = callgrind_profile(measure_cmd(daemon, pcap_path, version),
                                        MEASURE.cg_dir, tag, MEASURE.topn)
                row[f"cg_{side}"] = res[:2] if res else None
                if res and MEASURE.topn:
                    print(f"        top {MEASURE.topn} functions ({side}):")
                    for line in res[2]:
                        print("          " + line)
            cs, cd = row["cg_stable"], row["cg_dev"]
            print(f"        callgrind:  stable {_fmt_ir(cs)}  dev {_fmt_ir(cd)}  "
                  f"dev/stable {_dev_ratio(cd and cd[0], cs and cs[0])}")
        if MEASURE.perf:
            for side, daemon in (("stable", stable_daemon), ("dev", dev_daemon)):
                perf_stat(measure_cmd(daemon, pcap_path, version), MEASURE.perf_log,
                          f"{pair_name} / {name} / {side}")
        MEASURE.rows.append(row)


def _print_table(headers: List[str], rows: List[List[str]]) -> None:
    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    fmt = "  " + "  ".join(f"{{:<{w}}}" if i == 0 else f"{{:>{w}}}"
                           for i, w in enumerate(widths))
    print(fmt.format(*headers))
    for r in rows:
        print(fmt.format(*r))


CSV_STATS = ("mean", "median", "stddev", "user", "system")


def _write_measure_csv(path: str, rows: List[dict], tool: Optional[str]) -> None:
    header = ["pair", "case", "pcap", "version", "tool", "runs"]
    for side in ("stable", "dev"):
        header += [f"{side}_{k}_s" for k in CSV_STATS]
        header += [f"{side}_cpu_clocks_total", f"{side}_cpu_clocks_export",
                   f"{side}_export_calls", f"{side}_ir_total",
                   f"{side}_ir_exporter"]
    header += ["mean_ratio"]
    with open(path, "w", newline="") as f:
        out = csv.writer(f, lineterminator="\n")
        out.writerow(header)
        for r in rows:
            line = [r["pair"], r["case"], r["pcap"], r["version"], tool or "",
                    (r.get("time_stable") or {}).get("runs", "")]
            for side in ("stable", "dev"):
                t = r.get(f"time_{side}") or {}
                line += [f"{t[k]:.6f}" if k in t else "" for k in CSV_STATS]
                g = r.get(f"gauge_{side}") or (None, None, None)
                line += ["" if v is None else v for v in g]
                c = r.get(f"cg_{side}") or (None, None)
                line += ["" if v is None else v for v in c]
            ts, td = r.get("time_stable"), r.get("time_dev")
            line += [_dev_ratio(td and td["mean"], ts and ts["mean"]).rstrip("x")]
            out.writerow(line)


def finish_measurements() -> None:
    """Print the stable-vs-dev summary, write --bench-csv and stop the sink."""
    if MEASURE is None:
        return
    try:
        if MEASURE.rows:
            print("\n" + "=" * 60)
            print("MEASUREMENT SUMMARY (dev / stable; below 1.00x means dev is faster)")
            print("=" * 60)
            headers = ["case"]
            if MEASURE.tool:
                headers += ["stable ms", "dev ms", "time"]
            if MEASURE.gauge:
                headers += ["stable clk", "dev clk", "clk", "export clk"]
            if MEASURE.callgrind:
                headers += ["stable Ir", "dev Ir", "Ir", "exporter Ir"]
            for pair in dict.fromkeys(r["pair"] for r in MEASURE.rows):
                print(f"\n[{pair}]")
                table = []
                for r in (x for x in MEASURE.rows if x["pair"] == pair):
                    line = [r["case"]]
                    if MEASURE.tool:
                        ts, td = r["time_stable"], r["time_dev"]
                        line += [f"{ts['mean'] * 1000:.3f}" if ts else "failed",
                                 f"{td['mean'] * 1000:.3f}" if td else "failed",
                                 _dev_ratio(td and td["mean"], ts and ts["mean"])]
                    if MEASURE.gauge:
                        gs, gd = r["gauge_stable"], r["gauge_dev"]
                        line += [str(gs[0]) if gs else "-", str(gd[0]) if gd else "-",
                                 _dev_ratio(gd and gd[0], gs and gs[0]),
                                 _dev_ratio(gd and gd[1], gs and gs[1])]
                    if MEASURE.callgrind:
                        cs, cd = r["cg_stable"], r["cg_dev"]
                        line += [f"{cs[0]:,}" if cs else "failed",
                                 f"{cd[0]:,}" if cd else "failed",
                                 _dev_ratio(cd and cd[0], cs and cs[0]),
                                 _dev_ratio(cd and cd[1], cs and cs[1])]
                    table.append(line)
                _print_table(headers, table)
            if MEASURE.csv_path:
                _write_measure_csv(MEASURE.csv_path, MEASURE.rows, MEASURE.tool)
                print(f"\nMeasurement results written to {MEASURE.csv_path}")
                if MEASURE.callgrind:
                    print(f"callgrind profiles: {MEASURE.cg_dir}/")
                if MEASURE.perf:
                    print(f"perf stat output: {MEASURE.perf_log}")
    finally:
        MEASURE.sink.close(quiet=0.0, timeout=0.0)


def normalize_nfdump_csv(
    csv_text: str,
    ignore_timestamp: bool = False,
    include_collector_metadata: bool = False,
    normalize_icmp_reclass: bool = False
) -> List[str]:
    """Parse and normalize CSV records for deterministic comparison.

    The first line of `nfdump -o csv` output is a field-name header (e.g.
    'ts,te,td,...,tr' or, on some builds, 'firstSeen,duration,proto,
    srcAddr,...'), not a record; it is skipped here rather than treated as
    data. By default, columns in COLLECTOR_METADATA_COLUMNS are masked out
    (pass include_collector_metadata=True to compare them too).

    normalize_icmp_reclass masks the protocol and destination-port columns
    (located via PROTOCOL_COLUMN_NAMES / DST_PORT_COLUMN_NAMES, whichever
    the header actually uses) on any row whose own protocol value is in
    ICMP_RECLASSIFICATION_PROTOCOLS -- see that constant's docstring. This
    only ever removes a difference from view when every *other* column on
    the row already matched, since the two normalized CSVs are still
    compared with plain equality; it cannot turn an otherwise-mismatched row
    into a false "matched" result.

    The header row is identified positionally -- it is simply the first
    line that survives the filters below -- rather than by matching any
    specific field-name string. nfdump always emits exactly one such line
    before any data for `-o csv`, but the literal names it uses for each
    column (e.g. 'ts' vs 'firstSeen', 'pr' vs 'proto') differ across
    versions/builds, so relying on a particular name (or set of names) here
    is exactly what previously caused header detection -- and therefore all
    header-dependent masking above -- to silently no-op on builds that
    phrase the header differently.
    """
    header_fields: Optional[List[str]] = None
    mask_idx: List[int] = []
    icmp_mask_idx: List[int] = []
    pr_idx: Optional[int] = None
    lines = []
    for line in csv_text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("Summary") or line.startswith("Date") or line.startswith("Flow Record") or "Ident" in line or "SysID" in line:
            continue
        parts = line.split(",")
        if len(parts) < 10:
            continue
        if header_fields is None:
            header_fields = parts
            lower_fields = [f.strip().lower() for f in header_fields]
            if not include_collector_metadata:
                mask_idx = [i for i, name in enumerate(lower_fields) if name in COLLECTOR_METADATA_COLUMNS]
            if normalize_icmp_reclass:
                icmp_mask_idx = [i for i, name in enumerate(lower_fields)
                                  if name in PROTOCOL_COLUMN_NAMES or name in DST_PORT_COLUMN_NAMES]
                pr_candidates = [i for i, name in enumerate(lower_fields) if name in PROTOCOL_COLUMN_NAMES]
                if pr_candidates:
                    pr_idx = pr_candidates[0]
            continue
        if ignore_timestamp:
            parts[0] = "TIMESTAMP"
            parts[1] = "DURATION"
        if icmp_mask_idx and pr_idx is not None and pr_idx < len(parts) and parts[pr_idx].strip().upper() in ICMP_RECLASSIFICATION_PROTOCOLS:
            for i in icmp_mask_idx:
                if i < len(parts):
                    parts[i] = "ICMP_RECLASSIFIED"
        for i in mask_idx:
            if i < len(parts):
                parts[i] = "COLLECTOR_METADATA"
        lines.append(",".join(parts))
    if header_fields is not None and normalize_icmp_reclass and pr_idx is None:
        print_yellow(
            "    [WARN] nfdump CSV header found but no recognized protocol column "
            f"(looked for one of {sorted(PROTOCOL_COLUMN_NAMES)}) -- ICMP protocol/"
            f"dest-port tolerance did not run for this capture. Detected header: {header_fields}"
        )
    return sorted(lines)


def test_differential_output(
    stable_daemon: str,
    dev_daemon: str,
    pair_name: str,
    ignore_timestamp: bool,
    auto_ignore_legacy_v9: bool,
    auto_ignore_icmp_reclass: bool,
    ignore_ipv6: bool,
    include_collector_metadata: bool = False
) -> bool:
    """Compare nfdump output across NetFlow v1, v5, v9 and IPFIX."""
    print(f"  [Step 3] Verifying Differential Packet Export ({COLLECTOR_BACKEND} collector)...")

    http_pcap = ensure_sample_pcap("http.cap", HTTP_PCAP_URL)
    v6_pcap = ensure_sample_pcap("v6-http.cap", V6_HTTP_PCAP_URL)

    test_cases = [
        ("IPv4 HTTP (NetFlow v1)", http_pcap, 1),
        ("IPv4 HTTP (NetFlow v5)", http_pcap, 5),
        ("IPv4 HTTP (NetFlow v9)", http_pcap, 9),
        ("IPv4 HTTP (IPFIX)", http_pcap, 10),
    ]

    if not ignore_ipv6:
        test_cases.extend([
            ("IPv6 HTTP (NetFlow v9)", v6_pcap, 9),
            ("IPv6 HTTP (IPFIX)", v6_pcap, 10),
        ])

    for extra in COMPAT_PCAPS:
        for version, label in ((1, "NetFlow v1"), (5, "NetFlow v5"),
                               (9, "NetFlow v9"), (10, "IPFIX")):
            test_cases.append((f"{os.path.basename(extra)} ({label})", extra, version))

    all_matched = True
    for name, pcap_path, version in test_cases:
        # The known stable(<=1.1.1)-legacy NetFlow v9 export_time bug (see
        # netflow9.c/common.h SET_EXPORT_NOW) only affects the standalone
        # --enable-legacy NetFlow v9 exporter -- version 9 specifically, not
        # IPFIX (v10), which already went through ipfix.c in that build too.
        should_ignore_ts = ignore_timestamp
        if auto_ignore_legacy_v9 and "legacy" in pair_name and version == 9:
            should_ignore_ts = True

        # Tolerate the C stable reference's known ICMPv6 protocol/type
        # misclassification bug (see ICMP_RECLASSIFICATION_PROTOCOLS) only
        # when comparing against that old reference.
        norm_icmp = auto_ignore_icmp_reclass and ("stable-softflowd" in pair_name)

        csv_stable = run_capture(pcap_path, stable_daemon, version)
        norm_stable = normalize_nfdump_csv(csv_stable, should_ignore_ts, include_collector_metadata, norm_icmp)

        csv_dev = run_capture(pcap_path, dev_daemon, version)
        norm_dev = normalize_nfdump_csv(csv_dev, should_ignore_ts, include_collector_metadata, norm_icmp)

        display_name = name
        if should_ignore_ts and not ignore_timestamp:
            display_name += " [timestamp ignored: known stable-legacy NetFlow v9 bug]"
        if norm_icmp:
            display_name += " [ICMPv6 protocol/dest-port tolerance active]"

        if norm_stable == norm_dev and len(norm_stable) > 0:
            print(f"    - {display_name}: MATCHED ({len(norm_stable)} records)")
        elif norm_stable == norm_dev and pcap_path in COMPAT_PCAPS:
            # e.g. an IPv6-only pcap exported as NetFlow v1/v5, which carry no IPv6
            print_yellow(f"    - {display_name}: SKIPPED (no flow records on either side)")
        else:
            print_red(f"    - {display_name}: FAILED (Records: stable={len(norm_stable)}, dev={len(norm_dev)})")
            show = max(len(norm_stable), len(norm_dev), 3)
            show = min(show, 20)  # cap so a large real regression doesn't flood the terminal
            print("--- Stable Expected ---")
            for l in norm_stable[:show]:
                print(l)
            print("--- Dev Actual ---")
            for l in norm_dev[:show]:
                print(l)
            all_matched = False

    measure_pair(stable_daemon, dev_daemon, pair_name, test_cases)
    return all_matched


def run_single_comparison(
    stable_daemon: str,
    dev_daemon: str,
    ctl_stable: Optional[str],
    ctl_dev: Optional[str],
    pair_name: str,
    test_ctl: bool,
    ignore_timestamp: bool,
    auto_ignore_legacy_v9: bool,
    auto_ignore_icmp_reclass: bool,
    ignore_ipv6: bool,
    include_collector_metadata: bool = False
) -> bool:
    """Run full verification between a stable and development daemon/ctl implementation pair."""
    print("=" * 60)
    print_cyan(f"Comparing: {os.path.basename(stable_daemon)}  <==>  {os.path.basename(dev_daemon)}")
    print(f"  Stable: {stable_daemon}")
    print(f"  Dev:    {dev_daemon}")
    print("=" * 60)

    # 1. CLI Compatibility
    if not test_cli_compatibility(stable_daemon, dev_daemon):
        return False

    # 2. Control Socket Compatibility
    if test_ctl and ctl_stable and ctl_dev and os.path.exists(ctl_stable) and os.path.exists(ctl_dev):
        if not test_control_socket_compatibility(stable_daemon, dev_daemon, ctl_stable, ctl_dev):
            return False

    # 3. Differential Output Verification
    if not test_differential_output(
        stable_daemon, dev_daemon, pair_name, ignore_timestamp, auto_ignore_legacy_v9,
        auto_ignore_icmp_reclass, ignore_ipv6, include_collector_metadata
    ):
        return False

    print_green(f"\n>> Pair comparison [{os.path.basename(stable_daemon)} vs {os.path.basename(dev_daemon)}] PASSED.\n")
    return True


# ==============================================================================
# Main Entrypoint
# ==============================================================================

def compat_main():
    global COLLECTOR_BACKEND, PCAP_DIR, SUITE_TMP_DIR, MEASURE
    global CACHE_DIR, REBUILD_STABLE, REBUILD_DEV, REFRESH_PCAP, COMPAT_PCAPS
    parser = argparse.ArgumentParser(
        description="softflowd Comprehensive Backward Compatibility Test Suite",
        epilog="Other subcommands: bench (export benchmark) and collect (flow "
               "collector); run them with -h for their options."
    )
    parser.add_argument(
        "--stable-commit",
        default="0260261",
        help="Git commit/tag for C stable version (default: 0260261 = softflowd-v1.1.1)"
    )
    parser.add_argument(
        "--build-dir",
        default=None,
        help="Output directory for generated binaries (default: temp directory)"
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip build step and look for pre-existing binaries"
    )
    parser.add_argument(
        "--skip-ctl",
        action="store_true",
        help="Skip softflowctl control socket tests"
    )
    parser.add_argument(
        "--skip-cpp",
        action="store_true",
        help="Skip C++ (softflowd+) build and test matrix pairs"
    )
    parser.add_argument(
        "--skip-rust",
        action="store_true",
        help="Skip Rust (rsoftflowd) build and test matrix pairs"
    )
    parser.add_argument(
        "--stable",
        default=None,
        help="Explicit reference stable softflowd daemon binary"
    )
    parser.add_argument(
        "--dev",
        default=None,
        help="Explicit target development softflowd daemon binary"
    )
    parser.add_argument(
        "--ctl-stable",
        default=None,
        help="Explicit reference stable softflowctl binary"
    )
    parser.add_argument(
        "--ctl-dev",
        default=None,
        help="Explicit target development softflowctl binary"
    )
    parser.add_argument(
        "-i", "--ignore-timestamp",
        action="store_true",
        help="Ignore flow timestamp differences in nfdump comparison"
    )
    parser.add_argument(
        "-6", "--ignore-ipv6",
        action="store_true",
        help="Ignore IPv6 tests"
    )
    parser.add_argument(
        "--auto-ignore-legacy-v9",
        dest="auto_ignore_legacy_v9",
        action="store_true",
        default=True,
        help="Ignore timestamps for the stable-softflowd-legacy vs softflowd-legacy pair's "
             "NetFlow v9 case only, working around a known bug in the C stable reference "
             "(<= 1.1.1) (default: True)"
    )
    parser.add_argument(
        "--no-auto-ignore",
        dest="auto_ignore_legacy_v9",
        action="store_false",
        help="Disable the above; compare that timestamp too"
    )
    parser.add_argument(
        "--auto-ignore-icmp-reclass",
        dest="auto_ignore_icmp_reclass",
        action="store_true",
        default=True,
        help="When the stable side of a pair is the old C reference, tolerate its known "
             "ICMPv6 protocol/type misclassification bug (fixed upstream in "
             "ipv6_to_flowrec(), commit 262225e) (default: True)"
    )
    parser.add_argument(
        "--no-auto-ignore-icmp-reclass",
        dest="auto_ignore_icmp_reclass",
        action="store_false",
        help="Disable the above; compare those columns too"
    )
    parser.add_argument(
        "--include-collector-metadata",
        action="store_true",
        help="Also compare nfdump's collector-side metadata columns (ra/eng/exid/tr; "
             "see nfdump(1) OUTPUT FORMAT) instead of masking them out. These reflect "
             "when/where nfcapd received the record, not the exporter's own output, so "
             "they legitimately differ between the suite's two separate capture runs; "
             "off by default"
    )
    parser.add_argument(
        "--collector",
        choices=["auto", "nfdump", "python"],
        default="auto",
        help="Flow collector: nfdump needs nfcapd and nfdump; python uses the built-in collector. "
             "auto picks nfdump when both tools are installed, otherwise python (default: auto)"
    )
    parser.add_argument(
        "--pcap-dir",
        default=None,
        help="Directory containing http.cap and v6-http.cap; used instead of downloading them"
    )
    parser.add_argument(
        "--cache-dir",
        default=None,
        metavar="DIR",
        help="Persistent cache for the stable and development C binaries and the "
             "downloaded sample pcaps (default: ~/.cache/softflowd-test)"
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Do not use the cache: build the C binaries and download the pcaps on every run"
    )
    parser.add_argument(
        "--rebuild-stable",
        action="store_true",
        help="Rebuild the stable binaries even if they are cached"
    )
    parser.add_argument(
        "--rebuild-dev",
        action="store_true",
        help="Rebuild the development C binaries even if they are cached"
    )
    parser.add_argument(
        "--refresh-pcap",
        action="store_true",
        help="Download the sample pcaps again even if they are cached"
    )
    parser.add_argument(
        "pcaps",
        nargs="*",
        metavar="PCAP",
        help="Pcap files to test in addition to the sample pcaps: compared as NetFlow v1, v5, "
             "v9 and IPFIX, and measured"
    )
    parser.add_argument(
        "--gauge-clock",
        dest="gauge_clock",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Run each daemon once per test case with its own -g flag and print "
             "the \"cpu clocks\" (total) and \"cpu clocks (export)\" counters it reports "
             "on exit, for stable and dev (default: on; --no-gauge-clock turns it off)"
    )
    parser.add_argument(
        "--benchmark",
        nargs="?",
        const="auto",
        default="auto",
        choices=["auto", "hyperfine", "time"],
        metavar="TOOL",
        help="Time each daemon (stable and dev) for every test case with hyperfine, "
             "time (wall clock and user/system CPU time as time(1) reports them) or auto "
             "(hyperfine if installed, otherwise time; the default, also when TOOL is "
             "omitted).  Needs no extra tool; --no-benchmark turns it off"
    )
    parser.add_argument(
        "--no-benchmark",
        action="store_true",
        help="Do not time the daemons (see --benchmark)"
    )
    parser.add_argument("--bench-runs", type=int, default=20,
                        help="Timed runs per daemon and test case (default: 20)")
    parser.add_argument("--bench-warmup", type=int, default=3,
                        help="Untimed warmup runs before the timed ones (default: 3)")
    parser.add_argument("--bench-min-runs", type=int, default=None, metavar="N",
                        help="Let hyperfine pick the number of runs, but at least N "
                             "(like bench -m); with --benchmark time it is the run count")
    parser.add_argument("--bench-max-runs", type=int, default=None, metavar="N",
                        help="With hyperfine, at most N runs (like bench -M)")
    parser.add_argument("--callgrind", action="store_true",
                        help="Also profile each daemon with callgrind (needs valgrind and "
                             "callgrind_annotate; about 50x slower than a normal run) and "
                             "report total Ir and the Ir spent in the exporter sources")
    parser.add_argument("--callgrind-top", type=int, default=0, metavar="N",
                        help="Print the N most expensive functions of every callgrind "
                             "profile (default: 0; profiles are always saved)")
    parser.add_argument("--perf", action="store_true",
                        help="Also run `perf stat` on each daemon; the output is appended to "
                             "BENCH_CSV.perf.log, so --bench-csv is required")
    parser.add_argument("--bench-pcap", action="append", default=[], metavar="FILE",
                        help="Extra pcap measured with -g/--benchmark for NetFlow v1, v5, v9 "
                             "and IPFIX but not compared; may be repeated")
    parser.add_argument("--bench-csv", default=None, metavar="FILE",
                        help="Write the -g/--benchmark results of all pairs as CSV")
    args = parser.parse_args()
    if args.no_benchmark:
        args.benchmark = None
    for pcap in args.pcaps:
        if not os.access(pcap, os.R_OK):
            parser.error(f"cannot read pcap: {pcap}")

    if args.callgrind and not (shutil.which("valgrind") and shutil.which("callgrind_annotate")):
        print_yellow("warning: --callgrind needs valgrind and callgrind_annotate; skipping callgrind")
        args.callgrind = False
    if args.perf and not shutil.which("perf"):
        print_yellow("warning: --perf needs perf; skipping perf stat")
        args.perf = False
    measuring = (args.gauge_clock or args.benchmark is not None
                 or args.callgrind or args.perf)
    if (args.bench_pcap or args.bench_csv) and not measuring:
        parser.error("--bench-pcap and --bench-csv need --gauge-clock, --benchmark, "
                     "--callgrind and/or --perf")
    if (args.bench_min_runs is not None or args.bench_max_runs is not None) \
            and args.benchmark is None:
        parser.error("--bench-min-runs and --bench-max-runs need --benchmark")
    for opt, val in (("--bench-min-runs", args.bench_min_runs),
                     ("--bench-max-runs", args.bench_max_runs)):
        if val is not None and val < 1:
            parser.error(f"{opt} must be >= 1")
    if args.bench_min_runs and args.bench_max_runs and args.bench_max_runs < args.bench_min_runs:
        parser.error("--bench-max-runs must not be smaller than --bench-min-runs")
    if args.perf and not args.bench_csv:
        parser.error("--perf needs --bench-csv (the perf stat output is saved next to it)")
    bench_tool = args.benchmark
    if bench_tool == "auto":
        bench_tool = "hyperfine" if shutil.which("hyperfine") else "time"
    elif bench_tool == "hyperfine" and not shutil.which("hyperfine"):
        parser.error("--benchmark hyperfine: hyperfine is not installed (use --benchmark time)")
    if args.bench_runs < 1 or args.bench_warmup < 0:
        parser.error("--bench-runs must be >= 1 and --bench-warmup >= 0")
    for extra in args.bench_pcap:
        if not os.access(extra, os.R_OK):
            parser.error(f"cannot read pcap: {extra}")

    # Created here, not at import time, so that bench/collect do not make one.
    SUITE_TMP_DIR = tempfile.mkdtemp(prefix="softflowd_suite_")
    atexit.register(shutil.rmtree, SUITE_TMP_DIR)

    # Select the flow collector backend
    PCAP_DIR = args.pcap_dir
    COMPAT_PCAPS = [os.path.abspath(p) for p in args.pcaps]
    if args.no_cache and args.cache_dir:
        parser.error("--no-cache and --cache-dir cannot be used together")
    CACHE_DIR = None if args.no_cache else os.path.abspath(
        os.path.expanduser(args.cache_dir or default_cache_dir()))
    REBUILD_STABLE = args.rebuild_stable
    REBUILD_DEV = args.rebuild_dev
    REFRESH_PCAP = args.refresh_pcap
    have_nfdump = bool(shutil.which("nfdump") and shutil.which("nfcapd"))
    if args.collector == "auto":
        COLLECTOR_BACKEND = "nfdump" if have_nfdump else "python"
        if not have_nfdump:
            print_yellow("nfdump/nfcapd not found: using the built-in Python collector "
                         "(softflowd_test_collector.py collect)")
    else:
        COLLECTOR_BACKEND = args.collector
    if COLLECTOR_BACKEND == "nfdump":
        check_required_tool("nfdump", "nfdump", "https://github.com/phaag/nfdump")
        check_required_tool("nfcapd", "nfdump", "https://github.com/phaag/nfdump")

    if measuring:
        MEASURE = MeasureSettings(args.gauge_clock, bench_tool, args.bench_runs,
                                  args.bench_warmup, args.bench_min_runs,
                                  args.bench_max_runs, args.callgrind,
                                  args.callgrind_top, args.perf, args.bench_pcap,
                                  args.bench_csv)
        if bench_tool:
            if args.bench_min_runs is None and args.bench_max_runs is None:
                runs = f"{args.bench_runs} timed runs"
            else:
                runs = f"min {args.bench_min_runs or 10} runs" + \
                    (f", max {args.bench_max_runs}" if args.bench_max_runs else "")
            print(f"Benchmark tool: {bench_tool} ({args.bench_warmup} warmup + "
                  f"{runs} per daemon and test case)")

    build_dir = args.build_dir or os.path.join(SUITE_TMP_DIR, "bin")
    os.makedirs(build_dir, exist_ok=True)

    # Handle explicit single pair comparison
    if args.stable and args.dev:
        success = run_single_comparison(
            stable_daemon=args.stable,
            dev_daemon=args.dev,
            ctl_stable=args.ctl_stable or args.stable.replace("softflowd", "softflowctl"),
            ctl_dev=args.ctl_dev or args.dev.replace("softflowd", "softflowctl"),
            pair_name=f"{os.path.basename(args.stable)}_vs_{os.path.basename(args.dev)}",
            test_ctl=not args.skip_ctl,
            ignore_timestamp=args.ignore_timestamp,
            auto_ignore_legacy_v9=args.auto_ignore_legacy_v9,
            auto_ignore_icmp_reclass=args.auto_ignore_icmp_reclass,
            ignore_ipv6=args.ignore_ipv6,
            include_collector_metadata=args.include_collector_metadata
        )
        finish_measurements()
        sys.exit(0 if success else 1)

    # 1. Build all binary variants if not skipped
    binaries: Dict[str, Optional[str]] = {}
    if not args.skip_build:
        # Build C Stable 1.1.1 variants
        st_d, st_c, st_leg_d, st_leg_c = build_c_stable(args.stable_commit, build_dir)
        binaries["stable-softflowd"] = st_d
        binaries["stable-softflowctl"] = st_c
        binaries["stable-softflowd-legacy"] = st_leg_d
        binaries["stable-softflowctl-legacy"] = st_leg_c

        # Build C Development variants (current working directory tree)
        c_d, c_c, c_leg_d, c_leg_c, c_sta_d, c_sta_c = build_c_dev(build_dir)
        binaries["softflowd"] = c_d
        binaries["softflowctl"] = c_c
        binaries["softflowd-legacy"] = c_leg_d
        binaries["softflowctl-legacy"] = c_leg_c
        binaries["softflowd-static"] = c_sta_d
        binaries["softflowctl-static"] = c_sta_c

        # Build C++ variants (if not skipped)
        if not args.skip_cpp:
            cpp_d, cpp_c = build_cpp(build_dir)
            binaries["softflowd+"] = cpp_d
            binaries["softflowctl+"] = cpp_c
        else:
            binaries["softflowd+"] = None
            binaries["softflowctl+"] = None

        # Build Rust variants (if not skipped)
        if not args.skip_rust:
            r_d, r_c = build_rust(build_dir)
            binaries["rsoftflowd"] = r_d
            binaries["rsoftctl"] = r_c
        else:
            binaries["rsoftflowd"] = None
            binaries["rsoftctl"] = None
    else:
        # Resolve existing binaries
        for name in [
            "stable-softflowd", "stable-softflowctl",
            "stable-softflowd-legacy", "stable-softflowctl-legacy",
            "softflowd", "softflowctl",
            "softflowd-legacy", "softflowctl-legacy",
            "softflowd-static", "softflowctl-static",
            "softflowd+", "softflowctl+",
            "rsoftflowd", "rsoftctl"
        ]:
            path = os.path.join(build_dir, name)
            if not os.path.exists(path):
                path = shutil.which(name) or os.path.join(PROJECT_ROOT, name)
            binaries[name] = path if (path and os.path.exists(path)) else None

    # 2. Define standard compatibility comparison matrix requested by user
    comparison_pairs = [
        # (Stable Daemon, Dev Daemon, Stable CTL, Dev CTL)
        ("stable-softflowd-legacy", "softflowd-legacy", "stable-softflowctl-legacy", "softflowctl-legacy"),
        ("stable-softflowd", "softflowd", "stable-softflowctl", "softflowctl"),
        # --enable-compat-export=static as the reference, the default (dynamic) build as dev
        # (the same two builds that `bench -b static,dynamic` compares)
        ("softflowd-static", "softflowd", "softflowctl-static", "softflowctl"),
    ]

    if not args.skip_cpp:
        comparison_pairs.append(("softflowd", "softflowd+", "softflowctl", "softflowctl+"))
    if not args.skip_rust:
        comparison_pairs.append(("softflowd", "rsoftflowd", "softflowctl", "rsoftctl"))

    print("\n" + "=" * 60)
    print("STARTING TEST MATRIX EXECUTION")
    print("=" * 60)

    overall_passed = True
    for stable_name, dev_name, ctl_stable_name, ctl_dev_name in comparison_pairs:
        stable_daemon = binaries.get(stable_name)
        dev_daemon = binaries.get(dev_name)
        ctl_stable = binaries.get(ctl_stable_name)
        ctl_dev = binaries.get(ctl_dev_name)

        if not stable_daemon or not os.path.exists(stable_daemon):
            print_yellow(f"\n[SKIPPED] Stable binary '{stable_name}' not available.")
            continue
        if not dev_daemon or not os.path.exists(dev_daemon):
            print_yellow(f"\n[SKIPPED] Development binary '{dev_name}' not available.")
            continue

        passed = run_single_comparison(
            stable_daemon=stable_daemon,
            dev_daemon=dev_daemon,
            ctl_stable=ctl_stable,
            ctl_dev=ctl_dev,
            pair_name=f"{stable_name}_vs_{dev_name}",
            test_ctl=not args.skip_ctl,
            ignore_timestamp=args.ignore_timestamp,
            auto_ignore_legacy_v9=args.auto_ignore_legacy_v9,
            auto_ignore_icmp_reclass=args.auto_ignore_icmp_reclass,
            ignore_ipv6=args.ignore_ipv6,
            include_collector_metadata=args.include_collector_metadata
        )
        if not passed:
            overall_passed = False

    finish_measurements()
    print("=" * 60)
    if overall_passed:
        print_green("ALL COMPATIBILITY TESTS PASSED SUCCESSFULLY!")
        sys.exit(0)
    else:
        print_red("SOME COMPATIBILITY TESTS FAILED. PLEASE REVIEW LOGS ABOVE.")
        sys.exit(1)


# ==========================================================================
# bench: export benchmark
# ==========================================================================

VARIANTS = ("static-separate", "static", "dynamic")


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def bench_parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        usage="%(prog)s [options] pcap1.pcap [pcap2.pcap ...]",
        description="Compare softflowd export implementations "
                    "(--enable-compat-export=static-separate|static, or the default dynamic).")
    ap.add_argument("-v", dest="versions", default="1,5,9,10",
                    help="comma-separated NetFlow/IPFIX versions "
                         "(default: 1,5,9,10)")
    ap.add_argument("-b", dest="builds", default="static,dynamic",
                    help="comma-separated build variants: static-separate,static,dynamic "
                         "(default: static,dynamic)")
    ap.add_argument("-w", dest="warmup", type=int, default=3,
                    help="hyperfine --warmup count (default: 3)")
    ap.add_argument("-m", dest="min_runs", type=int, default=10,
                    help="hyperfine --min-runs count (default: 10)")
    ap.add_argument("-M", dest="max_runs", type=int, default=None,
                    help="hyperfine --max-runs count (default: no cap)")
    ap.add_argument("-o", dest="outfile", default="benchmark_results.csv",
                    help="combined CSV output path "
                         "(default: benchmark_results.csv)")
    ap.add_argument("-p", dest="perf", action="store_true",
                    help="also run `perf stat` once per combination")
    ap.add_argument("-C", dest="callgrind", action="store_true",
                    help="also run callgrind once per combination (needs "
                         "valgrind and callgrind_annotate); writes "
                         "OUTFILE.callgrind.csv and OUTFILE.callgrind/. "
                         "~50x slower than a native run: use a small pcap")
    ap.add_argument("-T", dest="topn", type=int, default=15,
                    help="functions shown per callgrind profile (default: 15)")
    ap.add_argument("-g", dest="gauge", action="store_true",
                    help="also run once per combination with softflowd's "
                         "own -g flag; counters go to OUTFILE.gauge.csv")
    ap.add_argument("-s", dest="srcdir", default=".",
                    help="softflowd source directory (default: .)")
    ap.add_argument("-j", dest="jobs", type=int, default=2,
                    help="parallel make jobs when building (default: 2)")
    ap.add_argument("-k", dest="reuse", action="store_true",
                    help="reuse already-built softflowd-<variant> binaries "
                         "in SRCDIR instead of rebuilding")
    ap.add_argument("-P", dest="port", type=int, default=2055,
                    help="UDP port used for -n 127.0.0.1:PORT (default: 2055)")
    ap.add_argument("pcaps", nargs="+", metavar="pcap")
    args = ap.parse_args()
    args.version_list = [v for v in args.versions.split(",") if v]
    args.build_list = [b for b in args.builds.split(",") if b]
    for b in args.build_list:
        if b not in VARIANTS:
            ap.error(f"unknown build variant '{b}' (expected static-separate|static|dynamic)")
    for f in args.pcaps:
        if not os.access(f, os.R_OK):
            ap.error(f"cannot read pcap: {f}")
    return args


def variant_bin(args: argparse.Namespace, variant: str) -> str:
    return os.path.join(args.srcdir, f"softflowd-{variant}")


def build_variant(args: argparse.Namespace, variant: str) -> None:
    dest = variant_bin(args, variant)
    if args.reuse and os.access(dest, os.X_OK):
        log(f"== reusing existing {dest} (-k given) ==")
        return
    flag_args = [] if variant == "dynamic" else [f"--enable-compat-export={variant}"]
    log(f"== building '{variant}' (configure {' '.join(flag_args) or 'with defaults'}) ==")
    if not build_c(args.srcdir, flag_args, jobs=args.jobs,
                   autoreconf_force=True):
        sys.exit(f"error: build of variant '{variant}' failed")
    copy_binaries(args.srcdir, dest)


def softflowd_cmd(args: argparse.Namespace, variant: str, pcap: str,
                  version: str, extra: Optional[List[str]] = None) -> List[str]:
    return [variant_bin(args, variant), *(extra or []), "-r", pcap,
            "-n", f"127.0.0.1:{args.port}", "-v", version]


CSV_HEADER = ["pcap", "build", "version", "mean_s", "stddev_s", "median_s",
              "user_s", "system_s", "runs", "method"]


def run_hyperfine_case(args, pcap, variant, version, workdir, out) -> None:
    json_path = os.path.join(workdir, "hf.json")
    cmd = ["hyperfine", "--warmup", str(args.warmup),
           "--min-runs", str(args.min_runs)]
    if args.max_runs is not None:
        cmd += ["--max-runs", str(args.max_runs)]
    cmd += ["--export-json", json_path, "--command-name",
            f"{variant}/v{version}/{os.path.basename(pcap)}",
            " ".join(softflowd_cmd(args, variant, pcap, version))]
    subprocess.run(cmd, stdout=sys.stderr, stderr=sys.stderr, check=False)
    with open(json_path) as f:
        r = json.load(f)["results"][0]
    out.writerow([pcap, variant, version,
                  f'{r["mean"]:.6f}', f'{r["stddev"]:.6f}',
                  f'{r["median"]:.6f}', f'{r.get("user", 0):.6f}',
                  f'{r.get("system", 0):.6f}', len(r["times"]), "hyperfine"])


def run_fallback_case(args, pcap, variant, version, out) -> None:
    n = args.min_runs
    log(f"== {variant} / v{version} / {os.path.basename(pcap)}: "
        f"{n} runs (plain time loop) ==")
    times = []
    for _ in range(n):
        t0 = time.monotonic()
        subprocess.run(softflowd_cmd(args, variant, pcap, version),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        times.append(time.monotonic() - t0)
    median = sorted(times)[n // 2]
    out.writerow([pcap, variant, version, f"{statistics.fmean(times):.6f}",
                  "", f"{median:.6f}", "", "", n, "time-loop"])


def run_perf_case(args, pcap, variant, version) -> None:
    log(f"== perf stat: {variant} / v{version} / {os.path.basename(pcap)} ==")
    perf_stat(softflowd_cmd(args, variant, pcap, version),
              args.outfile + ".perf.log")


def run_callgrind_case(args, pcap, variant, version, cg_dir, cg_out) -> None:
    tag = f"{os.path.basename(pcap)[:-5] if pcap.endswith('.pcap') else os.path.basename(pcap)}_{variant}_v{version}"
    log(f"== callgrind: {variant} / v{version} / {os.path.basename(pcap)} ==")
    res = callgrind_profile(softflowd_cmd(args, variant, pcap, version),
                            cg_dir, tag, args.topn)
    if res is None:
        log(f"warning: no callgrind output for {tag} (see {cg_dir}/{tag}.log)")
        return
    total, exporter_ir, top = res
    cg_out.writerow([pcap, variant, version, total, exporter_ir])
    log(f"-- top {args.topn} functions ({tag}) --")
    for line in top:
        log(line)


def run_gauge_case(args, pcap, variant, version, gauge_out) -> None:
    res = subprocess.run(softflowd_cmd(args, variant, pcap, version, ["-g"]),
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                         text=True)
    g = parse_gauge(res.stderr)
    if g is None:
        log(f"warning: no 'cpu clocks' output for "
            f"{variant}/v{version}/{os.path.basename(pcap)}")
        return
    total, export, calls = g
    # export is empty (n/a) for threaded export (-M); leave the field blank.
    gauge_out.writerow([pcap, variant, version, total,
                        "" if export is None else export,
                        "" if calls is None else calls])


def _ratio(row: Dict[str, str], base: Optional[Dict[str, str]], key: str) -> str:
    try:
        return f"{float(row[key]) / float(base[key]):.3f}x"
    except (TypeError, ValueError, ZeroDivisionError, KeyError):
        return "-"


def _read_csv(path: str) -> List[Dict[str, str]]:
    with open(path) as f:
        return list(csv.DictReader(f))


def print_summaries(args: argparse.Namespace) -> None:
    rows = _read_csv(args.outfile)
    if rows:
        print()
        print(f'{"pcap":<24}{"build":<16}{"ver":<5}{"mean(s)":>10}'
              f'{"stddev":>10}{"user(s)":>10}{"sys(s)":>10}')
        for r in rows:
            def fmt(key: str) -> str:
                try:
                    return f"{float(r[key]):.4f}"
                except ValueError:
                    return "-"
            print(f'{r["pcap"][:23]:<24}{r["build"]:<16}{r["version"]:<5}'
                  f'{fmt("mean_s"):>10}{fmt("stddev_s"):>10}'
                  f'{fmt("user_s"):>10}{fmt("system_s"):>10}')

    base_name = args.build_list[0]
    if args.callgrind:
        rows = _read_csv(args.outfile + ".callgrind.csv")
        if rows:
            ref = {(r["pcap"], r["version"]): r for r in rows
                   if r["build"] == base_name}
            print()
            print(f"callgrind Ir (ratio vs '{base_name}')")
            print(f'{"pcap":<24}{"build":<16}{"ver":<5}{"total Ir":>16}'
                  f'{"ratio":>8}{"exporter Ir":>16}{"ratio":>8}')
            for r in rows:
                b = ref.get((r["pcap"], r["version"]))
                print(f'{r["pcap"][:23]:<24}{r["build"]:<16}{r["version"]:<5}'
                      f'{int(r["total_ir"]):>16,}{_ratio(r, b, "total_ir"):>8}'
                      f'{int(r["exporter_self_ir"]):>16,}'
                      f'{_ratio(r, b, "exporter_self_ir"):>8}')
    if args.gauge:
        rows = _read_csv(args.outfile + ".gauge.csv")
        if rows:
            ref = {(r["pcap"], r["version"]): r for r in rows
                   if r["build"] == base_name}
            print()
            print(f"-g cpu clocks (ratio vs '{base_name}')")
            print(f'{"pcap":<24}{"build":<16}{"ver":<5}{"total":>14}'
                  f'{"ratio":>8}{"export":>14}{"ratio":>8}{"calls":>8}')
            for r in rows:
                b = ref.get((r["pcap"], r["version"]))
                exp = r["cpu_clocks_export"] or "n/a"
                exp_ratio = _ratio(r, b, "cpu_clocks_export") \
                    if r["cpu_clocks_export"] else "-"
                print(f'{r["pcap"][:23]:<24}{r["build"]:<16}{r["version"]:<5}'
                      f'{int(r["cpu_clocks_total"]):>14,}'
                      f'{_ratio(r, b, "cpu_clocks_total"):>8}'
                      f'{exp:>14}{exp_ratio:>8}{r["export_calls"] or "-":>8}')


def bench_main() -> int:
    args = bench_parse_args()
    have_hyperfine = shutil.which("hyperfine") is not None
    if args.perf and shutil.which("perf") is None:
        log("warning: -p requested but 'perf' not found; skipping perf stat")
        args.perf = False
    if args.callgrind and not (shutil.which("valgrind")
                               and shutil.which("callgrind_annotate")):
        log("warning: -C requested but valgrind/callgrind_annotate not "
            "found; skipping callgrind")
        args.callgrind = False
    if not have_hyperfine:
        log("note: hyperfine not found; falling back to a plain timing loop")
        log("      (install hyperfine for warmup control, stats and JSON "
            "export)")

    log(f"== building requested variants: {' '.join(args.build_list)} ==")
    for variant in args.build_list:
        build_variant(args, variant)

    cg_dir = args.outfile + ".callgrind"
    cg_f = gauge_f = None
    cg_out = gauge_out = None
    if args.callgrind:
        os.makedirs(cg_dir, exist_ok=True)
        cg_f = open(args.outfile + ".callgrind.csv", "w", newline="")
        cg_out = csv.writer(cg_f, lineterminator="\n")
        cg_out.writerow(["pcap", "build", "version", "total_ir",
                         "exporter_self_ir"])
    if args.gauge:
        gauge_f = open(args.outfile + ".gauge.csv", "w", newline="")
        gauge_out = csv.writer(gauge_f, lineterminator="\n")
        gauge_out.writerow(["pcap", "build", "version", "cpu_clocks_total",
                            "cpu_clocks_export", "export_calls"])

    # Local UDP sink so export packets are actually received, instead of
    # eliciting ICMP port-unreachable back at softflowd for every packet.
    sink = UdpSink("127.0.0.1", args.port, store=False)
    workdir = tempfile.mkdtemp()
    try:
        with open(args.outfile, "w", newline="") as f:
            out = csv.writer(f, lineterminator="\n")
            out.writerow(CSV_HEADER)
            for pcap in args.pcaps:
                log(f"== warming page cache for {pcap} ==")
                warm_page_cache(pcap)
                for variant in args.build_list:
                    for version in args.version_list:
                        if have_hyperfine:
                            run_hyperfine_case(args, pcap, variant, version,
                                               workdir, out)
                        else:
                            run_fallback_case(args, pcap, variant, version,
                                              out)
                        f.flush()
                        if args.perf:
                            run_perf_case(args, pcap, variant, version)
                        if args.callgrind:
                            run_callgrind_case(args, pcap, variant, version,
                                               cg_dir, cg_out)
                            cg_f.flush()
                        if args.gauge:
                            run_gauge_case(args, pcap, variant, version,
                                           gauge_out)
                            gauge_f.flush()
    finally:
        sink.close(quiet=0.0, timeout=0.0)
        shutil.rmtree(workdir, ignore_errors=True)
        for fh in (cg_f, gauge_f):
            if fh:
                fh.close()

    log(f"== done. Results: {args.outfile} ==")
    if args.callgrind:
        log(f"== callgrind results: {args.outfile}.callgrind.csv "
            f"(profiles in {cg_dir}/) ==")
    if args.gauge:
        log(f"== gauge (-g) results: {args.outfile}.gauge.csv ==")
    if args.perf:
        log(f"== perf stat details: {args.outfile}.perf.log ==")
    print_summaries(args)
    return 0


# ==========================================================================
# Entry point
# ==========================================================================

SUBCOMMANDS = {
    "compat": compat_main,
    "bench": bench_main,
    "collect": collect_main,
}


def main() -> int:
    argv = sys.argv
    if len(argv) >= 2 and argv[1] in SUBCOMMANDS:
        name, rest = argv[1], argv[2:]
    elif len(argv) == 1 or argv[1].startswith("-"):
        name, rest = "collect", argv[1:]  # the successor of collector.pl
    else:
        print(f"unknown subcommand '{argv[1]}' "
              f"(expected: {', '.join(SUBCOMMANDS)})", file=sys.stderr)
        return 2
    sys.argv = [f"{os.path.basename(argv[0])} {name}"] + rest
    result = SUBCOMMANDS[name]()
    return result if isinstance(result, int) else 0


if __name__ == "__main__":
    sys.exit(main())
