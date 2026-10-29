#!/usr/bin/env python3
"""
softflowd_test_collector.py -- test, benchmark and collector tools for softflowd.

One self-contained script (standard library only) with three subcommands:

  tools/softflowd_test_collector.py collect [-p PORT] [-b ADDR] [-6]  flow collector (default)
  tools/softflowd_test_collector.py compat  [options] [PCAP...]       backward compatibility and variants
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
- Optionally (--ntopng) checks the ZMQ export for ntopng, which is not compared against a
  reference: see --ntopng below.

Default comparison matrix:
  1. stable-softflowd-legacy vs softflowd-legacy
  2. stable-softflowd vs softflowd
  3. softflowd-static vs softflowd
  4. softflowd-direct vs softflowd
  5. softflowd vs softflowd+ (skippable)
  6. softflowd vs rsoftflowd (skippable)

Each pair is A vs B: A is the comparison source (reference), B the target, and
the binary names are shown in the titles of the results.

Usage:
    tools/softflowd_test_collector.py compat [OPTIONS] [PCAP...]

Positional PCAP files are tested in addition to the sample pcaps: each one is
exported as NetFlow v1, v5, v9 and IPFIX by daemons A and B of each pair, the flows are compared, and the daemons are measured on it.  A pcap
that yields no flow records on either side (an IPv6-only pcap has none in v1 and
v5) is reported as skipped, not as a failure.

Options:
    --stable-commit HASH    : Git commit/tag for C stable version (default: 0260261)
    --build-dir DIR         : Directory for temporary builds (default: temporary dir)
    --skip-build            : Skip compiling binaries (assume pre-built)
    --skip-ctl              : Skip softflowctl control socket tests
    --skip-cpp              : Skip C++ tests / builds
    --skip-rust             : Skip Rust tests / builds
    --skip-psamp            : Skip the PSAMP sender and receiver comparison (step 4), which the
                              pairs softflowd-static and softflowd-direct vs softflowd run
    --psamp                 : Run that comparison for the --a/--b pair too (C builds only)
    --ntopng                : Also check -v ntopng (TLV, ntopng 6.0 or later) and -v ntopng-json
                              (JSON, 5.x or earlier) on the sample pcaps, the PCAP files and a
                              3000 flow pcap.  Needs libzmq and builds softflowd-ntopng
                              (--enable-ntopng --enable-ntopng-json).  Off by default
    --ntopng-bin PATH       : softflowd to check with --ntopng instead of building one (with
                              --skip-build softflowd-ntopng in the build directory is used)
    --ntopng-cpp-bin PATH   : softflowd+ built with -DSOFTFLOW_NTOPNG=ON, whose -v ntopng messages
                              --ntopng compares byte for byte with those of the C build (default:
                              build one, or with --skip-build softflowd+-ntopng in the build
                              directory; with --skip-cpp or if it is missing, not compared)
    --a PATH                : Explicit comparison source (A, reference) softflowd daemon binary
    --b PATH                : Explicit comparison target (B) softflowd daemon binary
    --ctl-a PATH            : Explicit comparison source (A) softflowctl binary
    --ctl-b PATH            : Explicit comparison target (B) softflowctl binary
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
                              counters it reports on exit, for A and B.
                              On by default; --no-gauge-clock turns it off
    --benchmark [TOOL]        : Time each daemon (A and B) for every test
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
                              sources (export*.c, ipfix.c, netflow*.c, psamp.c).  Needs valgrind and
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
benchmark -- compare softflowd's NetFlow/IPFIX export implementations across
one or more pcap files and NetFlow/IPFIX versions.  Options and output files
are those of the former benchmark_export.sh.

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
     (export*.c, ipfix.c, netflow*.c, psamp.c).
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
import calendar
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
import signal
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


# ==============================================================================
# Build Functions
# ==============================================================================

# (short name, description, configure arguments, binary name suffix)
C_BUILD_VARIANTS = [
    ("default", "default", [], ""),
    ("legacy", "legacy (--enable-legacy)", ["--enable-legacy"], "-legacy"),
    ("static", "static (--enable-compat-export=static)", ["--enable-compat-export=static"], "-static"),
    ("direct", "direct-copies (--enable-direct-copies)", ["--enable-direct-copies"], "-direct"),
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

    res = run_command(["cargo", "build", "--release"], cwd=rust_dir)
    if res.returncode != 0:
        print_yellow("Warning: cargo build --release failed for Rust version.")
        return None, None

    rust_daemon = os.path.join(rust_dir, "target", "release", "rsoftflowd")
    rust_ctl = os.path.join(rust_dir, "target", "release", "rsoftflowctl")

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

def test_cli_compatibility(a_bin: str, b_bin: str) -> bool:
    """Verify CLI options handling and return code compatibility."""
    print("  [Step 1] Verifying CLI Options...")
    a_name, b_name = os.path.basename(a_bin), os.path.basename(b_bin)

    p_a = subprocess.run([a_bin, "-z"], capture_output=True, text=True)
    p_b = subprocess.run([b_bin, "-z"], capture_output=True, text=True)

    if p_a.returncode == 0 or p_b.returncode == 0:
        print_red("    FAILED: Invalid CLI options should return non-zero exit code.")
        return False

    p_a_res = subprocess.run([a_bin, "-h"], capture_output=True, text=True)
    p_b_res = subprocess.run([b_bin, "-h"], capture_output=True, text=True)
    a_help = p_a_res.stdout + p_a_res.stderr
    b_help = p_b_res.stdout + p_b_res.stderr

    required_options = ["-i", "-r", "-t", "-m", "-n", "-p", "-c", "-v", "-L", "-T", "-d", "-D"]
    missing_a = [opt for opt in required_options if opt not in a_help]
    missing_b = [opt for opt in required_options if opt not in b_help]

    if missing_a or missing_b:
        print_red(
            f"    FAILED: Help strings missing key options. A ({a_name}) missing: {missing_a}, B ({b_name}) missing: {missing_b}"
        )
        # If the B daemon doesn't support -d / -D or similar, warn or handle gracefully depending on implementation
        if not missing_a and len(missing_b) > 0 and all(o in ["-d", "-D"] for o in missing_b):
            print_yellow(f"    Warning: B daemon ({b_name}) help output omitted daemon background flags (-d/-D), continuing...")
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
    a_daemon: str, b_daemon: str, ctl_a: str, ctl_b: str
) -> bool:
    """Verify control socket queries and cross-compatibility."""
    print("  [Step 2] Verifying Control Socket Cross-Connection...")
    a_name, b_name = os.path.basename(a_daemon), os.path.basename(b_daemon)
    ctl_a_name, ctl_b_name = os.path.basename(ctl_a), os.path.basename(ctl_b)

    sock_a = os.path.join(SUITE_TMP_DIR, "ctl_a.sock")
    sock_b = os.path.join(SUITE_TMP_DIR, "ctl_b.sock")

    # 1. Test daemon A
    proc_a, o_fd, o_path, o_dir = start_blocked_daemon(a_daemon, sock_a)
    try:
        res1 = subprocess.run([ctl_a, "-c", sock_a, "statistics"], capture_output=True, text=True, timeout=3)
        if res1.returncode != 0:
            print_red(f"    FAILED: {ctl_a_name} failed to query {a_name}: {res1.stderr}")
            return False

        try:
            subprocess.run([ctl_b, "-c", sock_a, "statistics"], capture_output=True, text=True, timeout=3)
        except Exception:
            pass
    finally:
        stop_blocked_daemon(proc_a, o_fd, o_path, o_dir)

    # 2. Test daemon B
    proc_b, n_fd, n_path, n_dir = start_blocked_daemon(b_daemon, sock_b)
    try:
        res4 = subprocess.run([ctl_b, "-c", sock_b, "statistics"], capture_output=True, text=True, timeout=3)
        if res4.returncode != 0:
            print_red(f"    FAILED: {ctl_b_name} failed to query {b_name}: {res4.stderr}")
            return False
    finally:
        stop_blocked_daemon(proc_b, n_fd, n_path, n_dir)

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


def _b_over_a(b: Optional[float], a: Optional[float]) -> str:
    """b / a as "0.87x"; "-" when either side is missing."""
    if not b or not a:
        return "-"
    return f"{b / a:.2f}x"


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


# The C++ version is built with -fsanitize=address,undefined and without optimization by default (the build
# type Debug of cpp/CMakeLists.txt), which makes it 10 times slower or more than the optimized C version: the
# start of the sanitizers alone takes about 10 ms. The measurements use an optimized build of it instead.
BUILD_OPTIMIZED_FOR_MEASURE = True


def is_sanitizer_build(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return b"__asan_init" in f.read()
    except OSError:
        return False


def optimized_daemon(daemon: str) -> str:
    """The daemon to measure: DAEMON, or if it is built with a sanitizer, an optimized build of cpp/."""
    if not is_sanitizer_build(daemon):
        return daemon
    out = os.path.join(tempfile.gettempdir(), "softflowd_cpp_release")
    cached = os.path.join(out, os.path.basename(daemon))
    if BUILD_OPTIMIZED_FOR_MEASURE:
        print_cyan(f"  [Measure] {os.path.basename(daemon)} is built with AddressSanitizer; building an optimized "
                   f"one in {out} for the measurements...")
        cpp_dir = os.path.join(PROJECT_ROOT, "cpp")
        if run_command(["cmake", "-S", cpp_dir, "-B", out, "-DCMAKE_BUILD_TYPE=Release"]).returncode == 0 \
                and run_command(["cmake", "--build", out, "-j", "--target", os.path.basename(daemon)]).returncode == 0 \
                and os.path.exists(cached):
            return cached
    elif os.path.exists(cached):
        return cached
    print_yellow(f"Warning: {os.path.basename(daemon)} is built with AddressSanitizer, so that its times and "
                 f"clocks are not comparable with an optimized build (cmake -DCMAKE_BUILD_TYPE=Release).")
    return daemon


def measure_pair(a_daemon: str, b_daemon: str, pair_name: str,
                 cases: List[Tuple[str, str, int]]) -> None:
    """Measure daemons A and B of a pair on the compat test cases
    (plus --bench-pcap files) and remember the results for the summary."""
    if MEASURE is None:
        return
    b_daemon = optimized_daemon(b_daemon)
    if MEASURE.min_runs is None and MEASURE.max_runs is None:
        runs_label = f"x{MEASURE.runs}"
    else:
        runs_label = f"min {MEASURE.min_runs or 10}" + \
            (f" max {MEASURE.max_runs}" if MEASURE.max_runs else "")
    what = [w for w, on in (("-g counters", MEASURE.gauge),
                            (f"{MEASURE.tool} {runs_label}", MEASURE.tool),
                            ("callgrind", MEASURE.callgrind),
                            ("perf stat", MEASURE.perf)) if on]
    a_name, b_name = os.path.basename(a_daemon), os.path.basename(b_daemon)
    print(f"  [Step 4] Measuring A={a_name} vs B={b_name} ({', '.join(what)})...")
    cases = list(cases)
    for extra in MEASURE.extra_pcaps:
        for version, label in ((1, "NetFlow v1"), (5, "NetFlow v5"),
                               (9, "NetFlow v9"), (10, "IPFIX")):
            cases.append((f"{os.path.basename(extra)} ({label})", extra, version))
    for name, pcap_path, version in cases:
        row: dict = {"pair": pair_name, "a": a_name, "b": b_name, "case": name,
                     "pcap": os.path.basename(pcap_path), "version": version}
        print(f"    - {name}")
        warm_page_cache(pcap_path)
        if MEASURE.gauge:
            row["gauge_a"] = run_gauge_capture(pcap_path, a_daemon, version)
            row["gauge_b"] = run_gauge_capture(pcap_path, b_daemon, version)
            print(f"        cpu clocks: A[{_fmt_gauge(row['gauge_a'])}]"
                  f"  B[{_fmt_gauge(row['gauge_b'])}]")
        if MEASURE.tool:
            row["time_a"] = measure_runtime(a_daemon, pcap_path, version)
            row["time_b"] = measure_runtime(b_daemon, pcap_path, version)
            ta, tb = row["time_a"], row["time_b"]
            print(f"        time:       A {_fmt_ms(ta)}  B {_fmt_ms(tb)}  "
                  f"B/A {_b_over_a(tb and tb['mean'], ta and ta['mean'])}")
        if MEASURE.callgrind:
            for side, daemon in (("a", a_daemon), ("b", b_daemon)):
                tag = f"{_slug(pair_name)}_{_slug(name)}_{side}"
                res = callgrind_profile(measure_cmd(daemon, pcap_path, version),
                                        MEASURE.cg_dir, tag, MEASURE.topn)
                row[f"cg_{side}"] = res[:2] if res else None
                if res and MEASURE.topn:
                    print(f"        top {MEASURE.topn} functions ({side}):")
                    for line in res[2]:
                        print("          " + line)
            ca, cb = row["cg_a"], row["cg_b"]
            print(f"        callgrind:  A {_fmt_ir(ca)}  B {_fmt_ir(cb)}  "
                  f"B/A {_b_over_a(cb and cb[0], ca and ca[0])}")
        if MEASURE.perf:
            for side, daemon in (("a", a_daemon), ("b", b_daemon)):
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
    header = ["pair", "a", "b", "case", "pcap", "version", "tool", "runs"]
    for side in ("a", "b"):
        header += [f"{side}_{k}_s" for k in CSV_STATS]
        header += [f"{side}_cpu_clocks_total", f"{side}_cpu_clocks_export",
                   f"{side}_export_calls", f"{side}_ir_total",
                   f"{side}_ir_exporter"]
    header += ["mean_ratio"]
    with open(path, "w", newline="") as f:
        out = csv.writer(f, lineterminator="\n")
        out.writerow(header)
        for r in rows:
            line = [r["pair"], r["a"], r["b"], r["case"], r["pcap"], r["version"],
                    tool or "", (r.get("time_a") or {}).get("runs", "")]
            for side in ("a", "b"):
                t = r.get(f"time_{side}") or {}
                line += [f"{t[k]:.6f}" if k in t else "" for k in CSV_STATS]
                g = r.get(f"gauge_{side}") or (None, None, None)
                line += ["" if v is None else v for v in g]
                c = r.get(f"cg_{side}") or (None, None)
                line += ["" if v is None else v for v in c]
            ta, tb = r.get("time_a"), r.get("time_b")
            line += [_b_over_a(tb and tb["mean"], ta and ta["mean"]).rstrip("x")]
            out.writerow(line)


def finish_measurements() -> None:
    """Print the A-vs-B summary, write --bench-csv and stop the sink."""
    if MEASURE is None:
        return
    try:
        if MEASURE.rows:
            print("\n" + "=" * 60)
            print("MEASUREMENT SUMMARY (B / A; below 1.00x means B is faster)")
            print("=" * 60)
            for pair in dict.fromkeys(r["pair"] for r in MEASURE.rows):
                pair_rows = [x for x in MEASURE.rows if x["pair"] == pair]
                a_name, b_name = pair_rows[0]["a"], pair_rows[0]["b"]
                print(f"\n[A={a_name}  B={b_name}]")
                headers = ["case"]
                if MEASURE.tool:
                    headers += [f"A:{a_name} ms", f"B:{b_name} ms", "B/A time"]
                if MEASURE.gauge:
                    headers += [f"A:{a_name} clk", f"B:{b_name} clk", "B/A clk", "B/A export clk"]
                if MEASURE.callgrind:
                    headers += [f"A:{a_name} Ir", f"B:{b_name} Ir", "B/A Ir", "B/A exporter Ir"]
                table = []
                for r in pair_rows:
                    line = [r["case"]]
                    if MEASURE.tool:
                        ta, tb = r["time_a"], r["time_b"]
                        line += [f"{ta['mean'] * 1000:.3f}" if ta else "failed",
                                 f"{tb['mean'] * 1000:.3f}" if tb else "failed",
                                 _b_over_a(tb and tb["mean"], ta and ta["mean"])]
                    if MEASURE.gauge:
                        ga, gb = r["gauge_a"], r["gauge_b"]
                        line += [str(ga[0]) if ga else "-", str(gb[0]) if gb else "-",
                                 _b_over_a(gb and gb[0], ga and ga[0]),
                                 _b_over_a(gb and gb[1], ga and ga[1])]
                    if MEASURE.callgrind:
                        ca, cb = r["cg_a"], r["cg_b"]
                        line += [f"{ca[0]:,}" if ca else "failed",
                                 f"{cb[0]:,}" if cb else "failed",
                                 _b_over_a(cb and cb[0], ca and ca[0]),
                                 _b_over_a(cb and cb[1], ca and ca[1])]
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
    a_daemon: str,
    b_daemon: str,
    pair_name: str,
    ignore_timestamp: bool,
    auto_ignore_legacy_v9: bool,
    auto_ignore_icmp_reclass: bool,
    ignore_ipv6: bool,
    include_collector_metadata: bool = False
) -> bool:
    """Compare nfdump output across NetFlow v1, v5, v9 and IPFIX."""
    print(f"  [Step 3] Verifying Differential Packet Export ({COLLECTOR_BACKEND} collector)...")
    a_name, b_name = os.path.basename(a_daemon), os.path.basename(b_daemon)

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

        csv_a = run_capture(pcap_path, a_daemon, version)
        norm_a = normalize_nfdump_csv(csv_a, should_ignore_ts, include_collector_metadata, norm_icmp)

        csv_b = run_capture(pcap_path, b_daemon, version)
        norm_b = normalize_nfdump_csv(csv_b, should_ignore_ts, include_collector_metadata, norm_icmp)

        display_name = name
        if should_ignore_ts and not ignore_timestamp:
            display_name += " [timestamp ignored: known stable-legacy NetFlow v9 bug]"
        if norm_icmp:
            display_name += " [ICMPv6 protocol/dest-port tolerance active]"

        if norm_a == norm_b and len(norm_a) > 0:
            print(f"    - {display_name}: MATCHED ({len(norm_a)} records)")
        elif norm_a == norm_b and pcap_path in COMPAT_PCAPS:
            # e.g. an IPv6-only pcap exported as NetFlow v1/v5, which carry no IPv6
            print_yellow(f"    - {display_name}: SKIPPED (no flow records on either side)")
        else:
            print_red(f"    - {display_name}: FAILED (Records: A={len(norm_a)}, B={len(norm_b)})")
            show = max(len(norm_a), len(norm_b), 3)
            show = min(show, 20)  # cap so a large real regression doesn't flood the terminal
            print(f"--- A Expected ({a_name}) ---")
            for l in norm_a[:show]:
                print(l)
            print(f"--- B Actual ({b_name}) ---")
            for l in norm_b[:show]:
                print(l)
            all_matched = False

    measure_pair(a_daemon, b_daemon, pair_name, test_cases)
    return all_matched


# ==========================================================================
# PSAMP: softflowd -v psamp (sender) and softflowd -R (receiver)
# ==========================================================================
# psamp_roundtrip() and psamp_compare() are also used by tools/psamp_regress.py.

# Largest frame section of a PSAMP packet: IPFIX_SOFTFLOWD_MAX_PACKET_SIZE (1428)
# - IPFIX header (16) - set header (4) - selectionSequenceId (8)
# - observationTimeMicroseconds (8) - sectionExportedOctets (2); see psamp.c.
PSAMP_MAX_FRAME = 1390
PSAMP_TEMPLATE_ID = 3072
IPFIX_TEMPLATE_SET_ID = 2
# Columns of datagrams_to_csv() that depend on the wall clock: ts and te.
PSAMP_CSV_SKIP_COLUMNS = 2
# Packets of the pcap files of the PSAMP tests: more datagrams can overflow the
# UDP receive buffer of the receiver and make the result vary.
PSAMP_TEST_PACKETS = 50

PSAMP_RECEIVER_TIMEOUTS = [
    "general=86400", "tcp=86400", "tcp.rst=86400", "tcp.fin=86400",
    "udp=86400", "icmp=86400", "maxlife=86400", "expint=86400"]


def pcap_head(path: str, count: int) -> bytes:
    """The first `count` packets of a (little endian) pcap file."""
    with open(path, "rb") as f:
        data = f.read()
    out = bytearray(data[:24])
    off = 24
    for _ in range(count):
        if off + 16 > len(data):
            break
        length = struct.unpack("<I", data[off + 8:off + 12])[0]
        out += data[off:off + 16 + length]
        off += 16 + length
    return bytes(out)


def pcap_sized(sizes: Sequence[int], first_ts: int = 1000) -> bytes:
    """UDP/IPv4 packets whose Ethernet frames are `sizes` bytes long; packet i has the time first_ts + i."""
    eth = bytes.fromhex("00112233445566778899aabb0800")
    out = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for i, n in enumerate(sizes):
        payload = b"U" * (n - 42)
        udp = struct.pack(">HHHH", 1234, 53, 8 + len(payload), 0) + payload
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                         socket.inet_aton("10.0.0.1"), socket.inet_aton("10.0.0.2"))
        frame = eth + ip + udp
        out += struct.pack("<IIII", first_ts + i, 0, len(frame), len(frame)) + frame
    return out


def psamp_datagram(frame: bytes, stated_octets: int) -> bytes:
    """A PSAMP data message as softflowd sends it, but with a frame section that is not padded."""
    body = (struct.pack(">Q", 1) + struct.pack(">II", 0x83aa7e80 + 1000, 0) +
            struct.pack(">H", stated_octets) + frame)
    return (struct.pack(">HHIII", 10, 20 + len(body), 1000, 0, 0) +
            struct.pack(">HH", PSAMP_TEMPLATE_ID, 4 + len(body)) + body)


def psamp_make_pcaps(directory: str) -> Dict[str, str]:
    """Write the pcap files of the PSAMP tests to `directory`: v4s, v6s and sizes."""
    pcaps = {}
    gen = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gen_ci_smoke_pcap.py")
    for name, flags in (("v4", []), ("v6", ["-6"])):
        full = os.path.join(directory, name + ".pcap")
        subprocess.run([sys.executable, gen] + flags + [full], check=True, capture_output=True)
        small = os.path.join(directory, name + "s.pcap")
        with open(small, "wb") as f:
            f.write(pcap_head(full, PSAMP_TEST_PACKETS))
        pcaps[name + "s"] = small
    sized = os.path.join(directory, "sizes.pcap")
    with open(sized, "wb") as f:
        f.write(pcap_sized([60, 1389, PSAMP_MAX_FRAME, PSAMP_MAX_FRAME + 1, PSAMP_MAX_FRAME + 2, 1514]))
    pcaps["sizes"] = sized
    return pcaps


def psamp_messages(datagrams: Sequence[bytes]) -> List[Tuple[str, int, int, bytes]]:
    """(kind, sequence number, export time, datagram) of IPFIX messages; kind is T (template) or D (data)."""
    out = []
    for d in datagrams:
        _, _, export_time, seq, _ = struct.unpack(">HHIII", d[:16])
        set_id = struct.unpack(">H", d[16:18])[0]
        out.append(("T" if set_id == IPFIX_TEMPLATE_SET_ID else "D", seq, export_time, d))
    return out


def psamp_data_payloads(datagrams: Sequence[bytes]) -> List[bytes]:
    """The data messages without the IPFIX message header: independent of the template, the sequence number and the time."""
    return [d[16:] for kind, _, _, d in psamp_messages(datagrams) if kind == "D"]


def psamp_flows(datagrams: Sequence[bytes]) -> List[str]:
    """Sorted flow rows of exported datagrams without the wall-clock columns."""
    rows = datagrams_to_csv([(d, "x") for d in datagrams]).splitlines()[1:]
    return sorted(",".join(r.split(",")[PSAMP_CSV_SKIP_COLUMNS:]) for r in rows)


def _psamp_work_dir() -> str:
    global SUITE_TMP_DIR
    if not SUITE_TMP_DIR:
        SUITE_TMP_DIR = tempfile.mkdtemp(prefix="softflowd-psamp-")
    return SUITE_TMP_DIR


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def psamp_send(daemon: str, pcap: str, extra: Sequence[str] = ()) -> List[bytes]:
    """The PSAMP datagrams of `daemon -r PCAP -v psamp`."""
    sink = UdpSink("127.0.0.1", 0)
    try:
        subprocess.run([daemon, "-d", "-r", pcap, "-v", "psamp", *extra,
                        "-n", f"127.0.0.1:{sink.port}",
                        "-c", os.path.join(_psamp_work_dir(), f"psamp-tx-{sink.port}.ctl")],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=60)
    finally:
        sink.close()
    return [d for d, _ in sink.datagrams]


def psamp_ctl(ctl: str, ctl_path: str, command: str, timeout: float = 3.0) -> Optional[str]:
    """Output of softflowctl, or None if softflowd did not answer in time."""
    try:
        r = subprocess.run([ctl, "-c", ctl_path, command], capture_output=True,
                           stdin=subprocess.DEVNULL, timeout=timeout)
        return r.stdout.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return None


def psamp_roundtrip(daemon: str, ctl: str, pcap: str, version: int, wake: bool = True,
                    inject: Sequence[bytes] = (), stats: bool = False
                    ) -> Tuple[List[bytes], Optional[str], Optional[int], bool]:
    """Sender (-v psamp) -> receiver (-R) -> collector.

    The receiver runs with -a: the pcap files are from 1970, and with the
    current time it would expire the flows as soon as it looks at the timeouts.
    wake    send a short datagram at the end; the receiver of an old build blocks
            in recv() after the last datagram and does not serve softflowctl
            before another one arrives.
    inject  more datagrams for the receiver.
    stats   also ask softflowctl for the statistics.
    Returns (datagrams exported by the receiver, statistics or None, exit status, hung).
    """
    work = _psamp_work_dir()
    collector = UdpSink("127.0.0.1", 0)
    rx_port = _free_udp_port()
    ctl_path = os.path.join(work, f"psamp-rx-{rx_port}.ctl")
    cmd = [daemon, "-d", "-a", "-R", str(rx_port), "-n", f"127.0.0.1:{collector.port}",
           "-v", str(version), "-c", ctl_path]
    for t in PSAMP_RECEIVER_TIMEOUTS:
        cmd += ["-t", t]
    rx = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, start_new_session=True)
    stat = None
    hung = False
    try:
        for _ in range(50):  # wait for the control socket
            if os.path.exists(ctl_path):
                break
            time.sleep(0.1)
        subprocess.run([daemon, "-d", "-r", pcap, "-v", "psamp", "-n", f"127.0.0.1:{rx_port}",
                        "-c", os.path.join(work, f"psamp-tx-{rx_port}.ctl")],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=60)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            for d in inject:
                sender.sendto(d, ("127.0.0.1", rx_port))
            time.sleep(0.8)
            if wake:
                sender.sendto(b"x", ("127.0.0.1", rx_port))
                time.sleep(0.3)
        if stats:
            stat = psamp_ctl(ctl, ctl_path, "statistics")
        psamp_ctl(ctl, ctl_path, "shutdown")
        try:
            rx.wait(timeout=5)
        except subprocess.TimeoutExpired:
            hung = True
            rx.kill()
            rx.wait()
    finally:
        if rx.poll() is None:
            rx.kill()
            rx.wait()
        collector.close()
    return [d for d, _ in collector.datagrams], stat, rx.returncode, hung


def psamp_compare(a_daemon: str, b_daemon: str, ctl_a: str, ctl_b: str,
                  pcaps: Dict[str, str], report) -> None:
    """Compare what A and B send and receive as PSAMP; report(ok, text) gets one line per case.

    send       the data messages of `-v psamp` must be byte-identical (the template
               messages and the message header are left out).
    roundtrip  the flows that a receiver exports after receiving the PSAMP datagrams
               of the same build, as NetFlow v5, v9 and IPFIX, must be identical.
    """
    for name, pcap in pcaps.items():
        a, b = psamp_data_payloads(psamp_send(a_daemon, pcap)), psamp_data_payloads(psamp_send(b_daemon, pcap))
        report(bool(a) and a == b, f"PSAMP send {name}: {len(a)} / {len(b)} data messages")
    for name in ("v4s", "v6s"):
        for version in (5, 9, 10):
            a = psamp_flows(psamp_roundtrip(a_daemon, ctl_a, pcaps[name], version)[0])
            b = psamp_flows(psamp_roundtrip(b_daemon, ctl_b, pcaps[name], version)[0])
            # IPv6 flows cannot be exported as NetFlow v5: no flows on both sides is a pass.
            report(a == b, f"PSAMP receive {name} (version {version}): {len(a)} / {len(b)} flows")


def test_psamp_compat(a_daemon: str, b_daemon: str, ctl_a: Optional[str], ctl_b: Optional[str]) -> bool:
    """Compat step: the PSAMP sender and receiver of A and B.  For C and C++ builds: the Rust PSAMP records differ."""
    print("  [Step 4] Verifying PSAMP export and receive...")
    if not (ctl_a and ctl_b and os.path.exists(ctl_a) and os.path.exists(ctl_b)):
        print_yellow("    - SKIPPED (softflowctl is needed to stop the PSAMP receiver)")
        return True
    pcaps = psamp_make_pcaps(tempfile.mkdtemp(dir=_psamp_work_dir()))
    ok = [True]

    def report(passed: bool, text: str) -> None:
        if passed:
            print(f"    - {text}: MATCHED")
        else:
            print_red(f"    - {text}: FAILED")
            ok[0] = False

    psamp_compare(a_daemon, b_daemon, ctl_a, ctl_b, pcaps, report)
    return ok[0]


# ==========================================================================
# ntopng: check the ZMQ export (compat --ntopng)
# ==========================================================================
#
# softflowd is a ZMQ PUB socket that connects, as with `ntopng -i
# "tcp://*:5556c"`.  This side binds a TCP port and speaks just enough ZMTP 3.0
# to act as the SUB socket, then decodes every message the way ntopng does:
#   -v ntopng       zmq_msg_hdr_v4 (36 bytes, TLV flag) + nDPI serializer TLV
#   -v ntopng-json  zmq_msg_hdr_v2 (24 bytes) + JSON, for ntopng 5.x or earlier

NTOPNG_NAMES = {1: "IN_BYTES", 2: "IN_PKTS", 4: "PROTOCOL", 6: "TCP_FLAGS",
                7: "L4_SRC_PORT", 8: "IPV4_SRC_ADDR", 11: "L4_DST_PORT",
                12: "IPV4_DST_ADDR", 21: "LAST_SWITCHED", 22: "FIRST_SWITCHED",
                23: "OUT_BYTES", 24: "OUT_PKTS", 27: "IPV6_SRC_ADDR",
                28: "IPV6_DST_ADDR", 56: "IN_SRC_MAC", 57: "OUT_DST_MAC",
                58: "SRC_VLAN", 59: "DST_VLAN"}
NTOPNG_REQUIRED = (7, 11, 1, 2, 23, 24, 22, 21, 4)
NTOPNG_FLAG_IS_TLV = 1 << 1
NTOPNG_FLAG_IS_COMPRESSED = 1 << 2
NTOPNG_HDR_V4_LEN, NTOPNG_HDR_V2_LEN = 36, 24
NTOPNG_MAX_PAYLOAD = 131072  # CONST_ZMQ_PAYLOAD_LEN of ntopng
NTOPNG_DIALECTS = ("ntopng", "ntopng-json")


class NtopngFailure(Exception):
    pass


def ntopng_pcap_time_range(path: str) -> Optional[Tuple[int, int]]:
    """First and last packet time (seconds) of a classic pcap, None for others."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif data[:4] in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        return None
    pos, first, last = 24, None, None
    while pos + 16 <= len(data):
        sec, _, caplen, _ = struct.unpack(endian + "IIII", data[pos:pos + 16])
        first = sec if first is None else first
        last = sec
        pos += 16 + caplen
    return None if first is None else (first, last)


def _zmq_recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise EOFError
        data += chunk
    return data


def _zmq_read_frame(sock: socket.socket) -> Tuple[int, bytes]:
    flags = _zmq_recv_exact(sock, 1)[0]
    if flags & 0x02:
        size = struct.unpack("!Q", _zmq_recv_exact(sock, 8))[0]
    else:
        size = _zmq_recv_exact(sock, 1)[0]
    return flags, _zmq_recv_exact(sock, size)


def _zmq_sub_handshake(conn: socket.socket) -> None:
    """ZMTP 3.0 with the NULL mechanism, then subscribe to everything."""
    conn.sendall(b"\xff" + b"\x00" * 8 + b"\x7f" + b"\x03\x00" +
                 b"NULL".ljust(20, b"\x00") + b"\x00" + b"\x00" * 31)
    peer = _zmq_recv_exact(conn, 64)
    if peer[0] != 0xff or peer[9] != 0x7f or peer[10] < 3:
        raise NtopngFailure("the peer does not speak ZMTP 3.x")
    ready = b"\x05READY" + b"\x0bSocket-Type" + struct.pack("!I", 3) + b"SUB"
    conn.sendall(bytes([0x04, len(ready)]) + ready)
    flags, body = _zmq_read_frame(conn)
    if not flags & 0x04 or body[1:6] != b"READY":
        raise NtopngFailure("no READY command from the peer")
    conn.sendall(bytes([0x00, 1, 0x01]))


def ntopng_decode_header(hdr: bytes) -> dict:
    """Decode a zmq_msg_hdr_v4 (36 bytes) or zmq_msg_hdr_v2 (24 bytes)."""
    if len(hdr) == NTOPNG_HDR_V4_LEN:
        url, ver, flags, size, comp, msg_id = struct.unpack("!16sBB2xIII", hdr[:32])
        return dict(url=url.rstrip(b"\0"), version=ver, flags=flags, size=size,
                    msg_id=msg_id)
    if len(hdr) == NTOPNG_HDR_V2_LEN:
        url, ver, _, size, msg_id = struct.unpack("!16sBBHI", hdr)
        return dict(url=url.rstrip(b"\0"), version=ver, flags=0, size=size,
                    msg_id=msg_id)
    raise NtopngFailure(f"unexpected header length {len(hdr)}")


def ntopng_decode_tlv(data: bytes) -> List[dict]:
    """Decode the nDPI serializer TLV format into a list of records."""
    if data[:2] != b"\x01\x01":
        raise NtopngFailure(f"bad TLV preamble {data[:2]!r}")
    uint_len = {2: 1, 3: 2, 4: 4, 5: 8}
    pos, records, rec = 2, [], {}
    while pos < len(data):
        t = data[pos]
        pos += 1
        if t == 1:  # end of record
            records.append(rec)
            rec = {}
            continue
        kt, vt = t >> 4, t & 0x0f
        if kt not in uint_len or kt == 5:
            raise NtopngFailure(f"unsupported key type {kt} at {pos - 1}")
        key = int.from_bytes(data[pos:pos + uint_len[kt]], "big")
        pos += uint_len[kt]
        if vt in uint_len:
            val = int.from_bytes(data[pos:pos + uint_len[vt]], "big")
            pos += uint_len[vt]
        elif vt == 11:
            slen = int.from_bytes(data[pos:pos + 2], "big")
            val = data[pos + 2:pos + 2 + slen].decode()
            pos += 2 + slen
        else:
            raise NtopngFailure(f"unsupported value type {vt} at {pos - 1}")
        if pos > len(data):
            raise NtopngFailure("truncated TLV item")
        rec[key] = val
    if rec:
        raise NtopngFailure("the last record has no end of record marker")
    return records


def ntopng_decode_json(data: bytes) -> List[dict]:
    try:
        arr = json.loads(data)
    except ValueError as e:
        raise NtopngFailure(f"invalid JSON: {e}")
    if not isinstance(arr, list):
        raise NtopngFailure("the JSON payload is not an array")
    return [{int(k): v for k, v in flow.items()} for flow in arr]


def ntopng_check_record(rec: dict, where: str, bounds: Tuple[int, int]) -> None:
    for key in NTOPNG_REQUIRED:
        if key not in rec:
            raise NtopngFailure(f"{where}: missing {NTOPNG_NAMES[key]}")
    v4 = 8 in rec and 12 in rec
    v6 = 27 in rec and 28 in rec
    if v4 == v6:
        raise NtopngFailure(f"{where}: need either IPv4 or IPv6 addresses")
    for key in (7, 11):
        if not isinstance(rec[key], int) or not 0 <= rec[key] <= 65535:
            raise NtopngFailure(f"{where}: bad {NTOPNG_NAMES[key]} {rec[key]!r}")
    for key, family in ((8, socket.AF_INET), (12, socket.AF_INET),
                        (27, socket.AF_INET6), (28, socket.AF_INET6)):
        if key in rec:
            socket.inet_pton(family, rec[key])
    # Epoch seconds within the pcap, not milliseconds since boot.
    first, last = rec[22], rec[21]
    if not bounds[0] <= first <= last <= bounds[1]:
        raise NtopngFailure(f"{where}: timestamps first={first!r} last={last!r}, epoch "
                            f"seconds within {bounds[0]}..{bounds[1]} expected")
    if rec[2] + rec[24] == 0:
        raise NtopngFailure(f"{where}: flow without packets")
    if rec[1] < rec[2] or rec[23] < rec[24]:
        raise NtopngFailure(f"{where}: fewer bytes than packets")
    if rec[4] > 255:
        raise NtopngFailure(f"{where}: bad protocol {rec[4]!r}")


def ntopng_check_messages(messages: List[List[bytes]], dialect: str,
                          bounds: Tuple[int, int]) -> int:
    """Check all messages, return the number of flow records."""
    if not messages:
        raise NtopngFailure("no message received")
    total, prev_id = 0, None
    for i, parts in enumerate(messages):
        where = f"message {i}"
        if len(parts) != 2:
            raise NtopngFailure(f"{where}: {len(parts)} frames, expected 2")
        hdr, payload = ntopng_decode_header(parts[0]), parts[1]
        if hdr["url"] != b"flow":
            raise NtopngFailure(f"{where}: topic {hdr['url']!r}, expected flow")
        if prev_id is not None and hdr["msg_id"] != (prev_id + 1) & 0xffffffff:
            raise NtopngFailure(f"{where}: msg_id {hdr['msg_id']} does not follow {prev_id}")
        prev_id = hdr["msg_id"]
        if len(payload) > NTOPNG_MAX_PAYLOAD:
            raise NtopngFailure(f"{where}: payload of {len(payload)} bytes is too large")
        if hdr["size"] != len(payload):
            raise NtopngFailure(f"{where}: header size {hdr['size']}, payload {len(payload)} bytes")
        if dialect == "ntopng":
            if len(parts[0]) != NTOPNG_HDR_V4_LEN or hdr["version"] != 4 \
                    or hdr["flags"] & NTOPNG_FLAG_IS_COMPRESSED \
                    or not hdr["flags"] & NTOPNG_FLAG_IS_TLV:
                raise NtopngFailure(f"{where}: expected a v4 header (version 4, TLV flag)")
            records = ntopng_decode_tlv(payload)
        else:
            if len(parts[0]) != NTOPNG_HDR_V2_LEN or hdr["version"] != 2:
                raise NtopngFailure(f"{where}: expected a v2 header (24 bytes, version 2)")
            records = ntopng_decode_json(payload)
        if not records:
            raise NtopngFailure(f"{where}: no flow records")
        for n, rec in enumerate(records):
            ntopng_check_record(rec, f"{where} record {n}", bounds)
        total += len(records)
    return total


def ntopng_export(daemon: str, dialect: str, pcap: str,
                   extra: Sequence[str] = ()) -> List[List[bytes]]:
    """Run daemon -v DIALECT on pcap and return the received ZMQ messages.

    A ZMQ PUB socket drops what it sends before the subscription is in place,
    and a pcap is read and exported within milliseconds.  So the pcap is fed
    through stdin: its file header first (softflowd reads it before it
    connects), the packets once the subscription is established.
    """
    with open(pcap, "rb") as f:
        data = f.read()
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    srv.settimeout(15)
    proc = subprocess.Popen([daemon, "-r", "-", "-n", f"127.0.0.1:{srv.getsockname()[1]}",
                             "-v", dialect, *extra], stdin=subprocess.PIPE,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    messages: List[List[bytes]] = []
    try:
        proc.stdin.write(data[:24])
        proc.stdin.flush()
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            raise NtopngFailure("softflowd did not connect (built without ntopng support?)")
        with conn:
            conn.settimeout(15)
            _zmq_sub_handshake(conn)
            time.sleep(0.5)
            proc.stdin.write(data[24:])
            proc.stdin.close()
            conn.settimeout(0.5)
            parts: List[bytes] = []
            last_rx, deadline = time.time(), time.time() + 120
            while time.time() < deadline:
                try:
                    flags, body = _zmq_read_frame(conn)
                except socket.timeout:
                    if time.time() - last_rx > (1 if proc.poll() is not None else 5):
                        break
                    continue
                except EOFError:
                    break
                last_rx = time.time()
                if flags & 0x04:  # command, for example PING
                    continue
                parts.append(body)
                if not flags & 0x01:
                    messages.append(parts)
                    parts = []
    finally:
        srv.close()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    return messages


def ntopng_resolve_daemon(args: argparse.Namespace, build_dir: str) -> Optional[str]:
    """The softflowd built with --enable-ntopng --enable-ntopng-json."""
    if args.ntopng_bin:
        return args.ntopng_bin
    daemon = os.path.join(build_dir, "softflowd-ntopng")
    if args.skip_build:
        found = daemon if os.path.exists(daemon) else shutil.which("softflowd-ntopng")
        return found or None
    print("  -> Configuring and building C development ntopng "
          "(--enable-ntopng --enable-ntopng-json)...")
    if not build_c(PROJECT_ROOT, ["--enable-ntopng", "--enable-ntopng-json"]):
        print_red("Failed to build softflowd with ntopng support (libzmq is needed, "
                  "for example libzmq3-dev).")
        return None
    copy_binaries(PROJECT_ROOT, daemon)
    return daemon


def ntopng_resolve_cpp_daemon(args: argparse.Namespace, build_dir: str) -> Optional[str]:
    """The softflowd+ built with -DSOFTFLOW_NTOPNG=ON, or None if there is none."""
    if args.ntopng_cpp_bin:
        return args.ntopng_cpp_bin
    if args.skip_cpp:
        return None
    daemon = os.path.join(build_dir, "softflowd+-ntopng")
    if args.skip_build:
        return daemon if os.path.exists(daemon) else None
    print("  -> Configuring and building C++ ntopng (-DSOFTFLOW_NTOPNG=ON)...")
    out = os.path.join(SUITE_TMP_DIR, "build-cpp-ntopng")
    if run_command(["cmake", "-S", os.path.join(PROJECT_ROOT, "cpp"), "-B", out,
                    "-DSOFTFLOW_NTOPNG=ON"]).returncode != 0 \
            or run_command(["cmake", "--build", out, "-j"]).returncode != 0:
        print_yellow("Warning: the C++ version with ntopng support could not be built "
                     "(libzmq is needed); it is not compared.")
        return None
    shutil.copy2(os.path.join(out, "softflowd+"), daemon)
    return daemon


# Options of the byte for byte comparison of -v ntopng.  -a is always given: without it
# the absolute times depend on the wall clock, as for the other export versions.
NTOPNG_PARITY_ARGS = [["-a"], ["-a", "-T", "ether"], ["-a", "-m", "5"], ["-a", "-s", "10"]]


def ntopng_parity(daemon_a: str, daemon_b: str, pcaps: List[Tuple[str, str]]) -> bool:
    """Compare the ZMQ messages of -v ntopng (TLV) of A and B byte for byte."""
    ok = True
    for extra in NTOPNG_PARITY_ARGS:
        for label, pcap in pcaps:
            text = f"{label} (-v ntopng {' '.join(extra)})"
            try:
                msgs_a = ntopng_export(daemon_a, "ntopng", pcap, extra)
                msgs_b = ntopng_export(daemon_b, "ntopng", pcap, extra)
            except (NtopngFailure, OSError, EOFError) as e:
                print_red(f"    - {text}: FAILED: {e}")
                ok = False
                continue
            if msgs_a == msgs_b:
                print(f"    - {text}: MATCHED ({len(msgs_a)} messages, byte for byte)")
                continue
            ok = False
            why = f"{len(msgs_a)} messages in A, {len(msgs_b)} in B"
            for n, (x, y) in enumerate(zip(msgs_a, msgs_b)):
                if x != y:
                    why = f"message {n} differs"
                    for k, (fx, fy) in enumerate(zip(x, y)):
                        if fx != fy:
                            first = next((i for i in range(min(len(fx), len(fy)))
                                          if fx[i] != fy[i]), min(len(fx), len(fy)))
                            why += f" in frame {k} at byte {first} ({len(fx)} / {len(fy)} bytes)"
                            break
                    break
            print_red(f"    - {text}: FAILED: {why}")
    return ok


def ntopng_step(args: argparse.Namespace, build_dir: str) -> bool:
    """compat --ntopng: check -v ntopng (TLV) and -v ntopng-json on the pcaps."""
    print_cyan("\n[ntopng] Verifying the ZMQ export for ntopng...")
    daemon = ntopng_resolve_daemon(args, build_dir)
    if not daemon or not os.path.exists(daemon):
        print_red("  - FAILED: no softflowd built with --enable-ntopng --enable-ntopng-json "
                  "(use --ntopng-bin or build it)")
        return False
    gen = os.path.join(SUITE_TMP_DIR, "ntopng_many_flows.pcap")
    pcaps = [("IPv4 HTTP", ensure_sample_pcap("http.cap", HTTP_PCAP_URL)),
             ("IPv6 HTTP", ensure_sample_pcap("v6-http.cap", V6_HTTP_PCAP_URL))]
    pcaps += [(os.path.basename(p), p) for p in COMPAT_PCAPS]
    # Many flows: the export is split into several messages.
    many = 3000
    expected: Dict[str, int] = {}
    if subprocess.run([sys.executable, os.path.join(PROJECT_ROOT, "tools",
                                                    "gen_ci_smoke_pcap.py"),
                       "-n", str(many), gen], stdout=subprocess.DEVNULL).returncode == 0:
        pcaps.append((f"{many} flows", gen))
        expected[f"{many} flows"] = many
    ok = True
    totals: Dict[str, int] = {}
    for dialect in NTOPNG_DIALECTS:
        for label, pcap in pcaps:
            text = f"{label} (-v {dialect})"
            try:
                bounds = ntopng_pcap_time_range(pcap) or (1, 2 ** 32)
                messages = ntopng_export(daemon, dialect, pcap)
                total = ntopng_check_messages(messages, dialect, bounds)
                # No flow may be lost, for example at shutdown, and both formats
                # carry the same flows.
                want = expected.get(label, totals.get(label))
                if want is not None and total != want:
                    raise NtopngFailure(f"{total} flows received, expected {want}")
                totals.setdefault(label, total)
            except (NtopngFailure, OSError, EOFError) as e:
                print_red(f"    - {text}: FAILED: {e}")
                ok = False
            else:
                print(f"    - {text}: MATCHED ({len(messages)} messages, {total} flows)")
    # The C++ version has -v ntopng (TLV) only: its messages must be those of the C build.
    cpp_daemon = ntopng_resolve_cpp_daemon(args, build_dir)
    if cpp_daemon and os.path.exists(cpp_daemon):
        print_cyan("  [ntopng] softflowd vs softflowd+: the messages, byte for byte")
        ok = ntopng_parity(daemon, cpp_daemon, pcaps) and ok
    else:
        print_yellow("  [ntopng] softflowd+ with ntopng support not available: not compared")
    return ok


# ==========================================================================
# parity: what softflowd+ (C++) must do byte for byte like softflowd (C)
# ==========================================================================
#
# The pair softflowd vs softflowd+ (or any pair with --strict) is compared more
# strictly than the other pairs: not only the flows that a collector decodes,
# but the datagrams themselves, the replies of the control socket, the lines of
# the expiry debug log and the flows that a live capture exports.  These are
# the checks that were done by hand while softflowd+ followed softflowd.

PARITY_PAIRS = {("softflowd", "softflowd+")}

# Options added to `-a -r PCAP -n 127.0.0.1:PORT -v VERSION`.
PARITY_ARGS = {
    "1": [[], ["-m", "5"], ["-t", "maxlife=1", "-m", "7"], ["-s", "10"]],
    "5": [[], ["-m", "5"], ["-t", "maxlife=1", "-m", "7"], ["-s", "10"], ["-T", "ether"],
          ["-x", "2"]],
    "9": [[], ["-m", "5"], ["-T", "ether"], ["-b"], ["-x", "2", "-A", "micro"],
          ["-t", "maxlife=1", "-m", "7"], ["-s", "10"], ["-e", "192.0.2.1"]],
    "10": [[], ["-m", "5"], ["-T", "ether"], ["-b"], ["-x", "2", "-A", "micro"],
           ["-t", "maxlife=1", "-m", "7"], ["-s", "10"], ["-e", "192.0.2.1"]],
}
PARITY_DEBUG_ARGS = [[], ["-m", "5"], ["-m", "7", "-t", "maxlife=1"], ["-m", "100"],
                     ["-m", "3", "-t", "maxlife=2"]]
PARITY_DEBUG_RE = re.compile(
    r"Starting expiry scan|Queuing flow|Finished scan|sent [0-9]+ netflow|EXPIRED:|Forcing expiry")
# The control commands, sent while the daemon waits for a FIFO (-m 5: after every
# 5 packets), without and with flows in the table.
PARITY_CTL_EMPTY = ["help", "bogus", "", "timeouts", "statistics", "dump-flows", "debug+",
                    "debug-", "send-template", "stop-gather", "start-gather"]
PARITY_CTL_FLOWS = ["statistics", "dump-flows", "timeouts", "expire-all", "statistics",
                    "dump-flows", "delete-all", "statistics"]


def parity_make_pcaps(directory: str) -> Dict[str, str]:
    """smoke (240 packets, 40 flows), vlan (802.1Q tags and MACs), slow (10 s apart), many (600 flows)."""
    smoke = os.path.join(directory, "smoke.pcap")
    subprocess.run([sys.executable, os.path.join(PROJECT_ROOT, "tools", "gen_ci_smoke_pcap.py"),
                    smoke], check=True, stdout=subprocess.DEVNULL)
    with open(smoke, "rb") as f:
        data = f.read()

    def packets():
        off = 24
        while off < len(data):
            ts, us, caplen, origlen = struct.unpack("<IIII", data[off:off + 16])
            yield ts, us, origlen, bytearray(data[off + 16:off + 16 + caplen])
            off += 16 + caplen

    paths = {"smoke": smoke}
    out = bytearray(data[:24])
    for n, (ts, us, origlen, pkt) in enumerate(packets()):
        vid = 100 + (n % 3) * 7 + (0x2000 if n % 5 == 0 else 0)
        if n % 2 == 0:
            pkt[0:6] = bytes([2, 0, 0, 0, 0, 0x10 + n % 4])
        pkt = pkt[:12] + struct.pack(">HH", 0x8100, vid) + pkt[12:]
        out += struct.pack("<IIII", ts, us, len(pkt), origlen + 4) + pkt
    paths["vlan"] = os.path.join(directory, "vlan.pcap")
    with open(paths["vlan"], "wb") as f:
        f.write(out)
    out = bytearray(data[:24])
    for n, (ts, us, origlen, pkt) in enumerate(packets()):
        out += struct.pack("<IIII", 1000000 + n * 10, us, len(pkt), origlen) + pkt
    paths["slow"] = os.path.join(directory, "slow.pcap")
    with open(paths["slow"], "wb") as f:
        f.write(out)
    out = bytearray(data[:24])
    for i in range(600):
        eth = bytes([2, 0, 0, 0, 0, 1]) + bytes([2, 0, 0, 0, 0, 2]) + b"\x08\x00"
        payload = b"x" * 20
        udp = struct.pack(">HHHH", 1000 + i, 53, 8 + len(payload), 0) + payload
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), i, 0, 64, 17, 0,
                         bytes([10, 0, i // 250, i % 250]), bytes([10, 1, 0, 1]))
        frame = eth + ip + udp
        out += struct.pack("<IIII", 1000000 + i, i * 1000, len(frame), len(frame)) + frame
    paths["many"] = os.path.join(directory, "many.pcap")
    with open(paths["many"], "wb") as f:
        f.write(out)
    paths["loopback"] = os.path.join(directory, "loopback.pcap")
    with open(paths["loopback"], "wb") as f:
        f.write(parity_loopback_pcap(data[:24]))
    return paths


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


def parity_export(daemon: str, pcap: str, version: str, extra: List[str]) -> List[bytes]:
    """The datagrams that daemon -r PCAP -a sends over UDP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    sock.bind(("127.0.0.1", 0))
    try:
        subprocess.run([daemon, "-r", pcap, "-n", f"127.0.0.1:{sock.getsockname()[1]}",
                        "-v", version, "-a"] + extra, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=60)
        sock.setblocking(False)
        datagrams: List[bytes] = []
        while True:
            try:
                datagrams.append(sock.recv(65535))
            except BlockingIOError:
                return datagrams
    finally:
        sock.close()


def parity_datagrams_differ(a: List[bytes], b: List[bytes], version: str) -> Optional[str]:
    """None if the datagrams are the same; IPFIX may differ by the process id of its options record."""
    if len(a) != len(b):
        return f"{len(a)} datagrams from A, {len(b)} from B"
    for n, (x, y) in enumerate(zip(a, b)):
        if len(x) != len(y):
            return f"datagram {n}: {len(x)} bytes from A, {len(y)} from B"
        diff = [i for i in range(len(x)) if x[i] != y[i]]
        if not diff:
            continue
        if version == "10" and max(diff) - min(diff) <= 3:
            continue  # the process id of the options record
        return f"datagram {n}: bytes differ at offsets {diff[:8]}"
    return None


def parity_export_bytes(a_daemon: str, b_daemon: str, pcaps: Dict[str, str]) -> bool:
    ok = True
    runs = failures = 0
    for name, pcap in pcaps.items():
        for version, arg_sets in PARITY_ARGS.items():
            for extra in arg_sets:
                runs += 1
                try:
                    why = parity_datagrams_differ(parity_export(a_daemon, pcap, version, extra),
                                                  parity_export(b_daemon, pcap, version, extra),
                                                  version)
                except (OSError, subprocess.SubprocessError) as e:
                    why = str(e)
                if why:
                    failures += 1
                    ok = False
                    print_red(f"    - {name} -v {version} -a {' '.join(extra)}: DIFFERENT: {why}")
    if ok:
        print_green(f"    - exported datagrams, byte for byte ({runs} runs): MATCHED")
    else:
        print_red(f"    - exported datagrams: {failures} of {runs} runs DIFFER")
    return ok


def parity_debug_lines(daemon: str, pcap: str, extra: List[str]) -> List[str]:
    res = subprocess.run([daemon, "-r", pcap, "-n", "127.0.0.1:9", "-v", "9", "-a", "-D"] + extra,
                         capture_output=True, text=True, timeout=60)
    lines = []
    for line in (res.stdout + res.stderr).splitlines():
        if PARITY_DEBUG_RE.search(line):
            line = re.sub(r" ?\(0x[0-9a-f]+\)", "", line)  # pointers
            lines.append(re.sub(r" \([0-9a-f]+\)$", "", line))
    return lines


def parity_debug_log(a_daemon: str, b_daemon: str, pcaps: Dict[str, str]) -> bool:
    ok = True
    runs = 0
    for name, pcap in pcaps.items():
        for extra in PARITY_DEBUG_ARGS:
            runs += 1
            a, b = parity_debug_lines(a_daemon, pcap, extra), parity_debug_lines(b_daemon, pcap, extra)
            if a != b:
                ok = False
                first = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
                print_red(f"    - {name} {' '.join(extra)}: DIFFERENT at line {first + 1} "
                          f"({len(a)} and {len(b)} lines)")
                print(f"        A: {a[first] if first < len(a) else '(none)'}")
                print(f"        B: {b[first] if first < len(b) else '(none)'}")
    if ok:
        print_green(f"    - expiry lines of the debug log (-D), ({runs} runs): MATCHED")
    return ok


def parity_control_replies(a_daemon: str, b_daemon: str, ctl_a: str, ctl_b: str,
                           pcap: str) -> bool:
    """The reply and the exit status of softflowctl for every command, and the exit status of the daemon."""
    with open(pcap, "rb") as f:
        data = f.read()
    header, off, packets = data[:24], 24, []
    while off < len(data):
        caplen = struct.unpack("<I", data[off + 8:off + 12])[0]
        packets.append(data[off:off + 16 + caplen])
        off += 16 + caplen

    def normalize(text: bytes) -> bytes:
        text = re.sub(rb"softflowd\[\d+\]", b"softflowd[PID]", text)
        return re.sub(rb"since 20\d\d-[0-9T:-]+ UTC", b"since START UTC", text)  # process start

    def run(daemon: str, ctl: str, ending: str):
        fifo = os.path.join(SUITE_TMP_DIR, "parity.fifo")
        sock = os.path.join(SUITE_TMP_DIR, "parity.ctl")
        for p in (fifo, sock):
            if os.path.exists(p):
                os.remove(p)
        os.mkfifo(fifo)
        proc = subprocess.Popen([daemon, "-r", fifo, "-c", sock, "-n", "127.0.0.1:9", "-v", "9",
                                 "-a", "-m", "5"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        go, errors = threading.Event(), []

        def feed():
            try:
                with open(fifo, "wb") as w:
                    w.write(header)
                    w.flush()
                    for chunk in (packets[:5], packets[5:10], []):
                        go.wait(30)
                        go.clear()
                        w.write(b"".join(chunk))
                        w.flush()
            except OSError as e:  # the daemon went away: a broken pipe
                errors.append(e)
        threading.Thread(target=feed, daemon=True).start()
        replies = []

        def send(command: str) -> None:
            r = subprocess.run([ctl, "-c", sock, command], capture_output=True, timeout=10)
            replies.append((command, r.returncode, normalize(r.stdout), r.stderr))
        time.sleep(1.0)
        go.set()                      # the header is read; the daemon waits for packets
        time.sleep(0.3)
        for command in PARITY_CTL_EMPTY:
            send(command)
        go.set()                      # 5 packets
        time.sleep(1.0)
        for command in PARITY_CTL_FLOWS:
            send(command)
        go.set()                      # 5 more
        time.sleep(1.0)
        send("dump-flows")
        send(ending)
        time.sleep(0.5)
        go.set()
        try:
            rc = proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
            rc = None
        return replies, rc

    ok = True
    for ending in ("shutdown", "exit"):
        a, rc_a = run(a_daemon, ctl_a, ending)
        b, rc_b = run(b_daemon, ctl_b, ending)
        bad = [x[0] for x, y in zip(a, b) if x != y]
        if len(a) != len(b) or bad or rc_a != rc_b:
            ok = False
            print_red(f"    - control replies ending with {ending}: DIFFERENT "
                      f"(commands {bad}; daemon exit status A {rc_a}, B {rc_b})")
            for x, y in zip(a, b):
                if x != y:
                    print(f"        {x[0]!r}: A {x[1:3]}\n{' ' * 12}B {y[1:3]}")
                    break
        else:
            print_green(f"    - control replies ({len(a)} commands, ending with {ending}): MATCHED")
    return ok


def parity_multithread(daemon: str, pcaps: Dict[str, str]) -> bool:
    """-M (a thread for the export) must not change what is exported."""
    ok = True
    for version in ("5", "9", "10"):
        for extra in ([], ["-m", "5"]):
            single = parity_export(daemon, pcaps["smoke"], version, extra)
            multi = parity_export(daemon, pcaps["smoke"], version, extra + ["-M"])
            why = parity_datagrams_differ(single, multi, version)
            if why:
                ok = False
                print_red(f"    - -M -v {version} {' '.join(extra)}: DIFFERENT: {why}")
    if ok:
        print_green("    - -M exports the same datagrams as without: MATCHED")
    return ok


def parity_can_capture_lo() -> bool:
    """A live capture needs a privilege (root or CAP_NET_RAW) and a loopback device."""
    if os.geteuid() != 0 or not os.path.exists("/sys/class/net/lo"):
        return False
    return True


def parity_live(a_daemon: str, b_daemon: str, ctl_a: str, ctl_b: str) -> bool:
    """Both daemons capture the same traffic on lo: when the idle flows are exported (-t expint), and
    that a burst bigger than the flow table (-m) is exported completely, each flow once."""
    flt = "udp and dst port 41000"
    ok = True

    def start(daemon: str, ctl_path: str, port: int, extra: List[str]) -> subprocess.Popen:
        return subprocess.Popen([daemon, "-d", "-c", ctl_path, "-i", "lo", "-n", f"127.0.0.1:{port}",
                                 "-v", "5"] + extra + [flt],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def stop(procs, ctls, paths) -> None:
        for proc, ctl, path in zip(procs, ctls, paths):
            subprocess.run([ctl, "-c", path, "shutdown"], capture_output=True, timeout=10)
        for proc in procs:
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()

    def receive(socks, seconds: float):
        got = [[] for _ in socks]
        end = time.time() + seconds
        while time.time() < end:
            ready, _, _ = select.select(socks, [], [], 0.1)
            for s in ready:
                got[socks.index(s)].append((time.time(), s.recv(65535)))
        return got

    def records(datagrams):
        out = []
        for _, d in datagrams:
            for i in range((len(d) - 24) // 48):
                r = d[24 + 48 * i:24 + 48 * (i + 1)]
                out.append(struct.unpack(">HH", r[32:36]) + struct.unpack(">II", r[16:24]))
        return sorted(out)

    for title, extra, flows in (("idle expiry (-t expint=3)", ["-t", "general=2", "-t", "udp=2", "-t", "expint=3"], 10),
                                ("burst over -m 10", ["-m", "10", "-t", "udp=600"], 60)):
        socks, paths = [], [os.path.join(SUITE_TMP_DIR, f"live_{n}.ctl") for n in "ab"]
        for _ in range(2):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("127.0.0.1", 0))
            socks.append(s)
        procs = [start(a_daemon, paths[0], socks[0].getsockname()[1], extra),
                 start(b_daemon, paths[1], socks[1].getsockname()[1], extra)]
        time.sleep(1.5)
        sent = time.time()
        for i in range(flows):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("127.0.0.1", 30000 + i))
            s.sendto(b"x" * (40 + i % 50), ("127.0.0.1", 41000))
            s.close()
        if "expint=3" in extra:     # the idle flows are exported at the next multiple of 3 s
            got = receive(socks, 8.0)
            stop(procs, [ctl_a, ctl_b], paths)
        else:                       # a flow that is forced out is exported at once, the rest at shutdown
            time.sleep(1.5)
            stop(procs, [ctl_a, ctl_b], paths)
            got = receive(socks, 2.0)
        if "expint=3" in extra:
            times = [[round(t - sent, 1) for t, _ in g] for g in got]
            same = len(times[0]) == len(times[1]) > 0 and all(abs(x - y) <= 0.6
                                                                 for x, y in zip(times[0], times[1]))
            detail = f"A at {times[0]} s, B at {times[1]} s"
        else:
            rec_a, rec_b = records(got[0]), records(got[1])
            same = rec_a == rec_b and len(rec_a) == len(set(rec_a)) == flows
            detail = f"A {len(rec_a)} records, B {len(rec_b)} records, {flows} sent"
        if same:
            print_green(f"    - live on lo, {title}: MATCHED ({detail})")
        else:
            ok = False
            print_red(f"    - live on lo, {title}: DIFFERENT ({detail})")
        for s in socks:
            s.close()
    return ok


def parity_v5_header(datagram: bytes) -> Tuple[int, int]:
    """(record count, unix_secs) of a NetFlow v5 datagram."""
    _, count, _, secs, _ = struct.unpack(">HHIII", datagram[:16])
    return count, secs


def parity_expire_all_time(a_daemon: str, b_daemon: str, ctl_a: str, ctl_b: str, pcap: str) -> bool:
    """With -a, expire-all of a capture file that is being read (a FIFO) exports with the time of the
    last packet that was read, not with the time of the clock."""
    with open(pcap, "rb") as f:
        data = f.read()
    end = 24
    for _ in range(5):                  # -m 5: one batch of exactly 5 packets
        end += 16 + struct.unpack("<I", data[end + 8:end + 12])[0]
    results = []
    for n, (daemon, ctl) in enumerate(((a_daemon, ctl_a), (b_daemon, ctl_b))):
        sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sink.bind(("127.0.0.1", 0))
        sink.settimeout(3.0)
        fifo, path = (os.path.join(SUITE_TMP_DIR, f"expall_{n}.{ext}") for ext in ("fifo", "ctl"))
        for f in (fifo, path):
            if os.path.exists(f):
                os.remove(f)
        os.mkfifo(fifo)
        proc = subprocess.Popen([daemon, "-r", fifo, "-c", path, "-n", f"127.0.0.1:{sink.getsockname()[1]}",
                                 "-v", "5", "-m", "5", "-a"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        result = "no reply"
        with open(fifo, "wb") as w:
            w.write(data[:24])          # the packets must come after the header has been read,
            w.flush()                   # or libpcap keeps them in its buffer
            for _ in range(100):
                if os.path.exists(path):
                    break
                time.sleep(0.1)
            time.sleep(1.0)
            w.write(data[24:end])
            w.flush()
            time.sleep(1.0)
            r = subprocess.run([ctl, "-c", path, "expire-all"], capture_output=True, text=True, timeout=10)
            reply = r.stdout.strip().split(": ", 1)[-1]
            try:
                result = (reply,) + parity_v5_header(sink.recv(65535))
            except socket.timeout:
                result = (reply, "no datagram")
            subprocess.run([ctl, "-c", path, "shutdown"], capture_output=True, timeout=10)
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
        sink.close()
        results.append(result)
    if results[0] == results[1] and len(results[0]) == 3 and results[0][0].startswith("Expired 1"):
        print_green(f"    - expire-all while reading a file (-a): MATCHED (export time {results[0][2]}, the last packet)")
        return True
    print_red(f"    - expire-all while reading a file (-a): DIFFERENT (A {results[0]}, B {results[1]})")
    return False


def parity_live_time(a_daemon: str, b_daemon: str, ctl_a: str, ctl_b: str) -> bool:
    """The times of a live capture are those of libpcap, as phdr->ts in the original: (1) the packets that
    are read together keep their time, and (2) with -a the time of the last packet is the current time, so
    that no idle flow expires while no packet arrives, and statistics and expire-all show that time."""
    ok = True
    flt = "udp and dst port 41001"
    paths = [os.path.join(SUITE_TMP_DIR, f"livetime_{n}.ctl") for n in "ab"]
    ctls = (ctl_a, ctl_b)

    def run(extra: List[str], body) -> List:
        socks, procs = [], []
        for n, daemon in enumerate((a_daemon, b_daemon)):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("127.0.0.1", 0))
            s.settimeout(3.0)
            socks.append(s)
            if os.path.exists(paths[n]):
                os.remove(paths[n])
            procs.append(subprocess.Popen([daemon, "-d", "-c", paths[n], "-i", "lo", "-v", "5", "-n",
                                           f"127.0.0.1:{s.getsockname()[1]}"] + extra + [flt],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        for path in paths:
            for _ in range(100):
                if os.path.exists(path):
                    break
                time.sleep(0.1)
        time.sleep(1.5)
        try:
            return body(socks, procs)
        finally:
            for ctl, path in zip(ctls, paths):
                subprocess.run([ctl, "-c", path, "shutdown"], capture_output=True, timeout=10)
            for proc in procs:
                try:
                    proc.wait(10)
                except subprocess.TimeoutExpired:
                    proc.kill()
            for s in socks:
                s.close()

    def ctl_out(n: int, command: str) -> str:
        return subprocess.run([ctls[n], "-c", paths[n], command], capture_output=True, text=True,
                              timeout=10).stdout

    def record(sock) -> Tuple[int, int, int]:
        """(packets, first, last) of the flow of the test traffic in the next datagram."""
        d = sock.recv(65535)
        for i in range((len(d) - 24) // 48):
            r = d[24 + 48 * i:24 + 48 * (i + 1)]
            pkts = struct.unpack(">I", r[16:20])[0]
            first, last = struct.unpack(">II", r[24:32])
            if pkts:
                return pkts, first, last
        raise socket.timeout

    # (1) two packets that are captured 1 s apart, and read together because the daemon was stopped
    def stalled(socks, procs):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for p in procs:
            p.send_signal(signal.SIGSTOP)
        time.sleep(0.3)
        s.sendto(b"x" * 40, ("127.0.0.1", 41001))
        time.sleep(1.0)
        s.sendto(b"x" * 40, ("127.0.0.1", 41001))
        time.sleep(0.3)
        for p in procs:
            p.send_signal(signal.SIGCONT)
        time.sleep(1.0)
        s.close()
        out = []
        for n in range(2):
            ctl_out(n, "expire-all")
            try:
                pkts, first, last = record(socks[n])
                out.append((pkts, last - first))
            except socket.timeout:
                out.append(None)
        return out

    try:
        a, b = run([], stalled)
        same = a and b and a[0] == b[0] == 2 and abs(a[1] - b[1]) <= 2 and a[1] >= 900
        detail = f"duration A {a[1] if a else None} ms, B {b[1] if b else None} ms, 1000 ms between the packets"
    except (OSError, subprocess.SubprocessError) as e:
        same, detail = False, str(e)
    if same:
        print_green(f"    - live on lo, packets that are read together: MATCHED ({detail})")
    else:
        ok = False
        print_red(f"    - live on lo, packets that are read together: DIFFERENT ({detail})")

    # (2) -a: the time of the last packet is the current time
    def adjusted(socks, procs):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"x" * 40, ("127.0.0.1", 41001))
        sent = time.time()
        s.close()
        time.sleep(3.5)                 # idle for more than -t general=1 and expint=1
        out = []
        for n in range(2):
            stat = ctl_out(n, "statistics")
            since = re.search(r"since (\S+) UTC", stat)
            expired = re.search(r"Flows expired: (\d+)", stat)
            since_s = calendar.timegm(time.strptime(since.group(1), "%Y-%m-%dT%H:%M:%S")) if since else None
            ctl_out(n, "expire-all")
            try:
                secs = parity_v5_header(socks[n].recv(65535))[1]
            except socket.timeout:
                secs = None
            out.append((int(expired.group(1)) if expired else None,
                        None if since_s is None else round(since_s - sent),
                        None if secs is None else round(secs - sent)))
        return out

    try:
        a, b = run(["-a", "-t", "general=1", "-t", "expint=1"], adjusted)
        # a time of the packet that is cut to the second is 0 or 1 s before the time at which it was sent
        same = all(x[0] == 0 and x[1] in (0, -1) and x[2] in (0, -1) for x in (a, b))
        detail = (f"A: expired {a[0]} before expire-all, since {a[1]} s, export {a[2]} s; "
                  f"B: expired {b[0]}, since {b[1]} s, export {b[2]} s")
    except (OSError, subprocess.SubprocessError) as e:
        same, detail = False, str(e)
    if same:
        print_green(f"    - live on lo, -a (statistics, idle, expire-all): MATCHED ({detail})")
    else:
        ok = False
        print_red(f"    - live on lo, -a (statistics, idle, expire-all): DIFFERENT ({detail})")
    return ok


# Command lines that the C version reports as an error (or accepts in an odd way), for parity_cli_errors ().
# {pcap} is the capture file and {ctl} a control socket path. These are not compared on purpose, because the
# C version is wrong there: -I abc (perror () prints the text of an errno that strtol () did not set),
# -e of an unknown host (the same with getaddrinfo ()), -n host:99999 (the port is cut to 16 bits, and the
# C++ version shows the port as it was written), and -t maxlife=99999999999 (the C version drops the upper
# bits of the time, the C++ version rejects it). The statistics of -v psamp are not compared either: the
# C++ version does not count "Packets processed" for it. And the file name of -r that "Exporting flows from"
# shows is cut to 15 characters by the C version.
PARITY_CLI_ERROR_CASES = [
    [], ["-h"], ["--help"], ["-z"], ["--bogus"], ["-i"], ["-r"], ["-t"], ["-X"],
    ["-i", "lo", "-r", "{pcap}"], ["-r", "{pcap}", "-i", "lo"], ["-r", "{pcap}", "-r", "{pcap}"],
    ["-i", ""], ["-i", ":"], ["-i", "1:"], ["-r", "/nonexistent/x.pcap", "-n", "127.0.0.1:9"],
    ["-r", "/etc/passwd", "-n", "127.0.0.1:9"], ["-r", "{pcap}", "-n", "127.0.0.1:9", "this is not a filter"],
    ["-T", "bogus", "-r", "{pcap}"], ["-P", "bogus", "-r", "{pcap}"], ["-F", "bogus", "-r", "{pcap}"],
    ["-A", "bogus", "-r", "{pcap}"], ["-v", "99", "-r", "{pcap}"], ["-v", "abc", "-r", "{pcap}"],
    ["-v", "0", "-r", "{pcap}"], ["-m", "0", "-r", "{pcap}"], ["-m", "abc", "-r", "{pcap}"],
    ["-m", "-5", "-r", "{pcap}"], ["-x", "0", "-r", "{pcap}"], ["-x", "11", "-r", "{pcap}"],
    ["-L", "300", "-r", "{pcap}"], ["-L", "-1", "-r", "{pcap}"], ["-H", "zz", "-r", "{pcap}"],
    ["-n", "no.such.host.invalid:99", "-r", "{pcap}"], ["-n", "", "-r", "{pcap}"],
    ["-n", "127.0.0.1", "-r", "{pcap}"], ["-n", "127.0.0.1:abc", "-r", "{pcap}"],
    ["-n", "127.0.0.1:", "-r", "{pcap}"], ["-n", ":9", "-r", "{pcap}"],
    ["-t", "bogus", "-r", "{pcap}"], ["-t", "bogus=1", "-r", "{pcap}"], ["-t", "general=0", "-r", "{pcap}"],
    ["-t", "udp=abc", "-r", "{pcap}"], ["-t", "udp=", "-r", "{pcap}"], ["-t", "udp=-1", "-r", "{pcap}"],
    ["-t", "expint=abc", "-r", "{pcap}"], ["-t", "tcp", "-r", "{pcap}"],
    ["-I", "5x", "-r", "{pcap}"], ["-s", "abc", "-n", "127.0.0.1:9", "-r", "{pcap}"],
    ["-B", "abc", "-n", "127.0.0.1:9", "-r", "{pcap}"], ["-C", "abc", "-n", "127.0.0.1:9", "-r", "{pcap}"],
    ["-R", "abc", "-n", "127.0.0.1:9", "-r", "{pcap}"], ["-r", "{pcap}"], ["-n", "127.0.0.1:9"],
    ["-T", "port", "-n", "127.0.0.1:9", "-r", "{pcap}"], ["-T", "ICMP", "-r", "{pcap}"],
    ["-c", "none", "-n", "127.0.0.1:9", "-r", "{pcap}"], ["-c", "/nonexistent/dir/ctl", "-n", "127.0.0.1:9", "-r", "{pcap}"],
    ["-r", "{pcap}", "-c", "/nonexistent/dir/ctl", "-n", "127.0.0.1:9"],
    # The capture and the control socket are set up before the process forks (no -d).
    ["-i", "nonexistent0", "-n", "127.0.0.1:9"], ["-d", "-i", "nonexistent0", "-n", "127.0.0.1:9"],
    ["-i", "lo", "-n", "127.0.0.1:9", "-c", "{ctl}", "this is not a filter"],
    ["-i", "lo", "-n", "127.0.0.1:9", "-c", "/nonexistent/dir/ctl"],
    ["-i", "lo", "-n", "127.0.0.1:9", "-c", "/tmp/" + "x" * 120],
    ["-R", "0", "-c", "/nonexistent/dir/ctl"],
]


def parity_live_gauge(a_daemon: str, b_daemon: str, ctl_a: str, ctl_b: str) -> bool:
    """-g of a live capture reports the "cpu clocks" counters on the standard error when the daemon stops (with
    -d), as for a capture file, and with -M the clocks of the export are "n/a" for both."""
    ok = True
    for extra, label in (([], "-g"), (["-M"], "-g -M")):
        results = []
        for n, (daemon, ctl) in enumerate(((a_daemon, ctl_a), (b_daemon, ctl_b))):
            path = os.path.join(SUITE_TMP_DIR, f"livegauge_{n}.ctl")
            if os.path.exists(path):
                os.remove(path)
            proc = subprocess.Popen([daemon, "-d", "-g", "-i", "lo", "-v", "5", "-n", "127.0.0.1:9", "-c", path]
                                    + extra + ["udp and dst port 41002"],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                    text=True)
            for _ in range(100):
                if os.path.exists(path):
                    break
                time.sleep(0.1)
            time.sleep(1.0)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"x" * 40, ("127.0.0.1", 41002))
            s.close()
            time.sleep(0.5)
            subprocess.run([ctl, "-c", path, "shutdown"], capture_output=True, timeout=10)
            try:
                _, err = proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                _, err = proc.communicate()
            results.append(parse_gauge(err))
        a, b = results
        same = a is not None and b is not None and (a[1] is None) == (b[1] is None) and \
            (a[1] is None or a[2] == b[2])
        if same:
            print_green(f"    - live on lo, cpu clocks of {label}: MATCHED (A {_fmt_gauge(a)}, B {_fmt_gauge(b)})")
        else:
            ok = False
            print_red(f"    - live on lo, cpu clocks of {label}: DIFFERENT (A {a}, B {b})")
    return ok


def parity_statistics(a_daemon: str, b_daemon: str, pcap: str) -> bool:
    """The statistics that count the packets (the processed ones, and the ignored ones that are not IP or too
    short) are those of A for a capture with packets that are not IP, that are too short, that are IPv6 where
    IPv6 is not tracked, with -v psamp and with -s."""
    with open(pcap, "rb") as f:
        data = f.read()
    ipv6 = os.path.join(SUITE_TMP_DIR, "stat_v6.pcap")
    subprocess.run([sys.executable, os.path.join(PROJECT_ROOT, "tools", "gen_ci_smoke_pcap.py"), "-6", ipv6],
                   check=True, stdout=subprocess.DEVNULL)
    nonip, short = bytearray(data[:24]), bytearray(data[:24])
    off, n = 24, 0
    while off < len(data):
        ts, us, caplen, origlen = struct.unpack("<IIII", data[off:off + 16])
        frame = bytearray(data[off + 16:off + 16 + caplen])
        if n < 5:                       # five frames that are not IP, five that are too short for IP
            arp = bytearray(frame)
            arp[12:14] = b"\x08\x06"
            nonip += struct.pack("<IIII", ts, us, caplen, origlen) + arp
            frame = frame[:24]
            short += struct.pack("<IIII", ts, us, len(frame), origlen) + frame
        else:
            nonip += data[off:off + 16 + caplen]
            short += data[off:off + 16 + caplen]
        off += 16 + caplen
        n += 1
    paths = {}
    for name, content in (("nonip", nonip), ("short", short)):
        paths[name] = os.path.join(SUITE_TMP_DIR, f"stat_{name}.pcap")
        with open(paths[name], "wb") as f:
            f.write(content)
    cases = [("not IP", paths["nonip"], []), ("too short", paths["short"], []),
             ("IPv6 with -v 5", ipv6, ["-v", "5"]), ("IPv6 with -v 9", ipv6, ["-v", "9"]),
             ("-v psamp", pcap, ["-v", "psamp"]), ("-v psamp, not IP", paths["nonip"], ["-v", "psamp"]),
             ("-s 3, not IP", paths["nonip"], ["-s", "3"]), ("-s 3, too short", paths["short"], ["-s", "3"])]

    def stats(daemon: str, path: str, extra: List[str]) -> Tuple[str, ...]:
        r = subprocess.run([daemon, "-r", path, "-a", "-n", "127.0.0.1:9"] + extra, capture_output=True,
                           text=True, timeout=30, stdin=subprocess.DEVNULL)
        return tuple((re.search(pattern, r.stdout) or [None, "?"])[1]
                     for pattern in (r"Packets processed: (\d+)", r"Ignored packets: (.*)",
                                     r"Number of active flows: (\d+)"))
    different = [(label, stats(a_daemon, path, extra), stats(b_daemon, path, extra)) for label, path, extra in cases]
    different = [d for d in different if d[1] != d[2]]
    if not different:
        print_green(f"    - statistics of the packets (processed, ignored; {len(cases)} captures): MATCHED")
        return True
    for label, a, b in different:
        print_red(f"    - statistics of the packets, {label}: DIFFERENT (A {a}, B {b})")
    return False


def _clean_log(text: str, daemon: str) -> List[str]:
    """The lines of a log without the name, the version and the numbers that differ between A and B."""
    text = text.replace(daemon, "PROG").replace(os.path.basename(daemon), "PROG")
    text = re.sub(r"PROG v\d+\.\d+\.\d+ ", "PROG vX ", text)
    text = re.sub(r"\]:\d+", "]:PORT", text)
    return [line for line in text.splitlines() if line.strip()]


def parity_live_log(a_daemon: str, b_daemon: str, ctl_a: str, ctl_b: str) -> bool:
    """A live capture logs, in the foreground, the same lines to the standard error for A and for B: the start,
    and the end that the shutdown command and the exit command make (the first expires the flows)."""
    ok = True
    for command in ("shutdown", "exit"):
        logs = []
        for n, (daemon, ctl) in enumerate(((a_daemon, ctl_a), (b_daemon, ctl_b))):
            path = os.path.join(SUITE_TMP_DIR, f"livelog_{n}.ctl")
            if os.path.exists(path):
                os.remove(path)
            proc = subprocess.Popen([daemon, "-d", "-i", "lo", "-v", "5", "-n", "127.0.0.1:9", "-c", path,
                                     "udp and dst port 41003"], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for _ in range(100):
                if os.path.exists(path):
                    break
                time.sleep(0.1)
            time.sleep(1.0)
            subprocess.run([ctl, "-c", path, command], capture_output=True, timeout=10)
            try:
                out, err = proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, err = proc.communicate()
            logs.append((_clean_log(err, daemon), out.strip()))
        if logs[0] == logs[1]:
            print_green(f"    - live on lo, the log of the {command} command: MATCHED ({len(logs[0][0])} lines)")
        else:
            ok = False
            print_red(f"    - live on lo, the log of the {command} command: DIFFERENT (A {logs[0]}, B {logs[1]})")
    return ok


def parity_daemon(a_daemon: str, b_daemon: str, ctl_a: str, ctl_b: str) -> bool:
    """A daemon (no -d) drops its privileges to the user nobody in an empty root directory, logs to syslog, and
    leaves its pid file and control socket, as A does. Needs root, /var/empty, and a /dev/log that is free."""
    if not parity_can_capture_lo() or not os.path.isdir("/var/empty") or os.path.exists("/dev/log"):
        print_yellow("    - daemon (privileges, syslog): SKIPPED (needs root, /var/empty and no /dev/log)")
        return True
    results = []
    for n, (daemon, ctl) in enumerate(((a_daemon, ctl_a), (b_daemon, ctl_b))):
        sock, pidfile = (os.path.join(SUITE_TMP_DIR, f"daemon_{n}.{ext}") for ext in ("ctl", "pid"))
        sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sink.bind(("127.0.0.1", 0))
        sink.settimeout(5)
        logsock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        logsock.bind("/dev/log")
        logsock.settimeout(2)
        pid = None
        try:
            subprocess.run([daemon, "-i", "lo", "-v", "5", "-n", f"127.0.0.1:{sink.getsockname()[1]}", "-c", sock,
                            "-p", pidfile, "udp and dst port 41004"], timeout=10)
            for _ in range(100):
                if os.path.exists(pidfile) and os.path.exists(sock):
                    break
                time.sleep(0.1)
            time.sleep(1.0)
            with open(pidfile) as f:
                pid = int(f.read())
            with open(f"/proc/{pid}/status") as f:
                uids = next(line for line in f if line.startswith("Uid:")).split()[1:]
            root = os.readlink(f"/proc/{pid}/root")
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"x" * 40, ("127.0.0.1", 41004))
            s.close()
            time.sleep(0.5)
            reply = subprocess.run([ctl, "-c", sock, "expire-all"], capture_output=True, text=True,
                                   timeout=10).stdout.strip().split(": ", 1)[-1]
            try:
                exported = len(sink.recv(65535))
            except socket.timeout:
                exported = 0
            subprocess.run([ctl, "-c", sock, "shutdown"], capture_output=True, timeout=10)
            time.sleep(1.0)
            messages = []
            try:
                while True:
                    messages.append(logsock.recv(4096).decode(errors="replace").split("]:", 1)[-1].strip())
            except socket.timeout:
                pass
            results.append((uids, root, reply, exported, _clean_log("\n".join(messages), daemon),
                            os.path.exists(f"/proc/{pid}"), os.path.exists(pidfile), os.path.exists(sock)))
        except (OSError, subprocess.SubprocessError, StopIteration, ValueError) as e:
            results.append((f"failed: {e}",))
        finally:
            if pid is not None and os.path.exists(f"/proc/{pid}"):
                os.kill(pid, signal.SIGKILL)
            logsock.close()
            os.remove("/dev/log")
            sink.close()
    if results[0] == results[1] and len(results[0]) > 1 and results[0][0][0] != "0":
        print_green(f"    - daemon (privileges, syslog): MATCHED (uid {results[0][0][0]}, root {results[0][1]}, "
                    f"{len(results[0][4])} lines in syslog)")
        return True
    print_red(f"    - daemon (privileges, syslog): DIFFERENT (A {results[0]}, B {results[1]})")
    return False


def parity_cli_errors(a_daemon: str, b_daemon: str, pcap: str) -> bool:
    """A command line that is wrong, or odd, is reported by B as A reports it: the message, the usage (the
    options of B that A does not have follow it), the standard output and the exit status."""
    ctl = os.path.join(SUITE_TMP_DIR, "cli_errors.ctl")

    def run(daemon: str, args: List[str]) -> Tuple[str, str, object]:
        daemon = os.path.abspath(daemon)
        try:
            r = subprocess.run([daemon] + args, capture_output=True, text=True, timeout=10,
                               stdin=subprocess.DEVNULL, cwd=SUITE_TMP_DIR)
            out, err, rc = r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            out, err, rc = "", "", "TIMEOUT"
        norm = os.path.basename(daemon)

        def clean(t: str) -> str:
            t = t.replace(SUITE_TMP_DIR, "TMP").replace(pcap, "PCAP")      # the paths may contain the program name
            # A took 15 characters of the file name of -r, as it keeps it in a buffer for an interface name.
            t = re.sub(r"Exporting flows from \S* to ", "Exporting flows from SOURCE to ", t)
            t = t.replace("/var/run/softflowd.", "/var/run/DEFAULT.").replace(daemon, "PROG").replace(norm, "PROG")
            t = re.sub(r"version \d+\.\d+\.\d+", "version X", t)
            t = re.sub(r"PROG v\d+\.\d+\.\d+ ", "PROG vX ", t)
            return re.sub(r"This project's own additions.*", "", t, flags=re.S)
        return clean(out), clean(err), rc

    different = []
    for template in PARITY_CLI_ERROR_CASES:
        args = [a.format(pcap=pcap, ctl=ctl) for a in template]
        if "lo" in args and not parity_can_capture_lo() and "-i" in args and args[args.index("-i") + 1] == "lo":
            continue                    # needs root to open lo, as the other live checks
        a, b = run(a_daemon, args), run(b_daemon, args)
        if a != b:
            if a[2] != b[2]:
                what, x, y = "exit status", [str(a[2])], [str(b[2])]
            else:
                what, x, y = ("standard output", a[0], b[0]) if a[0] != b[0] else ("standard error", a[1], b[1])
                x, y = x.splitlines(), y.splitlines()
            line = next((i for i in range(max(len(x), len(y)))
                         if (x[i] if i < len(x) else None) != (y[i] if i < len(y) else None)), 0)
            different.append((" ".join(template) or "(no arguments)", what,
                              x[line] if line < len(x) else "(none)", y[line] if line < len(y) else "(none)"))
    if not different:
        print_green(f"    - command lines that are wrong ({len(PARITY_CLI_ERROR_CASES)} cases), message, usage and exit status: MATCHED")
        return True
    print_red(f"    - command lines that are wrong: {len(different)} of {len(PARITY_CLI_ERROR_CASES)} DIFFER")
    for text, what, x, y in different[:8]:
        print_red(f"        {text}: {what} differs: A {x!r}, B {y!r}")
    return False


def parity_gauge(a_daemon: str, b_daemon: str, pcap: str) -> bool:
    """-g reports the "cpu clocks" counters on the standard error, for A and for B, and with -M (threaded
    export) both report "n/a" for the clocks of the export. The numbers are not compared."""
    ok = True
    for extra, label in (([], "-g"), (["-M"], "-g -M")):
        results = []
        for daemon in (a_daemon, b_daemon):
            r = subprocess.run([daemon, "-g", "-r", pcap, "-n", "127.0.0.1:9", "-v", "5"] + extra,
                               capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
            results.append(parse_gauge(r.stderr))
        a, b = results
        calls = (a[2], b[2]) if a and b else None
        same = a is not None and b is not None and (a[1] is None) == (b[1] is None) and \
            (a[1] is None or a[2] == b[2])
        if same:
            print_green(f"    - cpu clocks of {label}: MATCHED (A {_fmt_gauge(a)}, B {_fmt_gauge(b)})")
        else:
            ok = False
            print_red(f"    - cpu clocks of {label}: DIFFERENT (A {a}, B {b}{'' if calls else ', a counter is missing'})")
    return ok


def parity_cli(a_daemon: str, b_daemon: str, pcap: str) -> bool:
    """-t is accepted or refused by A and B alike: the names, and the general timeout of 0."""
    ok = True
    specs = ["icmp=1m", "icmp=2h", "tcp=1h", "tcp.rst=5m", "tcp.fin=5m", "udp=1m", "general=1s",
             "maxlife=1h", "expint=10", "general=0", "bogus=1", "tcp", "tcp=", "tcp=xyz"]
    for spec in specs:
        rc = []
        for daemon in (a_daemon, b_daemon):
            rc.append(subprocess.run([daemon, "-r", pcap, "-n", "127.0.0.1:9", "-a", "-t", spec],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     timeout=30).returncode)
        if rc[0] != rc[1]:
            ok = False
            print_red(f"    - -t {spec}: DIFFERENT exit status (A {rc[0]}, B {rc[1]})")
    if ok:
        print_green(f"    - -t names and values ({len(specs)} cases), exit status: MATCHED")
    return ok


def test_parity(a_daemon: str, b_daemon: str, ctl_a: Optional[str], ctl_b: Optional[str]) -> bool:
    """Compat step for a strict pair: what was checked by hand while softflowd+ followed softflowd."""
    print("  [Step 5] Verifying that B does what A does, byte for byte...")
    pcaps = parity_make_pcaps(tempfile.mkdtemp(dir=SUITE_TMP_DIR))
    ok = parity_cli(a_daemon, b_daemon, pcaps["smoke"])
    ok = parity_cli_errors(a_daemon, b_daemon, pcaps["smoke"]) and ok
    ok = parity_gauge(a_daemon, b_daemon, pcaps["smoke"]) and ok
    ok = parity_statistics(a_daemon, b_daemon, pcaps["smoke"]) and ok
    ok = parity_export_bytes(a_daemon, b_daemon, pcaps) and ok
    ok = parity_debug_log(a_daemon, b_daemon, pcaps) and ok
    ok = parity_multithread(b_daemon, pcaps) and ok
    if ctl_a and ctl_b and os.path.exists(ctl_a) and os.path.exists(ctl_b):
        ok = parity_control_replies(a_daemon, b_daemon, ctl_a, ctl_b, pcaps["smoke"]) and ok
        ok = parity_expire_all_time(a_daemon, b_daemon, ctl_a, ctl_b, pcaps["smoke"]) and ok
        if parity_can_capture_lo():
            ok = parity_live(a_daemon, b_daemon, ctl_a, ctl_b) and ok
            ok = parity_live_time(a_daemon, b_daemon, ctl_a, ctl_b) and ok
            ok = parity_live_gauge(a_daemon, b_daemon, ctl_a, ctl_b) and ok
            ok = parity_live_log(a_daemon, b_daemon, ctl_a, ctl_b) and ok
            ok = parity_daemon(a_daemon, b_daemon, ctl_a, ctl_b) and ok
        else:
            print_yellow("    - live on lo: SKIPPED (needs root, to capture on lo)")
    else:
        print_yellow("    - control replies and live capture: SKIPPED (softflowctl is needed)")
    return ok



def run_single_comparison(
    a_daemon: str,
    b_daemon: str,
    ctl_a: Optional[str],
    ctl_b: Optional[str],
    pair_name: str,
    test_ctl: bool,
    ignore_timestamp: bool,
    auto_ignore_legacy_v9: bool,
    auto_ignore_icmp_reclass: bool,
    ignore_ipv6: bool,
    include_collector_metadata: bool = False,
    test_psamp: bool = False,
    test_strict: bool = False
) -> bool:
    """Run full verification between daemon/ctl implementation pair A (reference) and B (target)."""
    print("=" * 60)
    print_cyan(f"Comparing: A={os.path.basename(a_daemon)}  <==>  B={os.path.basename(b_daemon)}")
    print(f"  A (reference): {a_daemon}")
    print(f"  B (target):    {b_daemon}")
    print("=" * 60)

    # 1. CLI Compatibility
    if not test_cli_compatibility(a_daemon, b_daemon):
        return False

    # 2. Control Socket Compatibility
    if test_ctl and ctl_a and ctl_b and os.path.exists(ctl_a) and os.path.exists(ctl_b):
        if not test_control_socket_compatibility(a_daemon, b_daemon, ctl_a, ctl_b):
            return False

    # 3. Differential Output Verification
    if not test_differential_output(
        a_daemon, b_daemon, pair_name, ignore_timestamp, auto_ignore_legacy_v9,
        auto_ignore_icmp_reclass, ignore_ipv6, include_collector_metadata
    ):
        return False

    # 4. PSAMP (C builds and the C++ build)
    if test_psamp and not test_psamp_compat(a_daemon, b_daemon, ctl_a, ctl_b):
        return False

    # 5. Byte for byte (the pair softflowd vs softflowd+, or --strict)
    if test_strict and not test_parity(a_daemon, b_daemon, ctl_a, ctl_b):
        return False

    print_green(f"\n>> Pair comparison [A={os.path.basename(a_daemon)} vs B={os.path.basename(b_daemon)}] PASSED.\n")
    return True


# ==============================================================================
# Main Entrypoint
# ==============================================================================

def compat_main():
    global COLLECTOR_BACKEND, PCAP_DIR, SUITE_TMP_DIR, MEASURE
    global CACHE_DIR, REBUILD_STABLE, REBUILD_DEV, REFRESH_PCAP, COMPAT_PCAPS
    global BUILD_OPTIMIZED_FOR_MEASURE
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
        "--skip-psamp",
        action="store_true",
        help="Skip the PSAMP sender and receiver comparison of the C development pairs"
    )
    parser.add_argument(
        "--psamp",
        action="store_true",
        help="Also compare the PSAMP sender and receiver of the --a/--b pair "
             "(both must be C or C++ builds: the Rust PSAMP records differ)"
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Also compare the --a/--b pair byte for byte, as the pair softflowd vs "
             "softflowd+ always is (step 5): exported datagrams, control socket replies, "
             "the expiry lines of the debug log, -M and, as root, a live capture on lo. "
             "It also checks that a refactoring changes no output: --a is the softflowd+ "
             "before and --b the softflowd+ after (their usage must be the same)"
    )
    parser.add_argument(
        "--skip-parity",
        action="store_true",
        help="Skip the byte for byte comparison (step 5) of the pair softflowd vs softflowd+"
    )
    parser.add_argument(
        "--ntopng",
        action="store_true",
        help="Also check the ZMQ export for ntopng (-v ntopng: TLV for ntopng 6.0 or "
             "later, -v ntopng-json: JSON for 5.x or earlier) of a build with "
             "--enable-ntopng --enable-ntopng-json, which needs libzmq (default: off)"
    )
    parser.add_argument(
        "--ntopng-bin",
        default=None,
        help="softflowd built with --enable-ntopng --enable-ntopng-json for --ntopng "
             "(default: build one, or with --skip-build use softflowd-ntopng)"
    )
    parser.add_argument(
        "--ntopng-cpp-bin",
        default=None,
        help="softflowd+ built with -DSOFTFLOW_NTOPNG=ON for --ntopng, whose -v ntopng "
             "messages are compared byte for byte with those of the C build "
             "(default: build one, or with --skip-build use softflowd+-ntopng)"
    )
    parser.add_argument(
        "--a",
        default=None,
        help="Explicit comparison source (A, reference) softflowd daemon binary"
    )
    parser.add_argument(
        "--b",
        default=None,
        help="Explicit comparison target (B) softflowd daemon binary"
    )
    parser.add_argument(
        "--ctl-a",
        default=None,
        help="Explicit comparison source (A) softflowctl binary"
    )
    parser.add_argument(
        "--ctl-b",
        default=None,
        help="Explicit comparison target (B) softflowctl binary"
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
             "on exit, for A and B (default: on; --no-gauge-clock turns it off)"
    )
    parser.add_argument(
        "--benchmark",
        nargs="?",
        const="auto",
        default="auto",
        choices=["auto", "hyperfine", "time"],
        metavar="TOOL",
        help="Time each daemon (A and B) for every test case with hyperfine, "
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
    if args.ntopng_bin and not args.ntopng:
        parser.error("--ntopng-bin needs --ntopng")
    if args.ntopng_cpp_bin and not args.ntopng:
        parser.error("--ntopng-cpp-bin needs --ntopng")
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

    BUILD_OPTIMIZED_FOR_MEASURE = not args.skip_build
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
    if args.a and args.b:
        success = run_single_comparison(
            a_daemon=args.a,
            b_daemon=args.b,
            ctl_a=args.ctl_a or args.a.replace("softflowd", "softflowctl"),
            ctl_b=args.ctl_b or args.b.replace("softflowd", "softflowctl"),
            pair_name=f"{os.path.basename(args.a)}_vs_{os.path.basename(args.b)}",
            test_ctl=not args.skip_ctl,
            ignore_timestamp=args.ignore_timestamp,
            auto_ignore_legacy_v9=args.auto_ignore_legacy_v9,
            auto_ignore_icmp_reclass=args.auto_ignore_icmp_reclass,
            ignore_ipv6=args.ignore_ipv6,
            include_collector_metadata=args.include_collector_metadata,
            test_psamp=args.psamp,
            test_strict=args.strict
        )
        if args.ntopng:
            success = ntopng_step(args, build_dir) and success
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
        dev_paths = build_c_dev(build_dir)
        for i, (short, _, _, suffix) in enumerate(C_BUILD_VARIANTS):
            binaries[f"softflowd{suffix}"] = dev_paths[i * 2]
            binaries[f"softflowctl{suffix}"] = dev_paths[i * 2 + 1]

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
            "softflowd-direct", "softflowctl-direct",
            "softflowd+", "softflowctl+",
            "rsoftflowd", "rsoftctl"
        ]:
            path = os.path.join(build_dir, name)
            if not os.path.exists(path):
                path = shutil.which(name) or os.path.join(PROJECT_ROOT, name)
            binaries[name] = path if (path and os.path.exists(path)) else None

    # 2. Define standard compatibility comparison matrix requested by user
    # The pairs of C development builds, which also compare the PSAMP sender and receiver.
    PSAMP_PAIRS = {("softflowd-static", "softflowd"), ("softflowd-direct", "softflowd")}
    comparison_pairs = [
        # (A daemon, B daemon, A ctl, B ctl): A is the comparison source, B the target
        ("stable-softflowd-legacy", "softflowd-legacy", "stable-softflowctl-legacy", "softflowctl-legacy"),
        ("stable-softflowd", "softflowd", "stable-softflowctl", "softflowctl"),
        # --enable-compat-export=static as A, the default (dynamic) build as B
        # (the same two builds that `bench -b static,dynamic` compares)
        ("softflowd-static", "softflowd", "softflowctl-static", "softflowctl"),
        # --enable-direct-copies as a variant to check ASan/UBSan implications
        ("softflowd-direct", "softflowd", "softflowctl-direct", "softflowctl"),
    ]

    if not args.skip_cpp:
        comparison_pairs.append(("softflowd", "softflowd+", "softflowctl", "softflowctl+"))
    if not args.skip_rust:
        comparison_pairs.append(("softflowd", "rsoftflowd", "softflowctl", "rsoftctl"))

    print("\n" + "=" * 60)
    print("STARTING TEST MATRIX EXECUTION")
    print("=" * 60)

    overall_passed = True
    for a_name, b_name, ctl_a_name, ctl_b_name in comparison_pairs:
        a_daemon = binaries.get(a_name)
        b_daemon = binaries.get(b_name)
        ctl_a = binaries.get(ctl_a_name)
        ctl_b = binaries.get(ctl_b_name)

        if not a_daemon or not os.path.exists(a_daemon):
            print_yellow(f"\n[SKIPPED] A binary '{a_name}' not available.")
            continue
        if not b_daemon or not os.path.exists(b_daemon):
            print_yellow(f"\n[SKIPPED] B binary '{b_name}' not available.")
            continue

        passed = run_single_comparison(
            a_daemon=a_daemon,
            b_daemon=b_daemon,
            ctl_a=ctl_a,
            ctl_b=ctl_b,
            pair_name=f"{a_name}_vs_{b_name}",
            test_ctl=not args.skip_ctl,
            ignore_timestamp=args.ignore_timestamp,
            auto_ignore_legacy_v9=args.auto_ignore_legacy_v9,
            auto_ignore_icmp_reclass=args.auto_ignore_icmp_reclass,
            ignore_ipv6=args.ignore_ipv6,
            include_collector_metadata=args.include_collector_metadata,
            test_psamp=(not args.skip_psamp and ((a_name, b_name) in PSAMP_PAIRS
                                                 or (a_name, b_name) in PARITY_PAIRS)),
            test_strict=(not args.skip_parity and (a_name, b_name) in PARITY_PAIRS)
        )
        if not passed:
            overall_passed = False

    if args.ntopng:
        overall_passed = ntopng_step(args, build_dir) and overall_passed

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
