#!/usr/bin/env python3
"""
softflowd_test_collector.py -- test, benchmark and collector tools for softflowd.

Standard library only.  The collector itself lives in softflowd_collector.py
(same directory), which this script imports; three subcommands:

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
    --ntopng-cpp-bin PATH   : softflowd+ built with -DSOFTFLOWD_CPP_NTOPNG=ON, whose -v ntopng messages
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
import os
import shutil
import sys
import tempfile
from typing import Dict, Optional

import softflowd_test_helper as helper
import softflowd_test_verify as verify
from softflowd_collector import collect_main
from softflowd_test_bench import bench_main
from softflowd_test_build import (
    C_BUILD_VARIANTS,
    build_c_dev,
    build_c_stable,
    build_cpp,
    build_rust,
)
from softflowd_test_helper import (
    PROJECT_ROOT,
    check_required_tool,
    default_cache_dir,
    print_green,
    print_red,
    print_yellow,
)
from softflowd_test_ntopng import ntopng_step
from softflowd_test_parity import PARITY_PAIRS
from softflowd_test_parity_live import run_single_comparison
from softflowd_test_verify import MeasureSettings, finish_measurements


# ==============================================================================
# Main Entrypoint
# ==============================================================================

def compat_main():
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
        help="softflowd+ built with -DSOFTFLOWD_CPP_NTOPNG=ON for --ntopng, whose -v ntopng "
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
    helper.SUITE_TMP_DIR = tempfile.mkdtemp(prefix="softflowd_suite_")
    atexit.register(shutil.rmtree, helper.SUITE_TMP_DIR)

    # Select the flow collector backend
    helper.PCAP_DIR = args.pcap_dir
    helper.COMPAT_PCAPS = [os.path.abspath(p) for p in args.pcaps]
    if args.no_cache and args.cache_dir:
        parser.error("--no-cache and --cache-dir cannot be used together")
    helper.CACHE_DIR = None if args.no_cache else os.path.abspath(
        os.path.expanduser(args.cache_dir or default_cache_dir()))
    helper.REBUILD_STABLE = args.rebuild_stable
    helper.REBUILD_DEV = args.rebuild_dev
    helper.REFRESH_PCAP = args.refresh_pcap
    have_nfdump = bool(shutil.which("nfdump") and shutil.which("nfcapd"))
    if args.collector == "auto":
        helper.COLLECTOR_BACKEND = "nfdump" if have_nfdump else "python"
        if not have_nfdump:
            print_yellow("nfdump/nfcapd not found: using the built-in Python collector "
                         "(softflowd_test_collector.py collect)")
    else:
        helper.COLLECTOR_BACKEND = args.collector
    if helper.COLLECTOR_BACKEND == "nfdump":
        check_required_tool("nfdump", "nfdump", "https://github.com/phaag/nfdump")
        check_required_tool("nfcapd", "nfdump", "https://github.com/phaag/nfdump")

    verify.BUILD_OPTIMIZED_FOR_MEASURE = not args.skip_build
    if measuring:
        verify.MEASURE = MeasureSettings(args.gauge_clock, bench_tool, args.bench_runs,
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

    build_dir = args.build_dir or os.path.join(helper.SUITE_TMP_DIR, "bin")
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
