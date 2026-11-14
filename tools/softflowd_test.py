#!/usr/bin/env python3
"""
softflowd_test.py -- backward compatibility and variants test suite for softflowd.

Standard library only.  The same as `softflowd_test_suite.py compat` (or `test`).
The pieces of the suite are the softflowd_test_*.py modules next to this script;
see tools/README.md.

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
  3. softflowd-static vs softflowd (skippable)
  4. softflowd-direct vs softflowd (skippable)
  5. softflowd vs softflowd+ (skippable)
  6. softflowd vs rsoftflowd (skippable)

The pairs 3 to 5 are also compared by the PSAMP sender and receiver (step 5) and byte for
byte (step 6): the exported datagrams, the control socket replies, the logs, the command line
errors and a live capture.  The other pairs differ on purpose in some of these.

Each pair is A vs B: A is the comparison source (reference), B the target, and
the binary names are shown in the titles of the results.

Usage:
    tools/softflowd_test.py [OPTIONS] [PCAP...]

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
    --skip-static           : Skip the softflowd-static build (--enable-compat-export=static)
                              and its pair
    --skip-direct           : Skip the softflowd-direct build (--enable-direct-copies) and its pair
    --skip-psamp            : Skip the PSAMP sender and receiver comparison (step 5), which the
                              pairs 3 to 5 run
    --skip-parity           : Skip the byte for byte comparison (step 6) of the pairs 3 to 5
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
"""

import argparse
import atexit
import os
import shutil
import sys
import tempfile
from typing import Dict, Optional

import softflowd_test_helper as helper
import softflowd_test_measure as measure
from softflowd_test_args import parse_args
from softflowd_test_build import build_c_dev, build_c_stable, build_cpp, build_rust, dev_variants
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
from softflowd_test_measure import MeasureSettings, finish_measurements


# ==============================================================================
# Main Entrypoint
# ==============================================================================


def setup_suite(args: argparse.Namespace) -> str:
    """Set the settings of the suite from the command line (the helper and measure modules).

    Returns the directory of the binaries.
    """
    # Created here, not at import time, so that bench/collect do not make one.
    helper.SUITE_TMP_DIR = tempfile.mkdtemp(prefix="softflowd_suite_")
    atexit.register(shutil.rmtree, helper.SUITE_TMP_DIR)

    # Select the flow collector backend
    helper.PCAP_DIR = args.pcap_dir
    helper.COMPAT_PCAPS = [os.path.abspath(p) for p in args.pcaps]
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
                         "(softflowd_collector.py)")
    else:
        helper.COLLECTOR_BACKEND = args.collector
    if helper.COLLECTOR_BACKEND == "nfdump":
        check_required_tool("nfdump", "nfdump", "https://github.com/phaag/nfdump")
        check_required_tool("nfcapd", "nfdump", "https://github.com/phaag/nfdump")

    measure.BUILD_OPTIMIZED_FOR_MEASURE = not args.skip_build
    if args.measuring:
        measure.MEASURE = MeasureSettings(args.gauge_clock, args.bench_tool, args.bench_runs,
                                  args.bench_warmup, args.bench_min_runs,
                                  args.bench_max_runs, args.callgrind,
                                  args.callgrind_top, args.perf, args.bench_pcap,
                                  args.bench_csv)
        if args.bench_tool:
            if args.bench_min_runs is None and args.bench_max_runs is None:
                runs = f"{args.bench_runs} timed runs"
            else:
                runs = f"min {args.bench_min_runs or 10} runs" + \
                    (f", max {args.bench_max_runs}" if args.bench_max_runs else "")
            print(f"Benchmark tool: {args.bench_tool} ({args.bench_warmup} warmup + "
                  f"{runs} per daemon and test case)")

    build_dir = args.build_dir or os.path.join(helper.SUITE_TMP_DIR, "bin")
    os.makedirs(build_dir, exist_ok=True)
    return build_dir


def compare_pair(args: argparse.Namespace, a_daemon: str, b_daemon: str, ctl_a: Optional[str],
                 ctl_b: Optional[str], pair_name: str, test_psamp: bool, test_strict: bool) -> bool:
    """Compare A with B (all steps), with the comparison options of the command line."""
    return run_single_comparison(
        a_daemon=a_daemon,
        b_daemon=b_daemon,
        ctl_a=ctl_a,
        ctl_b=ctl_b,
        pair_name=pair_name,
        test_ctl=not args.skip_ctl,
        ignore_timestamp=args.ignore_timestamp,
        auto_ignore_legacy_v9=args.auto_ignore_legacy_v9,
        auto_ignore_icmp_reclass=args.auto_ignore_icmp_reclass,
        ignore_ipv6=args.ignore_ipv6,
        include_collector_metadata=args.include_collector_metadata,
        test_psamp=test_psamp,
        test_strict=test_strict
    )


def build_binaries(args: argparse.Namespace, build_dir: str) -> Dict[str, Optional[str]]:
    """Build the binaries of all variants; the variants that are skipped are None."""
    binaries: Dict[str, Optional[str]] = {}
    # Build C Stable 1.1.1 variants
    st_d, st_c, st_leg_d, st_leg_c = build_c_stable(args.stable_commit, build_dir)
    binaries["stable-softflowd"] = st_d
    binaries["stable-softflowctl"] = st_c
    binaries["stable-softflowd-legacy"] = st_leg_d
    binaries["stable-softflowctl-legacy"] = st_leg_c

    # Build C Development variants (current working directory tree)
    skipped = [v for v, skip in (("static", args.skip_static),
                                 ("direct", args.skip_direct)) if skip]
    dev_paths = build_c_dev(build_dir, skipped)
    for i, (short, _, _, suffix) in enumerate(dev_variants(skipped)):
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
    return binaries


def find_binaries(build_dir: str) -> Dict[str, Optional[str]]:
    """Look for the binaries that exist already (--skip-build): in the build directory, in the PATH
    and in the project directory.  Those that are not found are None."""
    binaries: Dict[str, Optional[str]] = {}
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
    return binaries


def comparison_pairs(args: argparse.Namespace) -> list:
    """The standard comparison matrix: (A daemon, B daemon, A ctl, B ctl) with the names of the binaries."""
    pairs = [
        # (A daemon, B daemon, A ctl, B ctl): A is the comparison source, B the target
        ("stable-softflowd-legacy", "softflowd-legacy", "stable-softflowctl-legacy", "softflowctl-legacy"),
        ("stable-softflowd", "softflowd", "stable-softflowctl", "softflowctl"),
    ]
    if not args.skip_static:
        # --enable-compat-export=static as A, the default (dynamic) build as B
        # (the same two builds that `bench -b static,dynamic` compares)
        pairs.append(("softflowd-static", "softflowd", "softflowctl-static", "softflowctl"))
    if not args.skip_direct:
        # --enable-direct-copies as a variant to check ASan/UBSan implications
        pairs.append(("softflowd-direct", "softflowd", "softflowctl-direct", "softflowctl"))

    if not args.skip_cpp:
        pairs.append(("softflowd", "softflowd+", "softflowctl", "softflowctl+"))
    if not args.skip_rust:
        pairs.append(("softflowd", "rsoftflowd", "softflowctl", "rsoftctl"))
    return pairs


def run_matrix(args: argparse.Namespace, binaries: Dict[str, Optional[str]]) -> bool:
    """Compare every pair of the matrix whose two binaries exist; True if all passed."""
    print("\n" + "=" * 60)
    print("STARTING TEST MATRIX EXECUTION")
    print("=" * 60)

    overall_passed = True
    for a_name, b_name, ctl_a_name, ctl_b_name in comparison_pairs(args):
        a_daemon = binaries.get(a_name)
        b_daemon = binaries.get(b_name)

        if not a_daemon or not os.path.exists(a_daemon):
            print_yellow(f"\n[SKIPPED] A binary '{a_name}' not available.")
            continue
        if not b_daemon or not os.path.exists(b_daemon):
            print_yellow(f"\n[SKIPPED] B binary '{b_name}' not available.")
            continue

        passed = compare_pair(
            args, a_daemon, b_daemon, binaries.get(ctl_a_name), binaries.get(ctl_b_name),
            pair_name=f"{a_name}_vs_{b_name}",
            test_psamp=(not args.skip_psamp and (a_name, b_name) in PARITY_PAIRS),
            test_strict=(not args.skip_parity and (a_name, b_name) in PARITY_PAIRS)
        )
        if not passed:
            overall_passed = False
    return overall_passed


def compat_main():
    args = parse_args()
    build_dir = setup_suite(args)

    # A single pair that the command line names
    if args.a and args.b:
        success = compare_pair(
            args, args.a, args.b,
            ctl_a=args.ctl_a or args.a.replace("softflowd", "softflowctl"),
            ctl_b=args.ctl_b or args.b.replace("softflowd", "softflowctl"),
            pair_name=f"{os.path.basename(args.a)}_vs_{os.path.basename(args.b)}",
            test_psamp=args.psamp,
            test_strict=args.strict
        )
        if args.ntopng:
            success = ntopng_step(args, build_dir) and success
        finish_measurements()
        sys.exit(0 if success else 1)

    binaries = find_binaries(build_dir) if args.skip_build else build_binaries(args, build_dir)
    overall_passed = run_matrix(args, binaries)

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


if __name__ == "__main__":
    compat_main()
