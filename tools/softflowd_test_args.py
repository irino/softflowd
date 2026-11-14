"""
The command line of softflowd_test.py: the options, and the checks of their combinations.
"""

import argparse
import os
import shutil

from softflowd_test_helper import print_yellow


def build_parser() -> argparse.ArgumentParser:
    """The parser of the options of the compat suite."""
    parser = argparse.ArgumentParser(
        description="softflowd Comprehensive Backward Compatibility Test Suite",
        epilog="See also softflowd_bench.py (export benchmark) and softflowd_collector.py "
               "(flow collector); softflowd_test_suite.py runs all three."
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
        "--skip-static",
        action="store_true",
        help="Skip the softflowd-static build (--enable-compat-export=static) and its pair"
    )
    parser.add_argument(
        "--skip-direct",
        action="store_true",
        help="Skip the softflowd-direct build (--enable-direct-copies) and its pair"
    )
    parser.add_argument(
        "--skip-psamp",
        action="store_true",
        help="Skip the PSAMP sender and receiver comparison (step 5) of the pairs that "
             "get the byte for byte comparison (softflowd-static, softflowd-direct and "
             "softflowd+ against softflowd)"
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
        help="Also compare the --a/--b pair byte for byte, as the pairs softflowd-static "
             "and softflowd-direct vs softflowd and softflowd vs softflowd+ always are "
             "(step 6): exported datagrams, control socket replies, "
             "the expiry lines of the debug log, -M and, as root, a live capture on lo. "
             "It also checks that a refactoring changes no output: --a is the softflowd+ "
             "before and --b the softflowd+ after (their usage must be the same)"
    )
    parser.add_argument(
        "--skip-parity",
        action="store_true",
        help="Skip the byte for byte comparison (step 6) of the pairs softflowd-static, "
             "softflowd-direct and softflowd+ against softflowd"
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
    return parser


def parse_args() -> argparse.Namespace:
    """Parse and check the command line.

    Besides the options, the result has args.measuring (something is measured) and
    args.bench_tool (the timing tool: hyperfine or time, or None).
    """
    parser = build_parser()
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
    if args.no_cache and args.cache_dir:
        parser.error("--no-cache and --cache-dir cannot be used together")
    args.measuring = measuring
    args.bench_tool = bench_tool
    return args
