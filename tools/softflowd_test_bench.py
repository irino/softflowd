"""
Export benchmark of softflowd: `softflowd_test_collector.py bench`.
"""

import argparse
import csv
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Dict, List, Optional

from softflowd_collector import UdpSink
from softflowd_test_helper import (
    build_c,
    callgrind_profile,
    copy_binaries,
    parse_gauge,
    perf_stat,
    warm_page_cache,
)


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
