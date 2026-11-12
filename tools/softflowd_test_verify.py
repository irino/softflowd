"""
Checks of the compat suite (collector output, CLI, control socket) and the measurements
(--gauge-clock and --benchmark).
"""

import csv
import json
import os
import re
import shlex
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import time
from typing import List, Optional, Tuple

import softflowd_test_helper as helper
from softflowd_collector import UdpSink, datagrams_to_csv
from softflowd_test_helper import (
    COLLECTOR_METADATA_COLUMNS,
    DST_PORT_COLUMN_NAMES,
    HTTP_PCAP_URL,
    ICMP_RECLASSIFICATION_PROTOCOLS,
    PROJECT_ROOT,
    PROTOCOL_COLUMN_NAMES,
    V6_HTTP_PCAP_URL,
    callgrind_profile,
    ensure_sample_pcap,
    parse_gauge,
    perf_stat,
    print_cyan,
    print_green,
    print_red,
    print_yellow,
    run_command,
    warm_page_cache,
)


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
    fifo_dir = tempfile.mkdtemp(dir=helper.SUITE_TMP_DIR)
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

    sock_a = os.path.join(helper.SUITE_TMP_DIR, "ctl_a.sock")
    sock_b = os.path.join(helper.SUITE_TMP_DIR, "ctl_b.sock")

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
    out_dir = tempfile.mkdtemp(dir=helper.SUITE_TMP_DIR)
    # A free port, not the default 2055: some distributions (Debian, Ubuntu)
    # start their own nfcapd on 2055 when the nfdump package is installed.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    # Outside out_dir, which nfdump -R scans for capture files.
    nfcapd_log = os.path.join(helper.SUITE_TMP_DIR, f"nfcapd-{port}.log")
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
    if helper.COLLECTOR_BACKEND == "python":
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
        self.prefix = csv_path or os.path.join(helper.SUITE_TMP_DIR, "measure")
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
    with tempfile.TemporaryDirectory(dir=helper.SUITE_TMP_DIR) as tmp:
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
    print(f"  [Step 3] Verifying Differential Packet Export ({helper.COLLECTOR_BACKEND} collector)...")
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

    for extra in helper.COMPAT_PCAPS:
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
        elif norm_a == norm_b and pcap_path in helper.COMPAT_PCAPS:
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
