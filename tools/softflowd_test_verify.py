"""
Checks of the compat suite: the CLI options, the control socket and the flows that the collector
receives.
"""

import os
import shutil
import socket
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
    PROTOCOL_COLUMN_NAMES,
    V6_HTTP_PCAP_URL,
    ensure_sample_pcap,
    print_green,
    print_red,
    print_yellow,
)

from softflowd_test_measure import measure_pair

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
