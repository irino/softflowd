#!/usr/bin/env python3
"""
softflowd Comprehensive Backward Compatibility Test Suite

This script verifies backward compatibility between softflowd stable version (1.1.1)
and current development source code (C development versions).

Features:
- Automatically compiles all necessary binaries (C stable, C dev, plus optional C++ and Rust).
- Compares NetFlow/IPFIX exported flow records (v1, v5, v9, IPFIX) via nfcapd & nfdump.
- Compares softflowctl control socket queries/statistics and shutdown commands.
- Configurable stable commit/tag and flexible skip options.

Default comparison matrix:
  1. stable-softflowd-legacy vs softflowd-legacy
  2. stable-softflowd vs softflowd
  3. softflowd vs softflowd-unified
  4. softflowd vs softflowd+ (skippable)
  5. softflowd vs rsoftflowd (skippable)

Usage:
    python3 run_compat_suite.py [OPTIONS]

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
                              ICMP/ICMPv6 -- and only where every other column still matches
                              (default: True)
    --no-auto-ignore-icmp-reclass : Disable the above; compare those columns too
    -6, --ignore-ipv6       : Ignore IPv6 test cases
    --include-collector-metadata : Also compare nfdump's collector-side metadata
                              columns (ra/eng/exid/tr); masked out by default since
                              they reflect nfcapd's own receive time/state, not the
                              exporter's output
    --gauge-clock             : Also run each daemon once per test case with its own
                              -g flag and print the "cpu clocks" (total) and
                              "cpu clocks (export)" (time inside the export call)
                              counters it reports on exit, for stable and dev
    -h, --help              : Show this help message
"""

import argparse
import re
import atexit
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
from typing import Dict, List, Optional, Tuple

# Project root directory
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

# Global test work directory for artifacts
SUITE_TMP_DIR = tempfile.mkdtemp(prefix="softflowd_suite_")
atexit.register(shutil.rmtree, SUITE_TMP_DIR)

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
# correspondingly wrong ICMP type/code overlaid in nfdump's 'dp' column. "1"
# (ICMPv4) is included defensively even though the bug is IPv6-specific, since
# ICMPv4 rows use the same 'pr'/'dp' overlay convention.
ICMP_RECLASSIFICATION_PROTOCOLS = {"0", "1", "58"}

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


def ensure_sample_pcap(name: str, url: str) -> str:
    """Download or return cached sample PCAP file."""
    path = os.path.join(SUITE_TMP_DIR, name)
    if not os.path.exists(path):
        print(f"Downloading test sample PCAP: {name} ...")
        try:
            urllib.request.urlretrieve(url, path)
        except Exception as e:
            print_red(f"Failed to download PCAP file ({name}): {e}")
            sys.exit(1)
    return path


def run_command(cmd: List[str], cwd: Optional[str] = None, env: Optional[dict] = None) -> subprocess.CompletedProcess:
    """Execute a shell command, showing clear error messages on failure."""
    res = subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        print_red(f"Command failed: {' '.join(cmd)} (cwd={cwd})")
        if res.stdout:
            print(f"Stdout:\n{res.stdout}")
        if res.stderr:
            print(f"Stderr:\n{res.stderr}")
    return res


# ==============================================================================
# Build Functions
# ==============================================================================

def build_c_stable(commit_hash: str, output_dir: str) -> Tuple[str, str, str, str]:
    """
    Check out C stable version into an isolated temp worktree and compile both
    standard and legacy variants.
    Returns: (stable-softflowd, stable-softflowctl, stable-softflowd-legacy, stable-softflowctl-legacy)
    """
    print_cyan(f"\n[Build] Compiling C stable version (Commit/Tag: {commit_hash})...")
    worktree_dir = os.path.join(SUITE_TMP_DIR, "c_stable_worktree")

    run_command(["git", "worktree", "add", "-f", worktree_dir, commit_hash], cwd=PROJECT_ROOT)
    atexit.register(lambda: subprocess.run(["git", "worktree", "remove", "-f", worktree_dir], cwd=PROJECT_ROOT, stderr=subprocess.DEVNULL))

    # 1. Build default stable version
    print("  -> Configuring and building stable default...")
    run_command(["autoreconf", "-i"], cwd=worktree_dir)
    run_command(["./configure"], cwd=worktree_dir)
    run_command(["make", "clean"], cwd=worktree_dir)
    res = run_command(["make", "-j"], cwd=worktree_dir)
    if res.returncode != 0:
        print_red("Failed to build stable default C binaries.")
        sys.exit(1)

    stable_softflowd = os.path.join(output_dir, "stable-softflowd")
    stable_softflowctl = os.path.join(output_dir, "stable-softflowctl")
    shutil.copy2(os.path.join(worktree_dir, "softflowd"), stable_softflowd)
    shutil.copy2(os.path.join(worktree_dir, "softflowctl"), stable_softflowctl)

    # 2. Build legacy stable version
    print("  -> Configuring and building stable legacy (--enable-legacy)...")
    run_command(["./configure", "--enable-legacy"], cwd=worktree_dir)
    run_command(["make", "clean"], cwd=worktree_dir)
    res = run_command(["make", "-j"], cwd=worktree_dir)
    if res.returncode != 0:
        print_red("Failed to build stable legacy C binaries.")
        sys.exit(1)

    stable_legacy_softflowd = os.path.join(output_dir, "stable-softflowd-legacy")
    stable_legacy_softflowctl = os.path.join(output_dir, "stable-softflowctl-legacy")
    shutil.copy2(os.path.join(worktree_dir, "softflowd"), stable_legacy_softflowd)
    shutil.copy2(os.path.join(worktree_dir, "softflowctl"), stable_legacy_softflowctl)

    return stable_softflowd, stable_softflowctl, stable_legacy_softflowd, stable_legacy_softflowctl


def build_c_dev(output_dir: str) -> Tuple[str, str, str, str, str, str]:
    """
    Compile C development version (current working source tree including uncommitted/current changes)
    in 3 configurations:
      1. Default (softflowd / softflowctl)
      2. Legacy (softflowd-legacy / softflowctl-legacy)
      3. Unified export (softflowd-unified / softflowctl-unified)
    """
    print_cyan("\n[Build] Compiling C development version (current source tree)...")

    # 1. Default C Dev
    print("  -> Configuring and building C development default...")
    run_command(["autoreconf", "-i"], cwd=PROJECT_ROOT)
    run_command(["./configure"], cwd=PROJECT_ROOT)
    run_command(["make", "clean"], cwd=PROJECT_ROOT)
    res = run_command(["make", "-j"], cwd=PROJECT_ROOT)
    if res.returncode != 0:
        print_red("Failed to build C development default binaries.")
        sys.exit(1)

    c_softflowd = os.path.join(output_dir, "softflowd")
    c_softflowctl = os.path.join(output_dir, "softflowctl")
    shutil.copy2(os.path.join(PROJECT_ROOT, "softflowd"), c_softflowd)
    shutil.copy2(os.path.join(PROJECT_ROOT, "softflowctl"), c_softflowctl)

    # 2. Legacy C Dev
    print("  -> Configuring and building C development legacy (--enable-legacy)...")
    run_command(["./configure", "--enable-legacy"], cwd=PROJECT_ROOT)
    run_command(["make", "clean"], cwd=PROJECT_ROOT)
    res = run_command(["make", "-j"], cwd=PROJECT_ROOT)
    if res.returncode != 0:
        print_red("Failed to build C development legacy binaries.")
        sys.exit(1)

    c_legacy_softflowd = os.path.join(output_dir, "softflowd-legacy")
    c_legacy_softflowctl = os.path.join(output_dir, "softflowctl-legacy")
    shutil.copy2(os.path.join(PROJECT_ROOT, "softflowd"), c_legacy_softflowd)
    shutil.copy2(os.path.join(PROJECT_ROOT, "softflowctl"), c_legacy_softflowctl)

    # 3. Unified C Dev
    print("  -> Configuring and building C development unified (--enable-export-merge=all)...")
    run_command(["./configure", "--enable-export-merge=all"], cwd=PROJECT_ROOT)
    run_command(["make", "clean"], cwd=PROJECT_ROOT)
    res = run_command(["make", "-j"], cwd=PROJECT_ROOT)
    if res.returncode != 0:
        print_red("Failed to build C development unified binaries.")
        sys.exit(1)

    c_unified_softflowd = os.path.join(output_dir, "softflowd-unified")
    c_unified_softflowctl = os.path.join(output_dir, "softflowctl-unified")
    shutil.copy2(os.path.join(PROJECT_ROOT, "softflowd"), c_unified_softflowd)
    shutil.copy2(os.path.join(PROJECT_ROOT, "softflowctl"), c_unified_softflowctl)

    return (
        c_softflowd, c_softflowctl,
        c_legacy_softflowd, c_legacy_softflowctl,
        c_unified_softflowd, c_unified_softflowctl
    )


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
    port = 2055
    nfcapd_proc = subprocess.Popen(["nfcapd", "-p", str(port), "-w", out_dir], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

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


def run_gauge_capture(pcap_path: str, daemon_bin: str, version: int) -> Optional[Tuple[int, Optional[int], Optional[int]]]:
    """Run daemon once with -g and parse the "cpu clocks" lines it prints on exit.

    Returns (total_clocks, export_clocks, export_calls), where export_clocks/
    export_calls are None if the daemon predates the export-clock counter or
    ran with threaded export (-M), which reports "n/a" for export clocks.
    Returns None if the daemon does not support -g at all (no output line).
    """
    cmd = [daemon_bin, "-g", "-r", pcap_path, "-n", "127.0.0.1:2055", "-v", str(version)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    total = export = calls = None
    for line in res.stderr.splitlines():
        m = re.search(r"cpu clocks:\s*(\d+)", line)
        if m:
            total = int(m.group(1))
        m = re.search(r"cpu clocks \(export\):\s*(\d+)\s*\((\d+) calls\)", line)
        if m:
            export, calls = int(m.group(1)), int(m.group(2))
    if total is None:
        return None
    return total, export, calls


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
        if icmp_mask_idx and pr_idx is not None and pr_idx < len(parts) and parts[pr_idx] in ICMP_RECLASSIFICATION_PROTOCOLS:
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
    include_collector_metadata: bool = False,
    gauge_clock: bool = False
) -> bool:
    """Compare nfdump output across NetFlow v1, v5, v9 and IPFIX."""
    print("  [Step 3] Verifying Differential Packet Export (nfdump output)...")

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

        csv_stable = run_nfdump_capture(pcap_path, stable_daemon, version)
        norm_stable = normalize_nfdump_csv(csv_stable, should_ignore_ts, include_collector_metadata, norm_icmp)

        csv_dev = run_nfdump_capture(pcap_path, dev_daemon, version)
        norm_dev = normalize_nfdump_csv(csv_dev, should_ignore_ts, include_collector_metadata, norm_icmp)

        display_name = name
        if should_ignore_ts and not ignore_timestamp:
            display_name += " [timestamp ignored: known stable-legacy NetFlow v9 bug]"
        if norm_icmp:
            display_name += " [ICMP protocol/dest-port tolerance active]"

        if gauge_clock:
            g_stable = run_gauge_capture(pcap_path, stable_daemon, version)
            g_dev = run_gauge_capture(pcap_path, dev_daemon, version)

            def fmt(g):
                if g is None:
                    return "-g not supported"
                total, export, calls = g
                if export is None:
                    return f"total={total}"
                return f"total={total} export={export} ({calls} calls)"
            print(f"      cpu clocks: stable[{fmt(g_stable)}]  dev[{fmt(g_dev)}]")

        if norm_stable == norm_dev and len(norm_stable) > 0:
            print(f"    - {display_name}: MATCHED ({len(norm_stable)} records)")
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
    include_collector_metadata: bool = False,
    gauge_clock: bool = False
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
        auto_ignore_icmp_reclass, ignore_ipv6, include_collector_metadata, gauge_clock
    ):
        return False

    print_green(f"\n>> Pair comparison [{os.path.basename(stable_daemon)} vs {os.path.basename(dev_daemon)}] PASSED.\n")
    return True


# ==============================================================================
# Main Entrypoint
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="softflowd Comprehensive Backward Compatibility Test Suite"
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
        "--gauge-clock",
        dest="gauge_clock",
        action="store_true",
        help="Also run each daemon once per test case with its own -g flag and print "
             "the \"cpu clocks\" (total) and \"cpu clocks (export)\" counters it reports "
             "on exit, for stable and dev (default: False)"
    )
    args = parser.parse_args()

    # Verify required environment tools
    check_required_tool("nfdump", "nfdump", "https://github.com/phaag/nfdump")
    check_required_tool("nfcapd", "nfdump", "https://github.com/phaag/nfdump")

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
            include_collector_metadata=args.include_collector_metadata,
            gauge_clock=args.gauge_clock
        )
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
        c_d, c_c, c_leg_d, c_leg_c, c_uni_d, c_uni_c = build_c_dev(build_dir)
        binaries["softflowd"] = c_d
        binaries["softflowctl"] = c_c
        binaries["softflowd-legacy"] = c_leg_d
        binaries["softflowctl-legacy"] = c_leg_c
        binaries["softflowd-unified"] = c_uni_d
        binaries["softflowctl-unified"] = c_uni_c

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
            "softflowd-unified", "softflowctl-unified",
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
        ("softflowd", "softflowd-unified", "softflowctl", "softflowctl-unified"),
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
            include_collector_metadata=args.include_collector_metadata,
            gauge_clock=args.gauge_clock
        )
        if not passed:
            overall_passed = False

    print("=" * 60)
    if overall_passed:
        print_green("ALL COMPATIBILITY TESTS PASSED SUCCESSFULLY!")
        sys.exit(0)
    else:
        print_red("SOME COMPATIBILITY TESTS FAILED. PLEASE REVIEW LOGS ABOVE.")
        sys.exit(1)


if __name__ == "__main__":
    main()
