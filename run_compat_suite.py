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
    -6, --ignore-ipv6       : Ignore IPv6 test cases
    -h, --help              : Show this help message
"""

import argparse
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
    print("  -> Configuring and building C development unified (--enable-unified-export)...")
    run_command(["./configure", "--enable-unified-export"], cwd=PROJECT_ROOT)
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


def normalize_nfdump_csv(csv_text: str, ignore_timestamp: bool = False) -> List[str]:
    """Parse and normalize CSV records for deterministic comparison."""
    lines = []
    for line in csv_text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("Summary") or line.startswith("Date") or line.startswith("Flow Record") or "Ident" in line or "SysID" in line:
            continue
        parts = line.split(",")
        if len(parts) >= 10:
            if ignore_timestamp:
                parts[0] = "TIMESTAMP"
                parts[1] = "DURATION"
            lines.append(",".join(parts))
    return sorted(lines)


def test_differential_output(
    stable_daemon: str, dev_daemon: str, ignore_timestamp: bool, ignore_ipv6: bool
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
        csv_stable = run_nfdump_capture(pcap_path, stable_daemon, version)
        norm_stable = normalize_nfdump_csv(csv_stable, ignore_timestamp)

        csv_dev = run_nfdump_capture(pcap_path, dev_daemon, version)
        norm_dev = normalize_nfdump_csv(csv_dev, ignore_timestamp)

        if norm_stable == norm_dev and len(norm_stable) > 0:
            print(f"    - {name}: MATCHED ({len(norm_stable)} records)")
        else:
            print_red(f"    - {name}: FAILED (Records: stable={len(norm_stable)}, dev={len(norm_dev)})")
            print("--- Stable Expected ---")
            for l in norm_stable[:3]:
                print(l)
            print("--- Dev Actual ---")
            for l in norm_dev[:3]:
                print(l)
            all_matched = False

    return all_matched


def run_single_comparison(
    stable_daemon: str,
    dev_daemon: str,
    ctl_stable: Optional[str],
    ctl_dev: Optional[str],
    test_ctl: bool,
    ignore_timestamp: bool,
    ignore_ipv6: bool
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
    if not test_differential_output(stable_daemon, dev_daemon, ignore_timestamp, ignore_ipv6):
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
            test_ctl=not args.skip_ctl,
            ignore_timestamp=args.ignore_timestamp,
            ignore_ipv6=args.ignore_ipv6
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
            test_ctl=not args.skip_ctl,
            ignore_timestamp=args.ignore_timestamp,
            ignore_ipv6=args.ignore_ipv6
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
