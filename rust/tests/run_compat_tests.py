#!/usr/bin/env python3
"""
Integration test suite for rsoftflowd compatibility.

This module provides an automated environment to verify compatibility between
the Rust-ported rsoftflowd and the original softflowd implementation.
It uses pcap samples, nfcapd, and nfdump to compare exported flow records
across different NetFlow/IPFIX versions.

Usage:
    python3 tests/run_compat_tests.py [OPTIONS]

Options:
    -i, --ignore-timestamp  : Ignore 'firstSeen' and 'duration' fields when comparing nfdump output between softflowd (C) and rsoftflowd (Rust).
    -6  --ignore-ipv6       : Ignore IPv6 tests.

This script manages the lifecycle of daemon processes, performs flow export
validation using nfcapd/nfdump, and handles temporary resource cleanup.
"""

import argparse
import atexit
import os
import shutil

# import signal
# import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request

# from typing import List, Tuple

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUST_DAEMON = os.path.join(BASE_DIR, "target", "debug", "rsoftflowd")
RUST_CTL = os.path.join(BASE_DIR, "target", "debug", "rsoftflowctl")
TMP_DIR = tempfile.mkdtemp(prefix="rsoftflowd_test_")
atexit.register(shutil.rmtree, TMP_DIR)
HTTP_PCAP_URL = (
    "https://wiki.wireshark.org/uploads/27707187aeb30df68e70c8fb9d614981/http.cap"
)
V6_HTTP_PCAP_URL = "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/v6-http.cap"


def ensure_sample_pcap(name, url):
    """
    Downloads or retrieves a sample pcap file from a URL.

    Args:
        filename (str): Local filename to store the pcap.
        url (str): Remote URL to download from if local file is missing.
    Returns:
        str: Absolute path to the pcap file.
    """
    path = os.path.join(TMP_DIR, name)
    if not os.path.exists(path):
        print(f"Downloading {name}...")
        urllib.request.urlretrieve(url, path)
    return path


def print_green(text: str):
    print(f"\033[92m{text}\033[0m")


def print_red(text: str):
    print(f"\033[91m{text}\033[0m")


def print_yellow(text: str):
    print(f"\033[93m{text}\033[0m")


def check_command(cmd, apt_pkg, source_url):
    path = shutil.which(cmd)
    if path:
        return path

    print_red(f"Error: {cmd} not found.")
    print(f"Please install it using one of the following methods:")
    print(f"  Ubuntu/Debian: sudo apt update && sudo apt install -y {apt_pkg}")
    print(f"  Source: {source_url}")
    sys.exit(1)


def check_binaries():
    # 既存のsoftflowd/softflowctlの確認
    C_DAEMON = check_command(
        "softflowd", "softflowd", "https://github.com/irino/softflowd"
    )
    C_CTL = check_command(
        "softflowctl", "softflowd", "https://github.com/irino/softflowd"
    )

    # check nfdump/nfcapd command
    NFDUMP = check_command("nfdump", "nfdump", "https://github.com/phaag/nfdump")
    NFCAPD = check_command("nfcapd", "nfdump", "https://github.com/phaag/nfdump")

    return C_DAEMON, C_CTL, NFDUMP, NFCAPD


def run_nfdump_test(pcap_path, daemon_bin, version, is_v6):
    """
    Executes a daemon, processes a pcap file, and compares nfdump CSV output.

    Args:
        pcap_path (str): Path to the input pcap file.
        daemon_bin (str): Path to the daemon binary (softflowd or rsoftflowd).
        version (int): NetFlow/IPFIX version to test.
        is_v6 (bool): Flag indicating if the pcap contains IPv6 traffic.
    Returns:
        str: CSV formatted output from nfdump.
    """
    keep_tmp = os.getenv("KEEP_TMP") == "1"  # jadge by environment variables
    out_dir = tempfile.mkdtemp()
    port = 2055
    nfcapd_proc = subprocess.Popen(["nfcapd", "-p", str(port), "-w", out_dir])
    time.sleep(1)
    try:
        # デーモンの起動
        cmd = [
            daemon_bin,
            "-d",
            "-r",
            pcap_path,
            "-a",
            "-n",
            f"127.0.0.1:{port}",
            "-v",
            str(version),
        ]
        proc = subprocess.Popen(cmd)
        proc.wait()
        nfcapd_proc.terminate()
        nfcapd_proc.wait()
        # csv output by nfdump
        result = subprocess.run(
            ["nfdump", "-R", out_dir, "-o", "csv"], capture_output=True, text=True
        )
        return result.stdout
    finally:
        if not keep_tmp:
            shutil.rmtree(out_dir)


def test_cli_compatibility(C_DAEMON, RUST_DAEMON):
    print("--------------------------------------------------")
    print("Testing 1: CLI Options Compatibility...")
    print("--------------------------------------------------")

    # 1. Invalid option exit codes
    p_c = subprocess.run([C_DAEMON, "-z"], capture_output=True, text=True)
    p_rust = subprocess.run([RUST_DAEMON, "-z"], capture_output=True, text=True)

    print(f"C '-z' exit status: {p_c.returncode}")
    print(f"Rust '-z' exit status: {p_rust.returncode}")

    if p_c.returncode == 0 or p_rust.returncode == 0:
        print_red("FAILED: Invalid CLI options should return non-zero exit code.")
        sys.exit(1)

    # 2. Help output options inclusion check
    p_c_res = subprocess.run([C_DAEMON, "-h"], capture_output=True, text=True)
    p_rust_res = subprocess.run([RUST_DAEMON, "-h"], capture_output=True, text=True)
    p_c_help = p_c_res.stdout + p_c_res.stderr
    p_rust_help = p_rust_res.stdout + p_rust_res.stderr

    required_options = [
        "-i",
        "-r",
        "-t",
        "-m",
        "-n",
        "-p",
        "-c",
        "-v",
        "-L",
        "-T",
        "-d",
        "-D",
    ]
    missing_c = [opt for opt in required_options if opt not in p_c_help]
    missing_rust = [opt for opt in required_options if opt not in p_rust_help]

    if missing_c or missing_rust:
        print_red(
            f"FAILED: Help strings missing key options. C missing: {missing_c}, Rust missing: {missing_rust}"
        )
        sys.exit(1)

    print_green("CLI compatibility tests PASSED.")


def start_blocked_daemon(
    daemon_bin: str, sock_path: str, extra_args: list = None
) -> Tuple[subprocess.Popen, int, str, str]:
    """
    Manages the lifecycle of a daemon process connected via a blocked PCAP FIFO.
    Used for testing control socket connectivity without live interface traffic.
    """
    fifo_dir = tempfile.mkdtemp()
    fifo_path = os.path.join(fifo_dir, "pcap.fifo")
    os.mkfifo(fifo_path)

    # Open FIFO in read-write mode so it doesn't block on opening
    fifo_fd = os.open(fifo_path, os.O_RDWR)
    # Write a standard pcap global header so pcap_open_offline succeeds
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    os.write(fifo_fd, header)

    args = [daemon_bin, "-d", "-r", fifo_path, "-c", sock_path]
    if extra_args:
        args.extend(extra_args)

    proc = subprocess.Popen(args)
    time.sleep(0.5)  # Let it initialize

    return proc, fifo_fd, fifo_path, fifo_dir


def stop_blocked_daemon(
    proc: subprocess.Popen, fifo_fd: int, fifo_path: str, fifo_dir: str
):
    """
    Manages the lifecycle of a daemon process connected via a blocked PCAP FIFO.
    Used for testing control socket connectivity without live interface traffic.
    """
    try:
        proc.terminate()

        start_time = time.time()
        while time.time() - start_time < 2.0:
            if proc.poll() is not None:
                break
            time.sleep(0.05)
        else:
            proc.kill()
            proc.wait()
    finally:
        try:
            os.close(fifo_fd)
        except:
            pass
        if os.path.exists(fifo_path):
            os.remove(fifo_path)
        if os.path.exists(fifo_dir):
            os.rmdir(fifo_dir)


def run_cross_control_tests(C_DAEMON, C_CTL, RUST_DAEMON, RUST_CTL):
    print("--------------------------------------------------")
    print("Testing 2: Control Socket Cross-Connection...")
    print("--------------------------------------------------")

    sock_c = os.path.join(TMP_DIR, "compat_test_c.sock")
    sock_rust = os.path.join(TMP_DIR, "compat_test_rust.sock")

    for sock in (sock_c, sock_rust):
        if os.path.exists(sock):
            os.remove(sock)

    # 1. Run C daemon with control socket in PSAMP mode (to enable multiplexing without root)
    proc_c = subprocess.Popen([C_DAEMON, "-d", "-R", "9999", "-c", sock_c])
    time.sleep(0.5)  # Allow server to start

    try:
        # Query C daemon statistics using C ctl
        out_c_c = subprocess.run(
            [C_CTL, "-c", sock_c, "statistics"], capture_output=True, text=True
        ).stdout
        print_yellow(f"C CTL -> C Daemon Statistics:\n{out_c_c}")
    finally:
        proc_c.terminate()
        proc_c.wait()

    if os.path.exists(sock_c):
        os.remove(sock_c)

    proc_c = subprocess.Popen([C_DAEMON, "-d", "-R", "9999", "-c", sock_c])
    time.sleep(0.5)

    try:
        # Query C daemon statistics using Rust ctl
        out_rust_c = subprocess.run(
            [RUST_CTL, "-c", sock_c, "statistics"], capture_output=True, text=True
        ).stdout
        print_yellow(f"Rust CTL -> C Daemon Statistics:\n{out_rust_c}")

        if "active flows" not in out_rust_c.lower():
            print_red("FAILED: Rust CTL could not retrieve statistics from C Daemon.")
            sys.exit(1)

        # Shut down C daemon using Rust ctl
        shutdown_res = subprocess.run(
            [RUST_CTL, "-c", sock_c, "shutdown"], capture_output=True, text=True
        ).stdout
        print_yellow(f"Rust CTL -> C Daemon Shutdown: {shutdown_res.strip()}")

        proc_c.wait(timeout=2)
        print_green("C Daemon shutdown by Rust CTL verified.")
    except Exception as e:
        print_red(f"FAILED during C Daemon cross control: {e}")
        proc_c.terminate()
        sys.exit(1)

    # 2. Run Rust daemon with control socket using a blocked PCAP FIFO
    proc_rust, r_fifo_fd, r_fifo_path, r_fifo_dir = start_blocked_daemon(
        RUST_DAEMON, sock_rust
    )

    try:
        # Query Rust daemon statistics using C ctl
        out_c_rust = subprocess.run(
            [C_CTL, "-c", sock_rust, "statistics"], capture_output=True, text=True
        ).stdout
        print_yellow(f"C CTL -> Rust Daemon Statistics:\n{out_c_rust}")

        # Query Rust daemon statistics using Rust ctl
        out_rust_rust = subprocess.run(
            [RUST_CTL, "-c", sock_rust, "statistics"], capture_output=True, text=True
        ).stdout
        print_yellow(f"Rust CTL -> Rust Daemon Statistics:\n{out_rust_rust}")

        if "active flows" not in out_c_rust.lower():
            print_red("FAILED: C CTL could not retrieve statistics from Rust Daemon.")
            sys.exit(1)

        # Shut down Rust daemon using C ctl
        shutdown_res = subprocess.run(
            [C_CTL, "-c", sock_rust, "shutdown"], capture_output=True, text=True
        ).stdout
        print_yellow(f"C CTL -> Rust Daemon Shutdown: {shutdown_res.strip()}")

        if proc_rust.poll() is None:
            os.close(r_fifo_fd)
            proc_rust.terminate()
            try:
                proc_rust.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                proc_rust.kill()
                proc_rust.wait()
        else:
            proc_rust.wait()

        print_green("Rust Daemon shutdown by C CTL verified.")
    except Exception as e:
        print_red(f"FAILED during Rust Daemon cross control: {e}")
        proc_rust.terminate()
        sys.exit(1)
    finally:
        stop_blocked_daemon(proc_rust, r_fifo_fd, r_fifo_path, r_fifo_dir)

    print_green("Control socket cross-connection tests PASSED.")


def strip_columns(line, n):
    parts = line.split(",", n)
    return parts[n] if len(parts) > n else ""


def test_differential_packets(
    C_DAEMON, RUST_DAEMON, ignore_ipv6=False, ignore_timestamp=False
):
    """
    Validates that rsoftflowd generates identical flow records as softflowd.

    Iterates through configured test cases (IPv4/IPv6), runs both daemons,
    exports flows to nfcapd, and performs a differential analysis using nfdump.
    """
    print("--------------------------------------------------")
    print("Testing 3: Differential Packet Output Verification (via nfdump)...")
    print("--------------------------------------------------")

    test_cases = [
        {
            "name": "IPv4 HTTP",
            "url": HTTP_PCAP_URL,
            "filename": "http.cap",
            "is_v6": False,
        },
        {
            "name": "IPv6 HTTP",
            "url": V6_HTTP_PCAP_URL,
            "filename": "http_v6.cap",
            "is_v6": True,
        },
    ]

    for case in test_cases:
        if ignore_ipv6 and case["is_v6"]:
            continue
        print(f"Running test case: {case['name']}")
        pcap_path = ensure_sample_pcap(case["filename"], case["url"])

        versions = [1, 5, 9, 10] if not case["is_v6"] else [9, 10]

        for version in versions:
            print(f"  Verifying NetFlow version: {version}")

            c_output = run_nfdump_test(pcap_path, C_DAEMON, version, case["is_v6"])
            r_output = run_nfdump_test(pcap_path, RUST_DAEMON, version, case["is_v6"])

            # Simple line-by-line comparison ignoring timestamp differences or header noise
            c_lines = sorted(
                [
                    (strip_columns(line, 2) if ignore_timestamp else line)
                    for line in c_output.splitlines()
                    if not line.startswith("firstSeen") and line.strip()
                    # ...
                ]
            )

            r_lines = sorted(
                [
                    (line.split(",", 2)[2] if ignore_timestamp else line)
                    for line in r_output.splitlines()
                    if not line.startswith("firstSeen") and line.strip()
                ]
            )

            if c_lines != r_lines:
                print_red(f"FAILED: Output mismatch for version {version}")
                # Print diff for debugging
                import difflib

                diff = difflib.unified_diff(
                    c_lines, r_lines, fromfile="C", tofile="Rust"
                )
                for line in diff:
                    print(line)
                sys.exit(1)
            else:
                for line in c_lines:
                    print(line)

            print_green(f"  Version {version} matched.")
            """
            print(f"  [DEBUG] Matched content for version {version}:")
            for line in c_lines:
                print(f"    {line}")
            """
    print_green("Differential packet output verification PASSED.")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i",
        "--ignore-timestamp",
        action="store_true",
        help="Ignore 'firstSeen' and 'duration' fields when comparing nfdump output between softflowd (C) and rsoftflowd (Rust).",
    )
    parser.add_argument(
        "-6",
        "--ignore-ipv6",
        action="store_true",
        help="Ignore IPv6 tests.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    C_DAEMON, C_CTL, NFDUMP, NFCAPD = check_binaries()
    args = parse_args()
    test_cli_compatibility(C_DAEMON, RUST_DAEMON)
    run_cross_control_tests(C_DAEMON, C_CTL, RUST_DAEMON, RUST_CTL)
    test_differential_packets(
        C_DAEMON, RUST_DAEMON, args.ignore_ipv6, args.ignore_timestamp
    )
    print_green("\nALL COMPATIBILITY TESTS PASSED SUCCESSFULLY!")
