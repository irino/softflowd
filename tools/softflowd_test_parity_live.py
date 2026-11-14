"""
Parity checks (2/2): what the builds of PARITY_PAIRS must do byte for byte like softflowd (C),
the checks of a live capture, the daemon, the CLI and the comparison of a pair.
"""

import calendar
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
from typing import List, Optional, Tuple

import softflowd_test_helper as helper
from softflowd_test_helper import (
    PROJECT_ROOT,
    parity_can_capture_lo,
    parse_gauge,
    print_cyan,
    print_green,
    print_red,
    print_yellow,
)
from softflowd_test_parity import (
    parity_control_replies,
    parity_debug_log,
    parity_expire_all_time,
    parity_export_bytes,
    parity_ipfix_records,
    parity_live,
    parity_make_pcaps,
    parity_multithread,
    parity_v5_header,
)
from softflowd_test_psamp import test_psamp_compat
from softflowd_test_measure import fmt_gauge
from softflowd_test_verify import (
    test_cli_compatibility,
    test_control_socket_compatibility,
    test_differential_output,
)


def parity_live_ifidx(a_daemon: str, b_daemon: str, ctl_a: str, ctl_b: str) -> bool:
    """-i IDX:INTERFACE together with -b on lo: the interface index and the direction that the Biflow
    records carry (the packets of both directions have the same address, as on any loopback)."""
    ok = True
    for ifidx, extra in (("7", []), ("7", ["-T", "ether"]), ("7", ["-T", "ether", "-H", "02:00:00:00:00:01"])):
        socks, paths, procs = [], [os.path.join(helper.SUITE_TMP_DIR, f"liveif_{n}.ctl") for n in "ab"], []
        for _ in range(2):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("127.0.0.1", 0))
            socks.append(s)
        for daemon, path, s in ((a_daemon, paths[0], socks[0]), (b_daemon, paths[1], socks[1])):
            procs.append(subprocess.Popen(
                [daemon, "-d", "-c", path, "-i", f"{ifidx}:lo", "-b", "-v", "10", "-n",
                 f"127.0.0.1:{s.getsockname()[1]}"] + extra + ["udp and port 41100"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        time.sleep(1.5)
        echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        echo.bind(("127.0.0.1", 41100))
        echo.settimeout(1)
        for i in range(6):
            c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            c.bind(("127.0.0.1", 30100 + i))
            c.settimeout(1)
            for n in range(1 + i % 3):
                c.sendto(b"q" * (20 + i), ("127.0.0.1", 41100))
                try:
                    _, peer = echo.recvfrom(2000)
                    echo.sendto(b"r" * (30 + n), peer)
                    c.recvfrom(2000)
                except socket.timeout:
                    pass
            c.close()
        echo.close()
        time.sleep(1.5)
        for proc, ctl, path in zip(procs, (ctl_a, ctl_b), paths):
            subprocess.run([ctl, "-c", path, "shutdown"], capture_output=True, timeout=10)
        for proc in procs:
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
        got = []
        for s in socks:
            s.setblocking(False)
            data = []
            while True:
                try:
                    data.append(s.recv(65535))
                except BlockingIOError:
                    break
            got.append(parity_ipfix_records(data))
            s.close()
        label = f"-i {ifidx}:lo -b {' '.join(extra)}".strip()
        if got[0] and got[0] == got[1]:
            print_green(f"    - live on lo, {label}: MATCHED ({len(got[0])} Biflow records)")
        else:
            ok = False
            print_red(f"    - live on lo, {label}: DIFFERENT (A {len(got[0])} records, B {len(got[1])} records)")
            for x, y in zip(got[0], got[1]):
                if x != y:
                    print(f"        A: {x}\n        B: {y}")
                    break
    return ok


LIVE_TIME_FILTER = "udp and dst port 41001"  # the test traffic of parity_live_time ()


def _run_live_pair(a_daemon: str, b_daemon: str, ctls: Tuple[str, str], paths: List[str],
                   extra: List[str], body) -> List:
    """Run A and B on lo with -v 5 and the test traffic filter, each with a UDP socket to export to and a
    control socket at paths[n], and return body (sockets, processes).  Both are shut down afterwards."""
    socks, procs = [], []
    for n, daemon in enumerate((a_daemon, b_daemon)):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        s.settimeout(3.0)
        socks.append(s)
        if os.path.exists(paths[n]):
            os.remove(paths[n])
        procs.append(subprocess.Popen([daemon, "-d", "-c", paths[n], "-i", "lo", "-v", "5", "-n",
                                       f"127.0.0.1:{s.getsockname()[1]}"] + extra + [LIVE_TIME_FILTER],
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


def _live_ctl_out(ctl: str, path: str, command: str) -> str:
    """The output of a softflowctl command."""
    return subprocess.run([ctl, "-c", path, command], capture_output=True, text=True, timeout=10).stdout


def _live_flow_record(sock) -> Tuple[int, int, int]:
    """(packets, first, last) of the flow of the test traffic in the next NetFlow v5 datagram."""
    d = sock.recv(65535)
    for i in range((len(d) - 24) // 48):
        r = d[24 + 48 * i:24 + 48 * (i + 1)]
        pkts = struct.unpack(">I", r[16:20])[0]
        first, last = struct.unpack(">II", r[24:32])
        if pkts:
            return pkts, first, last
    raise socket.timeout


def _live_time_stalled(a_daemon: str, b_daemon: str, ctls: Tuple[str, str], paths: List[str]) -> bool:
    """(1) two packets that are captured 1 s apart, and read together because the daemon was stopped."""
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
            _live_ctl_out(ctls[n], paths[n], "expire-all")
            try:
                pkts, first, last = _live_flow_record(socks[n])
                out.append((pkts, last - first))
            except socket.timeout:
                out.append(None)
        return out

    try:
        a, b = _run_live_pair(a_daemon, b_daemon, ctls, paths, [], stalled)
        same = a and b and a[0] == b[0] == 2 and abs(a[1] - b[1]) <= 2 and a[1] >= 900
        detail = f"duration A {a[1] if a else None} ms, B {b[1] if b else None} ms, 1000 ms between the packets"
    except (OSError, subprocess.SubprocessError) as e:
        same, detail = False, str(e)
    if same:
        print_green(f"    - live on lo, packets that are read together: MATCHED ({detail})")
    else:
        print_red(f"    - live on lo, packets that are read together: DIFFERENT ({detail})")
    return bool(same)


def _live_time_adjusted(a_daemon: str, b_daemon: str, ctls: Tuple[str, str], paths: List[str]) -> bool:
    """(2) -a: the time of the last packet is the current time."""
    def adjusted(socks, procs):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"x" * 40, ("127.0.0.1", 41001))
        sent = time.time()
        s.close()
        time.sleep(3.5)                 # idle for more than -t general=1 and expint=1
        out = []
        for n in range(2):
            stat = _live_ctl_out(ctls[n], paths[n], "statistics")
            since = re.search(r"since (\S+) UTC", stat)
            expired = re.search(r"Flows expired: (\d+)", stat)
            since_s = calendar.timegm(time.strptime(since.group(1), "%Y-%m-%dT%H:%M:%S")) if since else None
            _live_ctl_out(ctls[n], paths[n], "expire-all")
            try:
                secs = parity_v5_header(socks[n].recv(65535))[1]
            except socket.timeout:
                secs = None
            out.append((int(expired.group(1)) if expired else None,
                        None if since_s is None else round(since_s - sent),
                        None if secs is None else round(secs - sent)))
        return out

    try:
        a, b = _run_live_pair(a_daemon, b_daemon, ctls, paths, ["-a", "-t", "general=1", "-t", "expint=1"], adjusted)
        # a time of the packet that is cut to the second is 0 or 1 s before the time at which it was sent
        same = all(x[0] == 0 and x[1] in (0, -1) and x[2] in (0, -1) for x in (a, b))
        detail = (f"A: expired {a[0]} before expire-all, since {a[1]} s, export {a[2]} s; "
                  f"B: expired {b[0]}, since {b[1]} s, export {b[2]} s")
    except (OSError, subprocess.SubprocessError) as e:
        same, detail = False, str(e)
    if same:
        print_green(f"    - live on lo, -a (statistics, idle, expire-all): MATCHED ({detail})")
    else:
        print_red(f"    - live on lo, -a (statistics, idle, expire-all): DIFFERENT ({detail})")
    return same


def parity_live_time(a_daemon: str, b_daemon: str, ctl_a: str, ctl_b: str) -> bool:
    """The times of a live capture are those of libpcap, as phdr->ts in the original: (1) the packets that
    are read together keep their time, and (2) with -a the time of the last packet is the current time, so
    that no idle flow expires while no packet arrives, and statistics and expire-all show that time."""
    paths = [os.path.join(helper.SUITE_TMP_DIR, f"livetime_{n}.ctl") for n in "ab"]
    ctls = (ctl_a, ctl_b)
    ok = _live_time_stalled(a_daemon, b_daemon, ctls, paths)
    return _live_time_adjusted(a_daemon, b_daemon, ctls, paths) and ok


# Command lines that the C version reports as an error (or accepts in an odd way), for parity_cli_errors ().
# {pcap} is the capture file and {ctl} a control socket path. (The statistics of -v psamp are compared too, in
# parity_statistics (): the C++ version counts "Packets processed" and the ignored packets as the C version does.)
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
    # A number that is out of range, and an unknown host of -e (which is reported and not used).
    ["-I", "abc", "-r", "{pcap}"], ["-I", "99999999999999999999", "-r", "{pcap}"],
    ["-e", "no.such.host.invalid", "-n", "127.0.0.1:9", "-r", "{pcap}"],
    ["-n", "127.0.0.1:65536", "-r", "{pcap}"], ["-n", "127.0.0.1:99999", "-r", "{pcap}"],
    ["-n", "127.0.0.1:99999999999999999999", "-r", "{pcap}"], ["-n", "127.0.0.1:65535", "-r", "{pcap}"],
    ["-t", "maxlife=99999999999", "-r", "{pcap}"], ["-R", "99999", "-n", "127.0.0.1:9", "-r", "{pcap}"],
    ["-R", "-1", "-n", "127.0.0.1:9", "-r", "{pcap}"],
]


def parity_live_gauge(a_daemon: str, b_daemon: str, ctl_a: str, ctl_b: str) -> bool:
    """-g of a live capture reports the "cpu clocks" counters on the standard error when the daemon stops (with
    -d), as for a capture file, and with -M the clocks of the export are "n/a" for both."""
    ok = True
    for extra, label in (([], "-g"), (["-M"], "-g -M")):
        results = []
        for n, (daemon, ctl) in enumerate(((a_daemon, ctl_a), (b_daemon, ctl_b))):
            path = os.path.join(helper.SUITE_TMP_DIR, f"livegauge_{n}.ctl")
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
            print_green(f"    - live on lo, cpu clocks of {label}: MATCHED (A {fmt_gauge(a)}, B {fmt_gauge(b)})")
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
    ipv6 = os.path.join(helper.SUITE_TMP_DIR, "stat_v6.pcap")
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
        paths[name] = os.path.join(helper.SUITE_TMP_DIR, f"stat_{name}.pcap")
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


def _hide_program_name(text: str, daemon: str) -> str:
    """Replace the name of the program by PROG: the path and the file name of the daemon, and, for a
    build variant (softflowd-static), the name softflowd that the program prints for itself."""
    base = os.path.basename(daemon)
    text = text.replace(daemon, "PROG").replace(base, "PROG")
    if base.startswith("softflowd-"):
        text = text.replace("softflowd", "PROG")
    return text


def _clean_log(text: str, daemon: str) -> List[str]:
    """The lines of a log without the name, the version and the numbers that differ between A and B."""
    text = _hide_program_name(text, daemon)
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
            path = os.path.join(helper.SUITE_TMP_DIR, f"livelog_{n}.ctl")
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


def parity_live_signals(a_daemon: str, b_daemon: str, ctl_a: str, ctl_b: str) -> bool:
    """The signals in the foreground, for A and for B.  SIGUSR1 logs the number of the tracked flows and of the
    packets, and SIGHUP logs that a reload is not implemented; the process goes on (a signal that is not handled
    ends it).  SIGTERM and SIGINT end the process with the status 0 after the log of the shutdown, and the
    control socket is removed."""
    ok = True
    for sig, label in ((signal.SIGUSR1, "SIGUSR1"), (signal.SIGHUP, "SIGHUP"),
                       (signal.SIGTERM, "SIGTERM"), (signal.SIGINT, "SIGINT")):
        ends = sig in (signal.SIGTERM, signal.SIGINT)
        results = []
        for n, (daemon, ctl) in enumerate(((a_daemon, ctl_a), (b_daemon, ctl_b))):
            path = os.path.join(helper.SUITE_TMP_DIR, f"livesig_{n}.ctl")
            if os.path.exists(path):
                os.remove(path)
            proc = subprocess.Popen([daemon, "-d", "-i", "lo", "-v", "5", "-n", "127.0.0.1:9", "-c", path,
                                     "udp and dst port 41004"], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            for _ in range(100):
                if os.path.exists(path):
                    break
                time.sleep(0.1)
            time.sleep(1.0)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                sender.sendto(b"x" * 40, ("127.0.0.1", 41004))
            time.sleep(0.5)
            proc.send_signal(sig)
            time.sleep(1.0)
            alive = proc.poll() is None
            if alive:
                subprocess.run([ctl, "-c", path, "exit"], capture_output=True, timeout=10)
            try:
                _, err = proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                _, err = proc.communicate()
            lines = [line for line in _clean_log(err, daemon)
                     if "stats:" in line or "SIGHUP" in line or "Shutting down" in line]
            results.append((alive, proc.returncode if ends else None, os.path.exists(path) if ends else None,
                            lines))
        a, b = results
        good = a[0] != ends and a[3] and (not ends or (a[1] == 0 and not a[2]))
        if a == b and good:
            print_green(f"    - live on lo, {label}: MATCHED ({a[3][0]!r})")
        else:
            ok = False
            print_red(f"    - live on lo, {label}: DIFFERENT (A {a}, B {b})")
    return ok


def parity_daemon(a_daemon: str, b_daemon: str, ctl_a: str, ctl_b: str) -> bool:
    """A daemon (no -d) drops its privileges to the user nobody in an empty root directory, logs to syslog, and
    leaves its pid file and control socket, as A does. Needs root, /var/empty, and a /dev/log that is free."""
    if not parity_can_capture_lo() or not os.path.isdir("/var/empty") or os.path.exists("/dev/log"):
        print_yellow("    - daemon (privileges, syslog): SKIPPED (needs root, /var/empty and no /dev/log)")
        return True
    results = []
    for n, (daemon, ctl) in enumerate(((a_daemon, ctl_a), (b_daemon, ctl_b))):
        sock, pidfile = (os.path.join(helper.SUITE_TMP_DIR, f"daemon_{n}.{ext}") for ext in ("ctl", "pid"))
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
    ctl = os.path.join(helper.SUITE_TMP_DIR, "cli_errors.ctl")

    def run(daemon: str, args: List[str]) -> Tuple[str, str, object]:
        daemon = os.path.abspath(daemon)
        try:
            r = subprocess.run([daemon] + args, capture_output=True, text=True, timeout=10,
                               stdin=subprocess.DEVNULL, cwd=helper.SUITE_TMP_DIR)
            out, err, rc = r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            out, err, rc = "", "", "TIMEOUT"

        def clean(t: str) -> str:
            t = t.replace(helper.SUITE_TMP_DIR, "TMP").replace(pcap, "PCAP")      # the paths may contain the program name
            t = _hide_program_name(t.replace("/var/run/softflowd.", "/var/run/DEFAULT."), daemon)
            t = re.sub(r"version \d+\.\d+\.\d+", "version X", t)
            t = re.sub(r"PROG v\d+\.\d+\.\d+ ", "PROG vX ", t)
            # The block of the options that A does not have: its heading and the indented lines that follow
            # (the lines of a log may follow it, as with an option that is reported and the run goes on).
            return re.sub(r"This project's own additions[^\n]*\n(?:  [^\n]*\n)*", "", t)
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
            print_green(f"    - cpu clocks of {label}: MATCHED (A {fmt_gauge(a)}, B {fmt_gauge(b)})")
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
    print("  [Step 6] Verifying that B does what A does, byte for byte...")
    pcaps = parity_make_pcaps(tempfile.mkdtemp(dir=helper.SUITE_TMP_DIR))
    ok = parity_cli(a_daemon, b_daemon, pcaps["smoke"])
    ok = parity_cli_errors(a_daemon, b_daemon, pcaps["smoke"]) and ok
    ok = parity_gauge(a_daemon, b_daemon, pcaps["smoke"]) and ok
    ok = parity_statistics(a_daemon, b_daemon, pcaps["smoke"]) and ok
    ok = parity_export_bytes(a_daemon, b_daemon, pcaps) and ok
    ok = parity_debug_log(a_daemon, b_daemon, pcaps) and ok
    # -M must not change what softflowd+ exports.  The C builds do not keep this: with -M (a thread
    # for the export) the number of the datagrams and the uptime in their headers depend on the timing
    # (three runs of one C build with -M differ from each other), so there is nothing to compare.
    if os.path.basename(b_daemon).startswith("softflowd+"):
        ok = parity_multithread(b_daemon, pcaps) and ok
    else:
        print_yellow("    - -M: not compared (the export of a C build with -M depends on the timing)")
    if ctl_a and ctl_b and os.path.exists(ctl_a) and os.path.exists(ctl_b):
        ok = parity_control_replies(a_daemon, b_daemon, ctl_a, ctl_b, pcaps["smoke"]) and ok
        ok = parity_expire_all_time(a_daemon, b_daemon, ctl_a, ctl_b, pcaps["smoke"]) and ok
        if parity_can_capture_lo():
            ok = parity_live(a_daemon, b_daemon, ctl_a, ctl_b) and ok
            ok = parity_live_ifidx(a_daemon, b_daemon, ctl_a, ctl_b) and ok
            ok = parity_live_time(a_daemon, b_daemon, ctl_a, ctl_b) and ok
            ok = parity_live_gauge(a_daemon, b_daemon, ctl_a, ctl_b) and ok
            ok = parity_live_log(a_daemon, b_daemon, ctl_a, ctl_b) and ok
            ok = parity_live_signals(a_daemon, b_daemon, ctl_a, ctl_b) and ok
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

    # 4. Measuring (done by test_differential_output() when --gauge-clock etc. is on)
    # 5. PSAMP (C builds and the C++ build)
    if test_psamp and not test_psamp_compat(a_daemon, b_daemon, ctl_a, ctl_b):
        return False

    # 6. Byte for byte (the pairs of PARITY_PAIRS, or --strict)
    if test_strict and not test_parity(a_daemon, b_daemon, ctl_a, ctl_b):
        return False

    print_green(f"\n>> Pair comparison [A={os.path.basename(a_daemon)} vs B={os.path.basename(b_daemon)}] PASSED.\n")
    return True
