"""
Parity checks (1/2): what softflowd+ (C++) must do byte for byte like softflowd (C),
the offline checks of the exported datagrams.
"""

import os
import re
import select
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Dict, List, Optional, Tuple

import softflowd_test_helper as helper
from softflowd_test_helper import PROJECT_ROOT, parity_loopback_pcap, print_green, print_red


# ==========================================================================
# parity: what softflowd+ (C++) must do byte for byte like softflowd (C)
# ==========================================================================
#
# The pair softflowd vs softflowd+ (or any pair with --strict) is compared more
# strictly than the other pairs: not only the flows that a collector decodes,
# but the datagrams themselves, the replies of the control socket, the lines of
# the expiry debug log and the flows that a live capture exports.  These are
# the checks that were done by hand while softflowd+ followed softflowd.

PARITY_PAIRS = {("softflowd", "softflowd+")}

# Options added to `-a -r PCAP -n 127.0.0.1:PORT -v VERSION`.
PARITY_ARGS = {
    "1": [[], ["-m", "5"], ["-t", "maxlife=1", "-m", "7"], ["-s", "10"]],
    "5": [[], ["-m", "5"], ["-t", "maxlife=1", "-m", "7"], ["-s", "10"], ["-T", "ether"],
          ["-x", "2"]],
    "9": [[], ["-m", "5"], ["-T", "ether"], ["-b"], ["-x", "2", "-A", "micro"],
          ["-t", "maxlife=1", "-m", "7"], ["-s", "10"], ["-e", "192.0.2.1"],
          ["-b", "-T", "ether", "-H", "02:00:00:00:00:01"]],
    "10": [[], ["-m", "5"], ["-T", "ether"], ["-b"], ["-x", "2", "-A", "micro"],
           ["-t", "maxlife=1", "-m", "7"], ["-s", "10"], ["-e", "192.0.2.1"],
           ["-b", "-T", "ether", "-H", "02:00:00:00:00:01"]],
}
PARITY_DEBUG_ARGS = [[], ["-m", "5"], ["-m", "7", "-t", "maxlife=1"], ["-m", "100"],
                     ["-m", "3", "-t", "maxlife=2"]]
PARITY_DEBUG_RE = re.compile(
    r"Starting expiry scan|Queuing flow|Finished scan|sent [0-9]+ netflow|EXPIRED:|Forcing expiry")
# The control commands, sent while the daemon waits for a FIFO (-m 5: after every
# 5 packets), without and with flows in the table.
PARITY_CTL_EMPTY = ["help", "bogus", "", "timeouts", "statistics", "dump-flows", "debug+",
                    "debug-", "send-template", "stop-gather", "start-gather"]
PARITY_CTL_FLOWS = ["statistics", "dump-flows", "timeouts", "expire-all", "statistics",
                    "dump-flows", "delete-all", "statistics"]


def parity_make_pcaps(directory: str) -> Dict[str, str]:
    """smoke (240 packets, 40 flows), smoke6 (the same flows over IPv6), vlan (802.1Q tags and MACs),
    slow (10 s apart), many (600 flows), loopback (the same address at both ends)."""
    smoke = os.path.join(directory, "smoke.pcap")
    subprocess.run([sys.executable, os.path.join(PROJECT_ROOT, "tools", "gen_ci_smoke_pcap.py"),
                    smoke], check=True, stdout=subprocess.DEVNULL)
    # IPv6 (TCP, UDP and ICMPv6), so that the Biflow records of IPv6 are compared too.
    smoke6 = os.path.join(directory, "smoke6.pcap")
    subprocess.run([sys.executable, os.path.join(PROJECT_ROOT, "tools", "gen_ci_smoke_pcap.py"),
                    "-6", smoke6], check=True, stdout=subprocess.DEVNULL)
    with open(smoke, "rb") as f:
        data = f.read()

    def packets():
        off = 24
        while off < len(data):
            ts, us, caplen, origlen = struct.unpack("<IIII", data[off:off + 16])
            yield ts, us, origlen, bytearray(data[off + 16:off + 16 + caplen])
            off += 16 + caplen

    paths = {"smoke": smoke, "smoke6": smoke6}
    out = bytearray(data[:24])
    for n, (ts, us, origlen, pkt) in enumerate(packets()):
        vid = 100 + (n % 3) * 7 + (0x2000 if n % 5 == 0 else 0)
        if n % 2 == 0:
            pkt[0:6] = bytes([2, 0, 0, 0, 0, 0x10 + n % 4])
        pkt = pkt[:12] + struct.pack(">HH", 0x8100, vid) + pkt[12:]
        out += struct.pack("<IIII", ts, us, len(pkt), origlen + 4) + pkt
    paths["vlan"] = os.path.join(directory, "vlan.pcap")
    with open(paths["vlan"], "wb") as f:
        f.write(out)
    out = bytearray(data[:24])
    for n, (ts, us, origlen, pkt) in enumerate(packets()):
        out += struct.pack("<IIII", 1000000 + n * 10, us, len(pkt), origlen) + pkt
    paths["slow"] = os.path.join(directory, "slow.pcap")
    with open(paths["slow"], "wb") as f:
        f.write(out)
    out = bytearray(data[:24])
    for i in range(600):
        eth = bytes([2, 0, 0, 0, 0, 1]) + bytes([2, 0, 0, 0, 0, 2]) + b"\x08\x00"
        payload = b"x" * 20
        udp = struct.pack(">HHHH", 1000 + i, 53, 8 + len(payload), 0) + payload
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), i, 0, 64, 17, 0,
                         bytes([10, 0, i // 250, i % 250]), bytes([10, 1, 0, 1]))
        frame = eth + ip + udp
        out += struct.pack("<IIII", 1000000 + i, i * 1000, len(frame), len(frame)) + frame
    paths["many"] = os.path.join(directory, "many.pcap")
    with open(paths["many"], "wb") as f:
        f.write(out)
    paths["loopback"] = os.path.join(directory, "loopback.pcap")
    with open(paths["loopback"], "wb") as f:
        f.write(parity_loopback_pcap(data[:24]))
    return paths


def parity_export(daemon: str, pcap: str, version: str, extra: List[str]) -> List[bytes]:
    """The datagrams that daemon -r PCAP -a sends over UDP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    sock.bind(("127.0.0.1", 0))
    try:
        subprocess.run([daemon, "-r", pcap, "-n", f"127.0.0.1:{sock.getsockname()[1]}",
                        "-v", version, "-a"] + extra, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=60)
        # The loopback of some systems (WSL2, for one) delivers a datagram a little after send()
        # returns, so wait for a short quiet time instead of reading only what is already there.
        sock.settimeout(0.3)
        datagrams: List[bytes] = []
        while True:
            try:
                datagrams.append(sock.recv(65535))
            except socket.timeout:
                return datagrams
    finally:
        sock.close()


def parity_datagrams_differ(a: List[bytes], b: List[bytes], version: str) -> Optional[str]:
    """None if the datagrams are the same; IPFIX may differ by the process id of its options record."""
    if len(a) != len(b):
        return f"{len(a)} datagrams from A, {len(b)} from B"
    for n, (x, y) in enumerate(zip(a, b)):
        if len(x) != len(y):
            return f"datagram {n}: {len(x)} bytes from A, {len(y)} from B"
        diff = [i for i in range(len(x)) if x[i] != y[i]]
        if not diff:
            continue
        if version == "10" and max(diff) - min(diff) <= 3:
            continue  # the process id of the options record
        return f"datagram {n}: bytes differ at offsets {diff[:8]}"
    return None


def parity_export_bytes(a_daemon: str, b_daemon: str, pcaps: Dict[str, str]) -> bool:
    ok = True
    runs = failures = 0
    for name, pcap in pcaps.items():
        for version, arg_sets in PARITY_ARGS.items():
            for extra in arg_sets:
                runs += 1
                try:
                    why = parity_datagrams_differ(parity_export(a_daemon, pcap, version, extra),
                                                  parity_export(b_daemon, pcap, version, extra),
                                                  version)
                except (OSError, subprocess.SubprocessError) as e:
                    why = str(e)
                if why:
                    failures += 1
                    ok = False
                    print_red(f"    - {name} -v {version} -a {' '.join(extra)}: DIFFERENT: {why}")
    if ok:
        print_green(f"    - exported datagrams, byte for byte ({runs} runs): MATCHED")
    else:
        print_red(f"    - exported datagrams: {failures} of {runs} runs DIFFER")
    return ok


def parity_debug_lines(daemon: str, pcap: str, extra: List[str]) -> List[str]:
    # Send to a bound socket: nobody listening at a port returns ICMP errors, and when they arrive
    # makes send() fail at a different moment (the C version stops sending at a failed send()).
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    sink.bind(("127.0.0.1", 0))
    try:
        res = subprocess.run([daemon, "-r", pcap, "-n", f"127.0.0.1:{sink.getsockname()[1]}", "-v", "9",
                              "-a", "-D"] + extra, capture_output=True, text=True, timeout=60)
    finally:
        sink.close()
    lines = []
    for line in (res.stdout + res.stderr).splitlines():
        if PARITY_DEBUG_RE.search(line):
            line = re.sub(r" ?\(0x[0-9a-f]+\)", "", line)  # pointers
            lines.append(re.sub(r" \([0-9a-f]+\)$", "", line))
    return lines


def parity_debug_log(a_daemon: str, b_daemon: str, pcaps: Dict[str, str]) -> bool:
    ok = True
    runs = 0
    for name, pcap in pcaps.items():
        for extra in PARITY_DEBUG_ARGS:
            runs += 1
            a, b = parity_debug_lines(a_daemon, pcap, extra), parity_debug_lines(b_daemon, pcap, extra)
            if a != b:
                ok = False
                first = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
                print_red(f"    - {name} {' '.join(extra)}: DIFFERENT at line {first + 1} "
                          f"({len(a)} and {len(b)} lines)")
                print(f"        A: {a[first] if first < len(a) else '(none)'}")
                print(f"        B: {b[first] if first < len(b) else '(none)'}")
    if ok:
        print_green(f"    - expiry lines of the debug log (-D), ({runs} runs): MATCHED")
    return ok


def parity_control_replies(a_daemon: str, b_daemon: str, ctl_a: str, ctl_b: str,
                           pcap: str) -> bool:
    """The reply and the exit status of softflowctl for every command, and the exit status of the daemon."""
    with open(pcap, "rb") as f:
        data = f.read()
    header, off, packets = data[:24], 24, []
    while off < len(data):
        caplen = struct.unpack("<I", data[off + 8:off + 12])[0]
        packets.append(data[off:off + 16 + caplen])
        off += 16 + caplen

    def normalize(text: bytes) -> bytes:
        text = re.sub(rb"softflowd\[\d+\]", b"softflowd[PID]", text)
        return re.sub(rb"since 20\d\d-[0-9T:-]+ UTC", b"since START UTC", text)  # process start

    def run(daemon: str, ctl: str, ending: str):
        fifo = os.path.join(helper.SUITE_TMP_DIR, "parity.fifo")
        sock = os.path.join(helper.SUITE_TMP_DIR, "parity.ctl")
        for p in (fifo, sock):
            if os.path.exists(p):
                os.remove(p)
        os.mkfifo(fifo)
        proc = subprocess.Popen([daemon, "-r", fifo, "-c", sock, "-n", "127.0.0.1:9", "-v", "9",
                                 "-a", "-m", "5"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        go, errors = threading.Event(), []

        def feed():
            try:
                with open(fifo, "wb") as w:
                    w.write(header)
                    w.flush()
                    for chunk in (packets[:5], packets[5:10], []):
                        go.wait(30)
                        go.clear()
                        w.write(b"".join(chunk))
                        w.flush()
            except OSError as e:  # the daemon went away: a broken pipe
                errors.append(e)
        threading.Thread(target=feed, daemon=True).start()
        replies = []

        def send(command: str) -> None:
            r = subprocess.run([ctl, "-c", sock, command], capture_output=True, timeout=10)
            replies.append((command, r.returncode, normalize(r.stdout), r.stderr))
        time.sleep(1.0)
        go.set()                      # the header is read; the daemon waits for packets
        time.sleep(0.3)
        for command in PARITY_CTL_EMPTY:
            send(command)
        go.set()                      # 5 packets
        time.sleep(1.0)
        for command in PARITY_CTL_FLOWS:
            send(command)
        go.set()                      # 5 more
        time.sleep(1.0)
        send("dump-flows")
        send(ending)
        time.sleep(0.5)
        go.set()
        try:
            rc = proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
            rc = None
        return replies, rc

    ok = True
    for ending in ("shutdown", "exit"):
        a, rc_a = run(a_daemon, ctl_a, ending)
        b, rc_b = run(b_daemon, ctl_b, ending)
        bad = [x[0] for x, y in zip(a, b) if x != y]
        if len(a) != len(b) or bad or rc_a != rc_b:
            ok = False
            print_red(f"    - control replies ending with {ending}: DIFFERENT "
                      f"(commands {bad}; daemon exit status A {rc_a}, B {rc_b})")
            for x, y in zip(a, b):
                if x != y:
                    print(f"        {x[0]!r}: A {x[1:3]}\n{' ' * 12}B {y[1:3]}")
                    break
        else:
            print_green(f"    - control replies ({len(a)} commands, ending with {ending}): MATCHED")
    return ok


def parity_multithread(daemon: str, pcaps: Dict[str, str]) -> bool:
    """-M (a thread for the export) must not change what is exported."""
    ok = True
    for version in ("5", "9", "10"):
        for extra in ([], ["-m", "5"]):
            single = parity_export(daemon, pcaps["smoke"], version, extra)
            multi = parity_export(daemon, pcaps["smoke"], version, extra + ["-M"])
            why = parity_datagrams_differ(single, multi, version)
            if why:
                ok = False
                print_red(f"    - -M -v {version} {' '.join(extra)}: DIFFERENT: {why}")
    if ok:
        print_green("    - -M exports the same datagrams as without: MATCHED")
    return ok


def parity_live(a_daemon: str, b_daemon: str, ctl_a: str, ctl_b: str) -> bool:
    """Both daemons capture the same traffic on lo: when the idle flows are exported (-t expint), and
    that a burst bigger than the flow table (-m) is exported completely, each flow once."""
    flt = "udp and dst port 41000"
    ok = True

    def start(daemon: str, ctl_path: str, port: int, extra: List[str]) -> subprocess.Popen:
        return subprocess.Popen([daemon, "-d", "-c", ctl_path, "-i", "lo", "-n", f"127.0.0.1:{port}",
                                 "-v", "5"] + extra + [flt],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def stop(procs, ctls, paths) -> None:
        for proc, ctl, path in zip(procs, ctls, paths):
            subprocess.run([ctl, "-c", path, "shutdown"], capture_output=True, timeout=10)
        for proc in procs:
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()

    def receive(socks, seconds: float):
        got = [[] for _ in socks]
        end = time.time() + seconds
        while time.time() < end:
            ready, _, _ = select.select(socks, [], [], 0.1)
            for s in ready:
                got[socks.index(s)].append((time.time(), s.recv(65535)))
        return got

    def records(datagrams):
        out = []
        for _, d in datagrams:
            for i in range((len(d) - 24) // 48):
                r = d[24 + 48 * i:24 + 48 * (i + 1)]
                out.append(struct.unpack(">HH", r[32:36]) + struct.unpack(">II", r[16:24]))
        return sorted(out)

    for title, extra, flows in (("idle expiry (-t expint=3)", ["-t", "general=2", "-t", "udp=2", "-t", "expint=3"], 10),
                                ("burst over -m 10", ["-m", "10", "-t", "udp=600"], 60)):
        socks, paths = [], [os.path.join(helper.SUITE_TMP_DIR, f"live_{n}.ctl") for n in "ab"]
        for _ in range(2):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("127.0.0.1", 0))
            socks.append(s)
        procs = [start(a_daemon, paths[0], socks[0].getsockname()[1], extra),
                 start(b_daemon, paths[1], socks[1].getsockname()[1], extra)]
        time.sleep(1.5)
        sent = time.time()
        for i in range(flows):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("127.0.0.1", 30000 + i))
            s.sendto(b"x" * (40 + i % 50), ("127.0.0.1", 41000))
            s.close()
        if "expint=3" in extra:     # the idle flows are exported at the next multiple of 3 s
            got = receive(socks, 8.0)
            stop(procs, [ctl_a, ctl_b], paths)
        else:                       # a flow that is forced out is exported at once, the rest at shutdown
            time.sleep(1.5)
            stop(procs, [ctl_a, ctl_b], paths)
            got = receive(socks, 2.0)
        if "expint=3" in extra:
            times = [[round(t - sent, 1) for t, _ in g] for g in got]
            same = len(times[0]) == len(times[1]) > 0 and all(abs(x - y) <= 0.6
                                                                 for x, y in zip(times[0], times[1]))
            detail = f"A at {times[0]} s, B at {times[1]} s"
        else:
            rec_a, rec_b = records(got[0]), records(got[1])
            same = rec_a == rec_b and len(rec_a) == len(set(rec_a)) == flows
            detail = f"A {len(rec_a)} records, B {len(rec_b)} records, {flows} sent"
        if same:
            print_green(f"    - live on lo, {title}: MATCHED ({detail})")
        else:
            ok = False
            print_red(f"    - live on lo, {title}: DIFFERENT ({detail})")
        for s in socks:
            s.close()
    return ok


def parity_v5_header(datagram: bytes) -> Tuple[int, int]:
    """(record count, unix_secs) of a NetFlow v5 datagram."""
    _, count, _, secs, _ = struct.unpack(">HHIII", datagram[:16])
    return count, secs


def parity_expire_all_time(a_daemon: str, b_daemon: str, ctl_a: str, ctl_b: str, pcap: str) -> bool:
    """With -a, expire-all of a capture file that is being read (a FIFO) exports with the time of the
    last packet that was read, not with the time of the clock."""
    with open(pcap, "rb") as f:
        data = f.read()
    end = 24
    for _ in range(5):                  # -m 5: one batch of exactly 5 packets
        end += 16 + struct.unpack("<I", data[end + 8:end + 12])[0]
    results = []
    for n, (daemon, ctl) in enumerate(((a_daemon, ctl_a), (b_daemon, ctl_b))):
        sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sink.bind(("127.0.0.1", 0))
        sink.settimeout(3.0)
        fifo, path = (os.path.join(helper.SUITE_TMP_DIR, f"expall_{n}.{ext}") for ext in ("fifo", "ctl"))
        for f in (fifo, path):
            if os.path.exists(f):
                os.remove(f)
        os.mkfifo(fifo)
        proc = subprocess.Popen([daemon, "-r", fifo, "-c", path, "-n", f"127.0.0.1:{sink.getsockname()[1]}",
                                 "-v", "5", "-m", "5", "-a"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        result = "no reply"
        with open(fifo, "wb") as w:
            w.write(data[:24])          # the packets must come after the header has been read,
            w.flush()                   # or libpcap keeps them in its buffer
            for _ in range(100):
                if os.path.exists(path):
                    break
                time.sleep(0.1)
            time.sleep(1.0)
            w.write(data[24:end])
            w.flush()
            time.sleep(1.0)
            r = subprocess.run([ctl, "-c", path, "expire-all"], capture_output=True, text=True, timeout=10)
            reply = r.stdout.strip().split(": ", 1)[-1]
            try:
                result = (reply,) + parity_v5_header(sink.recv(65535))
            except socket.timeout:
                result = (reply, "no datagram")
            subprocess.run([ctl, "-c", path, "shutdown"], capture_output=True, timeout=10)
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
        sink.close()
        results.append(result)
    if results[0] == results[1] and len(results[0]) == 3 and results[0][0].startswith("Expired 1"):
        print_green(f"    - expire-all while reading a file (-a): MATCHED (export time {results[0][2]}, the last packet)")
        return True
    print_red(f"    - expire-all while reading a file (-a): DIFFERENT (A {results[0]}, B {results[1]})")
    return False


def parity_ipfix_records(datagrams: List[bytes]) -> List[Tuple]:
    """The data records of IPFIX messages as sorted tuples of (name or id, value) pairs: the templates are
    read from the same messages. The fields that differ from run to run (the times) are left out."""
    templates: Dict[int, List[Tuple[int, int, int]]] = {}
    out = []
    skip = {21, 22, 150, 151, 152, 153, 154, 155, 156, 157}
    for d in datagrams:
        off = 16
        while off + 4 <= len(d):
            sid, slen = struct.unpack(">HH", d[off:off + 4])
            body = d[off + 4:off + slen]
            if sid == 2:
                pos = 0
                while pos + 4 <= len(body):
                    tid, count = struct.unpack(">HH", body[pos:pos + 4])
                    pos += 4
                    fields = []
                    for _ in range(count):
                        ie, ln = struct.unpack(">HH", body[pos:pos + 4])
                        pos += 4
                        pen = 0
                        if ie & 0x8000:
                            pen = struct.unpack(">I", body[pos:pos + 4])[0]
                            pos += 4
                        fields.append((ie & 0x7fff, ln, pen))
                    templates[tid] = fields
            elif sid >= 256 and sid in templates:
                size = sum(f[1] for f in templates[sid])
                for r in range(len(body) // size if size else 0):
                    rec, pos = [], r * size
                    for ie, ln, pen in templates[sid]:
                        if ie not in skip or pen:
                            rec.append(((ie, pen), body[pos:pos + ln]))
                        pos += ln
                    out.append(tuple(rec))
            off += slen if slen else 4
    return sorted(out)
