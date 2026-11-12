"""
PSAMP checks of the compat suite: softflowd -v psamp (sender) and softflowd -R (receiver).

psamp_roundtrip() and psamp_compare() are also used by tools/psamp_regress.py.
"""

import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
from typing import Dict, List, Optional, Sequence, Tuple

import softflowd_test_helper as helper
from softflowd_collector import UdpSink, datagrams_to_csv
from softflowd_test_helper import print_red, print_yellow


# ==========================================================================
# PSAMP: softflowd -v psamp (sender) and softflowd -R (receiver)
# ==========================================================================
# psamp_roundtrip() and psamp_compare() are also used by tools/psamp_regress.py.

# Largest frame section of a PSAMP packet: IPFIX_SOFTFLOWD_MAX_PACKET_SIZE (1428)
# - IPFIX header (16) - set header (4) - selectionSequenceId (8)
# - observationTimeMicroseconds (8) - sectionExportedOctets (2); see psamp.c.
PSAMP_MAX_FRAME = 1390
PSAMP_TEMPLATE_ID = 3072
IPFIX_TEMPLATE_SET_ID = 2
# Columns of datagrams_to_csv() that depend on the wall clock: ts and te.
PSAMP_CSV_SKIP_COLUMNS = 2
# Packets of the pcap files of the PSAMP tests: more datagrams can overflow the
# UDP receive buffer of the receiver and make the result vary.
PSAMP_TEST_PACKETS = 50

PSAMP_RECEIVER_TIMEOUTS = [
    "general=86400", "tcp=86400", "tcp.rst=86400", "tcp.fin=86400",
    "udp=86400", "icmp=86400", "maxlife=86400", "expint=86400"]


def pcap_head(path: str, count: int) -> bytes:
    """The first `count` packets of a (little endian) pcap file."""
    with open(path, "rb") as f:
        data = f.read()
    out = bytearray(data[:24])
    off = 24
    for _ in range(count):
        if off + 16 > len(data):
            break
        length = struct.unpack("<I", data[off + 8:off + 12])[0]
        out += data[off:off + 16 + length]
        off += 16 + length
    return bytes(out)


def pcap_sized(sizes: Sequence[int], first_ts: int = 1000) -> bytes:
    """UDP/IPv4 packets whose Ethernet frames are `sizes` bytes long; packet i has the time first_ts + i."""
    eth = bytes.fromhex("00112233445566778899aabb0800")
    out = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for i, n in enumerate(sizes):
        payload = b"U" * (n - 42)
        udp = struct.pack(">HHHH", 1234, 53, 8 + len(payload), 0) + payload
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                         socket.inet_aton("10.0.0.1"), socket.inet_aton("10.0.0.2"))
        frame = eth + ip + udp
        out += struct.pack("<IIII", first_ts + i, 0, len(frame), len(frame)) + frame
    return out


def psamp_datagram(frame: bytes, stated_octets: int) -> bytes:
    """A PSAMP data message as softflowd sends it, but with a frame section that is not padded."""
    body = (struct.pack(">Q", 1) + struct.pack(">II", 0x83aa7e80 + 1000, 0) +
            struct.pack(">H", stated_octets) + frame)
    return (struct.pack(">HHIII", 10, 20 + len(body), 1000, 0, 0) +
            struct.pack(">HH", PSAMP_TEMPLATE_ID, 4 + len(body)) + body)


def psamp_make_pcaps(directory: str) -> Dict[str, str]:
    """Write the pcap files of the PSAMP tests to `directory`: v4s, v6s and sizes."""
    pcaps = {}
    gen = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gen_ci_smoke_pcap.py")
    for name, flags in (("v4", []), ("v6", ["-6"])):
        full = os.path.join(directory, name + ".pcap")
        subprocess.run([sys.executable, gen] + flags + [full], check=True, capture_output=True)
        small = os.path.join(directory, name + "s.pcap")
        with open(small, "wb") as f:
            f.write(pcap_head(full, PSAMP_TEST_PACKETS))
        pcaps[name + "s"] = small
    sized = os.path.join(directory, "sizes.pcap")
    with open(sized, "wb") as f:
        f.write(pcap_sized([60, 1389, PSAMP_MAX_FRAME, PSAMP_MAX_FRAME + 1, PSAMP_MAX_FRAME + 2, 1514]))
    pcaps["sizes"] = sized
    return pcaps


def psamp_messages(datagrams: Sequence[bytes]) -> List[Tuple[str, int, int, bytes]]:
    """(kind, sequence number, export time, datagram) of IPFIX messages; kind is T (template) or D (data)."""
    out = []
    for d in datagrams:
        _, _, export_time, seq, _ = struct.unpack(">HHIII", d[:16])
        set_id = struct.unpack(">H", d[16:18])[0]
        out.append(("T" if set_id == IPFIX_TEMPLATE_SET_ID else "D", seq, export_time, d))
    return out


def psamp_data_payloads(datagrams: Sequence[bytes]) -> List[bytes]:
    """The data messages without the IPFIX message header: independent of the template, the sequence number and the time."""
    return [d[16:] for kind, _, _, d in psamp_messages(datagrams) if kind == "D"]


def psamp_flows(datagrams: Sequence[bytes]) -> List[str]:
    """Sorted flow rows of exported datagrams without the wall-clock columns."""
    rows = datagrams_to_csv([(d, "x") for d in datagrams]).splitlines()[1:]
    return sorted(",".join(r.split(",")[PSAMP_CSV_SKIP_COLUMNS:]) for r in rows)


def _psamp_work_dir() -> str:
    if not helper.SUITE_TMP_DIR:
        helper.SUITE_TMP_DIR = tempfile.mkdtemp(prefix="softflowd-psamp-")
    return helper.SUITE_TMP_DIR


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def psamp_send(daemon: str, pcap: str, extra: Sequence[str] = ()) -> List[bytes]:
    """The PSAMP datagrams of `daemon -r PCAP -v psamp`."""
    sink = UdpSink("127.0.0.1", 0)
    try:
        subprocess.run([daemon, "-d", "-r", pcap, "-v", "psamp", *extra,
                        "-n", f"127.0.0.1:{sink.port}",
                        "-c", os.path.join(_psamp_work_dir(), f"psamp-tx-{sink.port}.ctl")],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=60)
    finally:
        sink.close()
    return [d for d, _ in sink.datagrams]


def psamp_ctl(ctl: str, ctl_path: str, command: str, timeout: float = 3.0) -> Optional[str]:
    """Output of softflowctl, or None if softflowd did not answer in time."""
    try:
        r = subprocess.run([ctl, "-c", ctl_path, command], capture_output=True,
                           stdin=subprocess.DEVNULL, timeout=timeout)
        return r.stdout.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return None


def psamp_roundtrip(daemon: str, ctl: str, pcap: str, version: int, wake: bool = True,
                    inject: Sequence[bytes] = (), stats: bool = False
                    ) -> Tuple[List[bytes], Optional[str], Optional[int], bool]:
    """Sender (-v psamp) -> receiver (-R) -> collector.

    The receiver runs with -a: the pcap files are from 1970, and with the
    current time it would expire the flows as soon as it looks at the timeouts.
    wake    send a short datagram at the end; the receiver of an old build blocks
            in recv() after the last datagram and does not serve softflowctl
            before another one arrives.
    inject  more datagrams for the receiver.
    stats   also ask softflowctl for the statistics.
    Returns (datagrams exported by the receiver, statistics or None, exit status, hung).
    """
    work = _psamp_work_dir()
    collector = UdpSink("127.0.0.1", 0)
    rx_port = _free_udp_port()
    ctl_path = os.path.join(work, f"psamp-rx-{rx_port}.ctl")
    cmd = [daemon, "-d", "-a", "-R", str(rx_port), "-n", f"127.0.0.1:{collector.port}",
           "-v", str(version), "-c", ctl_path]
    for t in PSAMP_RECEIVER_TIMEOUTS:
        cmd += ["-t", t]
    rx = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, start_new_session=True)
    stat = None
    hung = False
    try:
        for _ in range(50):  # wait for the control socket
            if os.path.exists(ctl_path):
                break
            time.sleep(0.1)
        subprocess.run([daemon, "-d", "-r", pcap, "-v", "psamp", "-n", f"127.0.0.1:{rx_port}",
                        "-c", os.path.join(work, f"psamp-tx-{rx_port}.ctl")],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=60)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            for d in inject:
                sender.sendto(d, ("127.0.0.1", rx_port))
            time.sleep(0.8)
            if wake:
                sender.sendto(b"x", ("127.0.0.1", rx_port))
                time.sleep(0.3)
        if stats:
            stat = psamp_ctl(ctl, ctl_path, "statistics")
        psamp_ctl(ctl, ctl_path, "shutdown")
        try:
            rx.wait(timeout=5)
        except subprocess.TimeoutExpired:
            hung = True
            rx.kill()
            rx.wait()
    finally:
        if rx.poll() is None:
            rx.kill()
            rx.wait()
        collector.close()
    return [d for d, _ in collector.datagrams], stat, rx.returncode, hung


def psamp_compare(a_daemon: str, b_daemon: str, ctl_a: str, ctl_b: str,
                  pcaps: Dict[str, str], report) -> None:
    """Compare what A and B send and receive as PSAMP; report(ok, text) gets one line per case.

    send       the data messages of `-v psamp` must be byte-identical (the template
               messages and the message header are left out).
    roundtrip  the flows that a receiver exports after receiving the PSAMP datagrams
               of the same build, as NetFlow v5, v9 and IPFIX, must be identical.
    """
    for name, pcap in pcaps.items():
        a, b = psamp_data_payloads(psamp_send(a_daemon, pcap)), psamp_data_payloads(psamp_send(b_daemon, pcap))
        report(bool(a) and a == b, f"PSAMP send {name}: {len(a)} / {len(b)} data messages")
    for name in ("v4s", "v6s"):
        for version in (5, 9, 10):
            a = psamp_flows(psamp_roundtrip(a_daemon, ctl_a, pcaps[name], version)[0])
            b = psamp_flows(psamp_roundtrip(b_daemon, ctl_b, pcaps[name], version)[0])
            # IPv6 flows cannot be exported as NetFlow v5: no flows on both sides is a pass.
            report(a == b, f"PSAMP receive {name} (version {version}): {len(a)} / {len(b)} flows")


def test_psamp_compat(a_daemon: str, b_daemon: str, ctl_a: Optional[str], ctl_b: Optional[str]) -> bool:
    """Compat step: the PSAMP sender and receiver of A and B.  For C and C++ builds: the Rust PSAMP records differ."""
    print("  [Step 4] Verifying PSAMP export and receive...")
    if not (ctl_a and ctl_b and os.path.exists(ctl_a) and os.path.exists(ctl_b)):
        print_yellow("    - SKIPPED (softflowctl is needed to stop the PSAMP receiver)")
        return True
    pcaps = psamp_make_pcaps(tempfile.mkdtemp(dir=_psamp_work_dir()))
    ok = [True]

    def report(passed: bool, text: str) -> None:
        if passed:
            print(f"    - {text}: MATCHED")
        else:
            print_red(f"    - {text}: FAILED")
            ok[0] = False

    psamp_compare(a_daemon, b_daemon, ctl_a, ctl_b, pcaps, report)
    return ok[0]
