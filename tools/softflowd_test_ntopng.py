"""
ntopng checks of the compat suite: the ZMQ export of softflowd -v ntopng.
"""

import argparse
import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
from typing import Dict, List, Optional, Sequence, Tuple

import softflowd_test_helper as helper
from softflowd_test_helper import (
    HTTP_PCAP_URL,
    PROJECT_ROOT,
    V6_HTTP_PCAP_URL,
    build_c,
    copy_binaries,
    ensure_sample_pcap,
    parity_can_capture_lo,
    parity_loopback_pcap,
    print_cyan,
    print_green,
    print_red,
    print_yellow,
    run_command,
)


# ==========================================================================
# ntopng: check the ZMQ export (compat --ntopng)
# ==========================================================================
#
# softflowd is a ZMQ PUB socket that connects, as with `ntopng -i
# "tcp://*:5556c"`.  This side binds a TCP port and speaks just enough ZMTP 3.0
# to act as the SUB socket, then decodes every message the way ntopng does:
#   -v ntopng       zmq_msg_hdr_v4 (36 bytes, TLV flag) + nDPI serializer TLV
#   -v ntopng-json  zmq_msg_hdr_v2 (24 bytes) + JSON, for ntopng 5.x or earlier

NTOPNG_NAMES = {1: "IN_BYTES", 2: "IN_PKTS", 4: "PROTOCOL", 6: "TCP_FLAGS",
                7: "L4_SRC_PORT", 8: "IPV4_SRC_ADDR", 11: "L4_DST_PORT",
                12: "IPV4_DST_ADDR", 21: "LAST_SWITCHED", 22: "FIRST_SWITCHED",
                23: "OUT_BYTES", 24: "OUT_PKTS", 27: "IPV6_SRC_ADDR",
                28: "IPV6_DST_ADDR", 56: "IN_SRC_MAC", 57: "OUT_DST_MAC",
                58: "SRC_VLAN", 59: "DST_VLAN"}
NTOPNG_REQUIRED = (7, 11, 1, 2, 23, 24, 22, 21, 4)
NTOPNG_FLAG_IS_TLV = 1 << 1
NTOPNG_FLAG_IS_COMPRESSED = 1 << 2
NTOPNG_HDR_V4_LEN, NTOPNG_HDR_V2_LEN = 36, 24
NTOPNG_MAX_PAYLOAD = 131072  # CONST_ZMQ_PAYLOAD_LEN of ntopng
NTOPNG_DIALECTS = ("ntopng", "ntopng-json")


class NtopngFailure(Exception):
    pass


def ntopng_pcap_time_range(path: str) -> Optional[Tuple[int, int]]:
    """First and last packet time (seconds) of a classic pcap, None for others."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif data[:4] in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        return None
    pos, first, last = 24, None, None
    while pos + 16 <= len(data):
        sec, _, caplen, _ = struct.unpack(endian + "IIII", data[pos:pos + 16])
        first = sec if first is None else first
        last = sec
        pos += 16 + caplen
    return None if first is None else (first, last)


def _zmq_recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise EOFError
        data += chunk
    return data


def _zmq_read_frame(sock: socket.socket) -> Tuple[int, bytes]:
    flags = _zmq_recv_exact(sock, 1)[0]
    if flags & 0x02:
        size = struct.unpack("!Q", _zmq_recv_exact(sock, 8))[0]
    else:
        size = _zmq_recv_exact(sock, 1)[0]
    return flags, _zmq_recv_exact(sock, size)


def _zmq_sub_handshake(conn: socket.socket) -> None:
    """ZMTP 3.0 with the NULL mechanism, then subscribe to everything."""
    conn.sendall(b"\xff" + b"\x00" * 8 + b"\x7f" + b"\x03\x00" +
                 b"NULL".ljust(20, b"\x00") + b"\x00" + b"\x00" * 31)
    peer = _zmq_recv_exact(conn, 64)
    if peer[0] != 0xff or peer[9] != 0x7f or peer[10] < 3:
        raise NtopngFailure("the peer does not speak ZMTP 3.x")
    ready = b"\x05READY" + b"\x0bSocket-Type" + struct.pack("!I", 3) + b"SUB"
    conn.sendall(bytes([0x04, len(ready)]) + ready)
    flags, body = _zmq_read_frame(conn)
    if not flags & 0x04 or body[1:6] != b"READY":
        raise NtopngFailure("no READY command from the peer")
    conn.sendall(bytes([0x00, 1, 0x01]))


def ntopng_decode_header(hdr: bytes) -> dict:
    """Decode a zmq_msg_hdr_v4 (36 bytes) or zmq_msg_hdr_v2 (24 bytes)."""
    if len(hdr) == NTOPNG_HDR_V4_LEN:
        url, ver, flags, size, comp, msg_id = struct.unpack("!16sBB2xIII", hdr[:32])
        return dict(url=url.rstrip(b"\0"), version=ver, flags=flags, size=size,
                    msg_id=msg_id)
    if len(hdr) == NTOPNG_HDR_V2_LEN:
        url, ver, _, size, msg_id = struct.unpack("!16sBBHI", hdr)
        return dict(url=url.rstrip(b"\0"), version=ver, flags=0, size=size,
                    msg_id=msg_id)
    raise NtopngFailure(f"unexpected header length {len(hdr)}")


def ntopng_decode_tlv(data: bytes) -> List[dict]:
    """Decode the nDPI serializer TLV format into a list of records."""
    if data[:2] != b"\x01\x01":
        raise NtopngFailure(f"bad TLV preamble {data[:2]!r}")
    uint_len = {2: 1, 3: 2, 4: 4, 5: 8}
    pos, records, rec = 2, [], {}
    while pos < len(data):
        t = data[pos]
        pos += 1
        if t == 1:  # end of record
            records.append(rec)
            rec = {}
            continue
        kt, vt = t >> 4, t & 0x0f
        if kt not in uint_len or kt == 5:
            raise NtopngFailure(f"unsupported key type {kt} at {pos - 1}")
        key = int.from_bytes(data[pos:pos + uint_len[kt]], "big")
        pos += uint_len[kt]
        if vt in uint_len:
            val = int.from_bytes(data[pos:pos + uint_len[vt]], "big")
            pos += uint_len[vt]
        elif vt == 11:
            slen = int.from_bytes(data[pos:pos + 2], "big")
            val = data[pos + 2:pos + 2 + slen].decode()
            pos += 2 + slen
        else:
            raise NtopngFailure(f"unsupported value type {vt} at {pos - 1}")
        if pos > len(data):
            raise NtopngFailure("truncated TLV item")
        rec[key] = val
    if rec:
        raise NtopngFailure("the last record has no end of record marker")
    return records


def ntopng_decode_json(data: bytes) -> List[dict]:
    try:
        arr = json.loads(data)
    except ValueError as e:
        raise NtopngFailure(f"invalid JSON: {e}")
    if not isinstance(arr, list):
        raise NtopngFailure("the JSON payload is not an array")
    return [{int(k): v for k, v in flow.items()} for flow in arr]


def ntopng_check_record(rec: dict, where: str, bounds: Tuple[int, int]) -> None:
    for key in NTOPNG_REQUIRED:
        if key not in rec:
            raise NtopngFailure(f"{where}: missing {NTOPNG_NAMES[key]}")
    v4 = 8 in rec and 12 in rec
    v6 = 27 in rec and 28 in rec
    if v4 == v6:
        raise NtopngFailure(f"{where}: need either IPv4 or IPv6 addresses")
    for key in (7, 11):
        if not isinstance(rec[key], int) or not 0 <= rec[key] <= 65535:
            raise NtopngFailure(f"{where}: bad {NTOPNG_NAMES[key]} {rec[key]!r}")
    for key, family in ((8, socket.AF_INET), (12, socket.AF_INET),
                        (27, socket.AF_INET6), (28, socket.AF_INET6)):
        if key in rec:
            socket.inet_pton(family, rec[key])
    # Epoch seconds within the pcap, not milliseconds since boot.
    first, last = rec[22], rec[21]
    if not bounds[0] <= first <= last <= bounds[1]:
        raise NtopngFailure(f"{where}: timestamps first={first!r} last={last!r}, epoch "
                            f"seconds within {bounds[0]}..{bounds[1]} expected")
    if rec[2] + rec[24] == 0:
        raise NtopngFailure(f"{where}: flow without packets")
    if rec[1] < rec[2] or rec[23] < rec[24]:
        raise NtopngFailure(f"{where}: fewer bytes than packets")
    if rec[4] > 255:
        raise NtopngFailure(f"{where}: bad protocol {rec[4]!r}")


def ntopng_check_messages(messages: List[List[bytes]], dialect: str,
                          bounds: Tuple[int, int]) -> int:
    """Check all messages, return the number of flow records."""
    if not messages:
        raise NtopngFailure("no message received")
    total, prev_id = 0, None
    for i, parts in enumerate(messages):
        where = f"message {i}"
        if len(parts) != 2:
            raise NtopngFailure(f"{where}: {len(parts)} frames, expected 2")
        hdr, payload = ntopng_decode_header(parts[0]), parts[1]
        if hdr["url"] != b"flow":
            raise NtopngFailure(f"{where}: topic {hdr['url']!r}, expected flow")
        if prev_id is not None and hdr["msg_id"] != (prev_id + 1) & 0xffffffff:
            raise NtopngFailure(f"{where}: msg_id {hdr['msg_id']} does not follow {prev_id}")
        prev_id = hdr["msg_id"]
        if len(payload) > NTOPNG_MAX_PAYLOAD:
            raise NtopngFailure(f"{where}: payload of {len(payload)} bytes is too large")
        if hdr["size"] != len(payload):
            raise NtopngFailure(f"{where}: header size {hdr['size']}, payload {len(payload)} bytes")
        if dialect == "ntopng":
            if len(parts[0]) != NTOPNG_HDR_V4_LEN or hdr["version"] != 4 \
                    or hdr["flags"] & NTOPNG_FLAG_IS_COMPRESSED \
                    or not hdr["flags"] & NTOPNG_FLAG_IS_TLV:
                raise NtopngFailure(f"{where}: expected a v4 header (version 4, TLV flag)")
            records = ntopng_decode_tlv(payload)
        else:
            if len(parts[0]) != NTOPNG_HDR_V2_LEN or hdr["version"] != 2:
                raise NtopngFailure(f"{where}: expected a v2 header (24 bytes, version 2)")
            records = ntopng_decode_json(payload)
        if not records:
            raise NtopngFailure(f"{where}: no flow records")
        for n, rec in enumerate(records):
            ntopng_check_record(rec, f"{where} record {n}", bounds)
        total += len(records)
    return total


def ntopng_export(daemon: str, dialect: str, pcap: str,
                   extra: Sequence[str] = ()) -> List[List[bytes]]:
    """Run daemon -v DIALECT on pcap and return the received ZMQ messages.

    A ZMQ PUB socket drops what it sends before the subscription is in place,
    and a pcap is read and exported within milliseconds.  So the pcap is fed
    through stdin: its file header first (softflowd reads it before it
    connects), the packets once the subscription is established.
    """
    with open(pcap, "rb") as f:
        data = f.read()
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    srv.settimeout(15)
    proc = subprocess.Popen([daemon, "-r", "-", "-n", f"127.0.0.1:{srv.getsockname()[1]}",
                             "-v", dialect, *extra], stdin=subprocess.PIPE,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    messages: List[List[bytes]] = []
    try:
        proc.stdin.write(data[:24])
        proc.stdin.flush()
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            raise NtopngFailure("softflowd did not connect (built without ntopng support?)")
        with conn:
            conn.settimeout(15)
            _zmq_sub_handshake(conn)
            time.sleep(0.5)
            proc.stdin.write(data[24:])
            proc.stdin.close()
            conn.settimeout(0.5)
            parts: List[bytes] = []
            last_rx, deadline = time.time(), time.time() + 120
            while time.time() < deadline:
                try:
                    flags, body = _zmq_read_frame(conn)
                except socket.timeout:
                    if time.time() - last_rx > (1 if proc.poll() is not None else 5):
                        break
                    continue
                except EOFError:
                    break
                last_rx = time.time()
                if flags & 0x04:  # command, for example PING
                    continue
                parts.append(body)
                if not flags & 0x01:
                    messages.append(parts)
                    parts = []
    finally:
        srv.close()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    return messages


def ntopng_resolve_daemon(args: argparse.Namespace, build_dir: str) -> Optional[str]:
    """The softflowd built with --enable-ntopng --enable-ntopng-json."""
    if args.ntopng_bin:
        return args.ntopng_bin
    daemon = os.path.join(build_dir, "softflowd-ntopng")
    if args.skip_build:
        found = daemon if os.path.exists(daemon) else shutil.which("softflowd-ntopng")
        return found or None
    print("  -> Configuring and building C development ntopng "
          "(--enable-ntopng --enable-ntopng-json)...")
    if not build_c(PROJECT_ROOT, ["--enable-ntopng", "--enable-ntopng-json"]):
        print_red("Failed to build softflowd with ntopng support (libzmq is needed, "
                  "for example libzmq3-dev).")
        return None
    copy_binaries(PROJECT_ROOT, daemon)
    return daemon


def ntopng_resolve_cpp_daemon(args: argparse.Namespace, build_dir: str) -> Optional[str]:
    """The softflowd+ built with -DSOFTFLOWD_CPP_NTOPNG=ON, or None if there is none."""
    if args.ntopng_cpp_bin:
        return args.ntopng_cpp_bin
    if args.skip_cpp:
        return None
    daemon = os.path.join(build_dir, "softflowd+-ntopng")
    if args.skip_build:
        return daemon if os.path.exists(daemon) else None
    print("  -> Configuring and building C++ ntopng (-DSOFTFLOWD_CPP_NTOPNG=ON)...")
    out = os.path.join(helper.SUITE_TMP_DIR, "build-cpp-ntopng")
    if run_command(["cmake", "-S", os.path.join(PROJECT_ROOT, "cpp"), "-B", out,
                    "-DSOFTFLOWD_CPP_NTOPNG=ON"]).returncode != 0 \
            or run_command(["cmake", "--build", out, "-j"]).returncode != 0:
        print_yellow("Warning: the C++ version with ntopng support could not be built "
                     "(libzmq is needed); it is not compared.")
        return None
    shutil.copy2(os.path.join(out, "softflowd+"), daemon)
    return daemon


# Options of the byte for byte comparison of -v ntopng.  -a is always given: without it
# the absolute times depend on the wall clock, as for the other export versions.
NTOPNG_PARITY_ARGS = [["-a"], ["-a", "-T", "ether"], ["-a", "-m", "5"], ["-a", "-s", "10"]]


def ntopng_parity(daemon_a: str, daemon_b: str, pcaps: List[Tuple[str, str]]) -> bool:
    """Compare the ZMQ messages of -v ntopng (TLV) of A and B byte for byte."""
    ok = True
    for extra in NTOPNG_PARITY_ARGS:
        for label, pcap in pcaps:
            text = f"{label} (-v ntopng {' '.join(extra)})"
            try:
                msgs_a = ntopng_export(daemon_a, "ntopng", pcap, extra)
                msgs_b = ntopng_export(daemon_b, "ntopng", pcap, extra)
            except (NtopngFailure, OSError, EOFError) as e:
                print_red(f"    - {text}: FAILED: {e}")
                ok = False
                continue
            if msgs_a == msgs_b:
                print(f"    - {text}: MATCHED ({len(msgs_a)} messages, byte for byte)")
                continue
            ok = False
            why = f"{len(msgs_a)} messages in A, {len(msgs_b)} in B"
            for n, (x, y) in enumerate(zip(msgs_a, msgs_b)):
                if x != y:
                    why = f"message {n} differs"
                    for k, (fx, fy) in enumerate(zip(x, y)):
                        if fx != fy:
                            first = next((i for i in range(min(len(fx), len(fy)))
                                          if fx[i] != fy[i]), min(len(fx), len(fy)))
                            why += f" in frame {k} at byte {first} ({len(fx)} / {len(fy)} bytes)"
                            break
                    break
            print_red(f"    - {text}: FAILED: {why}")
    return ok


def ntopng_has_dialect(daemon: str, dialect: str) -> bool:
    """Whether the usage of daemon lists the dialect of -v (a build without --enable-ntopng-json has no JSON)."""
    r = subprocess.run([daemon, "-h"], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
    return dialect in r.stdout + r.stderr


def ntopng_daemon_check(daemon: str, name: str) -> bool:
    """-v ntopng as a daemon (no -d) on lo exports the flows over ZeroMQ.  ZeroMQ starts its I/O threads in
    the process that makes the socket, and a fork () does not carry them to the child, so the socket has to be
    made after the fork.  Needs root (to capture on lo and to drop the privileges) and /var/empty."""
    if not parity_can_capture_lo() or not os.path.isdir("/var/empty"):
        print_yellow(f"    - {name} as a daemon (-v ntopng): SKIPPED (needs root and /var/empty)")
        return True
    pid_path = os.path.join(helper.SUITE_TMP_DIR, "ntopng_daemon.pid")
    ctl_path = os.path.join(helper.SUITE_TMP_DIR, "ntopng_daemon.ctl")
    for path in (pid_path, ctl_path):
        if os.path.exists(path):
            os.remove(path)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    srv.settimeout(15)
    count, error = 0, ""
    try:
        subprocess.run([daemon, "-i", "lo", "-v", "ntopng", "-n", f"127.0.0.1:{srv.getsockname()[1]}",
                        "-p", pid_path, "-c", ctl_path, "-t", "general=1", "-t", "expint=1",
                        "udp and dst port 41021"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=15)
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            conn = None
            error = "softflowd did not connect"
        if conn is not None:
            with conn:
                conn.settimeout(15)
                _zmq_sub_handshake(conn)
                time.sleep(0.5)
                for _ in range(5):
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                        sender.sendto(b"x" * 40, ("127.0.0.1", 41021))
                time.sleep(0.5)
                with open(pid_path) as f:       # the shutdown on SIGTERM expires and exports the flows
                    os.kill(int(f.read().strip()), signal.SIGTERM)
                conn.settimeout(0.5)
                last_rx, deadline = time.time(), time.time() + 20
                while time.time() < deadline and time.time() - last_rx < 4:
                    try:
                        flags, _ = _zmq_read_frame(conn)
                    except socket.timeout:
                        continue
                    except EOFError:
                        break
                    last_rx = time.time()
                    if not flags & 0x05:        # the last frame of a message that is not a command
                        count += 1
    except (OSError, ValueError, EOFError, subprocess.SubprocessError) as e:
        error = f"({type(e).__name__}) {e}"
    finally:
        srv.close()
        try:
            with open(pid_path) as f:
                os.kill(int(f.read().strip()), signal.SIGTERM)
        except (OSError, ValueError):
            pass
    if count > 0:
        print_green(f"    - {name} as a daemon (-v ntopng): MATCHED ({count} messages)")
        return True
    print_red(f"    - {name} as a daemon (-v ntopng): FAILED: no message received {error}")
    return False


def ntopng_step(args: argparse.Namespace, build_dir: str) -> bool:
    """compat --ntopng: check -v ntopng (TLV) and -v ntopng-json on the pcaps."""
    print_cyan("\n[ntopng] Verifying the ZMQ export for ntopng...")
    daemon = ntopng_resolve_daemon(args, build_dir)
    if not daemon or not os.path.exists(daemon):
        print_red("  - FAILED: no softflowd built with --enable-ntopng --enable-ntopng-json "
                  "(use --ntopng-bin or build it)")
        return False
    gen = os.path.join(helper.SUITE_TMP_DIR, "ntopng_many_flows.pcap")
    pcaps = [("IPv4 HTTP", ensure_sample_pcap("http.cap", HTTP_PCAP_URL)),
             ("IPv6 HTTP", ensure_sample_pcap("v6-http.cap", V6_HTTP_PCAP_URL))]
    pcaps += [(os.path.basename(p), p) for p in helper.COMPAT_PCAPS]
    # Both ends with the same address (IPv4 and IPv6, as on a loopback interface): one Biflow.
    with open(pcaps[0][1], "rb") as f:
        header = f.read(24)
    loopback = os.path.join(helper.SUITE_TMP_DIR, "ntopng_loopback.pcap")
    with open(loopback, "wb") as f:
        f.write(parity_loopback_pcap(header))
    pcaps.append(("same addresses (IPv4, IPv6)", loopback))
    # Many flows: the export is split into several messages.
    many = 3000
    expected: Dict[str, int] = {}
    if subprocess.run([sys.executable, os.path.join(PROJECT_ROOT, "tools",
                                                    "gen_ci_smoke_pcap.py"),
                       "-n", str(many), gen], stdout=subprocess.DEVNULL).returncode == 0:
        pcaps.append((f"{many} flows", gen))
        expected[f"{many} flows"] = many
    ok = True
    totals: Dict[str, int] = {}
    for dialect in NTOPNG_DIALECTS:
        if not ntopng_has_dialect(daemon, dialect):
            print_yellow(f"    - -v {dialect}: SKIPPED (this softflowd is built without it)")
            continue
        for label, pcap in pcaps:
            text = f"{label} (-v {dialect})"
            try:
                bounds = ntopng_pcap_time_range(pcap) or (1, 2 ** 32)
                messages = ntopng_export(daemon, dialect, pcap)
                total = ntopng_check_messages(messages, dialect, bounds)
                # No flow may be lost, for example at shutdown, and both formats
                # carry the same flows.
                want = expected.get(label, totals.get(label))
                if want is not None and total != want:
                    raise NtopngFailure(f"{total} flows received, expected {want}")
                totals.setdefault(label, total)
            except (NtopngFailure, OSError, EOFError) as e:
                print_red(f"    - {text}: FAILED: {e}")
                ok = False
            else:
                print(f"    - {text}: MATCHED ({len(messages)} messages, {total} flows)")
    # The C++ version has -v ntopng (TLV) only: its messages must be those of the C build.
    cpp_daemon = ntopng_resolve_cpp_daemon(args, build_dir)
    if cpp_daemon and os.path.exists(cpp_daemon):
        print_cyan("  [ntopng] softflowd vs softflowd+: the messages, byte for byte")
        ok = ntopng_parity(daemon, cpp_daemon, pcaps) and ok
        ok = ntopng_daemon_check(cpp_daemon, "softflowd+") and ok
    else:
        print_yellow("  [ntopng] softflowd+ with ntopng support not available: not compared")
    return ntopng_daemon_check(daemon, "softflowd") and ok
