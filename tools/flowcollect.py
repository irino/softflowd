#!/usr/bin/env python3
"""
Pure-Python NetFlow v1/v5/v9 and IPFIX collector for the softflowd test tools.

Standard library only.  It is used by run_compat_suite.py as a fallback when
nfcapd/nfdump are not installed, and it can be run on its own to print the
flows it receives (a replacement for collector.pl, which only understands
NetFlow v1 and v5):

    python3 tools/flowcollect.py -p 2055 [-6] [-b ADDRESS]

Every flow is reduced to one row using the same column names as `nfdump -o
csv` (ts, te, td, sa, da, sp, dp, pr, flg, stos, ipkt, ibyt, in, out), so the
normalisation in run_compat_suite.py can be shared.  Fields that are not
mapped to one of those columns are kept in the trailing "x" column as
"name=value" pairs instead of being dropped, so that a difference in any
exported field still shows up when two builds are compared.
"""

import argparse
import datetime
import ipaddress
import select
import socket
import struct
import sys
import threading
import time
from typing import Dict, List, Optional, Tuple

CSV_COLUMNS = ["ts", "te", "td", "sa", "da", "sp", "dp", "pr", "flg", "stos",
               "ipkt", "ibyt", "in", "out", "x"]

# Field type numbers shared by NetFlow v9 and IPFIX (RFC 3954 / IANA IPFIX
# registry); only the ones that are mapped to a CSV column are listed.
T_OCTETS, T_PACKETS, T_PROTO, T_TOS, T_TCP_FLAGS = 1, 2, 4, 5, 6
T_SPORT, T_SRC4, T_INPUT, T_DPORT, T_DST4, T_OUTPUT = 7, 8, 10, 11, 12, 14
T_LAST, T_FIRST = 21, 22
T_SRC6, T_DST6 = 27, 28
T_ICMP4, T_ICMP6 = 32, 139
T_FLOW_START_MS, T_FLOW_END_MS = 152, 153
T_SYSTEM_INIT_MS = 160

IP_TYPES = {T_SRC4: 4, T_DST4: 4, T_SRC6: 16, T_DST6: 16}
IPPROTO_ICMP, IPPROTO_ICMPV6 = 1, 58


def _value(raw: bytes) -> str:
    """Render a raw field value: an integer up to 8 bytes, hex otherwise."""
    if len(raw) <= 8:
        return str(int.from_bytes(raw, "big"))
    return raw.hex()


class Decoder:
    """Stateful decoder: keeps v9/IPFIX templates between datagrams."""

    def __init__(self) -> None:
        # (version, exporter address, domain id, template id) -> template
        self._templates: Dict[tuple, dict] = {}
        # (exporter address, domain id) -> systemInitTimeMilliseconds
        self._sys_init: Dict[tuple, int] = {}
        self.dropped = 0

    # -- public ------------------------------------------------------------

    def feed(self, data: bytes, exporter: str = "") -> List[dict]:
        """Decode one datagram; returns a list of flow dicts."""
        if len(data) < 2:
            self.dropped += 1
            return []
        version = struct.unpack("!H", data[:2])[0]
        try:
            if version in (1, 5):
                return self._fixed(data, version)
            if version == 9:
                return self._v9(data, exporter)
            if version == 10:
                return self._ipfix(data, exporter)
        except (struct.error, IndexError, ValueError):
            pass
        self.dropped += 1
        return []

    # -- NetFlow v1 / v5 ---------------------------------------------------

    def _fixed(self, data: bytes, version: int) -> List[dict]:
        hdr_len, rec_len = (16, 48) if version == 1 else (24, 48)
        count, uptime, secs, nsecs = struct.unpack("!HIII", data[2:16])
        flows = []
        for i in range(count):
            off = hdr_len + i * rec_len
            rec = data[off:off + rec_len]
            if len(rec) < rec_len:
                raise ValueError("short record")
            if version == 1:
                (src, dst, nh, inp, out, pkts, octets, first, last, sport,
                 dport, _pad, proto, tos, flags) = struct.unpack(
                     "!IIIHHIIIIHHHBBB", rec[:41])
                extra = {}
            else:
                (src, dst, nh, inp, out, pkts, octets, first, last, sport,
                 dport, _pad1, flags, proto, tos, sas, das, smk, dmk) = \
                    struct.unpack("!IIIHHIIIIHHBBBBHHBB", rec[:46])
                extra = {"src_as": sas, "dst_as": das,
                         "src_mask": smk, "dst_mask": dmk}
            extra["nexthop"] = str(ipaddress.IPv4Address(nh))
            base = secs * 1000 + nsecs // 1000000
            flows.append({
                "sa": str(ipaddress.IPv4Address(src)),
                "da": str(ipaddress.IPv4Address(dst)),
                "sp": sport, "dp": dport, "pr": proto, "flg": flags,
                "stos": tos, "ipkt": pkts, "ibyt": octets,
                "in": inp, "out": out,
                "first_ms": base - ((uptime - first) % (1 << 32)),
                "last_ms": base - ((uptime - last) % (1 << 32)),
                "extra": extra,
            })
        return flows

    # -- NetFlow v9 --------------------------------------------------------

    def _v9(self, data: bytes, exporter: str) -> List[dict]:
        _ver, _count, uptime, secs, _seq, domain = struct.unpack(
            "!HHIIII", data[:20])
        flows: List[dict] = []
        off = 20
        # Flowset lengths are taken as declared.  They are not required to be
        # multiples of 4: softflowd pads so that the *next* flowset starts on
        # a 4-byte boundary, which makes the length itself unaligned.
        while off + 4 <= len(data):
            fsid, flen = struct.unpack("!HH", data[off:off + 4])
            if flen < 4:
                break
            body = data[off + 4:off + flen]
            if fsid == 0:
                self._v9_templates(body, exporter, domain, options=False)
            elif fsid == 1:
                self._v9_templates(body, exporter, domain, options=True)
            elif fsid >= 256:
                tmpl = self._templates.get((9, exporter, domain, fsid))
                if tmpl is None:
                    self.dropped += 1
                elif not tmpl["options"]:
                    base = secs * 1000
                    for rec in self._records(body, tmpl["fields"]):
                        flows.append(self._flow_from_fields(
                            rec, uptime_ms=uptime, export_ms=base))
            off += flen
        return flows

    def _v9_templates(self, body: bytes, exporter: str, domain: int,
                      options: bool) -> None:
        off = 0
        while off + 4 <= len(body):
            if options:
                tid, scope_len, opt_len = struct.unpack(
                    "!HHH", body[off:off + 6])
                off += 6
                specs = [struct.unpack("!HH", body[off + 4 * i:off + 4 * i + 4])
                         for i in range((scope_len + opt_len) // 4)]
                off += scope_len + opt_len
            else:
                tid, nfields = struct.unpack("!HH", body[off:off + 4])
                off += 4
                specs = [struct.unpack("!HH", body[off + 4 * i:off + 4 * i + 4])
                         for i in range(nfields)]
                off += 4 * nfields
            self._templates[(9, exporter, domain, tid)] = {
                "options": options, "fields": list(specs)}
            if options and off % 4 == 2:
                off += 2  # trailing padding of the options template set

    # -- IPFIX -------------------------------------------------------------

    def _ipfix(self, data: bytes, exporter: str) -> List[dict]:
        _ver, length, export_time, _seq, domain = struct.unpack(
            "!HHIII", data[:16])
        flows: List[dict] = []
        off = 16
        end = min(length, len(data))
        while off + 4 <= end:
            sid, slen = struct.unpack("!HH", data[off:off + 4])
            if slen < 4:
                break
            body = data[off + 4:off + slen]
            if sid in (2, 3):
                self._ipfix_templates(body, exporter, domain, options=sid == 3)
            elif sid >= 256:
                tmpl = self._templates.get((10, exporter, domain, sid))
                if tmpl is None:
                    self.dropped += 1
                else:
                    for rec in self._records(body, tmpl["fields"]):
                        if tmpl["options"]:
                            self._note_options(rec, exporter, domain)
                        else:
                            flows.append(self._flow_from_fields(
                                rec, export_ms=export_time * 1000,
                                sys_init=self._sys_init.get((exporter, domain))))
            off += slen
        return flows

    def _ipfix_templates(self, body: bytes, exporter: str, domain: int,
                         options: bool) -> None:
        off = 0
        while off + 4 <= len(body):
            tid, nfields = struct.unpack("!HH", body[off:off + 4])
            off += 4
            if options:
                off += 2  # scope field count; scope fields are ordinary specs
            specs = []
            for _ in range(nfields):
                ie, flen = struct.unpack("!HH", body[off:off + 4])
                off += 4
                if ie & 0x8000:
                    off += 4  # enterprise number; the field is kept as "type"
                specs.append((ie & 0x7FFF, flen))
            self._templates[(10, exporter, domain, tid)] = {
                "options": options, "fields": specs}

    def _note_options(self, rec: List[Tuple[int, bytes]], exporter: str,
                      domain: int) -> None:
        for ftype, raw in rec:
            if ftype == T_SYSTEM_INIT_MS and len(raw) == 8:
                self._sys_init[(exporter, domain)] = int.from_bytes(raw, "big")

    # -- shared v9 / IPFIX -------------------------------------------------

    @staticmethod
    def _records(body: bytes, specs: List[Tuple[int, int]]):
        """Yield each record of a data set as a list of (type, raw bytes)."""
        fixed = sum(flen for _t, flen in specs if flen != 0xFFFF)
        variable = any(flen == 0xFFFF for _t, flen in specs)
        off = 0
        while off + fixed <= len(body) and (fixed or variable):
            rec = []
            for ftype, flen in specs:
                if flen == 0xFFFF:  # IPFIX variable-length field (RFC 7011)
                    flen = body[off]
                    off += 1
                    if flen == 255:
                        flen = struct.unpack("!H", body[off:off + 2])[0]
                        off += 2
                rec.append((ftype, body[off:off + flen]))
                off += flen
            yield rec

    @staticmethod
    def _flow_from_fields(rec: List[Tuple[int, bytes]],
                          uptime_ms: Optional[int] = None,
                          export_ms: Optional[int] = None,
                          sys_init: Optional[int] = None) -> dict:
        flow: dict = {"sp": 0, "dp": 0, "pr": 0, "flg": 0, "stos": 0,
                      "ipkt": 0, "ibyt": 0, "in": 0, "out": 0,
                      "sa": "0.0.0.0", "da": "0.0.0.0"}
        extra: Dict[str, str] = {}
        icmp: Optional[int] = None
        first = last = None
        simple = {T_SPORT: "sp", T_DPORT: "dp", T_PROTO: "pr",
                  T_TCP_FLAGS: "flg", T_TOS: "stos", T_PACKETS: "ipkt",
                  T_OCTETS: "ibyt", T_INPUT: "in", T_OUTPUT: "out"}
        for ftype, raw in rec:
            if ftype in IP_TYPES and len(raw) == IP_TYPES[ftype]:
                key = "sa" if ftype in (T_SRC4, T_SRC6) else "da"
                flow[key] = str(ipaddress.ip_address(raw))
            elif ftype in simple and len(raw) <= 8:
                flow[simple[ftype]] = int.from_bytes(raw, "big")
            elif ftype in (T_ICMP4, T_ICMP6) and len(raw) == 2:
                icmp = int.from_bytes(raw, "big")
            elif ftype == T_FIRST and len(raw) == 4:
                first = int.from_bytes(raw, "big")
            elif ftype == T_LAST and len(raw) == 4:
                last = int.from_bytes(raw, "big")
            elif ftype == T_FLOW_START_MS and len(raw) == 8:
                flow["first_ms"] = int.from_bytes(raw, "big")
            elif ftype == T_FLOW_END_MS and len(raw) == 8:
                flow["last_ms"] = int.from_bytes(raw, "big")
            else:
                extra["t%d" % ftype] = _value(raw)
        if icmp is not None and flow["pr"] in (IPPROTO_ICMP, IPPROTO_ICMPV6):
            flow["dp"] = icmp  # nfdump shows type * 256 + code here
        elif icmp is not None:
            extra["icmp"] = str(icmp)
        for key, rel in (("first_ms", first), ("last_ms", last)):
            if rel is None:
                continue
            if sys_init is not None:
                flow[key] = sys_init + rel
            elif uptime_ms is not None and export_ms is not None:
                flow[key] = export_ms - ((uptime_ms - rel) % (1 << 32))
            else:
                flow[key] = None
                extra["up_" + key[:-3]] = str(rel)
        flow["extra"] = extra
        return flow


def _fmt_time(ms: Optional[int]) -> str:
    if ms is None:
        return "-"
    dt = datetime.datetime.fromtimestamp(ms / 1000.0, datetime.timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + "%03d" % (ms % 1000)


def flow_to_row(flow: dict) -> List[str]:
    """Format a decoded flow as the CSV columns in CSV_COLUMNS."""
    first, last = flow.get("first_ms"), flow.get("last_ms")
    dur = "%.3f" % ((last - first) / 1000.0) if first is not None and \
        last is not None else "-"
    extra = ";".join("%s=%s" % kv for kv in sorted(flow["extra"].items()))
    return [_fmt_time(first), _fmt_time(last), dur, flow["sa"], flow["da"],
            str(flow["sp"]), str(flow["dp"]), str(flow["pr"]),
            str(flow["flg"]), str(flow["stos"]), str(flow["ipkt"]),
            str(flow["ibyt"]), str(flow["in"]), str(flow["out"]),
            extra or "-"]


def datagrams_to_csv(datagrams: List[Tuple[bytes, str]]) -> str:
    """Decode datagrams in arrival order and return nfdump-style CSV text."""
    dec = Decoder()
    lines = [",".join(CSV_COLUMNS)]
    for data, exporter in datagrams:
        for flow in dec.feed(data, exporter):
            lines.append(",".join(flow_to_row(flow)))
    return "\n".join(lines) + "\n"


class UdpSink:
    """Background UDP receiver that stores every datagram it gets."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        self.sock.bind((host, port))
        self.port = self.sock.getsockname()[1]
        self.datagrams: List[Tuple[bytes, str]] = []
        self._stop = threading.Event()
        self._last_rx = time.monotonic()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            ready, _, _ = select.select([self.sock], [], [], 0.1)
            if not ready:
                continue
            data, addr = self.sock.recvfrom(65535)
            self.datagrams.append((data, addr[0]))
            self._last_rx = time.monotonic()

    def close(self, quiet: float = 0.3, timeout: float = 3.0) -> None:
        """Wait until no datagram arrived for `quiet` seconds, then stop."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and \
                time.monotonic() - self._last_rx < quiet:
            time.sleep(0.05)
        self._stop.set()
        self._thread.join()
        self.sock.close()


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Print NetFlow v1/v5/v9 and IPFIX flows received on a "
                    "UDP port (CSV, nfdump column names).")
    ap.add_argument("-p", "--port", type=int, required=True,
                    help="UDP port to listen on")
    ap.add_argument("-b", "--bind", default=None,
                    help="address to listen on (default: any)")
    ap.add_argument("-6", "--ipv6", action="store_true",
                    help="listen on IPv6 (default: IPv4)")
    args = ap.parse_args()
    host = args.bind or ("::" if args.ipv6 else "0.0.0.0")
    sink_sock = socket.socket(
        socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM)
    sink_sock.bind((host, args.port))
    dec = Decoder()
    print(",".join(CSV_COLUMNS), flush=True)
    try:
        while True:
            data, addr = sink_sock.recvfrom(65535)
            for flow in dec.feed(data, addr[0]):
                print(",".join(flow_to_row(flow)), flush=True)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
