#!/usr/bin/env python3
"""Check IPFIX record layouts by replaying a generated IPv6 capture."""

import argparse
import ipaddress
import socket
import tempfile
from pathlib import Path

from gen_ci_smoke_pcap import eth_hdr, icmp_hdr, ip6_hdr, pcap_global_header, pcap_rec, udp_hdr
from softflowd_test_parity import parity_export, parity_ipfix_records


def make_capture(path):
    macs = ("02:00:00:00:00:01", "02:00:00:00:00:02")
    udp = udp_hdr(12345, 161, 4) + b"data"
    reply = udp_hdr(161, 12345, 8) + b"response"
    echo6 = bytes([128]) + icmp_hdr()[1:]
    packets = (
        # IPv6 carrying protocol 1 must use the regular IPv6 record layout.
        ("2001:db8::1", "2001:db8:1::1", socket.IPPROTO_ICMP, icmp_hdr(), macs),
        ("2001:db8::2", "2001:db8:1::2", socket.IPPROTO_UDP, udp, macs),
        ("2001:db8:1::2", "2001:db8::2", socket.IPPROTO_UDP, reply, macs[::-1]),
        ("2001:db8::3", "2001:db8:1::3", socket.IPPROTO_ICMPV6, echo6, macs),
    )
    frames = [pcap_global_header()]
    for sec, (src, dst, proto, payload, (src_mac, dst_mac)) in enumerate(packets, 1000):
        ethernet = eth_hdr(src_mac, dst_mac, 0x86DD)
        frame = ethernet + ip6_hdr(src, dst, proto, len(payload)) + payload
        frames.append(pcap_rec(sec, frame))
    path.write_bytes(b"".join(frames))


def exported_flows(datagrams, biflow):
    flows = []
    for record in parity_ipfix_records(datagrams):
        fields = dict(record)
        src, dst = (str(ipaddress.IPv6Address(fields[ie, 0])) for ie in (27, 28))
        # Protocol, packets, octets, ports or ICMPv6 type/code.
        values = [int.from_bytes(fields.get((ie, 0), b""), "big")
                  for ie in (4, 2, 1, 7, 11, 139)]
        if biflow:
            values.extend(
                int.from_bytes(fields[ie, 29305], "big") if (ie, 29305) in fields else None
                for ie in (2, 1)
            )
        flows.append((src, dst, *values))
    return sorted(flows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("softflowd", type=Path, help="path to a built softflowd binary")
    args = parser.parse_args()

    expected = [
        ("2001:db8::1", "2001:db8:1::1", 1, 1, 48, 0, 2048, 0),
        ("2001:db8::2", "2001:db8:1::2", 17, 1, 52, 12345, 161, 0),
        ("2001:db8::3", "2001:db8:1::3", 58, 1, 48, 0, 0, 32768),
    ]
    uniflow = sorted(expected + [("2001:db8:1::2", "2001:db8::2", 17, 1, 56, 161, 12345, 0)])
    biflow = [expected[0] + (0, 0), expected[1] + (1, 56), expected[2] + (None, None)]
    # Expire protocol 1 first so its record shares a Set with the following UDP records.
    options = ["-T", "ether", "-t", "general=10", "-t", "udp=30", "-t", "icmp=60"]
    passed = True
    with tempfile.TemporaryDirectory(prefix="ipfix_regress_") as tmp:
        pcap = Path(tmp, "ipv6.pcap")
        make_capture(pcap)
        for label, flags, wanted in (("uniflow", [], uniflow), ("biflow", ["-b"], biflow)):
            datagrams = parity_export(str(args.softflowd.resolve()), str(pcap), "10", options + flags)
            got = exported_flows(datagrams, bool(flags))
            if got == wanted:
                print(f"OK   IPFIX {label}: all IPv6 records match")
            else:
                print(f"FAIL IPFIX {label}: expected {wanted}, got {got}")
                passed = False
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
