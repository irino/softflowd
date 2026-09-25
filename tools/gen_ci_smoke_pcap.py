#!/usr/bin/env python3
"""Generate a tiny, deterministic pcap for CI smoke-testing softflowd.
Stdlib-only (no scapy) so CI doesn't need to install anything extra."""
import struct, socket, sys

PCAP_MAGIC = 0xa1b2c3d4
LINKTYPE_ETHERNET = 1


def pcap_global_header():
    return struct.pack('<IHHiIII', PCAP_MAGIC, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET)


def pcap_rec(ts, data):
    sec = int(ts)
    usec = int((ts - sec) * 1_000_000)
    return struct.pack('<IIII', sec, usec, len(data), len(data)) + data


def ip_checksum(hdr):
    if len(hdr) % 2:
        hdr += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(hdr) // 2), hdr))
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return (~s) & 0xffff


def eth_hdr(smac, dmac, ethertype=0x0800):
    return (bytes.fromhex(dmac.replace(':', '')) +
            bytes.fromhex(smac.replace(':', '')) +
            struct.pack('!H', ethertype))


def ip_hdr(src, dst, proto, payload_len, ident):
    ident &= 0xffff
    total_len = 20 + payload_len
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total_len, ident, 0, 64,
                       proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    csum = ip_checksum(hdr)
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, total_len, ident, 0, 64,
                        proto, csum, socket.inet_aton(src), socket.inet_aton(dst))


def tcp_hdr(sport, dport, flags):
    flagmap = {'S': 0x02, 'A': 0x10, 'F': 0x01, 'PA': 0x18}
    f = flagmap.get(flags, 0x10)
    return struct.pack('!HHIIBBHHH', sport, dport, 1000, 0, 5 << 4, f, 8192, 0, 0)


def udp_hdr(sport, dport, payload_len):
    return struct.pack('!HHHH', sport, dport, 8 + payload_len, 0)


def icmp_hdr():
    return struct.pack('!BBHHH', 8, 0, 0, 1, 1)


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else 'ci_smoke.pcap'
    smac, dmac = "02:00:00:00:00:01", "02:00:00:00:00:02"
    n_flows = 40
    pkts_per_flow = 6
    t = 1_000_000.0
    out = [pcap_global_header()]
    ident = 0
    protos = ["tcp", "udp", "icmp"]
    for f in range(n_flows):
        src = f"10.0.{(f >> 8) & 0xff}.{f & 0xff}"
        dst = f"172.16.{(f >> 8) & 0xff}.{f & 0xff}"
        sport = 1024 + (f % 60000)
        dport = [80, 443, 22, 53][f % 4]
        proto_choice = protos[f % 3]
        for k in range(pkts_per_flow):
            t += 0.01
            payload = b"x" * (f % 32)
            if proto_choice == "tcp":
                flags = "S" if k == 0 else ("F" if k == pkts_per_flow - 1 else "PA")
                l4 = tcp_hdr(sport, dport, flags) + payload
                ip = ip_hdr(src, dst, 6, len(l4), ident); ident += 1
            elif proto_choice == "udp":
                l4 = udp_hdr(sport, dport, len(payload)) + payload
                ip = ip_hdr(src, dst, 17, len(l4), ident); ident += 1
            else:
                l4 = icmp_hdr() + payload
                ip = ip_hdr(src, dst, 1, len(l4), ident); ident += 1
            frame = eth_hdr(smac, dmac) + ip + l4
            out.append(pcap_rec(t, frame))
    with open(out_path, "wb") as fh:
        fh.write(b"".join(out))
    print(f"wrote {out_path}: {n_flows * pkts_per_flow} packets, {n_flows} flows")


if __name__ == "__main__":
    main()
