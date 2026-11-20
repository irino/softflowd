use crate::common::{TimeVal, TrackLevel};
use byteorder::{BigEndian, ByteOrder};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// Standard Datalink Types
pub const DLT_EN10MB: i32 = 1;
pub const DLT_PPP: i32 = 5;
pub const DLT_LINUX_SLL: i32 = 113;
pub const DLT_RAW: i32 = 12;
pub const DLT_NULL: i32 = 0;
pub const DLT_LOOP: i32 = 108;
pub const DLT_PFLOG: i32 = 117;

/// Whether the data link type is one that softflowd reads.
///
/// Original: packet.c, datalink_check() with no packet: the table `lt`.
pub fn datalink_supported(linktype: i32) -> bool {
    matches!(
        linktype,
        DLT_EN10MB | DLT_PPP | DLT_LINUX_SLL | DLT_RAW | DLT_NULL | DLT_LOOP | DLT_PFLOG
    )
}

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_DCCP: u8 = 33;
const IPPROTO_SCTP: u8 = 132;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;

// IPv6 Extension Headers
const IPPROTO_HOPOPTS: u8 = 0;
const IPPROTO_ROUTING: u8 = 43;
const IPPROTO_FRAGMENT: u8 = 44;
const IPPROTO_DSTOPTS: u8 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    NonIp,
    TooShort,
    /// An IPv6 packet that is too short: C does not look at it without -6 (it is
    /// counted as not IP), as the family comes from the datalink header.
    TooShortV6,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPacket {
    pub af: u16, // libc::AF_INET = 2, libc::AF_INET6 = 10
    pub protocol: u8,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub vlan_id: u16,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub mpls_labels: Vec<u32>,
    pub tcp_flags: u8,
    pub tos: u8,
    pub is_frag: bool,
    pub is_first: bool,
    pub ip6_flowlabel: u32,
    pub length: u32,
    pub timestamp: TimeVal,
}

// The arguments mirror the C version, which passes the same values.
#[allow(clippy::too_many_arguments)]
pub fn parse_packet(
    linktype: i32,
    pkt: &[u8],
    caplen: u32,
    orig_len: u32,
    track_level: TrackLevel,
    max_mpls_label: u8,
    full_l4hdr_check: bool,
    timestamp: TimeVal,
) -> Result<ParsedPacket, ParseError> {
    let caplen = caplen as usize;
    let orig_len = orig_len as usize;
    let mut offset: usize;
    let mut vlan_id = 0;
    let mut mpls_labels = Vec::new();
    let mut src_mac = [0; 6];
    let mut dst_mac = [0; 6];
    let af: u16;

    // 1. Parse Datalink Layer
    match linktype {
        DLT_EN10MB => {
            if caplen <= 14 {
                return Err(ParseError::NonIp);
            }
            dst_mac.copy_from_slice(&pkt[0..6]);
            src_mac.copy_from_slice(&pkt[6..12]);
            let mut ethertype = BigEndian::read_u16(&pkt[12..14]);
            offset = 14;

            // Handle VLAN tags (0x8100 = 802.1Q, 0x88a8 = 802.1ad)
            while ethertype == 0x8100 || ethertype == 0x88a8 {
                if caplen < offset + 4 {
                    return Err(ParseError::NonIp);
                }
                let tci = u16::from_be_bytes([pkt[offset], pkt[offset + 1]]);
                vlan_id = tci & 0x0FFF;
                ethertype = u16::from_be_bytes([pkt[offset + 2], pkt[offset + 3]]);
                offset += 4;
            }

            // Handle MPLS (0x8847)
            if ethertype == 0x8847 {
                loop {
                    if caplen < offset + 4 {
                        return Err(ParseError::NonIp);
                    }
                    let shim = u32::from_be_bytes([
                        pkt[offset],
                        pkt[offset + 1],
                        pkt[offset + 2],
                        pkt[offset + 3],
                    ]);
                    mpls_labels.push(shim);
                    offset += 4;
                    // Check Bottom of Stack bit (bit 8 from right, shifted by 8)
                    if (shim & 0x00000100) != 0 || mpls_labels.len() >= max_mpls_label as usize {
                        break;
                    }
                }
                // Try to infer payload IP version
                if caplen < offset + 1 {
                    return Err(ParseError::NonIp);
                }
                let ip_ver = (pkt[offset] & 0xF0) >> 4;
                if ip_ver == 4 {
                    af = 2; // AF_INET
                } else if ip_ver == 6 {
                    af = 10; // AF_INET6
                } else {
                    return Err(ParseError::NonIp);
                }
            } else if ethertype == 0x0800 {
                af = 2; // AF_INET
            } else if ethertype == 0x86dd {
                af = 10; // AF_INET6
            } else {
                return Err(ParseError::NonIp);
            }
        }
        DLT_RAW => {
            if caplen == 0 {
                return Err(ParseError::NonIp);
            }
            let ip_ver = (pkt[0] & 0xF0) >> 4;
            if ip_ver == 4 {
                af = 2;
            } else if ip_ver == 6 {
                af = 10;
            } else {
                return Err(ParseError::NonIp);
            }
            offset = 0;
        }
        DLT_NULL | DLT_LOOP => {
            if caplen <= 4 {
                return Err(ParseError::NonIp);
            }
            let family = if linktype == DLT_NULL {
                // Null loopback is local host byte order
                u32::from_ne_bytes([pkt[0], pkt[1], pkt[2], pkt[3]])
            } else {
                // Loop is always big endian
                u32::from_be_bytes([pkt[0], pkt[1], pkt[2], pkt[3]])
            };
            // Map family to AF
            if family == 2 {
                af = 2;
            } else if family == 10 || family == 24 || family == 28 || family == 30 {
                // Loopback IPv6 families vary across OS, check standard ones
                af = 10;
            } else {
                return Err(ParseError::NonIp);
            }
            offset = 4;
        }
        DLT_LINUX_SLL => {
            if caplen <= 16 {
                return Err(ParseError::NonIp);
            }
            let protocol = u16::from_be_bytes([pkt[14], pkt[15]]);
            offset = 16;
            if protocol == 0x0800 {
                af = 2;
            } else if protocol == 0x86dd {
                af = 10;
            } else {
                return Err(ParseError::NonIp);
            }
        }
        DLT_PPP => {
            if caplen <= 5 {
                return Err(ParseError::NonIp);
            }
            let protocol = u16::from_be_bytes([pkt[3], pkt[4]]);
            offset = 5;
            if protocol == 0x0021 {
                af = 2;
            } else if protocol == 0x0057 {
                af = 10;
            } else {
                return Err(ParseError::NonIp);
            }
        }
        DLT_PFLOG => {
            if caplen <= 48 {
                return Err(ParseError::NonIp);
            }
            let family = pkt[1];
            offset = 48;
            if caplen < offset + 1 {
                return Err(ParseError::NonIp);
            }
            let ip_ver = (pkt[offset] & 0xF0) >> 4;
            if family == 2 || ip_ver == 4 {
                af = 2;
            } else if family == 24 || family == 28 || family == 10 || ip_ver == 6 {
                af = 10;
            } else {
                return Err(ParseError::NonIp);
            }
        }
        _ => return Err(ParseError::NonIp),
    }

    if caplen < offset {
        return Err(if af == 10 {
            ParseError::TooShortV6
        } else {
            ParseError::TooShort
        });
    }

    // 2. Parse IP Layer
    let src_ip;
    let dst_ip;
    let protocol;
    let tos;
    let mut is_frag = false;
    let mut is_first = true;
    let mut ip6_flowlabel = 0;
    let mut next_header_offset;

    // 2. Parse IP Layer
    if af == 2 {
        // IPv4
        if caplen < offset + 20 {
            return Err(ParseError::TooShort);
        }
        let version = (pkt[offset] & 0xF0) >> 4;
        if version != 4 {
            return Err(ParseError::TooShort);
        }
        let ihl = ((pkt[offset] & 0x0F) * 4) as usize;
        if caplen < offset + ihl {
            return Err(ParseError::TooShort);
        }
        tos = pkt[offset + 1];
        protocol = pkt[offset + 9];

        let ip_src_bytes = &pkt[offset + 12..offset + 16];
        let ip_dst_bytes = &pkt[offset + 16..offset + 20];
        src_ip = IpAddr::V4(Ipv4Addr::new(
            ip_src_bytes[0],
            ip_src_bytes[1],
            ip_src_bytes[2],
            ip_src_bytes[3],
        ));
        dst_ip = IpAddr::V4(Ipv4Addr::new(
            ip_dst_bytes[0],
            ip_dst_bytes[1],
            ip_dst_bytes[2],
            ip_dst_bytes[3],
        ));

        let frag_field = u16::from_be_bytes([pkt[offset + 6], pkt[offset + 7]]);
        let frag_offset = frag_field & 0x1FFF;
        let more_frags = (frag_field & 0x2000) != 0;

        is_frag = frag_offset != 0 || more_frags;
        is_first = frag_offset == 0;

        next_header_offset = offset + ihl;
    } else if af == 10 {
        // IPv6
        if caplen < offset + 40 {
            return Err(ParseError::TooShortV6);
        }
        let version = (pkt[offset] & 0xF0) >> 4;
        if version != 6 {
            return Err(ParseError::TooShortV6);
        }

        let flow_field = u32::from_be_bytes([
            pkt[offset],
            pkt[offset + 1],
            pkt[offset + 2],
            pkt[offset + 3],
        ]);
        tos = ((flow_field & 0x0FF00000) >> 20) as u8;
        ip6_flowlabel = flow_field & 0x000FFFFF;

        let mut ip_src_bytes = [0; 16];
        let mut ip_dst_bytes = [0; 16];
        ip_src_bytes.copy_from_slice(&pkt[offset + 8..offset + 24]);
        ip_dst_bytes.copy_from_slice(&pkt[offset + 24..offset + 40]);
        src_ip = IpAddr::V6(Ipv6Addr::from(ip_src_bytes));
        dst_ip = IpAddr::V6(Ipv6Addr::from(ip_dst_bytes));

        let mut nxt = pkt[offset + 6];
        next_header_offset = offset + 40;

        // Traverse extension headers
        loop {
            let remain = caplen.saturating_sub(next_header_offset);
            if nxt == IPPROTO_HOPOPTS || nxt == IPPROTO_ROUTING || nxt == IPPROTO_DSTOPTS {
                if remain < 2 {
                    break;
                }
                let ext_len = (pkt[next_header_offset + 1] as usize + 1) << 3;
                if remain < ext_len {
                    break;
                }
                nxt = pkt[next_header_offset];
                next_header_offset += ext_len;
            } else if nxt == IPPROTO_FRAGMENT {
                if remain < 8 {
                    break;
                }
                is_frag = true;
                let frag_offlg =
                    u16::from_be_bytes([pkt[next_header_offset + 2], pkt[next_header_offset + 3]]);
                let frag_offset = frag_offlg & 0xFFF8;
                if frag_offset != 0 {
                    is_first = false;
                }
                nxt = pkt[next_header_offset];
                next_header_offset += 8;
            } else {
                break;
            }
        }
        protocol = nxt;
    } else {
        return Err(ParseError::TooShort);
    }

    let mut src_port = 0;
    let mut dst_port = 0;
    let mut tcp_flags = 0;

    // 3. Parse Transport Layer (Only if it's the first fragment)
    if is_first && track_level >= TrackLevel::IpProtoPort {
        let remain = caplen.saturating_sub(next_header_offset);
        match protocol {
            IPPROTO_TCP => {
                let min_len = if full_l4hdr_check { 20 } else { 14 };
                if remain >= min_len {
                    src_port =
                        u16::from_be_bytes([pkt[next_header_offset], pkt[next_header_offset + 1]]);
                    dst_port = u16::from_be_bytes([
                        pkt[next_header_offset + 2],
                        pkt[next_header_offset + 3],
                    ]);
                    tcp_flags = pkt[next_header_offset + 13];
                }
            }
            // C: the ports of UDP, DCCP and SCTP are where the ports of UDP are.  The
            // whole header is 8 octets for UDP and 12 for DCCP (struct dccp_hdr); SCTP
            // has no header structure in C, so its ports are all that is required.
            IPPROTO_UDP | IPPROTO_DCCP | IPPROTO_SCTP => {
                let min_len = match protocol {
                    IPPROTO_UDP if full_l4hdr_check => 8,
                    IPPROTO_DCCP if full_l4hdr_check => 12,
                    _ => 4,
                };
                if remain >= min_len {
                    src_port =
                        u16::from_be_bytes([pkt[next_header_offset], pkt[next_header_offset + 1]]);
                    dst_port = u16::from_be_bytes([
                        pkt[next_header_offset + 2],
                        pkt[next_header_offset + 3],
                    ]);
                }
            }
            IPPROTO_ICMP => {
                let min_len = if full_l4hdr_check { 8 } else { 2 };
                if remain >= min_len {
                    let icmp_type = pkt[next_header_offset] as u16;
                    let icmp_code = pkt[next_header_offset + 1] as u16;
                    src_port = 0;
                    // Encode ICMP type * 256 + code like Cisco
                    dst_port = (icmp_type << 8) | icmp_code;
                }
            }
            IPPROTO_ICMPV6 => {
                let min_len = if full_l4hdr_check { 8 } else { 2 };
                if remain >= min_len {
                    let icmp_type = pkt[next_header_offset] as u16;
                    let icmp_code = pkt[next_header_offset + 1] as u16;
                    src_port = 0;
                    dst_port = (icmp_type << 8) | icmp_code;
                }
            }
            _ => {}
        }
    }

    Ok(ParsedPacket {
        af,
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        vlan_id,
        src_mac,
        dst_mac,
        mpls_labels,
        tcp_flags,
        tos,
        is_frag,
        is_first,
        ip6_flowlabel,
        length: orig_len.saturating_sub(offset) as u32,
        timestamp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_packet_non_ip() {
        let pkt = vec![0; 14]; // Ethernet header with unknown ethertype 0x0000
        let ts = TimeVal {
            tv_sec: 0,
            tv_usec: 0,
        };
        let res = parse_packet(DLT_EN10MB, &pkt, 14, 14, TrackLevel::Full, 0, false, ts);
        assert_eq!(res, Err(ParseError::NonIp));
    }

    #[test]
    fn test_parse_packet_too_short() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0; 12]);
        pkt.extend_from_slice(&[0x08, 0x00]); // IPv4 ethertype
        pkt.push(0x45); // IPv4 version, IHL=5 but truncated header
        let ts = TimeVal {
            tv_sec: 0,
            tv_usec: 0,
        };
        let res = parse_packet(
            DLT_EN10MB,
            &pkt,
            pkt.len() as u32,
            pkt.len() as u32,
            TrackLevel::Full,
            0,
            false,
            ts,
        );
        assert_eq!(res, Err(ParseError::TooShort));
    }

    fn parse_eth(pkt: &[u8]) -> Result<ParsedPacket, ParseError> {
        let ts = TimeVal {
            tv_sec: 0,
            tv_usec: 0,
        };
        parse_packet(
            DLT_EN10MB,
            pkt,
            pkt.len() as u32,
            pkt.len() as u32,
            TrackLevel::Full,
            0,
            false,
            ts,
        )
    }

    /// C (datalink_check): a packet that is not longer than the datalink header is
    /// not IP; with one byte more it is an IP packet that is too short.
    #[test]
    fn test_d37_ethernet_header_only_is_not_ip() {
        let mut pkt = vec![0u8; 12];
        pkt.extend_from_slice(&[0x08, 0x00]);
        assert_eq!(parse_eth(&pkt), Err(ParseError::NonIp));
        pkt.push(0x45);
        assert_eq!(parse_eth(&pkt), Err(ParseError::TooShort));
    }

    /// A short IPv6 packet has its own error, so that it can be counted as not IP
    /// when IPv6 is off (-6), as in C.
    #[test]
    fn test_d37_short_ipv6_is_reported_as_ipv6() {
        let mut pkt = vec![0u8; 12];
        pkt.extend_from_slice(&[0x86, 0xdd]);
        pkt.extend_from_slice(&[0x60, 0, 0, 0]);
        assert_eq!(parse_eth(&pkt), Err(ParseError::TooShortV6));
    }
}
