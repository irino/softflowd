/**
 * @file packet.cpp
 * @brief The decoding of a captured packet: PacketParser, which reads the IP and the transport headers, and the classification of the frame.
 *
 * Split from softflowd.cpp. PacketParser and classify_frame () are declared
 * in packet.hpp.
 */
#include "softflowd_cpp/packet.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#if __has_include(<linux/dccp.h>)
#include <linux/dccp.h>
#define SOFTFLOWD_CPP_HAVE_LINUX_DCCP_H 1
#endif

namespace softflowd_cpp {

// =======================================================================
// PacketParser (original: softflowd.c's ipv4_to_flowrec() /
//               ipv6_to_flowrec() / transport_to_flowrec())
// =======================================================================

namespace {

/**
 * @brief Reads a big-endian 16-bit value.
 *
 * @param data The bytes.
 * @param offset Where the 2 bytes start; the caller makes sure that they are in @p data.
 * @return The value.
 */
std::uint16_t
read_be16 (std::span<const std::uint8_t> data,
           std::size_t offset) {
  return static_cast<std::uint16_t> ((data[offset] << 8) | data[offset + 1]);
}

/**
 * @brief Reads a big-endian 32-bit value.
 *
 * @param data The bytes.
 * @param offset Where the 4 bytes start; the caller makes sure that they are in @p data.
 * @return The value.
 */
std::uint32_t
read_be32 (std::span<const std::uint8_t> data,
           std::size_t offset) {
  return (static_cast<std::uint32_t> (data[offset]) << 24) |
         (static_cast<std::uint32_t> (data[offset + 1]) << 16) |
         (static_cast<std::uint32_t> (data[offset + 2]) << 8) |
         static_cast<std::uint32_t> (data[offset + 3]);
}

constexpr std::uint8_t kProtoIcmp = 1;        ///< The IP protocol number of ICMP.
constexpr std::uint8_t kProtoTcp = 6;         ///< The IP protocol number of TCP.
constexpr std::uint8_t kProtoUdp = 17;        ///< The IP protocol number of UDP.
constexpr std::uint8_t kProtoDccp = 33;       ///< The IP protocol number of DCCP.
constexpr std::uint8_t kProtoSctp = 132;      ///< The IP protocol number of SCTP.
constexpr std::uint8_t kProtoIcmpV6 = 58;     ///< The IP protocol number of ICMPv6.
constexpr std::uint8_t kNextHopByHop = 0;     ///< The next header value of the IPv6 Hop-by-Hop Options header.
constexpr std::uint8_t kNextRouting = 43;     ///< The next header value of the IPv6 Routing header.
constexpr std::uint8_t kNextFragment = 44;    ///< The next header value of the IPv6 Fragment header.
constexpr std::uint8_t kNextDstOptions = 60;  ///< The next header value of the IPv6 Destination Options header.

}  // namespace

std::optional<ParsedPacket>
PacketParser::parse (std::span<const std::uint8_t> ip_payload,
                     AddressFamily af) const {
  if (af == AddressFamily::IPv4) {
    return parse_ipv4 (ip_payload);
  }
  if (af == AddressFamily::IPv6) {
    return parse_ipv6 (ip_payload);
  }
  return std::nullopt;
}

std::optional<ParsedPacket>
PacketParser::parse_ipv4 (std::span<const std::uint8_t> data) const {
  // Original: `caplen < 20 || caplen < ip->ip_hl * 4 || ip->ip_v != 4`.
  // Here, each subsequent stage only proceeds once the required length
  // is actually available (a subspan can never read past the end of the
  // span it was taken from).
  if (data.size() < 20) {
    return std::nullopt;  // runt packet
  }
  const std::uint8_t version = static_cast<std::uint8_t> (data[0] >> 4);
  if (version != 4) {
    return std::nullopt;
  }
  const std::size_t header_len =
    static_cast<std::size_t> (data[0] & 0x0F) * 4;
  if (header_len < 20 || data.size() < header_len) {
    return std::nullopt;
  }

  ParsedPacket packet;
  packet.tos = data[1];

  const std::uint16_t frag_field = read_be16 (data, 6);
  packet.is_fragment = (frag_field & 0x3FFF) != 0;
  packet.is_first_fragment = (frag_field & 0x1FFF) == 0;

  packet.protocol =
    track_level_ >= TrackLevel::IpProto ? data[9] : std::uint8_t{0};

  packet.src.family = AddressFamily::IPv4;
  packet.dst.family = AddressFamily::IPv4;
  for (int i = 0; i < 4; ++i) {
    packet.src.bytes[static_cast<std::size_t> (i)] =
      data[12 + static_cast<std::size_t> (i)];
    packet.dst.bytes[static_cast<std::size_t> (i)] =
      data[16 + static_cast<std::size_t> (i)];
  }

  if (track_level_ < TrackLevel::IpProtoPort) {
    packet.tos = 0;
  }

  if (packet.is_first_fragment && track_level_ >= TrackLevel::Port) {
    parse_transport (packet, data.subspan (header_len), data[9]);
  }

  return packet;
}

std::optional<ParsedPacket>
PacketParser::parse_ipv6 (std::span<const std::uint8_t> data) const {
  // Original: ipv6_to_flowrec()'s extension-header walk. As noted in
  // packet.hpp, the original had a real bug here:
  //   eh6 = (const struct ip6_ext *) pkt + size;
  // Using data.subspan(size), whose offset is unambiguously byte-based by
  // its type signature, prevents the same kind of bug from resurfacing.
  if (data.size() < 40) {
    return std::nullopt;  // runt packet
  }
  const std::uint8_t version = static_cast<std::uint8_t> (data[0] >> 4);
  if (version != 6) {
    return std::nullopt;
  }

  ParsedPacket packet;
  packet.src.family = AddressFamily::IPv6;
  packet.dst.family = AddressFamily::IPv6;
  for (int i = 0; i < 16; ++i) {
    packet.src.bytes[static_cast<std::size_t> (i)] =
      data[8 + static_cast<std::size_t> (i)];
    packet.dst.bytes[static_cast<std::size_t> (i)] =
      data[24 + static_cast<std::size_t> (i)];
  }

  const std::uint32_t vtc_flow = read_be32 (data, 0);
  packet.ip6_flowlabel = vtc_flow & 0x000FFFFFu;
  packet.tos = track_level_ >= TrackLevel::IpProtoPort
                 ? static_cast<std::uint8_t> ((vtc_flow >> 20) & 0xFFu)
                 : std::uint8_t{0};

  std::uint8_t next_header = data[6];
  std::size_t offset = 40;
  packet.is_fragment = false;
  packet.is_first_fragment = true;

  // Original: an unbounded `for (;;) { ... }` loop. It exited via
  // `if (remain < eh6size) return (size);`, but remain was a signed int
  // and could reach exactly 0 without the loop making further progress if
  // eh6size also evaluated to 0 along some path -- a latent
  // infinite-loop risk. Here the loop condition itself guarantees
  // forward progress: it requires at least 8 more bytes to remain before
  // even considering another iteration, so it always terminates.
  while (offset + 8 <= data.size()) {
    if (next_header == kNextHopByHop || next_header == kNextRouting ||
        next_header == kNextDstOptions) {
      const std::uint8_t ext_len_units = data[offset + 1];
      const std::size_t ext_header_size =
        (static_cast<std::size_t> (ext_len_units) + 1) * 8;
      if (offset + ext_header_size > data.size()) {
        return packet;  // runt: return what was parsed so far
      }
      next_header = data[offset];
      offset += ext_header_size;
    } else if (next_header == kNextFragment) {
      packet.is_fragment = true;
      if (offset + 8 > data.size()) {
        return packet;
      }
      const std::uint16_t off_flags = read_be16 (data, offset + 2);
      packet.is_first_fragment = (off_flags >> 3) == 0;
      next_header = data[offset];
      offset += 8;
    } else {
      break;
    }
  }

  packet.protocol =
    track_level_ >= TrackLevel::IpProto ? next_header : std::uint8_t{0};

  if (packet.is_first_fragment && track_level_ >= TrackLevel::Port &&
      offset <= data.size()) {
    parse_transport (packet, data.subspan (offset), next_header);
  }

  return packet;
}

/// Bytes up to and including a member, as in C's MEMBER_END().
#define SOFTFLOWD_CPP_MEMBER_END(type, member) \
  (offsetof (type, member) + sizeof (static_cast<type *> (nullptr)->member))

void
PacketParser::parse_transport (
  ParsedPacket &packet, std::span<const std::uint8_t> transport_payload,
  std::uint8_t protocol) const {
  // Original: transport_to_flowrec(). By default only the bytes that are
  // read are required (the ports, the TCP flags, the ICMP type and code);
  // full_l4hdr_check_ (-f) requires the whole header instead. Protocols
  // other than TCP, UDP, DCCP, SCTP, ICMP and ICMPv6 are not looked at.
  std::size_t min_len = 0;
  switch (protocol) {
    case kProtoTcp:
      min_len = full_l4hdr_check_
                  ? sizeof (struct tcphdr)
                  : SOFTFLOWD_CPP_MEMBER_END (struct tcphdr, th_flags);
      break;
    case kProtoUdp:
      min_len = full_l4hdr_check_
                  ? sizeof (struct udphdr)
                  : SOFTFLOWD_CPP_MEMBER_END (struct udphdr, uh_dport);
      break;
    case kProtoDccp:
#ifdef SOFTFLOWD_CPP_HAVE_LINUX_DCCP_H
      min_len = full_l4hdr_check_
                  ? sizeof (struct dccp_hdr)
                  : SOFTFLOWD_CPP_MEMBER_END (struct dccp_hdr, dccph_dport);
#else
      min_len = SOFTFLOWD_CPP_MEMBER_END (struct udphdr, uh_dport);
#endif
      break;
    case kProtoSctp:  // no header struct available: ports only
      min_len = SOFTFLOWD_CPP_MEMBER_END (struct udphdr, uh_dport);
      break;
    case kProtoIcmp:
      min_len = full_l4hdr_check_
                  ? sizeof (struct icmp)
                  : SOFTFLOWD_CPP_MEMBER_END (struct icmp, icmp_code);
      break;
    case kProtoIcmpV6:
      min_len = full_l4hdr_check_
                  ? sizeof (struct icmp6_hdr)
                  : SOFTFLOWD_CPP_MEMBER_END (struct icmp6_hdr, icmp6_code);
      break;
    default:
      return;
  }
  if (transport_payload.size() < min_len) {
    return;  // runt packet
  }

  if (protocol == kProtoTcp) {
    packet.tcp_flags = transport_payload[offsetof (struct tcphdr, th_flags)];
  }
  if (protocol == kProtoIcmp || protocol == kProtoIcmpV6) {
    // Original: the Cisco-router-compatible encoding (icmp_type * 256 +
    // icmp_code, stored as the destination port). ICMP and ICMPv6 both
    // start with type and code.
    packet.src_port = 0;
    packet.dst_port = static_cast<std::uint16_t> (
      (static_cast<std::uint16_t> (
         transport_payload[offsetof (struct icmp, icmp_type)])
       << 8) |
      transport_payload[offsetof (struct icmp, icmp_code)]);
  } else {
    // UDP, TCP, DCCP and SCTP all start with the source and destination
    // ports.
    packet.src_port =
      read_be16 (transport_payload, offsetof (struct udphdr, uh_sport));
    packet.dst_port =
      read_be16 (transport_payload, offsetof (struct udphdr, uh_dport));
  }
}

FlowKey
make_flow_key (const ParsedPacket &packet, TrackLevel track_level,
               std::array<std::uint16_t, 2> vlanid,
               std::array<std::array<std::uint8_t, 6>, 2> ethermac) {
  const std::uint8_t tos = track_level >= TrackLevel::FullTos ? packet.tos : 0;
  if (track_level < TrackLevel::FullVlan) {
    vlanid = {0, 0};
  }
  if (track_level < TrackLevel::FullVlanEther) {
    ethermac = {};
  }
  return FlowKey::make_canonical (packet.src, packet.dst, packet.src_port,
                                  packet.dst_port, packet.protocol, tos,
                                  vlanid, ethermac);
}

std::uint8_t
flow_direction (const FlowKey &key, const ParsedPacket &packet) {
  const bool same_address = key.addr()[0] == key.addr()[1];
  return key.addr()[0] == packet.src &&
             (!same_address || key.port()[0] == packet.src_port)
           ? 0
           : 1;
}

namespace {

/**
 * @brief One entry of an MPLS label stack.
 *
 * @original -x number_of_mpls_labels. An MPLS-encapsulated frame (EtherType
 * 0x8847 unicast / 0x8848 multicast) carries one or more 4-byte label
 * stack entries before the actual IP header; there is no explicit
 * "next protocol" field, so -- following the same convention other MPLS-
 * aware tools use -- the IP version nibble of the first byte after the
 * label stack determines whether what follows is IPv4 or IPv6.
 * Original: `tmp.mplsLabels[i] = *(((const u_int32_t *) (frame +
 * datalink_size)) + i);` -- a raw, NOT byte-swapped, 4-byte memory copy of
 * each MPLS shim header straight from the wire into a u_int32_t. Read
 * this way (no ntohl()) and later written out the same way (another raw
 * memcpy(), not htonl()) in ipfix_flow_to_flowset(), the net effect
 * cancels out to a verbatim pass-through of the original wire bytes' top
 * 3 octets (label(20 bits) | EXP(3 bits) | S(1 bit), dropping only the
 * TTL octet) into the IPFIX mplsTopLabelStackSectionN field -- see
 * export_record.cpp's write_mpls_labels(). So `section` here is exactly those
 * top 3 octets (bits 31-8 of the 4-byte shim), stored verbatim rather
 * than decomposed into a label number, so it can be passed through
 * unchanged instead of needing to be (incompletely -- see the EXP bits)
 * reconstructed at export time.
 */
struct MplsShimEntry {
  std::uint32_t section;  ///< The top 3 octets of the entry: the label (20 bits), EXP (3 bits) and S (1 bit); the TTL is dropped.
  bool bottom_of_stack;   ///< true for the last entry of the stack (the S bit).
};

/**
 * @brief Reads the entries of an MPLS label stack, up to the one with the S bit.
 *
 * Parses consecutive 4-byte MPLS label stack entries from the front of
 * `data`, stopping at the entry with the bottom-of-stack (S) bit set.
 * Returns std::nullopt for a truncated or pathologically deep (more than
 * 32 entries -- comfortably beyond anything a real network would ever
 * impose) label stack, the same way the rest of this project's parsing
 * functions signal "not a well-formed packet" rather than reading past
 * the end of `data`.
 *
 * @param data The bytes, from the first entry.
 * @param consumed The size of the stack in bytes; it is set only when the stack is read.
 * @return The entries, or nothing when the stack is cut short or has more than 32 entries.
 */
std::optional<std::vector<MplsShimEntry>>
parse_mpls_label_stack (std::span<const std::uint8_t> data, std::size_t &consumed) {
  std::vector<MplsShimEntry> labels;
  std::size_t offset = 0;
  for (;;) {
    if (offset + 4 > data.size()) {
      return std::nullopt;  // truncated label stack
    }
    const std::uint32_t shim =
      (static_cast<std::uint32_t> (data[offset]) << 24) |
      (static_cast<std::uint32_t> (data[offset + 1]) << 16) |
      (static_cast<std::uint32_t> (data[offset + 2]) << 8) |
      static_cast<std::uint32_t> (data[offset + 3]);
    const bool bottom = (shim & 0x00000100u) != 0;  // the S bit
    labels.push_back (MplsShimEntry{shim >> 8, bottom});
    offset += 4;
    if (bottom) {
      break;
    }
    if (labels.size() > 32) {
      return std::nullopt;  // implausibly deep; treat as malformed
    }
  }
  consumed = offset;
  return labels;
}

}  // namespace

/**
 * @brief Finds the address family of a frame, and its VLAN tag, MPLS labels and Ethernet addresses.
 *
 * Shared by run_pcap_file() and run_live_capture(): classifies one
 * captured frame's address family (and, for MPLS-encapsulated frames, its
 * label stack) from its data-link header, mapping the original DATALINK
 * table's ft_off/ft_len fields onto this project's DatalinkKind.
 *
 * @param pkt The captured frame.
 * @param dl_kind The kind of the data-link header.
 * @param ip_bytes The bytes of the frame after the data-link header.
 * @return The classification, or nothing when the frame is too short or is not IP (or MPLS with IP).
 */
std::optional<FrameClassification>
classify_frame (const softflowd_cpp::CapturedPacket &pkt, softflowd_cpp::DatalinkKind dl_kind,
                std::span<const std::uint8_t> ip_bytes) {
  using namespace softflowd_cpp;
  if (dl_kind == DatalinkKind::Ethernet) {
    if (pkt.data.size() < 14) {
      return std::nullopt;
    }
    FrameClassification frame;
    // Original: ether_to_flowrec() -- the frame's source and destination.
    std::copy_n (pkt.data.begin() + 6, 6, frame.ethermac[0].begin());
    std::copy_n (pkt.data.begin(), 6, frame.ethermac[1].begin());
    std::uint16_t ethertype =
      static_cast<std::uint16_t> ((pkt.data[12] << 8) | pkt.data[13]);
    if (ethertype == 0x8100) {
      // Original: datalink_check() reads the 802.1Q tag, keeps the VID
      // without the PCP and DEI bits, and looks at the encapsulated type.
      if (pkt.data.size() < 18) {
        return std::nullopt;
      }
      frame.vlanid =
        static_cast<std::uint16_t> (((pkt.data[14] << 8) | pkt.data[15]) & 0xFFF);
      frame.vlan_size = 4;
      ethertype =
        static_cast<std::uint16_t> ((pkt.data[16] << 8) | pkt.data[17]);
    }
    ip_bytes = ip_bytes.subspan (std::min (frame.vlan_size, ip_bytes.size()));
    if (ethertype == 0x0800) {
      frame.af = AddressFamily::IPv4;
      frame.ip_offset = frame.vlan_size;
      return frame;
    }
    if (ethertype == 0x86dd) {
      frame.af = AddressFamily::IPv6;
      frame.ip_offset = frame.vlan_size;
      return frame;
    }
    if (ethertype == 0x8847 || ethertype == 0x8848) {
      std::size_t consumed = 0;
      auto shim_entries = parse_mpls_label_stack (ip_bytes, consumed);
      if (!shim_entries.has_value() || consumed >= ip_bytes.size()) {
        return std::nullopt;
      }
      frame.mpls_labels.reserve (shim_entries->size());
      for (const auto &entry : *shim_entries) {
        frame.mpls_labels.push_back (entry.section);
      }
      frame.af = (ip_bytes[consumed] >> 4) == 6 ? AddressFamily::IPv6
                                                : AddressFamily::IPv4;
      frame.ip_offset = frame.vlan_size + consumed;
      return frame;
    }
    return std::nullopt;  // not an IP (or MPLS-encapsulated IP) frame
  }
  if (ip_bytes.empty()) {
    return std::nullopt;
  }
  const AddressFamily af =
    (ip_bytes[0] >> 4) == 6 ? AddressFamily::IPv6 : AddressFamily::IPv4;
  return FrameClassification{af, 0, {}, 0, 0, {}};
}

}  // namespace softflowd_cpp
