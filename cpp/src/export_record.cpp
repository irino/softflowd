// Original files: export_template.c (and compat/ipfix.c, compat/netflow9.c)
//
// The data records of NetFlow v9 and IPFIX and IpfixExporter::build_packets ().
// Renamed from export.cpp. The exporters of NetFlow v1 and v5 are in
// export_fixed.cpp, the templates of v9 and IPFIX in export_template.cpp, what
// the exporters share in export_common.cpp, and PSAMP, like the C version, has
// a file of its own.
#include "softflowd_cpp/export.hpp"
#include "softflowd_cpp/export_internal.hpp"
#include "softflowd_cpp/packet.hpp"

#include <algorithm>
#include <cstring>

namespace softflowd_cpp {

namespace {

/**
 * @brief Writes the start and the end time of a flow in the encoding that time_field_pair() describes.
 *
 * SysUpTime gives 32-bit milliseconds since boot_time, Seconds 32-bit epoch seconds and Milliseconds 64-bit epoch milliseconds. Microseconds and Nanoseconds both give 64-bit NTP timestamps that are made from epoch microseconds.
 *
 * @param writer The buffer to append to.
 * @param format The time format of -A.
 * @param boot_time The time when the exporter started, which SysUpTime counts from.
 * @param now The current time on Clock.
 * @param wall_now The wall-clock time that corresponds to @p now.
 * @param first The time of the first packet of the flow.
 * @param last The time of the last packet of the flow.
 */
void
write_time_values (ByteWriter &writer, IpfixTimeFormat format, TimePoint boot_time,
                   TimePoint now, std::chrono::system_clock::time_point wall_now,
                   TimePoint first, TimePoint last) {
  if (format == IpfixTimeFormat::SysUpTime) {
    writer.put_u32 (uptime_ms_unclamped (boot_time, first));
    writer.put_u32 (uptime_ms_unclamped (boot_time, last));
    return;
  }
  const std::uint64_t start_ms = epoch_ms (now, wall_now, first);
  const std::uint64_t end_ms = epoch_ms (now, wall_now, last);
  switch (format) {
    case IpfixTimeFormat::SysUpTime:
      break;  // handled above
    case IpfixTimeFormat::Seconds:
      writer.put_u32 (static_cast<std::uint32_t> (start_ms / 1000));
      writer.put_u32 (static_cast<std::uint32_t> (end_ms / 1000));
      break;
    case IpfixTimeFormat::Milliseconds:
      writer.put_u64 (start_ms);
      writer.put_u64 (end_ms);
      break;
    case IpfixTimeFormat::Microseconds:
    case IpfixTimeFormat::Nanoseconds:
      writer.put_u64 (unix_us_to_ntp64 (epoch_us (now, wall_now, first)));
      writer.put_u64 (unix_us_to_ntp64 (epoch_us (now, wall_now, last)));
      break;
  }
}

/**
 * @brief The VLAN IDs and the Ethernet addresses of a record, as seen from the sending and the receiving end.
 *
 * @original field_vlan and field_ether of the flow template. -T vlan adds the
 * VLAN IDs and -T ether adds the Ethernet addresses as well. The fields are
 * those of the flow endpoint that sends (vlanId and sourceMacAddress) and of
 * the one that receives (postVlanId and postDestinationMacAddress).
 */
struct L2Fields {
  std::uint16_t vlan;                        ///< The VLAN ID of the sending end (vlanId).
  std::uint16_t post_vlan;                   ///< The VLAN ID of the receiving end (postVlanId).
  std::array<std::uint8_t, 6> src_mac;       ///< The Ethernet address of the sending end (sourceMacAddress).
  std::array<std::uint8_t, 6> post_dst_mac;  ///< The Ethernet address of the receiving end (postDestinationMacAddress).
};

/**
 * @brief What follows the transport fields of a record: the VLAN and Ethernet fields of the track level, then the MPLS labels.
 *
 * What follows the transport fields of a record: the VLAN and Ethernet
 * fields of the tracking level, then the MPLS labels.
 */
struct TailFormat {
  std::uint8_t mpls_label_count;  ///< The number of mplsLabelStackSection fields (-x).
  TrackLevel track_level;         ///< The track level (-T), which decides whether the VLAN IDs and the Ethernet addresses are written.
  std::uint32_t if_index;         ///< The value of ingressInterface and egressInterface.
};

/**
 * @brief Writes the MPLS label stack of a flow as a fixed number of 3-octet fields.
 *
 * @param writer The buffer to append to.
 * @param labels The labels of the flow.
 * @param mpls_label_count The number of fields to write; the labels that the flow does not have are written as zero.
 *
 * @original -x. Writes mpls_label_count 3-octet mplsLabelStackSectionN
 * fields (IANA Information Elements 70-79). Values are passed straight
 * through from MplsLabelStack -- see its doc comment and
 * packet.cpp's MplsShimEntry for why that's already exactly the right
 * 24-bit (label|EXP|S) value, verbatim from the original packet, with no
 * reconstruction needed here. Indices beyond the flow's actual label
 * count (fewer real labels than mpls_label_count) are zero-filled,
 * matching the original's raw, zero-initialized flow-\>mplsLabels[]
 * entries beyond the real captured depth.
 */
void
write_mpls_labels (ByteWriter &writer, const MplsLabelStack &labels,
                   std::uint8_t mpls_label_count) {
  for (std::uint8_t i = 0; i < mpls_label_count; ++i) {
    const std::uint32_t section = (i < labels.size()) ? labels[i] : 0;
    writer.put_u8 (static_cast<std::uint8_t> (section >> 16));
    writer.put_u8 (static_cast<std::uint8_t> (section >> 8));
    writer.put_u8 (static_cast<std::uint8_t> (section));
  }
}

/**
 * @brief Writes the VLAN IDs and the Ethernet addresses of the track level, and then the MPLS labels.
 *
 * @param writer The buffer to append to.
 * @param r The record, which has l2 and mpls_labels.
 * @param tail The track level, the number of MPLS labels and the interface index.
 * @tparam Record IpfixDirectionalRecord or BiflowRecord.
 */
template <typename Record>
void
write_tail (ByteWriter &writer, const Record &r, const TailFormat &tail) {
  if (tail.track_level >= TrackLevel::FullVlan) {
    writer.put_u16 (r.l2.vlan);
    writer.put_u16 (r.l2.post_vlan);
  }
  if (tail.track_level >= TrackLevel::FullVlanEther) {
    for (const std::uint8_t b : r.l2.src_mac) {
      writer.put_u8 (b);
    }
    for (const std::uint8_t b : r.l2.post_dst_mac) {
      writer.put_u8 (b);
    }
  }
  write_mpls_labels (writer, *r.mpls_labels, tail.mpls_label_count);
}

// ---- Unidirectional (default, -b not given) record shape ----

/**
 * @brief Tells whether a protocol number is that of ICMP or of ICMPv6.
 *
 * @param protocol The IP protocol number.
 * @return true for 1 and 58.
 */
bool
is_icmp_protocol (std::uint8_t protocol) {
  constexpr std::uint8_t kProtoIcmp = 1;
  constexpr std::uint8_t kProtoIcmpV6 = 58;
  return protocol == kProtoIcmp || protocol == kProtoIcmpV6;
}

/**
 * @brief One direction of a flow, as a record of the unidirectional (no -b) template takes it.
 *
 * The addresses and the MPLS labels point into the exported flow, which has to outlive the record.
 */
struct IpfixDirectionalRecord {
  const IpAddress *src;               ///< The address of the end that sent the packets.
  const IpAddress *dst;               ///< The address of the end that received the packets.
  std::uint16_t src_port;             ///< The port of the sending end; for ICMP, the ICMP type and code are in the port of the receiving end.
  std::uint16_t dst_port;             ///< The port of the receiving end.
  std::uint64_t octets;               ///< The octets sent in this direction.
  std::uint64_t packets;              ///< The packets sent in this direction.
  TimePoint first;                    ///< The time of the first packet of the flow.
  TimePoint last;                     ///< The time of the last packet of the flow.
  std::uint8_t protocol;              ///< The IP protocol number.
  std::uint8_t tos;                   ///< The type of service seen from the sending end.
  std::uint8_t tcp_flags;             ///< The TCP flags seen from the sending end.
  std::uint8_t flow_end_reason;       ///< The flowEndReason of the flow.
  std::uint8_t direction;             ///< The flowDirection; as ipfix_flow_direction() of the C version, it is the index (0 or 1) of the end when no -H direction MAC is given.
  const MplsLabelStack *mpls_labels;  ///< The MPLS labels of the flow.
  L2Fields l2;                        ///< The VLAN IDs and the Ethernet addresses, from the sending end.
  bool first_in_flow;                 ///< true for the first record that is made from a flow; see pack_interleaved().
};

/**
 * @brief Makes the VLAN and Ethernet fields of one end of a flow.
 *
 * @param key The key of the flow.
 * @param flow The flow; it is not used.
 * @param i The index (0 or 1) of the sending end.
 * @return The fields, with the end i as the sending end and the other end as the receiving end.
 */
L2Fields
l2_fields (const FlowKey &key, const Flow &flow, std::size_t i) {
  (void) flow;
  return L2Fields{key.vlanid()[i], key.vlanid()[i ^ 1], key.ethermac()[i],
                  key.ethermac()[i ^ 1]};
}

/**
 * @brief Decides the flowDirection of one end of a flow.
 *
 * @param key The key of the flow.
 * @param i The index (0 or 1) of the end.
 * @param mac The direction MAC address of -H, if there is one.
 * @return 1 (egress) or 0 (ingress) when the direction MAC address is the Ethernet address of the end or of the other end, and otherwise the index i.
 *
 * @original ipfix_flow_direction(). With a direction MAC the flowDirection
 * is egress (1) when the source MAC of endpoint i is the direction MAC and
 * ingress (0) when its destination MAC is; otherwise it is the endpoint
 * index i.
 */
std::uint8_t
flow_direction (const FlowKey &key, std::size_t i,
                const std::optional<std::array<std::uint8_t, 6>> &mac) {
  if (mac.has_value()) {
    if (key.ethermac()[i] == *mac) {
      return 1;
    }
    if (key.ethermac()[i ^ 1] == *mac) {
      return 0;
    }
  }
  return static_cast<std::uint8_t> (i);
}

/**
 * @brief Turns flows into a list of unidirectional records: one record for each direction that carried octets, with the two directions of a flow next to each other.
 *
 * @param records The flows, in the order of their expiry.
 * @param out The list to append to.
 * @param direction_mac The direction MAC address of -H, if there is one.
 *
 * @original ipfix_flow_to_template_index()/valuate_icmp() route ICMP and
 * ICMPv6 flows to their own template (icmpTypeCode instead of a
 * source/destination port pair). Unlike an earlier version of this file,
 * records are kept in ONE list, in original per-flow order (both
 * directions of a given flow adjacent, flows in expiry order) --
 * matching send_ipfix_flows()'s single interleaved pass over `flows[]`,
 * where Sets are opened/closed based on whichever (address family,
 * ICMP-ness) each flow's *next* record happens to have, not grouped
 * ahead of time. Pre-grouping by family/ICMP-ness (as an earlier version
 * of this function did) changes packet boundaries and Set ordering
 * whenever a capture mixes address families or ICMP/non-ICMP flows.
 */
void
flatten (std::span<const ExportRecord> records,
         std::vector<IpfixDirectionalRecord> &out,
         const std::optional<std::array<std::uint8_t, 6>> &direction_mac) {
  for (const auto &record : records) {
    const auto &key = record.key;
    const auto &flow = record.flow;
    bool first_in_flow = true;
    for (int dir = 0; dir < 2; ++dir) {
      const auto d = static_cast<std::size_t> (dir);
      // Original: ipfix_flow_to_flowset() skips a direction without
      // octets.
      if (flow.octets[d] == 0) {
        continue;
      }
      out.push_back (IpfixDirectionalRecord{
        &key.addr()[d],
        &key.addr()[static_cast<std::size_t> (dir ^ 1)],
        key.port()[d],
        key.port()[static_cast<std::size_t> (dir ^ 1)],
        flow.octets[d],
        flow.packets[d],
        flow.flow_start,
        flow.flow_last,
        key.protocol(),
        flow.tos[d],
        flow.tcp_flags[d],
        flow.flow_end_reason,
        flow_direction (key, d, direction_mac),
        &flow.mpls_labels,
        l2_fields (key, flow, d),
        std::exchange (first_in_flow, false),
      });
    }
  }
}

/**
 * @brief Writes the fields that every unidirectional record has after the addresses and the times: octetDeltaCount, packetDeltaCount, ingressInterface, egressInterface, flowDirection and flowEndReason.
 *
 * The octet and packet counts are limited to 32 bits.
 *
 * @param writer The buffer to append to.
 * @param r The record.
 * @param if_index The interface index.
 *
 * @original field_common -- octetDeltaCount, packetDeltaCount,
 * ingressInterface, egressInterface, flowDirection, flowEndReason. Written
 * identically regardless of address family or ICMP-ness, between the
 * address fields/timestamps and the transport-or-ICMP fields.
 *
 * ingressInterface/egressInterface are the index of -i idx:interface (0 when
 * there is none, as for a capture file).
 */
void
write_common_fields (ByteWriter &writer, const IpfixDirectionalRecord &r,
                     std::uint32_t if_index) {
  writer.put_u32 (static_cast<std::uint32_t> (
    std::min<std::uint64_t> (r.octets, 0xFFFFFFFFu)));  // octetDeltaCount
  writer.put_u32 (static_cast<std::uint32_t> (
    std::min<std::uint64_t> (r.packets, 0xFFFFFFFFu)));  // packetDeltaCount
  writer.put_u32 (if_index);                             // ingressInterface
  writer.put_u32 (if_index);                             // egressInterface
  writer.put_u8 (r.direction);                           // flowDirection
  writer.put_u8 (r.flow_end_reason);                     // flowEndReason
}

/**
 * @brief Writes a unidirectional record of an IPv4 flow: the addresses, the times, the common fields, the ports, the protocol, the TCP flags, the IP version, the ToS and the tail.
 *
 * @param writer The buffer to append to.
 * @param r The record.
 * @param time_format The format of the start and end times (-A).
 * @param tail The VLAN, Ethernet and MPLS fields that follow the transport fields.
 * @param boot_time The time when the exporter started, which SysUpTime counts from.
 * @param now The current time on Clock.
 * @param wall_now The wall-clock time that corresponds to @p now.
 */
void
write_v4_record (ByteWriter &writer, const IpfixDirectionalRecord &r,
                 IpfixTimeFormat time_format, const TailFormat &tail, TimePoint boot_time,
                 TimePoint now, std::chrono::system_clock::time_point wall_now) {
  writer.put_ipv4 (*r.src);  // sourceIPv4Address
  writer.put_ipv4 (*r.dst);  // destinationIPv4Address
  write_time_values (writer, time_format, boot_time, now, wall_now, r.first, r.last);
  write_common_fields (writer, r, tail.if_index);
  writer.put_u16 (r.src_port);  // sourceTransportPort
  writer.put_u16 (r.dst_port);  // destinationTransportPort
  writer.put_u8 (r.protocol);   // protocolIdentifier
  writer.put_u8 (r.tcp_flags);  // tcpControlBits
  writer.put_u8 (4);            // ipVersion
  writer.put_u8 (r.tos);        // ipClassOfService
  write_tail (writer, r, tail);
}

/**
 * @brief Writes a unidirectional record of an IPv6 flow, in the order of write_v4_record() and with the IP version 6.
 *
 * @param writer The buffer to append to.
 * @param r The record.
 * @param time_format The format of the start and end times (-A).
 * @param tail The VLAN, Ethernet and MPLS fields that follow the transport fields.
 * @param boot_time The time when the exporter started, which SysUpTime counts from.
 * @param now The current time on Clock.
 * @param wall_now The wall-clock time that corresponds to @p now.
 */
void
write_v6_record (ByteWriter &writer, const IpfixDirectionalRecord &r,
                 IpfixTimeFormat time_format, const TailFormat &tail, TimePoint boot_time,
                 TimePoint now, std::chrono::system_clock::time_point wall_now) {
  writer.put_ipv6 (*r.src);
  writer.put_ipv6 (*r.dst);
  write_time_values (writer, time_format, boot_time, now, wall_now, r.first, r.last);
  write_common_fields (writer, r, tail.if_index);
  writer.put_u16 (r.src_port);
  writer.put_u16 (r.dst_port);
  writer.put_u8 (r.protocol);
  writer.put_u8 (r.tcp_flags);
  writer.put_u8 (6);  // ipVersion
  writer.put_u8 (r.tos);
  write_tail (writer, r, tail);
}

/**
 * @brief Writes a unidirectional record of an ICMP flow: the addresses, the times, the common fields, icmpTypeCode, the protocol, the IP version 4, the ToS and the tail.
 *
 * @param writer The buffer to append to.
 * @param r The record.
 * @param time_format The format of the start and end times (-A).
 * @param tail The VLAN, Ethernet and MPLS fields that follow the transport fields.
 * @param boot_time The time when the exporter started, which SysUpTime counts from.
 * @param now The current time on Clock.
 * @param wall_now The wall-clock time that corresponds to @p now.
 *
 * @original field_icmp4/field_icmp6 -- icmpTypeCode replaces the
 * source/destination port pair and there is no tcpControlBits field.
 * dst_port already carries (icmp_type \<\< 8 | icmp_code) -- see
 * PacketParser's ICMP handling in packet.cpp -- matching the original's
 * `di[i]-\>icmpTypeCode = flow-\>port[i ^ 1]`.
 */
void
write_v4_icmp_record (ByteWriter &writer, const IpfixDirectionalRecord &r,
                      IpfixTimeFormat time_format, const TailFormat &tail, TimePoint boot_time,
                      TimePoint now, std::chrono::system_clock::time_point wall_now) {
  writer.put_ipv4 (*r.src);
  writer.put_ipv4 (*r.dst);
  write_time_values (writer, time_format, boot_time, now, wall_now, r.first, r.last);
  write_common_fields (writer, r, tail.if_index);
  writer.put_u16 (r.dst_port);  // icmpTypeCode
  writer.put_u8 (r.protocol);   // protocolIdentifier
  writer.put_u8 (4);            // ipVersion
  writer.put_u8 (r.tos);        // ipClassOfService
  write_tail (writer, r, tail);
}

/**
 * @brief Writes a unidirectional record of an ICMPv6 flow, in the order of write_v4_icmp_record() and with the IP version 6.
 *
 * @param writer The buffer to append to.
 * @param r The record.
 * @param time_format The format of the start and end times (-A).
 * @param tail The VLAN, Ethernet and MPLS fields that follow the transport fields.
 * @param boot_time The time when the exporter started, which SysUpTime counts from.
 * @param now The current time on Clock.
 * @param wall_now The wall-clock time that corresponds to @p now.
 */
void
write_v6_icmp_record (ByteWriter &writer, const IpfixDirectionalRecord &r,
                      IpfixTimeFormat time_format, const TailFormat &tail, TimePoint boot_time,
                      TimePoint now, std::chrono::system_clock::time_point wall_now) {
  writer.put_ipv6 (*r.src);
  writer.put_ipv6 (*r.dst);
  write_time_values (writer, time_format, boot_time, now, wall_now, r.first, r.last);
  write_common_fields (writer, r, tail.if_index);
  writer.put_u16 (r.dst_port);
  writer.put_u8 (r.protocol);
  writer.put_u8 (6);
  writer.put_u8 (r.tos);
  write_tail (writer, r, tail);
}

// ---- Biflow (-b) record shape: one record per flow, not per direction ----

/**
 * @brief A whole flow, with both directions, as a record of the biflow (-b) template takes it.
 *
 * The addresses and the MPLS labels point into the exported flow, which has to outlive the record.
 */
struct BiflowRecord {
  const IpAddress *src;               ///< The address of the first end of the key (addr()[0]), the forward direction.
  const IpAddress *dst;               ///< The address of the second end of the key.
  std::uint16_t src_port;             ///< The port of the first end.
  std::uint16_t dst_port;             ///< The port of the second end.
  std::uint8_t protocol;              ///< The IP protocol number.
  std::uint8_t tos;                   ///< The ToS of the forward direction (flow.tos[0]).
  std::uint8_t rev_tos;               ///< The ToS of the reverse direction (flow.tos[1]).
  std::uint8_t flow_end_reason;       ///< The flowEndReason of the flow.
  std::uint8_t direction;             ///< The flowDirection of the forward end.
  std::uint64_t fwd_octets;           ///< The octets from the first end to the second.
  std::uint64_t fwd_packets;          ///< The packets from the first end to the second.
  std::uint8_t fwd_tcp_flags;         ///< The TCP flags seen from the first end.
  std::uint64_t rev_octets;           ///< The octets from the second end to the first.
  std::uint64_t rev_packets;          ///< The packets from the second end to the first.
  std::uint8_t rev_tcp_flags;         ///< The TCP flags seen from the second end.
  TimePoint first;                    ///< The time of the first packet of the flow.
  TimePoint last;                     ///< The time of the last packet of the flow.
  const MplsLabelStack *mpls_labels;  ///< The MPLS labels of the flow.
  L2Fields l2;                        ///< The VLAN IDs and the Ethernet addresses, from the first end.
};

/**
 * @brief Turns flows into a list of biflow records: one record for each flow that has packets in either direction.
 *
 * @param records The flows, in the order of their expiry.
 * @param out The list to append to.
 * @param direction_mac The direction MAC address of -H, if there is one.
 */
void
flatten_biflow (std::span<const ExportRecord> records,
                std::vector<BiflowRecord> &out,
                const std::optional<std::array<std::uint8_t, 6>> &direction_mac) {
  for (const auto &record : records) {
    const auto &key = record.key;
    const auto &flow = record.flow;
    if (flow.packets[0] == 0 && flow.packets[1] == 0) {
      continue;  // no traffic in either direction; nothing to report
    }
    out.push_back (BiflowRecord{
      &key.addr()[0],
      &key.addr()[1],
      key.port()[0],
      key.port()[1],
      key.protocol(),
      flow.tos[0],
      flow.tos[1],
      flow.flow_end_reason,
      flow_direction (key, 0, direction_mac),
      flow.octets[0],
      flow.packets[0],
      flow.tcp_flags[0],
      flow.octets[1],
      flow.packets[1],
      flow.tcp_flags[1],
      flow.flow_start,
      flow.flow_last,
      &flow.mpls_labels,
      l2_fields (key, flow, 0),
    });
  }
}

/**
 * @brief Writes the reverse fields that end a biflow record: the octets, the packets and the ToS of the reverse direction, and then the reverse icmpTypeCode for ICMP or else the reverse TCP flags.
 *
 * The octet and packet counts are limited to 32 bits.
 *
 * @param writer The buffer to append to.
 * @param r The record.
 * @param is_icmp true for an ICMP or ICMPv6 flow.
 *
 * @original ipfix_flow_to_flowset()'s bi_flag branch writes ONE record per
 * flow (frecnum=1, always i=0 -- "forward" is always FlowKey's canonical
 * addr()[0]/port()[0]) with the SAME field layout/order as the
 * unidirectional case (address, time, common(18), transport-or-icmp) --
 * see write_v4_record()/write_v4_icmp_record() -- followed by a
 * Reverse-Information-Element tail: reverse octetDeltaCount(4),
 * packetDeltaCount(4), ipClassOfService(1) [field_bicommon], then EITHER
 * reverse tcpControlBits(1) [field_bitransport] OR reverse icmpTypeCode(2)
 * [field_biicmp4/6] depending on protocol -- never both. flowDirection is
 * always 0 here (ipfix_flow_direction()'s fallback for i=0, the only
 * index this loop ever uses).
 *
 * The reverse part is encoded for the reverse direction (i=1), so the
 * reverse icmpTypeCode is `flow-\>port[i ^ 1]` == port[0] in the original,
 * not the port[1] of the forward icmpTypeCode.
 */
void
write_biflow_common_tail (ByteWriter &writer, const BiflowRecord &r, bool is_icmp) {
  writer.put_u32 (static_cast<std::uint32_t> (
    std::min<std::uint64_t> (r.rev_octets, 0xFFFFFFFFu)));  // reverse octetDeltaCount
  writer.put_u32 (static_cast<std::uint32_t> (
    std::min<std::uint64_t> (r.rev_packets, 0xFFFFFFFFu)));  // reverse packetDeltaCount
  writer.put_u8 (r.rev_tos);                                 // reverse ipClassOfService
  if (is_icmp) {
    writer.put_u16 (r.src_port);  // reverse icmpTypeCode == flow->port[0] == src_port
  } else {
    writer.put_u8 (r.rev_tcp_flags);  // reverse tcpControlBits
  }
}

/**
 * @brief Writes a biflow record of an IPv4 flow: the forward fields in the order of write_v4_record(), the tail and the reverse fields.
 *
 * @param writer The buffer to append to.
 * @param r The record.
 * @param time_format The format of the start and end times (-A).
 * @param tail The VLAN, Ethernet and MPLS fields that follow the transport fields.
 * @param boot_time The time when the exporter started, which SysUpTime counts from.
 * @param now The current time on Clock.
 * @param wall_now The wall-clock time that corresponds to @p now.
 */
void
write_biflow_v4_record (ByteWriter &writer, const BiflowRecord &r,
                        IpfixTimeFormat time_format,
                        const TailFormat &tail, TimePoint boot_time, TimePoint now,
                        std::chrono::system_clock::time_point wall_now) {
  writer.put_ipv4 (*r.src);
  writer.put_ipv4 (*r.dst);
  write_time_values (writer, time_format, boot_time, now, wall_now, r.first, r.last);
  writer.put_u32 (static_cast<std::uint32_t> (
    std::min<std::uint64_t> (r.fwd_octets, 0xFFFFFFFFu)));
  writer.put_u32 (static_cast<std::uint32_t> (
    std::min<std::uint64_t> (r.fwd_packets, 0xFFFFFFFFu)));
  writer.put_u32 (tail.if_index);  // ingressInterface
  writer.put_u32 (tail.if_index);  // egressInterface
  writer.put_u8 (r.direction);     // flowDirection of endpoint 0; see doc comment above
  writer.put_u8 (r.flow_end_reason);
  writer.put_u16 (r.src_port);
  writer.put_u16 (r.dst_port);
  writer.put_u8 (r.protocol);
  writer.put_u8 (r.fwd_tcp_flags);
  writer.put_u8 (4);  // ipVersion
  writer.put_u8 (r.tos);
  write_tail (writer, r, tail);
  write_biflow_common_tail (writer, r, /*is_icmp=*/false);
}

/**
 * @brief Writes a biflow record of an ICMP flow: the forward fields in the order of write_v4_icmp_record(), the tail and the reverse fields.
 *
 * @param writer The buffer to append to.
 * @param r The record.
 * @param time_format The format of the start and end times (-A).
 * @param tail The VLAN, Ethernet and MPLS fields that follow the transport fields.
 * @param boot_time The time when the exporter started, which SysUpTime counts from.
 * @param now The current time on Clock.
 * @param wall_now The wall-clock time that corresponds to @p now.
 */
void
write_biflow_v4_icmp_record (ByteWriter &writer, const BiflowRecord &r,
                             IpfixTimeFormat time_format,
                             const TailFormat &tail, TimePoint boot_time,
                             TimePoint now,
                             std::chrono::system_clock::time_point wall_now) {
  writer.put_ipv4 (*r.src);
  writer.put_ipv4 (*r.dst);
  write_time_values (writer, time_format, boot_time, now, wall_now, r.first, r.last);
  writer.put_u32 (static_cast<std::uint32_t> (
    std::min<std::uint64_t> (r.fwd_octets, 0xFFFFFFFFu)));
  writer.put_u32 (static_cast<std::uint32_t> (
    std::min<std::uint64_t> (r.fwd_packets, 0xFFFFFFFFu)));
  writer.put_u32 (tail.if_index);  // ingressInterface
  writer.put_u32 (tail.if_index);  // egressInterface
  writer.put_u8 (r.direction);     // flowDirection
  writer.put_u8 (r.flow_end_reason);
  writer.put_u16 (r.dst_port);  // forward icmpTypeCode == flow->port[i^1] == port[1] == dst_port
  writer.put_u8 (r.protocol);
  writer.put_u8 (4);
  writer.put_u8 (r.tos);
  write_tail (writer, r, tail);
  write_biflow_common_tail (writer, r, /*is_icmp=*/true);
}

/**
 * @brief Writes a biflow record of an IPv6 flow: the forward fields in the order of write_v6_record(), the tail and the reverse fields.
 *
 * @param writer The buffer to append to.
 * @param r The record.
 * @param time_format The format of the start and end times (-A).
 * @param tail The VLAN, Ethernet and MPLS fields that follow the transport fields.
 * @param boot_time The time when the exporter started, which SysUpTime counts from.
 * @param now The current time on Clock.
 * @param wall_now The wall-clock time that corresponds to @p now.
 */
void
write_biflow_v6_record (ByteWriter &writer, const BiflowRecord &r,
                        IpfixTimeFormat time_format,
                        const TailFormat &tail, TimePoint boot_time, TimePoint now,
                        std::chrono::system_clock::time_point wall_now) {
  writer.put_ipv6 (*r.src);
  writer.put_ipv6 (*r.dst);
  write_time_values (writer, time_format, boot_time, now, wall_now, r.first, r.last);
  writer.put_u32 (static_cast<std::uint32_t> (
    std::min<std::uint64_t> (r.fwd_octets, 0xFFFFFFFFu)));
  writer.put_u32 (static_cast<std::uint32_t> (
    std::min<std::uint64_t> (r.fwd_packets, 0xFFFFFFFFu)));
  writer.put_u32 (tail.if_index);  // ingressInterface
  writer.put_u32 (tail.if_index);  // egressInterface
  writer.put_u8 (r.direction);     // flowDirection
  writer.put_u8 (r.flow_end_reason);
  writer.put_u16 (r.src_port);
  writer.put_u16 (r.dst_port);
  writer.put_u8 (r.protocol);
  writer.put_u8 (r.fwd_tcp_flags);
  writer.put_u8 (6);
  writer.put_u8 (r.tos);
  write_tail (writer, r, tail);
  write_biflow_common_tail (writer, r, /*is_icmp=*/false);
}

/**
 * @brief Writes a biflow record of an ICMPv6 flow: the forward fields in the order of write_v6_icmp_record(), the tail and the reverse fields.
 *
 * @param writer The buffer to append to.
 * @param r The record.
 * @param time_format The format of the start and end times (-A).
 * @param tail The VLAN, Ethernet and MPLS fields that follow the transport fields.
 * @param boot_time The time when the exporter started, which SysUpTime counts from.
 * @param now The current time on Clock.
 * @param wall_now The wall-clock time that corresponds to @p now.
 */
void
write_biflow_v6_icmp_record (ByteWriter &writer, const BiflowRecord &r,
                             IpfixTimeFormat time_format,
                             const TailFormat &tail, TimePoint boot_time,
                             TimePoint now,
                             std::chrono::system_clock::time_point wall_now) {
  writer.put_ipv6 (*r.src);
  writer.put_ipv6 (*r.dst);
  write_time_values (writer, time_format, boot_time, now, wall_now, r.first, r.last);
  writer.put_u32 (static_cast<std::uint32_t> (
    std::min<std::uint64_t> (r.fwd_octets, 0xFFFFFFFFu)));
  writer.put_u32 (static_cast<std::uint32_t> (
    std::min<std::uint64_t> (r.fwd_packets, 0xFFFFFFFFu)));
  writer.put_u32 (tail.if_index);  // ingressInterface
  writer.put_u32 (tail.if_index);  // egressInterface
  writer.put_u8 (r.direction);     // flowDirection
  writer.put_u8 (r.flow_end_reason);
  writer.put_u16 (r.dst_port);
  writer.put_u8 (r.protocol);
  writer.put_u8 (6);
  writer.put_u8 (r.tos);
  write_tail (writer, r, tail);
  write_biflow_common_tail (writer, r, /*is_icmp=*/true);
}

}  // namespace

std::vector<std::vector<std::uint8_t>>
IpfixExporter::build_packets (
  std::span<const ExportRecord> records, TimePoint now,
  std::chrono::system_clock::time_point wall_now,
  std::vector<std::size_t> *template_only_packets) {
  std::vector<std::vector<std::uint8_t>> packets;
  const TailFormat tail_{mpls_label_count_, track_level_, if_index_};

  // The record-count bookkeeping (data_records_in_packet, used only for
  // RFC 7011's "Sequence Number counts Data Records" rule) and the
  // packet/Set assembly loop are identical in shape between biflow and
  // non-biflow modes; only which per-record write function is called
  // and how the two per-family lists are populated differ.
  // Original: ipfix_flow_to_template_index() -- routes ICMP/ICMPv6 flows
  // to the dedicated ICMP template ID, everything else to the ordinary
  // one. Shared by both the non-biflow and biflow packing passes below
  // since both use the same four template IDs.
  const auto template_id_for = [&] (bool is_v6, bool is_icmp) -> std::uint16_t {
    if (!is_v6)
      return is_icmp ? kIpfixTemplateIdIcmpV4 : kIpfixTemplateIdV4;
    return is_icmp ? kIpfixTemplateIdIcmpV6 : kIpfixTemplateIdV6;
  };

  // Original: send_ipfix_flows()'s single interleaved pass over
  // `flows[]`, opening a new Set only when the (address family,
  // ICMP-ness) of the next record differs from the currently-open Set
  // (or none is open yet), and budgeting packet space by byte count
  // against kIpfixMaxPacketSize rather than a fixed records-per-Set
  // limit. Shared between the non-biflow and biflow paths -- the
  // original's own packing loop is likewise the same code for both,
  // parameterized only by bi_flag's effect on frecnum/record layout.
  const auto pack_interleaved = [&] (auto &all, auto is_v6_of, auto is_icmp_of,
                                     auto record_size_of, auto reserve_of,
                                     auto write_dispatch) {
    std::size_t idx = 0;
    while (idx < all.size()) {
      ByteWriter body;
      std::uint32_t data_records_in_packet = 0;
      // The packet buffer of the original holds the header too.
      const std::size_t header_len = header_size();

      const bool send_template = (packets_since_template_ == 0);
      if (send_template) {
        write_template_set (body);
        write_options_set (body);
        if (template_only_packets != nullptr) {
          // The count of NetFlow v9 is 1 and its sequence number counts
          // packets; the sequence number of IPFIX is that of the next data
          // record, as in the original.
          ByteWriter packet;
          write_header (packet,
                        version_ == MessageVersion::Ipfix
                          ? static_cast<std::uint16_t> (header_len + body.size())
                          : std::uint16_t{1},
                        now, wall_now);
          if (version_ == MessageVersion::NetFlow9) {
            ++v9_sequence_;
          }
          packet.put_bytes (body.bytes());
          template_only_packets->push_back (packets.size());
          packets.push_back (packet.take());
          body = ByteWriter{};
        }
      }

      std::size_t set_header_pos = 0;
      bool set_open = false;
      bool last_is_v6 = false, last_is_icmp = false;
      std::size_t last_valid = 0;  // rollback point; see ByteWriter::truncate()'s doc

      while (idx < all.size()) {
        const auto &r = all[idx];
        const bool is_v6 = is_v6_of (r);
        const bool is_icmp = is_icmp_of (r);
        const std::size_t rec_size = record_size_of (is_v6, is_icmp);

        if (!set_open || is_v6 != last_is_v6 || is_icmp != last_is_icmp) {
          if (set_open) {
            finish_set (body, set_header_pos, header_len);  // pads to 4 bytes; see finish_set()
          }
          if (header_len + body.size() + 4 > kIpfixMaxPacketSize) {
            set_open = false;
            break;  // this packet is full; resume at `idx` next packet
          }
          set_header_pos = body.size();
          last_valid = body.size();
          body.put_u16 (template_id_for (is_v6, is_icmp));
          body.put_u16 (0);  // length placeholder, patched by finish_set()
          set_open = true;
          last_is_v6 = is_v6;
          last_is_icmp = is_icmp;
        }

        // Original: ipfix_flow_to_flowset() needs room for both
        // directions of a flow (one record for a biflow), even when
        // only one of them is sent. The second record of a flow
        // needs no check because that room is already reserved.
        const std::size_t reserve = reserve_of (r);
        if (reserve != 0 &&
            header_len + body.size() + rec_size * reserve >
              kIpfixMaxPacketSize) {
          // Doesn't fit. Roll back to the last point after which
          // nothing more was successfully written: if that's
          // the Set header itself (no record has fit in this
          // Set yet), the rollback erases the header entirely
          // (matches the original's `last_valid` rollback) and
          // there is nothing left to finalize; if at least one
          // record did fit, the rollback is a no-op (nothing
          // past last_valid to discard) and the Set -- with
          // just those already-written records -- still needs
          // finish_set() below. Either way, this record is
          // retried as the first one in the next packet.
          body.truncate (last_valid);
          set_open = (last_valid > set_header_pos);
          break;
        }
        write_dispatch (body, r, is_v6, is_icmp);
        data_records_in_packet += 1;
        last_valid = body.size();  // this Set now has >=1 record; no more rollback
        ++idx;
      }
      if (set_open) {
        finish_set (body, set_header_pos, header_len);
      }

      // Original: `*records_sent += records;` happens BEFORE
      // `ipfix->sequence = htonl(*records_sent ...)` -- the header's
      // Sequence Number for a packet is the cumulative Data Record
      // count INCLUDING this packet's own records, not the count
      // from before it.
      sequence_ += data_records_in_packet;
      ByteWriter packet;
      const auto length_or_count = static_cast<std::uint16_t> (
        version_ == MessageVersion::Ipfix
          ? header_len + body.size()
          : data_records_in_packet);
      write_header (packet, length_or_count, now, wall_now);
      if (version_ == MessageVersion::NetFlow9) {
        ++v9_sequence_;
      }
      packet.put_bytes (body.bytes());
      packets.push_back (packet.take());

      packets_since_template_ = send_template ? 1 : packets_since_template_ + 1;
      if (packets_since_template_ >= kIpfixTemplateResendInterval) {
        packets_since_template_ = 0;
      }
    }
  };

  if (!biflow_) {
    std::vector<IpfixDirectionalRecord> all;
    flatten (records, all, direction_mac_);

    const std::size_t sizes[2][2] = {
      // [is_v6][is_icmp]
      {record_size (false, false, time_format_, mpls_label_count_, track_level_),
       record_size (false, true, time_format_, mpls_label_count_, track_level_)},
      {record_size (true, false, time_format_, mpls_label_count_, track_level_),
       record_size (true, true, time_format_, mpls_label_count_, track_level_)},
    };
    pack_interleaved (
      all,
      [] (const IpfixDirectionalRecord &r) { return r.src->family == AddressFamily::IPv6; },
      [] (const IpfixDirectionalRecord &r) { return is_icmp_protocol (r.protocol); },
      [&] (bool is_v6, bool is_icmp) { return sizes[is_v6 ? 1 : 0][is_icmp ? 1 : 0]; },
      [] (const IpfixDirectionalRecord &r) -> std::size_t { return r.first_in_flow ? 2 : 0; },
      [&] (ByteWriter &w, const IpfixDirectionalRecord &r, bool is_v6, bool is_icmp) {
        if (!is_v6 && !is_icmp) {
          write_v4_record (w, r, time_format_, tail_, boot_time_, now,
                           wall_now);
        } else if (!is_v6 && is_icmp) {
          write_v4_icmp_record (w, r, time_format_, tail_, boot_time_, now,
                                wall_now);
        } else if (is_v6 && !is_icmp) {
          write_v6_record (w, r, time_format_, tail_, boot_time_, now,
                           wall_now);
        } else {
          write_v6_icmp_record (w, r, time_format_, tail_, boot_time_, now,
                                wall_now);
        }
      });
  } else {
    std::vector<BiflowRecord> all;
    flatten_biflow (records, all, direction_mac_);

    // Original: field_bicommon (9 bytes: reverse octets/packets/tos)
    // plus either field_bitransport (1 byte: reverse tcpControlBits)
    // or field_biicmp4/6 (2 bytes: reverse icmpTypeCode) tacked onto
    // the ordinary per-family/ICMP-ness record size -- see
    // write_biflow_common_tail().
    const std::size_t bi_sizes[2][2] = {
      {record_size (false, false, time_format_, mpls_label_count_, track_level_) + 9 + 1,
       record_size (false, true, time_format_, mpls_label_count_, track_level_) + 9 + 2},
      {record_size (true, false, time_format_, mpls_label_count_, track_level_) + 9 + 1,
       record_size (true, true, time_format_, mpls_label_count_, track_level_) + 9 + 2},
    };
    pack_interleaved (
      all,
      [] (const BiflowRecord &r) { return r.src->family == AddressFamily::IPv6; },
      [] (const BiflowRecord &r) { return is_icmp_protocol (r.protocol); },
      [&] (bool is_v6, bool is_icmp) { return bi_sizes[is_v6 ? 1 : 0][is_icmp ? 1 : 0]; },
      [] (const BiflowRecord &) -> std::size_t { return 1; },
      [&] (ByteWriter &w, const BiflowRecord &r, bool is_v6, bool is_icmp) {
        if (!is_v6 && !is_icmp) {
          write_biflow_v4_record (w, r, time_format_, tail_, boot_time_,
                                  now, wall_now);
        } else if (!is_v6 && is_icmp) {
          write_biflow_v4_icmp_record (w, r, time_format_, tail_,
                                       boot_time_, now, wall_now);
        } else if (is_v6 && !is_icmp) {
          write_biflow_v6_record (w, r, time_format_, tail_, boot_time_,
                                  now, wall_now);
        } else {
          write_biflow_v6_icmp_record (w, r, time_format_, tail_,
                                       boot_time_, now, wall_now);
        }
      });
  }

  return packets;
}

}  // namespace softflowd_cpp
