// Original files: export.c (and compat/ipfix.c)
//
// The exporters of NetFlow v1, v5, v9 and IPFIX. What they share is in
// export_common.cpp, and PSAMP, like the C version, has a file of its own.
#include "softflow/export.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <unistd.h>  // getpid() -- see write_options_set()
#include <utility>

namespace softflow {

// ---------------------------------------------------------------------------
// NetFlow v1
// ---------------------------------------------------------------------------

void
Netflow1Exporter::write_header (
  ByteWriter &writer, std::uint16_t count, TimePoint now,
  std::chrono::system_clock::time_point wall_now) const {
  const auto unix_time = std::chrono::system_clock::to_time_t (wall_now);
  const auto since_epoch = wall_now.time_since_epoch();
  const auto nsecs = std::chrono::duration_cast<std::chrono::nanoseconds> (
                       since_epoch % std::chrono::seconds (1))
                       .count();

  writer.put_u16 (1);  // version
  writer.put_u16 (count);
  writer.put_u32 (uptime_ms (boot_time_, now));
  writer.put_u32 (static_cast<std::uint32_t> (unix_time));
  writer.put_u32 (static_cast<std::uint32_t> (nsecs < 0 ? nsecs + 1'000'000'000
                                                        : nsecs));
}

std::vector<std::vector<std::uint8_t>>
Netflow1Exporter::build_packets (
  std::span<const ExportRecord> records, TimePoint now,
  std::chrono::system_clock::time_point wall_now) const {
  std::vector<std::vector<std::uint8_t>> packets;

  // Original: send_fixed_flow() in export.c. A flow adds one record per
  // IPv4 direction that carried data; the two directions of one flow are
  // never split across packets, so the current packet is flushed first
  // when they do not both fit.
  struct DirectionalRecord {
    const IpAddress *src;
    const IpAddress *dst;
    std::uint16_t src_port;
    std::uint16_t dst_port;
    std::uint64_t octets;
    std::uint64_t packets;
    TimePoint first;
    TimePoint last;
    std::uint8_t protocol;
    std::uint8_t tos;
    std::uint8_t tcp_flags;
  };

  std::vector<DirectionalRecord> pending;

  auto flush = [&] () {
    if (pending.empty()) {
      return;
    }
    ByteWriter writer;
    write_header (writer, static_cast<std::uint16_t> (pending.size()), now,
                  wall_now);
    for (const auto &r : pending) {
      // Original: struct NF1_FLOW, 48 bytes.
      writer.put_ipv4 (*r.src);  // srcaddr
      writer.put_ipv4 (*r.dst);  // dstaddr
      writer.put_u32 (0);        // nexthop (not tracked)
      writer.put_u16 (0);        // input ifIndex (not tracked)
      writer.put_u16 (0);        // output ifIndex (not tracked)
      writer.put_u32 (static_cast<std::uint32_t> (
        std::min<std::uint64_t> (r.packets, 0xFFFFFFFFu)));  // dPkts
      writer.put_u32 (static_cast<std::uint32_t> (
        std::min<std::uint64_t> (r.octets, 0xFFFFFFFFu)));  // dOctets
      writer.put_u32 (uptime_ms (boot_time_, r.first));     // First
      writer.put_u32 (uptime_ms (boot_time_, r.last));      // Last
      writer.put_u16 (r.src_port);
      writer.put_u16 (r.dst_port);
      writer.put_u16 (0);  // pad1
      writer.put_u8 (r.protocol);
      writer.put_u8 (r.tos);
      writer.put_u8 (r.tcp_flags);
      writer.put_u8 (0);   // pad2
      writer.put_u32 (0);  // reserved
      writer.put_u16 (0);  // reserved (total record size: 48 bytes)
    }
    auto bytes = writer.take();
    if (debug_) {
      // Original: send_multi_destinations() logs every packet length.
      std::fprintf (stderr, "Sending flow packet len = %zu\n", bytes.size());
    }
    packets.push_back (std::move (bytes));
    pending.clear();
  };

  for (const auto &record : records) {
    const auto &key = record.key;
    const auto &flow = record.flow;

    // NetFlow v1 carries IPv4 only: one record per direction with data.
    std::size_t need = 0;
    for (std::size_t d = 0; d < 2; ++d) {
      if (flow.octets[d] > 0 &&
          key.addr()[d].family == AddressFamily::IPv4) {
        ++need;
      }
    }
    if (need == 0) {
      continue;
    }

    if (pending.size() + need > kNetflow1MaxRecordsPerPacket) {
      flush();
    }

    for (int dir = 0; dir < 2; ++dir) {
      const auto d = static_cast<std::size_t> (dir);
      if (flow.octets[d] == 0 ||
          key.addr()[d].family != AddressFamily::IPv4) {
        continue;  // no IPv4 traffic was seen in this direction
      }
      pending.push_back (DirectionalRecord{
        &key.addr()[d],
        &key.addr()[d ^ 1],
        key.port()[d],
        key.port()[d ^ 1],
        flow.octets[d],
        flow.packets[d],
        flow.flow_start,
        flow.flow_last,
        key.protocol(),
        flow.tos[d],
        flow.tcp_flags[d],
      });
    }
  }
  flush();

  return packets;
}

// ---------------------------------------------------------------------------
// NetFlow v5
// ---------------------------------------------------------------------------

namespace {

struct Netflow5DirectionalRecord {
  const IpAddress *src;
  const IpAddress *dst;
  std::uint16_t src_port;
  std::uint16_t dst_port;
  std::uint64_t octets;
  std::uint64_t packets;
  TimePoint first;
  TimePoint last;
  std::uint8_t protocol;
  std::uint8_t tos;
  std::uint8_t tcp_flags;
};

}  // namespace

void
Netflow5Exporter::write_header (
  ByteWriter &writer, std::uint16_t count, TimePoint now,
  std::chrono::system_clock::time_point wall_now) const {
  const auto unix_time = std::chrono::system_clock::to_time_t (wall_now);
  const auto since_epoch = wall_now.time_since_epoch();
  auto nsecs = std::chrono::duration_cast<std::chrono::nanoseconds> (
                 since_epoch % std::chrono::seconds (1))
                 .count();
  if (nsecs < 0) {
    nsecs += 1'000'000'000;
  }

  writer.put_u16 (5);  // version
  writer.put_u16 (count);
  writer.put_u32 (uptime_ms (boot_time_, now));
  writer.put_u32 (static_cast<std::uint32_t> (unix_time));
  writer.put_u32 (static_cast<std::uint32_t> (nsecs));
  writer.put_u32 (flow_seq_);  // flow_sequence
  writer.put_u8 (0);           // engine_type
  writer.put_u8 (0);           // engine_id
  // Original: sampling_interval is (mode 1 << 14) | (rate & 0x3FFF) when -s is
  // above 1, and 0 otherwise.
  writer.put_u16 (sampling_rate_ > 1
                    ? static_cast<std::uint16_t> ((0x01 << 14) | (sampling_rate_ & 0x3FFF))
                    : 0);
}

std::vector<std::vector<std::uint8_t>>
Netflow5Exporter::build_packets (
  std::span<const ExportRecord> records, TimePoint now,
  std::chrono::system_clock::time_point wall_now) {
  std::vector<std::vector<std::uint8_t>> packets;

  // Original: send_fixed_flow() in export.c. A flow adds one record per
  // IPv4 direction that carried data; the two directions of one flow are
  // never split across packets, so the current packet is flushed first
  // when they do not both fit.
  std::vector<Netflow5DirectionalRecord> pending;

  auto flush = [&] () {
    if (pending.empty()) {
      return;
    }
    ByteWriter writer;
    write_header (writer, static_cast<std::uint16_t> (pending.size()), now,
                  wall_now);
    for (const auto &r : pending) {
      // Original: struct NF5_FLOW, 48 bytes.
      writer.put_ipv4 (*r.src);
      writer.put_ipv4 (*r.dst);
      writer.put_u32 (0);  // nexthop
      writer.put_u16 (0);  // input ifIndex
      writer.put_u16 (0);  // output ifIndex
      writer.put_u32 (static_cast<std::uint32_t> (
        std::min<std::uint64_t> (r.packets, 0xFFFFFFFFu)));
      writer.put_u32 (static_cast<std::uint32_t> (
        std::min<std::uint64_t> (r.octets, 0xFFFFFFFFu)));
      writer.put_u32 (uptime_ms (boot_time_, r.first));
      writer.put_u32 (uptime_ms (boot_time_, r.last));
      writer.put_u16 (r.src_port);
      writer.put_u16 (r.dst_port);
      writer.put_u8 (0);  // pad1
      writer.put_u8 (r.tcp_flags);
      writer.put_u8 (r.protocol);
      writer.put_u8 (r.tos);
      writer.put_u16 (0);  // src_as (not tracked)
      writer.put_u16 (0);  // dst_as (not tracked)
      writer.put_u8 (0);   // src_mask (not tracked)
      writer.put_u8 (0);   // dst_mask (not tracked)
      writer.put_u16 (0);  // pad2
    }
    flow_seq_ += static_cast<std::uint32_t> (pending.size());
    auto bytes = writer.take();
    if (debug_) {
      // Original: send_multi_destinations() logs every packet length.
      std::fprintf (stderr, "Sending flow packet len = %zu\n", bytes.size());
    }
    packets.push_back (std::move (bytes));
    pending.clear();
  };

  for (const auto &record : records) {
    const auto &key = record.key;
    const auto &flow = record.flow;

    std::size_t need = 0;
    for (std::size_t d = 0; d < 2; ++d) {
      if (flow.octets[d] > 0 &&
          key.addr()[d].family == AddressFamily::IPv4) {
        ++need;
      }
    }
    if (need == 0) {
      continue;
    }

    if (pending.size() + need > kNetflow5MaxRecordsPerPacket) {
      flush();
    }

    for (int dir = 0; dir < 2; ++dir) {
      const auto d = static_cast<std::size_t> (dir);
      if (flow.octets[d] == 0 ||
          key.addr()[d].family != AddressFamily::IPv4) {
        continue;  // NetFlow v5 doesn't do IPv6, matching the original
      }
      pending.push_back (Netflow5DirectionalRecord{
        &key.addr()[d],
        &key.addr()[d ^ 1],
        key.port()[d],
        key.port()[d ^ 1],
        flow.octets[d],
        flow.packets[d],
        flow.flow_start,
        flow.flow_last,
        key.protocol(),
        flow.tos[d],
        flow.tcp_flags[d],
      });
    }
  }
  flush();

  return packets;
}

// ---------------------------------------------------------------------------
// NetFlow v9 and IPFIX
// ---------------------------------------------------------------------------

namespace {


// Returns the (start, end) Information Element (type, length) pair for
// the configured -A time_format, and writes the corresponding (start,
// end) values for one record. Keeping the "which fields" and "which
// values" logic paired up like this (rather than as two separately
// maintained switches) makes it structurally impossible for the template
// to describe a different encoding than what's actually written.
struct TimeFieldPair {
  IpfixFieldSpec start_field;
  IpfixFieldSpec end_field;
};

// Original: ipfix_fields.h's field_timesec/field_timemsec/field_timeusec/
// field_timensec/field_timesysup all declare the Start field before the
// End field (and compat/ipfix.c's copy_data_time() writes dt->u32.start
// before dt->u32.end, i.e. the same order) -- start-then-end, not
// end-then-start.
TimeFieldPair
time_field_pair (IpfixTimeFormat format) {
  switch (format) {
    case IpfixTimeFormat::SysUpTime:
      return {{22, 4}, {21, 4}};  // flowStartSysUpTime, flowEndSysUpTime
    case IpfixTimeFormat::Seconds:
      return {{150, 4}, {151, 4}};  // flowStartSeconds, flowEndSeconds
    case IpfixTimeFormat::Milliseconds:
      return {{152, 8}, {153, 8}};  // flowStartMilliseconds, flowEndMilliseconds
    case IpfixTimeFormat::Microseconds:
      return {{154, 8}, {155, 8}};  // flowStartMicroseconds, flowEndMicroseconds
    case IpfixTimeFormat::Nanoseconds:
      return {{156, 8}, {157, 8}};  // flowStartNanoseconds, flowEndNanoseconds
  }
  return {{22, 4}, {21, 4}};
}

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

// Original: field_vlan and field_ether of the flow template. -T vlan adds the
// VLAN IDs and -T ether adds the Ethernet addresses as well. The fields are
// those of the flow endpoint that sends (vlanId and sourceMacAddress) and of
// the one that receives (postVlanId and postDestinationMacAddress).
struct L2Fields {
  std::uint16_t vlan, post_vlan;
  std::array<std::uint8_t, 6> src_mac, post_dst_mac;
};

// What follows the transport fields of a record: the VLAN and Ethernet
// fields of the tracking level, then the MPLS labels.
struct TailFormat {
  std::uint8_t mpls_label_count;
  TrackLevel track_level;
};

std::size_t
l2_size (TrackLevel level) {
  return (level >= TrackLevel::FullVlan ? std::size_t{4} : std::size_t{0}) +
         (level >= TrackLevel::FullVlanEther ? std::size_t{12} : std::size_t{0});
}

// Original: -x. Writes mpls_label_count 3-octet mplsLabelStackSectionN
// fields (IANA Information Elements 70-79). Values are passed straight
// through from MplsLabelStack -- see its doc comment and
// softflowd.cpp's MplsShimEntry for why that's already exactly the right
// 24-bit (label|EXP|S) value, verbatim from the original packet, with no
// reconstruction needed here. Indices beyond the flow's actual label
// count (fewer real labels than mpls_label_count) are zero-filled,
// matching the original's raw, zero-initialized flow->mplsLabels[]
// entries beyond the real captured depth.
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

bool
is_icmp_protocol (std::uint8_t protocol) {
  constexpr std::uint8_t kProtoIcmp = 1;
  constexpr std::uint8_t kProtoIcmpV6 = 58;
  return protocol == kProtoIcmp || protocol == kProtoIcmpV6;
}

struct IpfixDirectionalRecord {
  const IpAddress *src;
  const IpAddress *dst;
  std::uint16_t src_port;
  std::uint16_t dst_port;
  std::uint64_t octets;
  std::uint64_t packets;
  TimePoint first;
  TimePoint last;
  std::uint8_t protocol;
  std::uint8_t tos;
  std::uint8_t tcp_flags;
  std::uint8_t flow_end_reason;
  std::uint8_t direction;  // Original: ipfix_flow_direction()'s fallback
                           // of the canonical array index (0 or 1) when
                           // no -H direction MAC is configured.
  const MplsLabelStack *mpls_labels;
  L2Fields l2;
  bool first_in_flow;  // first record of its flow; see pack_interleaved()
};

// Original: ipfix_flow_to_template_index()/valuate_icmp() route ICMP and
// ICMPv6 flows to their own template (icmpTypeCode instead of a
// source/destination port pair). Unlike an earlier version of this file,
// records are kept in ONE list, in original per-flow order (both
// directions of a given flow adjacent, flows in expiry order) --
// matching send_ipfix_flows()'s single interleaved pass over `flows[]`,
// where Sets are opened/closed based on whichever (address family,
// ICMP-ness) each flow's *next* record happens to have, not grouped
// ahead of time. Pre-grouping by family/ICMP-ness (as an earlier version
// of this function did) changes packet boundaries and Set ordering
// whenever a capture mixes address families or ICMP/non-ICMP flows.
L2Fields
l2_fields (const FlowKey &key, const Flow &flow, std::size_t i) {
  (void) flow;
  return L2Fields{key.vlanid()[i], key.vlanid()[i ^ 1], key.ethermac()[i],
                  key.ethermac()[i ^ 1]};
}

// Original: ipfix_flow_direction(). With a direction MAC the flowDirection
// is egress (1) when the source MAC of endpoint i is the direction MAC and
// ingress (0) when its destination MAC is; otherwise it is the endpoint
// index i.
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

// Original: field_common -- octetDeltaCount, packetDeltaCount,
// ingressInterface, egressInterface, flowDirection, flowEndReason. Written
// identically regardless of address family or ICMP-ness, between the
// address fields/timestamps and the transport-or-ICMP fields.
//
// ingressInterface/egressInterface are hardcoded to 0, matching this
// project's existing convention in the NetFlow v1 and v5 exporters above
// (interface index isn't tracked anywhere in this codebase).
void
write_common_fields (ByteWriter &writer, const IpfixDirectionalRecord &r) {
  writer.put_u32 (static_cast<std::uint32_t> (
    std::min<std::uint64_t> (r.octets, 0xFFFFFFFFu)));  // octetDeltaCount
  writer.put_u32 (static_cast<std::uint32_t> (
    std::min<std::uint64_t> (r.packets, 0xFFFFFFFFu)));  // packetDeltaCount
  writer.put_u32 (0);                                    // ingressInterface
  writer.put_u32 (0);                                    // egressInterface
  writer.put_u8 (r.direction);                           // flowDirection
  writer.put_u8 (r.flow_end_reason);                     // flowEndReason
}

void
write_v4_record (ByteWriter &writer, const IpfixDirectionalRecord &r,
                 IpfixTimeFormat time_format, const TailFormat &tail, TimePoint boot_time,
                 TimePoint now, std::chrono::system_clock::time_point wall_now) {
  writer.put_ipv4 (*r.src);  // sourceIPv4Address
  writer.put_ipv4 (*r.dst);  // destinationIPv4Address
  write_time_values (writer, time_format, boot_time, now, wall_now, r.first, r.last);
  write_common_fields (writer, r);
  writer.put_u16 (r.src_port);  // sourceTransportPort
  writer.put_u16 (r.dst_port);  // destinationTransportPort
  writer.put_u8 (r.protocol);   // protocolIdentifier
  writer.put_u8 (r.tcp_flags);  // tcpControlBits
  writer.put_u8 (4);            // ipVersion
  writer.put_u8 (r.tos);        // ipClassOfService
  write_tail (writer, r, tail);
}

void
write_v6_record (ByteWriter &writer, const IpfixDirectionalRecord &r,
                 IpfixTimeFormat time_format, const TailFormat &tail, TimePoint boot_time,
                 TimePoint now, std::chrono::system_clock::time_point wall_now) {
  writer.put_ipv6 (*r.src);
  writer.put_ipv6 (*r.dst);
  write_time_values (writer, time_format, boot_time, now, wall_now, r.first, r.last);
  write_common_fields (writer, r);
  writer.put_u16 (r.src_port);
  writer.put_u16 (r.dst_port);
  writer.put_u8 (r.protocol);
  writer.put_u8 (r.tcp_flags);
  writer.put_u8 (6);  // ipVersion
  writer.put_u8 (r.tos);
  write_tail (writer, r, tail);
}

// Original: field_icmp4/field_icmp6 -- icmpTypeCode replaces the
// source/destination port pair and there is no tcpControlBits field.
// dst_port already carries (icmp_type << 8 | icmp_code) -- see
// PacketParser's ICMP handling in softflowd.cpp -- matching the original's
// `di[i]->icmpTypeCode = flow->port[i ^ 1]`.
void
write_v4_icmp_record (ByteWriter &writer, const IpfixDirectionalRecord &r,
                      IpfixTimeFormat time_format, const TailFormat &tail, TimePoint boot_time,
                      TimePoint now, std::chrono::system_clock::time_point wall_now) {
  writer.put_ipv4 (*r.src);
  writer.put_ipv4 (*r.dst);
  write_time_values (writer, time_format, boot_time, now, wall_now, r.first, r.last);
  write_common_fields (writer, r);
  writer.put_u16 (r.dst_port);  // icmpTypeCode
  writer.put_u8 (r.protocol);   // protocolIdentifier
  writer.put_u8 (4);            // ipVersion
  writer.put_u8 (r.tos);        // ipClassOfService
  write_tail (writer, r, tail);
}

void
write_v6_icmp_record (ByteWriter &writer, const IpfixDirectionalRecord &r,
                      IpfixTimeFormat time_format, const TailFormat &tail, TimePoint boot_time,
                      TimePoint now, std::chrono::system_clock::time_point wall_now) {
  writer.put_ipv6 (*r.src);
  writer.put_ipv6 (*r.dst);
  write_time_values (writer, time_format, boot_time, now, wall_now, r.first, r.last);
  write_common_fields (writer, r);
  writer.put_u16 (r.dst_port);
  writer.put_u8 (r.protocol);
  writer.put_u8 (6);
  writer.put_u8 (r.tos);
  write_tail (writer, r, tail);
}

// ---- Biflow (-b) record shape: one record per flow, not per direction ----

struct BiflowRecord {
  const IpAddress *src;  // FlowKey's canonical addr()[0] -- the "forward" direction
  const IpAddress *dst;
  std::uint16_t src_port;
  std::uint16_t dst_port;
  std::uint8_t protocol;
  std::uint8_t tos;      // forward (flow.tos[0])
  std::uint8_t rev_tos;  // reverse (flow.tos[1])
  std::uint8_t flow_end_reason;
  std::uint8_t direction;  // flowDirection of the forward endpoint
  std::uint64_t fwd_octets, fwd_packets;
  std::uint8_t fwd_tcp_flags;
  std::uint64_t rev_octets, rev_packets;
  std::uint8_t rev_tcp_flags;
  TimePoint first, last;
  const MplsLabelStack *mpls_labels;
  L2Fields l2;
};

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

// Original: ipfix_flow_to_flowset()'s bi_flag branch writes ONE record per
// flow (frecnum=1, always i=0 -- "forward" is always FlowKey's canonical
// addr()[0]/port()[0]) with the SAME field layout/order as the
// unidirectional case (address, time, common(18), transport-or-icmp) --
// see write_v4_record()/write_v4_icmp_record() -- followed by a
// Reverse-Information-Element tail: reverse octetDeltaCount(4),
// packetDeltaCount(4), ipClassOfService(1) [field_bicommon], then EITHER
// reverse tcpControlBits(1) [field_bitransport] OR reverse icmpTypeCode(2)
// [field_biicmp4/6] depending on protocol -- never both. flowDirection is
// always 0 here (ipfix_flow_direction()'s fallback for i=0, the only
// index this loop ever uses).
//
// The reverse part is encoded for the reverse direction (i=1), so the
// reverse icmpTypeCode is `flow->port[i ^ 1]` == port[0] in the original,
// not the port[1] of the forward icmpTypeCode.
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
  writer.put_u32 (0);  // ingressInterface
  writer.put_u32 (0);  // egressInterface
  writer.put_u8 (r.direction);  // flowDirection of endpoint 0; see doc comment above
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
  writer.put_u32 (0);
  writer.put_u32 (0);
  writer.put_u8 (0);
  writer.put_u8 (r.flow_end_reason);
  writer.put_u16 (r.dst_port);  // forward icmpTypeCode == flow->port[i^1] == port[1] == dst_port
  writer.put_u8 (r.protocol);
  writer.put_u8 (4);
  writer.put_u8 (r.tos);
  write_tail (writer, r, tail);
  write_biflow_common_tail (writer, r, /*is_icmp=*/true);
}

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
  writer.put_u32 (0);
  writer.put_u32 (0);
  writer.put_u8 (0);
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
  writer.put_u32 (0);
  writer.put_u32 (0);
  writer.put_u8 (0);
  writer.put_u8 (r.flow_end_reason);
  writer.put_u16 (r.dst_port);
  writer.put_u8 (r.protocol);
  writer.put_u8 (6);
  writer.put_u8 (r.tos);
  write_tail (writer, r, tail);
  write_biflow_common_tail (writer, r, /*is_icmp=*/true);
}

}  // namespace

void
IpfixExporter::write_header (
  ByteWriter &writer, std::uint16_t length_or_count, TimePoint now,
  std::chrono::system_clock::time_point wall_now) const {
  const auto export_time = std::chrono::system_clock::to_time_t (wall_now);

  if (version_ == MessageVersion::NetFlow9) {
    // Original: struct NETFLOW9_HEADER. The count is the number of data
    // records and the sequence number counts packets.
    writer.put_u16 (9);  // version
    writer.put_u16 (length_or_count);
    writer.put_u32 (uptime_ms_unclamped (boot_time_, now));
    writer.put_u32 (static_cast<std::uint32_t> (export_time));
    writer.put_u32 (v9_sequence_);
    writer.put_u32 (observation_domain_id_);
    return;
  }
  writer.put_u16 (10);  // version
  writer.put_u16 (length_or_count);
  writer.put_u32 (static_cast<std::uint32_t> (export_time));
  writer.put_u32 (sequence_);
  writer.put_u32 (observation_domain_id_);
}

void
IpfixExporter::write_options_set (ByteWriter &writer) const {
  if (version_ == MessageVersion::NetFlow9) {
    // Original: nflow9_init_option(). An Options Template FlowSet (ID 1)
    // whose scope is the interface (4 octets) and whose option
    // fields are samplingInterval, samplingAlgorithm and interfaceName,
    // followed by its data record. Neither is padded.
    constexpr std::uint16_t kOptionTemplateFlowSetId = 1;
    constexpr std::uint16_t kOptionDataSetId = 256;
    constexpr std::uint16_t kScopeInterface = 2;
    constexpr std::size_t kIfNameLength = 16;  // IFNAMSIZ
    {
      const std::size_t set_start = writer.size();
      writer.put_u16 (kOptionTemplateFlowSetId);
      writer.put_u16 (0);  // Length placeholder
      writer.put_u16 (kOptionDataSetId);
      writer.put_u16 (4);   // scope length in octets (one field)
      writer.put_u16 (12);  // option length in octets (three fields)
      writer.put_u16 (kScopeInterface);
      writer.put_u16 (4);
      writer.put_u16 (34);  // SAMPLING_INTERVAL
      writer.put_u16 (4);
      writer.put_u16 (35);  // SAMPLING_ALGORITHM
      writer.put_u16 (1);
      writer.put_u16 (82);  // IF_NAME
      writer.put_u16 (static_cast<std::uint16_t> (kIfNameLength));
      finish_set_unpadded (writer, set_start);
    }
    {
      const std::size_t set_start = writer.size();
      writer.put_u16 (kOptionDataSetId);
      writer.put_u16 (0);  // Length placeholder
      writer.put_u32 (if_index_);
      writer.put_u32 (sampling_rate_ > 1 ? sampling_rate_ : 1);
      writer.put_u8 (1);  // deterministic sampling
      // interfaceName: empty unless the original is built with
      // --enable-ifname, which is off by default.
      for (std::size_t i = 0; i < kIfNameLength; ++i) {
        writer.put_u8 (0);
      }
      finish_set_unpadded (writer, set_start);
    }
    return;
  }
  // Original: ipfix_init_option() -- an Options Template Set (RFC 7011
  // section 3.4.2.2, Set ID 3) followed by its one Options Data Record
  // (Set ID 256, this project's arbitrarily-chosen but fixed template
  // ID, matching IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID). Scope field is
  // meteringProcessId; option fields carry systemInitTimeMilliseconds
  // (the reference point IpfixTimeFormat::SysUpTime's Start/End fields
  // are relative to -- see time_field_pair()) plus sampling/exporter
  // metadata this project doesn't otherwise track (sent as zero/empty,
  // matching a default, unconfigured original).
  static const std::vector<IpfixFieldSpec> kScopeFields = {
    {143, 4},  // meteringProcessId
  };
  static const std::vector<IpfixFieldSpec> kOptionFields = {
    {160, 8},   // systemInitTimeMilliseconds
    {305, 4},   // samplingPacketInterval (PSAMP)
    {306, 4},   // samplingPacketSpace (PSAMP)
    {304, 2},   // selectorAlgorithm (PSAMP)
    {82, 16},   // interfaceName (IFNAMSIZ == 16 on Linux)
    {130, 4},   // exporterIPv4Address
    {131, 16},  // exporterIPv6Address
    {403, 4},   // originalExporterIPv4Address
    {404, 16},  // originalExporterIPv6Address
  };
  constexpr std::uint16_t kOptionTemplateSetId = 3;
  constexpr std::uint16_t kOptionDataSetId = 256;

  {
    const std::size_t set_start = writer.size();
    writer.put_u16 (kOptionTemplateSetId);
    writer.put_u16 (0);                 // Length placeholder
    writer.put_u16 (kOptionDataSetId);  // template_id
    writer.put_u16 (static_cast<std::uint16_t> (
      kScopeFields.size() + kOptionFields.size()));                     // count
    writer.put_u16 (static_cast<std::uint16_t> (kScopeFields.size()));  // scope_count
    for (const auto &f : kScopeFields) {
      writer.put_u16 (f.type);
      writer.put_u16 (f.length);
    }
    for (const auto &f : kOptionFields) {
      writer.put_u16 (f.type);
      writer.put_u16 (f.length);
    }
    finish_set_unpadded (writer, set_start);
  }
  {
    const std::size_t set_start = writer.size();
    writer.put_u16 (kOptionDataSetId);
    writer.put_u16 (0);                                      // Length placeholder
    writer.put_u32 (static_cast<std::uint32_t> (getpid()));  // scope_pid
    const auto boot_epoch_ms = std::chrono::duration_cast<std::chrono::milliseconds> (
      boot_wall_time_.time_since_epoch());
    writer.put_u64 (static_cast<std::uint64_t> (
      std::max<std::int64_t> (0, boot_epoch_ms.count())));         // systemInitTimeMilliseconds
    writer.put_u32 (sampling_rate_ > 1 ? sampling_rate_ : 1);      // samplingPacketInterval
    writer.put_u32 (sampling_rate_ > 0 ? sampling_rate_ - 1 : 0);  // samplingPacketSpace
    writer.put_u16 (1);                                            // selectorAlgorithm (PSAMP_selectorAlgorithm_count)
    for (int i = 0; i < 16; ++i) {
      // interfaceName: empty unless the original is built with
      // --enable-ifname, which is off by default.
      writer.put_u8 (0);
    }
    // exporterIPv4/6Address and originalExporterIPv4/6Address all carry the
    // address of -e, or zero when there is none for the family.
    const std::array<std::uint8_t, 4> v4 =
      exporter_addresses_.v4.value_or (std::array<std::uint8_t, 4>{});
    const std::array<std::uint8_t, 16> v6 =
      exporter_addresses_.v6.value_or (std::array<std::uint8_t, 16>{});
    for (int i = 0; i < 2; ++i) {
      for (const std::uint8_t b : v4) {
        writer.put_u8 (b);
      }
      for (const std::uint8_t b : v6) {
        writer.put_u8 (b);
      }
    }
    finish_set_unpadded (writer, set_start);
  }
}

void
IpfixExporter::write_template_set (ByteWriter &writer) const {
  // Original: each entry in `templates[]` (compat/ipfix.c) is a self-contained
  // struct with its OWN Set header (IPFIX_SET_HEADER, Set ID 2) baked
  // in, and memcpy_template() copies each one out individually -- so on
  // the wire, four separate Template Sets are sent (one per template),
  // not one Set containing four Template Records. finish_set() pads
  // each to a 4-byte boundary and patches its own length, same as any
  // other Set.
  const auto write_template = [&] (std::uint16_t template_id,
                                   std::span<const IpfixFieldSpec> fields) {
    const std::size_t set_start = writer.size();
    // Set ID 2 identifies a Template Set (IPFIX; NetFlow v9 uses 0)
    writer.put_u16 (version_ == MessageVersion::Ipfix ? 2 : 0);
    writer.put_u16 (0);  // Length placeholder, patched by finish_set()
    writer.put_u16 (template_id);
    writer.put_u16 (static_cast<std::uint16_t> (fields.size()));
    for (const auto &f : fields) {
      if (f.enterprise == 0) {
        writer.put_u16 (f.type);
        writer.put_u16 (f.length);
      } else {
        // Enterprise-specific Information Element (RFC 7011
        // section 3.2): the top bit of the type field is set, and
        // a 4-byte Enterprise Number follows the normal 4-byte
        // (type, length) pair.
        writer.put_u16 (static_cast<std::uint16_t> (f.type | 0x8000u));
        writer.put_u16 (f.length);
        writer.put_u32 (f.enterprise);
      }
    }
    finish_set_unpadded (writer, set_start);
  };

  const auto [start_field, end_field] = time_field_pair (time_format_);

  // Original: field_common -- octetDeltaCount, packetDeltaCount,
  // ingressInterface, egressInterface, flowDirection, flowEndReason.
  // Shared by every non-biflow template between the timestamps and the
  // transport-or-ICMP fields; see write_common_fields().
  static const std::vector<IpfixFieldSpec> kCommonFields = {
    {1, 4},    // octetDeltaCount
    {2, 4},    // packetDeltaCount
    {10, 4},   // ingressInterface
    {14, 4},   // egressInterface
    {61, 1},   // flowDirection
    {136, 1},  // flowEndReason
  };

  if (!biflow_) {
    // Field order must exactly match write_v4_record()/write_v6_record()/
    // write_v4_icmp_record()/write_v6_icmp_record(): address, time,
    // common, then transport (ordinary flows) or icmpTypeCode (ICMP
    // flows) -- see compat/ipfix.c's ipfix_init_template_unity().
    std::vector<IpfixFieldSpec> v4_fields = {
      {8, 4},
      {12, 4},  // sourceIPv4Address, destinationIPv4Address
    };
    std::vector<IpfixFieldSpec> v6_fields = {
      {27, 16},
      {28, 16},  // sourceIPv6Address, destinationIPv6Address
    };
    for (auto *fields : {&v4_fields, &v6_fields}) {
      fields->push_back (start_field);
      fields->push_back (end_field);
      fields->insert (fields->end(), kCommonFields.begin(), kCommonFields.end());
    }
    std::vector<IpfixFieldSpec> v4_icmp_fields = v4_fields;
    std::vector<IpfixFieldSpec> v6_icmp_fields = v6_fields;

    v4_fields.push_back ({7, 2});   // sourceTransportPort
    v4_fields.push_back ({11, 2});  // destinationTransportPort
    v4_fields.push_back ({4, 1});   // protocolIdentifier
    v4_fields.push_back ({6, 1});   // tcpControlBits
    v4_fields.push_back ({60, 1});  // ipVersion
    v4_fields.push_back ({5, 1});   // ipClassOfService

    v6_fields.push_back ({7, 2});
    v6_fields.push_back ({11, 2});
    v6_fields.push_back ({4, 1});
    v6_fields.push_back ({6, 1});
    v6_fields.push_back ({60, 1});
    v6_fields.push_back ({5, 1});

    v4_icmp_fields.push_back ({32, 2});  // icmpTypeCodeIPv4
    v4_icmp_fields.push_back ({4, 1});   // protocolIdentifier
    v4_icmp_fields.push_back ({60, 1});  // ipVersion
    v4_icmp_fields.push_back ({5, 1});   // ipClassOfService

    v6_icmp_fields.push_back ({139, 2});  // icmpTypeCodeIPv6
    v6_icmp_fields.push_back ({4, 1});
    v6_icmp_fields.push_back ({60, 1});
    v6_icmp_fields.push_back ({5, 1});

    for (auto *fields : {&v4_fields, &v6_fields, &v4_icmp_fields, &v6_icmp_fields}) {
      if (track_level_ >= TrackLevel::FullVlan) {
        fields->push_back ({58, 2});  // vlanId
        fields->push_back ({59, 2});  // postVlanId
      }
      if (track_level_ >= TrackLevel::FullVlanEther) {
        fields->push_back ({56, 6});  // sourceMacAddress
        fields->push_back ({57, 6});  // postDestinationMacAddress
      }
    }
    for (std::uint8_t i = 0; i < mpls_label_count_; ++i) {
      const IpfixFieldSpec mpls{static_cast<std::uint16_t> (70 + i), 3};
      for (auto *fields : {&v4_fields, &v6_fields, &v4_icmp_fields, &v6_icmp_fields}) {
        fields->push_back (mpls);
      }
    }
    write_template (kIpfixTemplateIdV4, v4_fields);
    write_template (kIpfixTemplateIdIcmpV4, v4_icmp_fields);
    write_template (kIpfixTemplateIdV6, v6_fields);
    write_template (kIpfixTemplateIdIcmpV6, v6_icmp_fields);
  } else {
    // Field order must exactly match write_biflow_v4_record()/
    // write_biflow_v4_icmp_record()/write_biflow_v6_record()/
    // write_biflow_v6_icmp_record(): the SAME forward layout as the
    // non-biflow branch above (address, time, common, transport-or-
    // icmp), then MPLS, then the Reverse Information Elements (RFC
    // 5103): reverse octetDeltaCount/packetDeltaCount/
    // ipClassOfService [field_bicommon], then EITHER reverse
    // tcpControlBits [field_bitransport] OR reverse icmpTypeCode
    // [field_biicmp4/6].
    std::vector<IpfixFieldSpec> v4_fields = {
      {8, 4},
      {12, 4},  // sourceIPv4Address, destinationIPv4Address
    };
    std::vector<IpfixFieldSpec> v6_fields = {
      {27, 16},
      {28, 16},  // sourceIPv6Address, destinationIPv6Address
    };
    for (auto *fields : {&v4_fields, &v6_fields}) {
      fields->push_back (start_field);
      fields->push_back (end_field);
      fields->insert (fields->end(), kCommonFields.begin(), kCommonFields.end());
    }
    std::vector<IpfixFieldSpec> v4_icmp_fields = v4_fields;
    std::vector<IpfixFieldSpec> v6_icmp_fields = v6_fields;

    v4_fields.push_back ({7, 2});
    v4_fields.push_back ({11, 2});
    v4_fields.push_back ({4, 1});
    v4_fields.push_back ({6, 1});
    v4_fields.push_back ({60, 1});
    v4_fields.push_back ({5, 1});

    v6_fields.push_back ({7, 2});
    v6_fields.push_back ({11, 2});
    v6_fields.push_back ({4, 1});
    v6_fields.push_back ({6, 1});
    v6_fields.push_back ({60, 1});
    v6_fields.push_back ({5, 1});

    v4_icmp_fields.push_back ({32, 2});  // icmpTypeCodeIPv4
    v4_icmp_fields.push_back ({4, 1});
    v4_icmp_fields.push_back ({60, 1});
    v4_icmp_fields.push_back ({5, 1});

    v6_icmp_fields.push_back ({139, 2});  // icmpTypeCodeIPv6
    v6_icmp_fields.push_back ({4, 1});
    v6_icmp_fields.push_back ({60, 1});
    v6_icmp_fields.push_back ({5, 1});

    for (auto *fields : {&v4_fields, &v6_fields, &v4_icmp_fields, &v6_icmp_fields}) {
      if (track_level_ >= TrackLevel::FullVlan) {
        fields->push_back ({58, 2});  // vlanId
        fields->push_back ({59, 2});  // postVlanId
      }
      if (track_level_ >= TrackLevel::FullVlanEther) {
        fields->push_back ({56, 6});  // sourceMacAddress
        fields->push_back ({57, 6});  // postDestinationMacAddress
      }
    }
    for (std::uint8_t i = 0; i < mpls_label_count_; ++i) {
      const IpfixFieldSpec mpls{static_cast<std::uint16_t> (70 + i), 3};
      for (auto *fields : {&v4_fields, &v6_fields, &v4_icmp_fields, &v6_icmp_fields}) {
        fields->push_back (mpls);
      }
    }

    const IpfixFieldSpec reverse_octets{1, 4, kIpfixReversePen};
    const IpfixFieldSpec reverse_packets{2, 4, kIpfixReversePen};
    const IpfixFieldSpec reverse_tos{5, 1, kIpfixReversePen};
    const IpfixFieldSpec reverse_tcp_flags{6, 1, kIpfixReversePen};
    const IpfixFieldSpec reverse_icmp4{32, 2, kIpfixReversePen};
    const IpfixFieldSpec reverse_icmp6{139, 2, kIpfixReversePen};
    for (auto *fields : {&v4_fields, &v6_fields, &v4_icmp_fields, &v6_icmp_fields}) {
      fields->push_back (reverse_octets);
      fields->push_back (reverse_packets);
      fields->push_back (reverse_tos);
    }
    v4_fields.push_back (reverse_tcp_flags);
    v6_fields.push_back (reverse_tcp_flags);
    v4_icmp_fields.push_back (reverse_icmp4);
    v6_icmp_fields.push_back (reverse_icmp6);

    write_template (kIpfixTemplateIdV4, v4_fields);
    write_template (kIpfixTemplateIdIcmpV4, v4_icmp_fields);
    write_template (kIpfixTemplateIdV6, v6_fields);
    write_template (kIpfixTemplateIdIcmpV6, v6_icmp_fields);
  }
}

// Total on-wire size, in bytes, of one directional record for a given
// (is-v6, is-ICMP) combination -- addr + time + common(18) +
// transport(8)-or-icmp(5) + MPLS labels. Every record sharing the same
// (family, ICMP-ness) is exactly this size (no per-record variable-length
// fields), so the packing loop can budget space by arithmetic instead of
// needing a trial write-and-rollback per record the way the original's
// ipfix_flow_to_flowset() return value signals a size failure.
std::size_t
record_size (bool is_v6, bool is_icmp, IpfixTimeFormat time_format,
             std::uint8_t mpls_label_count, TrackLevel track_level) {
  const auto [start_field, end_field] = time_field_pair (time_format);
  const std::size_t addr_size = is_v6 ? 32 : 8;
  const std::size_t time_size =
    static_cast<std::size_t> (start_field.length) + end_field.length;
  constexpr std::size_t kCommonSize = 18;
  const std::size_t transport_or_icmp_size = is_icmp ? 5 : 8;
  return addr_size + time_size + kCommonSize + transport_or_icmp_size +
         l2_size (track_level) + static_cast<std::size_t> (mpls_label_count) * 3;
}

std::vector<std::vector<std::uint8_t>>
IpfixExporter::build_packets (
  std::span<const ExportRecord> records, TimePoint now,
  std::chrono::system_clock::time_point wall_now,
  std::vector<std::size_t> *template_only_packets) {
  std::vector<std::vector<std::uint8_t>> packets;
  const TailFormat tail_{mpls_label_count_, track_level_};

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

}  // namespace softflow
