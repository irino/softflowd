#include "softflow/ipfix.hpp"

#include <algorithm>
#include <unistd.h> // getpid() -- see write_options_set()

namespace softflow {

namespace {

// RFC 5103's IANA-assigned Reverse Information Element Private Enterprise
// Number. An enterprise-specific Information Element in a Template with
// this PEN and the same IE number as a standard field represents "the
// same field, but for the reverse direction of a biflow".
constexpr std::uint32_t kReversePen = 29305;

struct FieldSpec {
    std::uint16_t type;
    std::uint16_t length;
    std::uint32_t enterprise = 0; // 0 = standard IE; nonzero = enterprise-specific
};

void finish_set(ByteWriter& writer, std::size_t set_start) {
    // Original: IPFIX Sets are padded to a 4-byte boundary the same way as
    // NetFlow v9 FlowSets (RFC 7011 section 3.3.2), and the padding is
    // likewise included in the Set's own Length field. This applies to
    // DATA Sets only -- see finish_set_unpadded() for Template/Options
    // Sets, which the original never pads.
    const std::size_t raw_length = writer.size() - set_start;
    const std::size_t pad = (4 - (raw_length % 4)) % 4;
    for (std::size_t i = 0; i < pad; ++i) {
        writer.put_u8(0);
    }
    writer.patch_u16(set_start + 2, static_cast<std::uint16_t>(raw_length + pad));
}

// Original: memcpy_template() and the Options Template/Data writes in
// send_ipfix_common()'s "Refresh template headers" block never apply the
// 4-byte padding logic -- that only appears later, scoped to the
// per-flow DATA Set loop. A Template/Options Set's length is therefore
// its raw (frequently non-multiple-of-4) byte count.
void finish_set_unpadded(ByteWriter& writer, std::size_t set_start) {
    const std::size_t raw_length = writer.size() - set_start;
    writer.patch_u16(set_start + 2, static_cast<std::uint16_t>(raw_length));
}

// Converts a monotonic Clock timestamp `t` into an absolute
// epoch-millisecond value, using the relationship between the monotonic
// "now" and wall-clock "wall_now" supplied for this export call. This is
// the only place in the codebase that bridges the two clocks -- Flow
// itself never stores wall-clock time (see softflowd.hpp's rationale for
// using a monotonic Clock throughout).
std::uint64_t epoch_ms(TimePoint now,
                        std::chrono::system_clock::time_point wall_now,
                        TimePoint t) {
    const auto age = now - t; // how long ago `t` was, relative to `now`
    const auto wall_t = wall_now - age;
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        wall_t.time_since_epoch());
    return static_cast<std::uint64_t>(std::max<std::int64_t>(0, ms.count()));
}

// Original: -A micro/nano. RFC 7011 section 6.1.9 specifies these as the
// 64-bit NTP Timestamp format (RFC 5905): 32-bit seconds since the NTP
// epoch (1900-01-01), plus a 32-bit binary fraction of a second.
std::uint64_t epoch_ms_to_ntp64(std::uint64_t epoch_ms_value) {
    constexpr std::uint64_t kNtpEpochOffsetSeconds = 2208988800ULL; // 1900 -> 1970
    const std::uint64_t seconds = epoch_ms_value / 1000;
    const std::uint64_t ms_remainder = epoch_ms_value % 1000;
    const auto ntp_seconds = static_cast<std::uint32_t>(seconds + kNtpEpochOffsetSeconds);
    const auto ntp_fraction =
        static_cast<std::uint32_t>((ms_remainder * 4294967296ULL) / 1000ULL);
    return (static_cast<std::uint64_t>(ntp_seconds) << 32) | ntp_fraction;
}

// Original: netflow9.c/legacy softflowd's uptime-relative encoding --
// milliseconds elapsed between `boot_time` and `t`. Shared with
// Netflow9Exporter's identically-named helper in netflow9.cpp; kept as a
// separate copy here since the two files don't share a private header.
std::uint32_t uptime_ms(TimePoint boot_time, TimePoint t) {
    return static_cast<std::uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(t - boot_time).count());
}

// Returns the (start, end) Information Element (type, length) pair for
// the configured -A time_format, and writes the corresponding (start,
// end) values for one record. Keeping the "which fields" and "which
// values" logic paired up like this (rather than as two separately
// maintained switches) makes it structurally impossible for the template
// to describe a different encoding than what's actually written.
struct TimeFieldPair {
    FieldSpec start_field;
    FieldSpec end_field;
};

// Original: ipfix.c's field_timesec/field_timemsec/field_timeusec/
// field_timensec/field_timesysup all declare the Start field before the
// End field (and copy_data_time() writes dt->u32.start before
// dt->u32.end, i.e. the same order) -- start-then-end, not end-then-start.
TimeFieldPair time_field_pair(IpfixTimeFormat format) {
    switch (format) {
    case IpfixTimeFormat::SysUpTime:
        return {{22, 4}, {21, 4}}; // flowStartSysUpTime, flowEndSysUpTime
    case IpfixTimeFormat::Seconds:
        return {{150, 4}, {151, 4}}; // flowStartSeconds, flowEndSeconds
    case IpfixTimeFormat::Milliseconds:
        return {{152, 8}, {153, 8}}; // flowStartMilliseconds, flowEndMilliseconds
    case IpfixTimeFormat::Microseconds:
        return {{154, 8}, {155, 8}}; // flowStartMicroseconds, flowEndMicroseconds
    case IpfixTimeFormat::Nanoseconds:
        return {{156, 8}, {157, 8}}; // flowStartNanoseconds, flowEndNanoseconds
    }
    return {{22, 4}, {21, 4}};
}

void write_time_values(ByteWriter& writer, IpfixTimeFormat format, TimePoint boot_time,
                        TimePoint now, std::chrono::system_clock::time_point wall_now,
                        TimePoint first, TimePoint last) {
    if (format == IpfixTimeFormat::SysUpTime) {
        writer.put_u32(uptime_ms(boot_time, first));
        writer.put_u32(uptime_ms(boot_time, last));
        return;
    }
    const std::uint64_t start_ms = epoch_ms(now, wall_now, first);
    const std::uint64_t end_ms = epoch_ms(now, wall_now, last);
    switch (format) {
    case IpfixTimeFormat::SysUpTime:
        break; // handled above
    case IpfixTimeFormat::Seconds:
        writer.put_u32(static_cast<std::uint32_t>(start_ms / 1000));
        writer.put_u32(static_cast<std::uint32_t>(end_ms / 1000));
        break;
    case IpfixTimeFormat::Milliseconds:
        writer.put_u64(start_ms);
        writer.put_u64(end_ms);
        break;
    case IpfixTimeFormat::Microseconds:
    case IpfixTimeFormat::Nanoseconds:
        writer.put_u64(epoch_ms_to_ntp64(start_ms));
        writer.put_u64(epoch_ms_to_ntp64(end_ms));
        break;
    }
}

// Original: -x. See netflow9.cpp's identically-named helper for the
// rationale; duplicated here rather than shared, matching this project's
// per-file boundaries (netflow9.cpp and ipfix.cpp intentionally don't
// share an implementation file, mirroring the original's separate
// netflow9.c/ipfix.c).
// Original: -x. Writes mpls_label_count 3-octet mplsLabelStackSectionN
// fields (IANA Information Elements 70-79). Values are passed straight
// through from MplsLabelStack -- see its doc comment and
// softflowd.cpp's MplsShimEntry for why that's already exactly the right
// 24-bit (label|EXP|S) value, verbatim from the original packet, with no
// reconstruction needed here. Indices beyond the flow's actual label
// count (fewer real labels than mpls_label_count) are zero-filled,
// matching the original's raw, zero-initialized flow->mplsLabels[]
// entries beyond the real captured depth.
void write_mpls_labels(ByteWriter& writer, const MplsLabelStack& labels,
                        std::uint8_t mpls_label_count) {
    for (std::uint8_t i = 0; i < mpls_label_count; ++i) {
        const std::uint32_t section = (i < labels.size()) ? labels[i] : 0;
        writer.put_u8(static_cast<std::uint8_t>(section >> 16));
        writer.put_u8(static_cast<std::uint8_t>(section >> 8));
        writer.put_u8(static_cast<std::uint8_t>(section));
    }
}

// ---- Unidirectional (default, -b not given) record shape ----

bool is_icmp_protocol(std::uint8_t protocol) {
    constexpr std::uint8_t kProtoIcmp = 1;
    constexpr std::uint8_t kProtoIcmpV6 = 58;
    return protocol == kProtoIcmp || protocol == kProtoIcmpV6;
}

struct DirectionalRecord {
    const IpAddress* src;
    const IpAddress* dst;
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
    std::uint8_t direction; // Original: ipfix_flow_direction()'s fallback
                             // of the canonical array index (0 or 1) when
                             // no -H direction MAC is configured.
    const MplsLabelStack* mpls_labels;
};

// Original: ipfix_flow_to_template_index()/valuate_icmp() route ICMP and
// ICMPv6 flows to their own template (icmpTypeCode instead of a
// source/destination port pair). Unlike an earlier version of this file,
// records are kept in ONE list, in original per-flow order (both
// directions of a given flow adjacent, flows in expiry order) --
// matching send_ipfix_common()'s single interleaved pass over `flows[]`,
// where Sets are opened/closed based on whichever (address family,
// ICMP-ness) each flow's *next* record happens to have, not grouped
// ahead of time. Pre-grouping by family/ICMP-ness (as an earlier version
// of this function did) changes packet boundaries and Set ordering
// whenever a capture mixes address families or ICMP/non-ICMP flows.
void flatten(std::span<const ExportRecord> records,
             std::vector<DirectionalRecord>& out) {
    for (const auto& record : records) {
        const auto& key = record.key;
        const auto& flow = record.flow;
        for (int dir = 0; dir < 2; ++dir) {
            const auto d = static_cast<std::size_t>(dir);
            if (flow.packets[d] == 0) {
                continue;
            }
            out.push_back(DirectionalRecord{
                &key.addr()[d],
                &key.addr()[static_cast<std::size_t>(dir ^ 1)],
                key.port()[d],
                key.port()[static_cast<std::size_t>(dir ^ 1)],
                flow.octets[d],
                flow.packets[d],
                flow.flow_start,
                flow.flow_last,
                key.protocol(),
                flow.tos[d],
                flow.tcp_flags[d],
                flow.flow_end_reason,
                static_cast<std::uint8_t>(dir),
                &flow.mpls_labels,
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
// project's existing convention in netflow1.cpp/netflow5.cpp (interface
// index isn't tracked anywhere in this codebase).
void write_common_fields(ByteWriter& writer, const DirectionalRecord& r) {
    writer.put_u32(static_cast<std::uint32_t>(
        std::min<std::uint64_t>(r.octets, 0xFFFFFFFFu)));  // octetDeltaCount
    writer.put_u32(static_cast<std::uint32_t>(
        std::min<std::uint64_t>(r.packets, 0xFFFFFFFFu))); // packetDeltaCount
    writer.put_u32(0);                                      // ingressInterface
    writer.put_u32(0);                                      // egressInterface
    writer.put_u8(r.direction);                             // flowDirection
    writer.put_u8(r.flow_end_reason);                        // flowEndReason
}

void write_v4_record(ByteWriter& writer, const DirectionalRecord& r,
                      IpfixTimeFormat time_format, std::uint8_t mpls_label_count, TimePoint boot_time,
                      TimePoint now, std::chrono::system_clock::time_point wall_now) {
    writer.put_ipv4(*r.src);                                 // sourceIPv4Address
    writer.put_ipv4(*r.dst);                                 // destinationIPv4Address
    write_time_values(writer, time_format, boot_time, now, wall_now, r.first, r.last);
    write_common_fields(writer, r);
    writer.put_u16(r.src_port);                              // sourceTransportPort
    writer.put_u16(r.dst_port);                              // destinationTransportPort
    writer.put_u8(r.protocol);                                // protocolIdentifier
    writer.put_u8(r.tcp_flags);                                // tcpControlBits
    writer.put_u8(4);                                          // ipVersion
    writer.put_u8(r.tos);                                      // ipClassOfService
    write_mpls_labels(writer, *r.mpls_labels, mpls_label_count);
}

void write_v6_record(ByteWriter& writer, const DirectionalRecord& r,
                      IpfixTimeFormat time_format, std::uint8_t mpls_label_count, TimePoint boot_time,
                      TimePoint now, std::chrono::system_clock::time_point wall_now) {
    writer.put_ipv6(*r.src);
    writer.put_ipv6(*r.dst);
    write_time_values(writer, time_format, boot_time, now, wall_now, r.first, r.last);
    write_common_fields(writer, r);
    writer.put_u16(r.src_port);
    writer.put_u16(r.dst_port);
    writer.put_u8(r.protocol);
    writer.put_u8(r.tcp_flags);
    writer.put_u8(6);                                          // ipVersion
    writer.put_u8(r.tos);
    write_mpls_labels(writer, *r.mpls_labels, mpls_label_count);
}

// Original: field_icmp4/field_icmp6 -- icmpTypeCode replaces the
// source/destination port pair and there is no tcpControlBits field.
// dst_port already carries (icmp_type << 8 | icmp_code) -- see
// PacketParser's ICMP handling in softflowd.cpp -- matching the original's
// `di[i]->icmpTypeCode = flow->port[i ^ 1]`.
void write_v4_icmp_record(ByteWriter& writer, const DirectionalRecord& r,
                           IpfixTimeFormat time_format, std::uint8_t mpls_label_count, TimePoint boot_time,
                           TimePoint now, std::chrono::system_clock::time_point wall_now) {
    writer.put_ipv4(*r.src);
    writer.put_ipv4(*r.dst);
    write_time_values(writer, time_format, boot_time, now, wall_now, r.first, r.last);
    write_common_fields(writer, r);
    writer.put_u16(r.dst_port);                                // icmpTypeCode
    writer.put_u8(r.protocol);                                  // protocolIdentifier
    writer.put_u8(4);                                            // ipVersion
    writer.put_u8(r.tos);                                        // ipClassOfService
    write_mpls_labels(writer, *r.mpls_labels, mpls_label_count);
}

void write_v6_icmp_record(ByteWriter& writer, const DirectionalRecord& r,
                           IpfixTimeFormat time_format, std::uint8_t mpls_label_count, TimePoint boot_time,
                           TimePoint now, std::chrono::system_clock::time_point wall_now) {
    writer.put_ipv6(*r.src);
    writer.put_ipv6(*r.dst);
    write_time_values(writer, time_format, boot_time, now, wall_now, r.first, r.last);
    write_common_fields(writer, r);
    writer.put_u16(r.dst_port);
    writer.put_u8(r.protocol);
    writer.put_u8(6);
    writer.put_u8(r.tos);
    write_mpls_labels(writer, *r.mpls_labels, mpls_label_count);
}

// ---- Biflow (-b) record shape: one record per flow, not per direction ----

struct BiflowRecord {
    const IpAddress* src; // FlowKey's canonical addr()[0] -- the "forward" direction
    const IpAddress* dst;
    std::uint16_t src_port;
    std::uint16_t dst_port;
    std::uint8_t protocol;
    std::uint8_t tos;     // forward (flow.tos[0])
    std::uint8_t rev_tos; // reverse (flow.tos[1])
    std::uint8_t flow_end_reason;
    std::uint64_t fwd_octets, fwd_packets;
    std::uint8_t fwd_tcp_flags;
    std::uint64_t rev_octets, rev_packets;
    std::uint8_t rev_tcp_flags;
    TimePoint first, last;
    const MplsLabelStack* mpls_labels;
};

void flatten_biflow(std::span<const ExportRecord> records,
                     std::vector<BiflowRecord>& out) {
    for (const auto& record : records) {
        const auto& key = record.key;
        const auto& flow = record.flow;
        if (flow.packets[0] == 0 && flow.packets[1] == 0) {
            continue; // no traffic in either direction; nothing to report
        }
        out.push_back(BiflowRecord{
            &key.addr()[0], &key.addr()[1], key.port()[0], key.port()[1],
            key.protocol(), flow.tos[0], flow.tos[1], flow.flow_end_reason,
            flow.octets[0], flow.packets[0], flow.tcp_flags[0],
            flow.octets[1], flow.packets[1], flow.tcp_flags[1],
            flow.flow_start, flow.flow_last, &flow.mpls_labels,
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
// The reverse icmpTypeCode is `flow->port[1]` in the original -- the SAME
// raw value as the forward record's own icmpTypeCode field
// (`flow->port[i ^ 1]` with i=0, i.e. also port[1]), not a value for the
// "other" direction's own type/code. Reproduced here as-is rather than
// corrected, since this is about matching the original's actual output.
void write_biflow_common_tail(ByteWriter& writer, const BiflowRecord& r, bool is_icmp) {
    writer.put_u32(static_cast<std::uint32_t>(
        std::min<std::uint64_t>(r.rev_octets, 0xFFFFFFFFu))); // reverse octetDeltaCount
    writer.put_u32(static_cast<std::uint32_t>(
        std::min<std::uint64_t>(r.rev_packets, 0xFFFFFFFFu))); // reverse packetDeltaCount
    writer.put_u8(r.rev_tos); // reverse ipClassOfService
    if (is_icmp) {
        writer.put_u16(r.dst_port); // reverse icmpTypeCode == flow->port[1] == dst_port
    } else {
        writer.put_u8(r.rev_tcp_flags); // reverse tcpControlBits
    }
}

void write_biflow_v4_record(ByteWriter& writer, const BiflowRecord& r,
                             IpfixTimeFormat time_format,
                             std::uint8_t mpls_label_count, TimePoint boot_time, TimePoint now,
                             std::chrono::system_clock::time_point wall_now) {
    writer.put_ipv4(*r.src);
    writer.put_ipv4(*r.dst);
    write_time_values(writer, time_format, boot_time, now, wall_now, r.first, r.last);
    writer.put_u32(static_cast<std::uint32_t>(
        std::min<std::uint64_t>(r.fwd_octets, 0xFFFFFFFFu)));
    writer.put_u32(static_cast<std::uint32_t>(
        std::min<std::uint64_t>(r.fwd_packets, 0xFFFFFFFFu)));
    writer.put_u32(0); // ingressInterface
    writer.put_u32(0); // egressInterface
    writer.put_u8(0);  // flowDirection -- always 0 in biflow mode; see doc comment above
    writer.put_u8(r.flow_end_reason);
    writer.put_u16(r.src_port);
    writer.put_u16(r.dst_port);
    writer.put_u8(r.protocol);
    writer.put_u8(r.fwd_tcp_flags);
    writer.put_u8(4); // ipVersion
    writer.put_u8(r.tos);
    write_mpls_labels(writer, *r.mpls_labels, mpls_label_count);
    write_biflow_common_tail(writer, r, /*is_icmp=*/false);
}

void write_biflow_v4_icmp_record(ByteWriter& writer, const BiflowRecord& r,
                                  IpfixTimeFormat time_format,
                                  std::uint8_t mpls_label_count, TimePoint boot_time,
                                  TimePoint now,
                                  std::chrono::system_clock::time_point wall_now) {
    writer.put_ipv4(*r.src);
    writer.put_ipv4(*r.dst);
    write_time_values(writer, time_format, boot_time, now, wall_now, r.first, r.last);
    writer.put_u32(static_cast<std::uint32_t>(
        std::min<std::uint64_t>(r.fwd_octets, 0xFFFFFFFFu)));
    writer.put_u32(static_cast<std::uint32_t>(
        std::min<std::uint64_t>(r.fwd_packets, 0xFFFFFFFFu)));
    writer.put_u32(0);
    writer.put_u32(0);
    writer.put_u8(0);
    writer.put_u8(r.flow_end_reason);
    writer.put_u16(r.dst_port); // forward icmpTypeCode == flow->port[i^1] == port[1] == dst_port
    writer.put_u8(r.protocol);
    writer.put_u8(4);
    writer.put_u8(r.tos);
    write_mpls_labels(writer, *r.mpls_labels, mpls_label_count);
    write_biflow_common_tail(writer, r, /*is_icmp=*/true);
}

void write_biflow_v6_record(ByteWriter& writer, const BiflowRecord& r,
                             IpfixTimeFormat time_format,
                             std::uint8_t mpls_label_count, TimePoint boot_time, TimePoint now,
                             std::chrono::system_clock::time_point wall_now) {
    writer.put_ipv6(*r.src);
    writer.put_ipv6(*r.dst);
    write_time_values(writer, time_format, boot_time, now, wall_now, r.first, r.last);
    writer.put_u32(static_cast<std::uint32_t>(
        std::min<std::uint64_t>(r.fwd_octets, 0xFFFFFFFFu)));
    writer.put_u32(static_cast<std::uint32_t>(
        std::min<std::uint64_t>(r.fwd_packets, 0xFFFFFFFFu)));
    writer.put_u32(0);
    writer.put_u32(0);
    writer.put_u8(0);
    writer.put_u8(r.flow_end_reason);
    writer.put_u16(r.src_port);
    writer.put_u16(r.dst_port);
    writer.put_u8(r.protocol);
    writer.put_u8(r.fwd_tcp_flags);
    writer.put_u8(6);
    writer.put_u8(r.tos);
    write_mpls_labels(writer, *r.mpls_labels, mpls_label_count);
    write_biflow_common_tail(writer, r, /*is_icmp=*/false);
}

void write_biflow_v6_icmp_record(ByteWriter& writer, const BiflowRecord& r,
                                  IpfixTimeFormat time_format,
                                  std::uint8_t mpls_label_count, TimePoint boot_time,
                                  TimePoint now,
                                  std::chrono::system_clock::time_point wall_now) {
    writer.put_ipv6(*r.src);
    writer.put_ipv6(*r.dst);
    write_time_values(writer, time_format, boot_time, now, wall_now, r.first, r.last);
    writer.put_u32(static_cast<std::uint32_t>(
        std::min<std::uint64_t>(r.fwd_octets, 0xFFFFFFFFu)));
    writer.put_u32(static_cast<std::uint32_t>(
        std::min<std::uint64_t>(r.fwd_packets, 0xFFFFFFFFu)));
    writer.put_u32(0);
    writer.put_u32(0);
    writer.put_u8(0);
    writer.put_u8(r.flow_end_reason);
    writer.put_u16(r.dst_port);
    writer.put_u8(r.protocol);
    writer.put_u8(6);
    writer.put_u8(r.tos);
    write_mpls_labels(writer, *r.mpls_labels, mpls_label_count);
    write_biflow_common_tail(writer, r, /*is_icmp=*/true);
}

} // namespace

void IpfixExporter::write_header(
    ByteWriter& writer, std::uint16_t message_length,
    std::chrono::system_clock::time_point wall_now) const {
    const auto export_time = std::chrono::system_clock::to_time_t(wall_now);

    writer.put_u16(10); // version
    writer.put_u16(message_length);
    writer.put_u32(static_cast<std::uint32_t>(export_time));
    writer.put_u32(sequence_);
    writer.put_u32(observation_domain_id_);
}

void IpfixExporter::write_options_set(ByteWriter& writer) const {
    // Original: ipfix_init_option() -- an Options Template Set (RFC 7011
    // section 3.4.2.2, Set ID 3) followed by its one Options Data Record
    // (Set ID 256, this project's arbitrarily-chosen but fixed template
    // ID, matching IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID). Scope field is
    // meteringProcessId; option fields carry systemInitTimeMilliseconds
    // (the reference point IpfixTimeFormat::SysUpTime's Start/End fields
    // are relative to -- see time_field_pair()) plus sampling/exporter
    // metadata this project doesn't otherwise track (sent as zero/empty,
    // matching a default, unconfigured original).
    static const std::vector<FieldSpec> kScopeFields = {
        {143, 4}, // meteringProcessId
    };
    static const std::vector<FieldSpec> kOptionFields = {
        {160, 8},  // systemInitTimeMilliseconds
        {305, 4},  // samplingPacketInterval (PSAMP)
        {306, 4},  // samplingPacketSpace (PSAMP)
        {304, 2},  // selectorAlgorithm (PSAMP)
        {82, 16},  // interfaceName (IFNAMSIZ == 16 on Linux)
        {130, 4},  // exporterIPv4Address
        {131, 16}, // exporterIPv6Address
        {403, 4},  // originalExporterIPv4Address
        {404, 16}, // originalExporterIPv6Address
    };
    constexpr std::uint16_t kOptionTemplateSetId = 3;
    constexpr std::uint16_t kOptionDataSetId = 256;

    {
        const std::size_t set_start = writer.size();
        writer.put_u16(kOptionTemplateSetId);
        writer.put_u16(0); // Length placeholder
        writer.put_u16(kOptionDataSetId);              // template_id
        writer.put_u16(static_cast<std::uint16_t>(
            kScopeFields.size() + kOptionFields.size())); // count
        writer.put_u16(static_cast<std::uint16_t>(kScopeFields.size())); // scope_count
        for (const auto& f : kScopeFields) {
            writer.put_u16(f.type);
            writer.put_u16(f.length);
        }
        for (const auto& f : kOptionFields) {
            writer.put_u16(f.type);
            writer.put_u16(f.length);
        }
        finish_set_unpadded(writer, set_start);
    }
    {
        const std::size_t set_start = writer.size();
        writer.put_u16(kOptionDataSetId);
        writer.put_u16(0); // Length placeholder
        writer.put_u32(static_cast<std::uint32_t>(getpid())); // scope_pid
        const auto boot_epoch_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            boot_wall_time_.time_since_epoch());
        writer.put_u64(static_cast<std::uint64_t>(
            std::max<std::int64_t>(0, boot_epoch_ms.count()))); // systemInitTimeMilliseconds
        writer.put_u32(1); // samplingPacketInterval
        writer.put_u32(0); // samplingPacketSpace
        writer.put_u16(1); // selectorAlgorithm (PSAMP_selectorAlgorithm_count)
        for (int i = 0; i < 16; ++i) {
            // interfaceName (IFNAMSIZ==16): original truncates -i dev (or
            // in -r mode, the capture file path) to this many bytes with
            // strncpy(), which -- since it does NOT null-pad short
            // strings out to the full width -- leaves the remaining bytes
            // as whatever memset(0) initialized them to: zero. Truncating
            // to 16 bytes and zero-filling the rest reproduces that.
            writer.put_u8(static_cast<std::uint8_t>(
                i < static_cast<int>(interface_name_.size()) && i < 16
                    ? interface_name_[static_cast<std::size_t>(i)]
                    : 0));
        }
        writer.put_u32(0); // exporterIPv4Address -- not tracked
        for (int i = 0; i < 16; ++i) {
            writer.put_u8(0); // exporterIPv6Address
        }
        writer.put_u32(0); // originalExporterIPv4Address
        for (int i = 0; i < 16; ++i) {
            writer.put_u8(0); // originalExporterIPv6Address
        }
        finish_set_unpadded(writer, set_start);
    }
}

void IpfixExporter::write_template_set(ByteWriter& writer) const {
    // Original: each entry in `templates[]` (ipfix.c) is a self-contained
    // struct with its OWN Set header (IPFIX_SET_HEADER, Set ID 2) baked
    // in, and memcpy_template() copies each one out individually -- so on
    // the wire, four separate Template Sets are sent (one per template),
    // not one Set containing four Template Records. finish_set() pads
    // each to a 4-byte boundary and patches its own length, same as any
    // other Set.
    const auto write_template = [&](std::uint16_t template_id,
                                     std::span<const FieldSpec> fields) {
        const std::size_t set_start = writer.size();
        writer.put_u16(2); // Set ID 2 identifies a Template Set (IPFIX; NetFlow v9 uses 0)
        writer.put_u16(0); // Length placeholder, patched by finish_set()
        writer.put_u16(template_id);
        writer.put_u16(static_cast<std::uint16_t>(fields.size()));
        for (const auto& f : fields) {
            if (f.enterprise == 0) {
                writer.put_u16(f.type);
                writer.put_u16(f.length);
            } else {
                // Enterprise-specific Information Element (RFC 7011
                // section 3.2): the top bit of the type field is set, and
                // a 4-byte Enterprise Number follows the normal 4-byte
                // (type, length) pair.
                writer.put_u16(static_cast<std::uint16_t>(f.type | 0x8000u));
                writer.put_u16(f.length);
                writer.put_u32(f.enterprise);
            }
        }
        finish_set_unpadded(writer, set_start);
    };

    const auto [start_field, end_field] = time_field_pair(time_format_);

    // Original: field_common -- octetDeltaCount, packetDeltaCount,
    // ingressInterface, egressInterface, flowDirection, flowEndReason.
    // Shared by every non-biflow template between the timestamps and the
    // transport-or-ICMP fields; see write_common_fields().
    static const std::vector<FieldSpec> kCommonFields = {
        {1, 4},   // octetDeltaCount
        {2, 4},   // packetDeltaCount
        {10, 4},  // ingressInterface
        {14, 4},  // egressInterface
        {61, 1},  // flowDirection
        {136, 1}, // flowEndReason
    };

    if (!biflow_) {
        // Field order must exactly match write_v4_record()/write_v6_record()/
        // write_v4_icmp_record()/write_v6_icmp_record(): address, time,
        // common, then transport (ordinary flows) or icmpTypeCode (ICMP
        // flows) -- see ipfix.c's ipfix_init_template_unity().
        std::vector<FieldSpec> v4_fields = {
            {8, 4}, {12, 4}, // sourceIPv4Address, destinationIPv4Address
        };
        std::vector<FieldSpec> v6_fields = {
            {27, 16}, {28, 16}, // sourceIPv6Address, destinationIPv6Address
        };
        for (auto* fields : {&v4_fields, &v6_fields}) {
            fields->push_back(start_field);
            fields->push_back(end_field);
            fields->insert(fields->end(), kCommonFields.begin(), kCommonFields.end());
        }
        std::vector<FieldSpec> v4_icmp_fields = v4_fields;
        std::vector<FieldSpec> v6_icmp_fields = v6_fields;

        v4_fields.push_back({7, 2});   // sourceTransportPort
        v4_fields.push_back({11, 2});  // destinationTransportPort
        v4_fields.push_back({4, 1});   // protocolIdentifier
        v4_fields.push_back({6, 1});   // tcpControlBits
        v4_fields.push_back({60, 1});  // ipVersion
        v4_fields.push_back({5, 1});   // ipClassOfService

        v6_fields.push_back({7, 2});
        v6_fields.push_back({11, 2});
        v6_fields.push_back({4, 1});
        v6_fields.push_back({6, 1});
        v6_fields.push_back({60, 1});
        v6_fields.push_back({5, 1});

        v4_icmp_fields.push_back({32, 2});  // icmpTypeCodeIPv4
        v4_icmp_fields.push_back({4, 1});   // protocolIdentifier
        v4_icmp_fields.push_back({60, 1});  // ipVersion
        v4_icmp_fields.push_back({5, 1});   // ipClassOfService

        v6_icmp_fields.push_back({139, 2}); // icmpTypeCodeIPv6
        v6_icmp_fields.push_back({4, 1});
        v6_icmp_fields.push_back({60, 1});
        v6_icmp_fields.push_back({5, 1});

        for (std::uint8_t i = 0; i < mpls_label_count_; ++i) {
            const FieldSpec mpls{static_cast<std::uint16_t>(70 + i), 3};
            for (auto* fields : {&v4_fields, &v6_fields, &v4_icmp_fields, &v6_icmp_fields}) {
                fields->push_back(mpls);
            }
        }
        write_template(kIpfixTemplateIdV4, v4_fields);
        write_template(kIpfixTemplateIdIcmpV4, v4_icmp_fields);
        write_template(kIpfixTemplateIdV6, v6_fields);
        write_template(kIpfixTemplateIdIcmpV6, v6_icmp_fields);
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
        std::vector<FieldSpec> v4_fields = {
            {8, 4}, {12, 4}, // sourceIPv4Address, destinationIPv4Address
        };
        std::vector<FieldSpec> v6_fields = {
            {27, 16}, {28, 16}, // sourceIPv6Address, destinationIPv6Address
        };
        for (auto* fields : {&v4_fields, &v6_fields}) {
            fields->push_back(start_field);
            fields->push_back(end_field);
            fields->insert(fields->end(), kCommonFields.begin(), kCommonFields.end());
        }
        std::vector<FieldSpec> v4_icmp_fields = v4_fields;
        std::vector<FieldSpec> v6_icmp_fields = v6_fields;

        v4_fields.push_back({7, 2});
        v4_fields.push_back({11, 2});
        v4_fields.push_back({4, 1});
        v4_fields.push_back({6, 1});
        v4_fields.push_back({60, 1});
        v4_fields.push_back({5, 1});

        v6_fields.push_back({7, 2});
        v6_fields.push_back({11, 2});
        v6_fields.push_back({4, 1});
        v6_fields.push_back({6, 1});
        v6_fields.push_back({60, 1});
        v6_fields.push_back({5, 1});

        v4_icmp_fields.push_back({32, 2}); // icmpTypeCodeIPv4
        v4_icmp_fields.push_back({4, 1});
        v4_icmp_fields.push_back({60, 1});
        v4_icmp_fields.push_back({5, 1});

        v6_icmp_fields.push_back({139, 2}); // icmpTypeCodeIPv6
        v6_icmp_fields.push_back({4, 1});
        v6_icmp_fields.push_back({60, 1});
        v6_icmp_fields.push_back({5, 1});

        for (std::uint8_t i = 0; i < mpls_label_count_; ++i) {
            const FieldSpec mpls{static_cast<std::uint16_t>(70 + i), 3};
            for (auto* fields : {&v4_fields, &v6_fields, &v4_icmp_fields, &v6_icmp_fields}) {
                fields->push_back(mpls);
            }
        }

        const FieldSpec reverse_octets{1, 4, kReversePen};
        const FieldSpec reverse_packets{2, 4, kReversePen};
        const FieldSpec reverse_tos{5, 1, kReversePen};
        const FieldSpec reverse_tcp_flags{6, 1, kReversePen};
        const FieldSpec reverse_icmp4{32, 2, kReversePen};
        const FieldSpec reverse_icmp6{139, 2, kReversePen};
        for (auto* fields : {&v4_fields, &v6_fields, &v4_icmp_fields, &v6_icmp_fields}) {
            fields->push_back(reverse_octets);
            fields->push_back(reverse_packets);
            fields->push_back(reverse_tos);
        }
        v4_fields.push_back(reverse_tcp_flags);
        v6_fields.push_back(reverse_tcp_flags);
        v4_icmp_fields.push_back(reverse_icmp4);
        v6_icmp_fields.push_back(reverse_icmp6);

        write_template(kIpfixTemplateIdV4, v4_fields);
        write_template(kIpfixTemplateIdIcmpV4, v4_icmp_fields);
        write_template(kIpfixTemplateIdV6, v6_fields);
        write_template(kIpfixTemplateIdIcmpV6, v6_icmp_fields);
    }
}

// Total on-wire size, in bytes, of one directional record for a given
// (is-v6, is-ICMP) combination -- addr + time + common(18) +
// transport(8)-or-icmp(5) + MPLS labels. Every record sharing the same
// (family, ICMP-ness) is exactly this size (no per-record variable-length
// fields), so the packing loop can budget space by arithmetic instead of
// needing a trial write-and-rollback per record the way the original's
// ipfix_flow_to_flowset() return value signals a size failure.
std::size_t record_size(bool is_v6, bool is_icmp, IpfixTimeFormat time_format,
                         std::uint8_t mpls_label_count) {
    const auto [start_field, end_field] = time_field_pair(time_format);
    const std::size_t addr_size = is_v6 ? 32 : 8;
    const std::size_t time_size =
        static_cast<std::size_t>(start_field.length) + end_field.length;
    constexpr std::size_t kCommonSize = 18;
    const std::size_t transport_or_icmp_size = is_icmp ? 5 : 8;
    return addr_size + time_size + kCommonSize + transport_or_icmp_size +
           static_cast<std::size_t>(mpls_label_count) * 3;
}

std::vector<std::vector<std::uint8_t>>
IpfixExporter::build_packets(
    std::span<const ExportRecord> records, TimePoint now,
    std::chrono::system_clock::time_point wall_now) {
    std::vector<std::vector<std::uint8_t>> packets;

    // The record-count bookkeeping (data_records_in_packet, used only for
    // RFC 7011's "Sequence Number counts Data Records" rule) and the
    // packet/Set assembly loop are identical in shape between biflow and
    // non-biflow modes; only which per-record write function is called
    // and how the two per-family lists are populated differ.
    // Original: ipfix_flow_to_template_index() -- routes ICMP/ICMPv6 flows
    // to the dedicated ICMP template ID, everything else to the ordinary
    // one. Shared by both the non-biflow and biflow packing passes below
    // since both use the same four template IDs.
    const auto template_id_for = [&](bool is_v6, bool is_icmp) -> std::uint16_t {
        if (!is_v6) return is_icmp ? kIpfixTemplateIdIcmpV4 : kIpfixTemplateIdV4;
        return is_icmp ? kIpfixTemplateIdIcmpV6 : kIpfixTemplateIdV6;
    };

    // Original: send_ipfix_common()'s single interleaved pass over
    // `flows[]`, opening a new Set only when the (address family,
    // ICMP-ness) of the next record differs from the currently-open Set
    // (or none is open yet), and budgeting packet space by byte count
    // against kIpfixMaxPacketSize rather than a fixed records-per-Set
    // limit. Shared between the non-biflow and biflow paths -- the
    // original's own packing loop is likewise the same code for both,
    // parameterized only by bi_flag's effect on frecnum/record layout.
    const auto pack_interleaved = [&](auto& all, auto is_v6_of, auto is_icmp_of,
                                       auto record_size_of, auto write_dispatch) {
        std::size_t idx = 0;
        while (idx < all.size()) {
            ByteWriter body;
            std::uint32_t data_records_in_packet = 0;

            const bool send_template = (packets_since_template_ == 0);
            if (send_template) {
                write_template_set(body);
                write_options_set(body);
            }

            std::size_t set_header_pos = 0;
            bool set_open = false;
            bool last_is_v6 = false, last_is_icmp = false;
            std::size_t last_valid = 0; // rollback point; see ByteWriter::truncate()'s doc

            while (idx < all.size()) {
                const auto& r = all[idx];
                const bool is_v6 = is_v6_of(r);
                const bool is_icmp = is_icmp_of(r);
                const std::size_t rec_size = record_size_of(is_v6, is_icmp);

                if (!set_open || is_v6 != last_is_v6 || is_icmp != last_is_icmp) {
                    if (set_open) {
                        finish_set(body, set_header_pos); // pads to 4 bytes; see finish_set()
                    }
                    if (body.size() + 4 > kIpfixMaxPacketSize) {
                        set_open = false;
                        break; // this packet is full; resume at `idx` next packet
                    }
                    set_header_pos = body.size();
                    last_valid = body.size();
                    body.put_u16(template_id_for(is_v6, is_icmp));
                    body.put_u16(0); // length placeholder, patched by finish_set()
                    set_open = true;
                    last_is_v6 = is_v6;
                    last_is_icmp = is_icmp;
                }

                if (body.size() + rec_size > kIpfixMaxPacketSize) {
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
                    body.truncate(last_valid);
                    set_open = (last_valid > set_header_pos);
                    break;
                }
                write_dispatch(body, r, is_v6, is_icmp);
                data_records_in_packet += 1;
                last_valid = body.size(); // this Set now has >=1 record; no more rollback
                ++idx;
            }
            if (set_open) {
                finish_set(body, set_header_pos);
            }

            // Original: `*records_sent += records;` happens BEFORE
            // `ipfix->sequence = htonl(*records_sent ...)` -- the header's
            // Sequence Number for a packet is the cumulative Data Record
            // count INCLUDING this packet's own records, not the count
            // from before it.
            sequence_ += data_records_in_packet;
            ByteWriter packet;
            const auto message_length =
                static_cast<std::uint16_t>(16 /* header */ + body.size());
            write_header(packet, message_length, wall_now);
            packet.put_bytes(body.bytes());
            packets.push_back(packet.take());

            packets_since_template_ = send_template ? 1 : packets_since_template_ + 1;
            if (packets_since_template_ >= kIpfixTemplateResendInterval) {
                packets_since_template_ = 0;
            }
        }
    };

    if (!biflow_) {
        std::vector<DirectionalRecord> all;
        flatten(records, all);

        const std::size_t sizes[2][2] = {
            // [is_v6][is_icmp]
            {record_size(false, false, time_format_, mpls_label_count_),
             record_size(false, true, time_format_, mpls_label_count_)},
            {record_size(true, false, time_format_, mpls_label_count_),
             record_size(true, true, time_format_, mpls_label_count_)},
        };
        pack_interleaved(
            all,
            [](const DirectionalRecord& r) { return r.src->family == AddressFamily::IPv6; },
            [](const DirectionalRecord& r) { return is_icmp_protocol(r.protocol); },
            [&](bool is_v6, bool is_icmp) { return sizes[is_v6 ? 1 : 0][is_icmp ? 1 : 0]; },
            [&](ByteWriter& w, const DirectionalRecord& r, bool is_v6, bool is_icmp) {
                if (!is_v6 && !is_icmp) {
                    write_v4_record(w, r, time_format_, mpls_label_count_, boot_time_, now,
                                     wall_now);
                } else if (!is_v6 && is_icmp) {
                    write_v4_icmp_record(w, r, time_format_, mpls_label_count_, boot_time_, now,
                                          wall_now);
                } else if (is_v6 && !is_icmp) {
                    write_v6_record(w, r, time_format_, mpls_label_count_, boot_time_, now,
                                     wall_now);
                } else {
                    write_v6_icmp_record(w, r, time_format_, mpls_label_count_, boot_time_, now,
                                          wall_now);
                }
            });
    } else {
        std::vector<BiflowRecord> all;
        flatten_biflow(records, all);

        // Original: field_bicommon (9 bytes: reverse octets/packets/tos)
        // plus either field_bitransport (1 byte: reverse tcpControlBits)
        // or field_biicmp4/6 (2 bytes: reverse icmpTypeCode) tacked onto
        // the ordinary per-family/ICMP-ness record size -- see
        // write_biflow_common_tail().
        const std::size_t bi_sizes[2][2] = {
            {record_size(false, false, time_format_, mpls_label_count_) + 9 + 1,
             record_size(false, true, time_format_, mpls_label_count_) + 9 + 2},
            {record_size(true, false, time_format_, mpls_label_count_) + 9 + 1,
             record_size(true, true, time_format_, mpls_label_count_) + 9 + 2},
        };
        pack_interleaved(
            all,
            [](const BiflowRecord& r) { return r.src->family == AddressFamily::IPv6; },
            [](const BiflowRecord& r) { return is_icmp_protocol(r.protocol); },
            [&](bool is_v6, bool is_icmp) { return bi_sizes[is_v6 ? 1 : 0][is_icmp ? 1 : 0]; },
            [&](ByteWriter& w, const BiflowRecord& r, bool is_v6, bool is_icmp) {
                if (!is_v6 && !is_icmp) {
                    write_biflow_v4_record(w, r, time_format_, mpls_label_count_, boot_time_,
                                            now, wall_now);
                } else if (!is_v6 && is_icmp) {
                    write_biflow_v4_icmp_record(w, r, time_format_, mpls_label_count_,
                                                 boot_time_, now, wall_now);
                } else if (is_v6 && !is_icmp) {
                    write_biflow_v6_record(w, r, time_format_, mpls_label_count_, boot_time_,
                                            now, wall_now);
                } else {
                    write_biflow_v6_icmp_record(w, r, time_format_, mpls_label_count_,
                                                 boot_time_, now, wall_now);
                }
            });
    }

    return packets;
}

} // namespace softflow
