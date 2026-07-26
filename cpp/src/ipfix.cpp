#include "softflow/ipfix.hpp"

#include <algorithm>

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
    // likewise included in the Set's own Length field.
    const std::size_t raw_length = writer.size() - set_start;
    const std::size_t pad = (4 - (raw_length % 4)) % 4;
    for (std::size_t i = 0; i < pad; ++i) {
        writer.put_u8(0);
    }
    writer.patch_u16(set_start + 2, static_cast<std::uint16_t>(raw_length + pad));
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

// Returns the (end, start) Information Element (type, length) pair for
// the configured -A time_format, and writes the corresponding (end,
// start) values for one record. Keeping the "which fields" and "which
// values" logic paired up like this (rather than as two separately
// maintained switches) makes it structurally impossible for the template
// to describe a different encoding than what's actually written.
struct TimeFieldPair {
    FieldSpec end_field;
    FieldSpec start_field;
};

TimeFieldPair time_field_pair(IpfixTimeFormat format) {
    switch (format) {
    case IpfixTimeFormat::Seconds:
        return {{151, 4}, {150, 4}}; // flowEndSeconds, flowStartSeconds
    case IpfixTimeFormat::Milliseconds:
        return {{153, 8}, {152, 8}}; // flowEndMilliseconds, flowStartMilliseconds
    case IpfixTimeFormat::Microseconds:
        return {{155, 8}, {154, 8}}; // flowEndMicroseconds, flowStartMicroseconds
    case IpfixTimeFormat::Nanoseconds:
        return {{157, 8}, {156, 8}}; // flowEndNanoseconds, flowStartNanoseconds
    }
    return {{153, 8}, {152, 8}};
}

void write_time_values(ByteWriter& writer, IpfixTimeFormat format, TimePoint now,
                        std::chrono::system_clock::time_point wall_now,
                        TimePoint first, TimePoint last) {
    const std::uint64_t end_ms = epoch_ms(now, wall_now, last);
    const std::uint64_t start_ms = epoch_ms(now, wall_now, first);
    switch (format) {
    case IpfixTimeFormat::Seconds:
        writer.put_u32(static_cast<std::uint32_t>(end_ms / 1000));
        writer.put_u32(static_cast<std::uint32_t>(start_ms / 1000));
        break;
    case IpfixTimeFormat::Milliseconds:
        writer.put_u64(end_ms);
        writer.put_u64(start_ms);
        break;
    case IpfixTimeFormat::Microseconds:
    case IpfixTimeFormat::Nanoseconds:
        writer.put_u64(epoch_ms_to_ntp64(end_ms));
        writer.put_u64(epoch_ms_to_ntp64(start_ms));
        break;
    }
}

// Original: -x. See netflow9.cpp's identically-named helper for the
// rationale; duplicated here rather than shared, matching this project's
// per-file boundaries (netflow9.cpp and ipfix.cpp intentionally don't
// share an implementation file, mirroring the original's separate
// netflow9.c/ipfix.c).
// Original: -x. Writes mpls_label_count 3-octet mplsLabelStackSectionN
// fields (IANA Information Elements 70-79). Per the IANA definition, this
// 24-bit field mirrors the top 3 bytes of the original 4-byte MPLS shim
// (label(20 bits) | EXP(3 bits) | S(1 bit) | TTL(8 bits)) -- i.e. bits
// 31-8 of the shim, with the would-be TTL-adjacent bit set to 0. Since
// this project's packet parser only extracts the label value itself (see
// softflowd.cpp's parse_mpls_label_stack()), EXP is always encoded as 0.
void write_mpls_labels(ByteWriter& writer, const MplsLabelStack& labels,
                        std::uint8_t mpls_label_count) {
    for (std::uint8_t i = 0; i < mpls_label_count; ++i) {
        std::uint32_t section = 0;
        if (i < labels.size()) {
            const bool bottom = (static_cast<std::size_t>(i) + 1 == labels.size());
            section = (labels[i] << 4) | (bottom ? 0x1u : 0u);
        }
        writer.put_u8(static_cast<std::uint8_t>(section >> 16));
        writer.put_u8(static_cast<std::uint8_t>(section >> 8));
        writer.put_u8(static_cast<std::uint8_t>(section));
    }
}

// ---- Unidirectional (default, -b not given) record shape ----

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
    const MplsLabelStack* mpls_labels;
};

void flatten(std::span<const ExportRecord> records,
             std::vector<DirectionalRecord>& v4,
             std::vector<DirectionalRecord>& v6) {
    for (const auto& record : records) {
        const auto& key = record.key;
        const auto& flow = record.flow;
        for (int dir = 0; dir < 2; ++dir) {
            const auto d = static_cast<std::size_t>(dir);
            if (flow.packets[d] == 0) {
                continue;
            }
            DirectionalRecord dr{
                &key.addr()[d],
                &key.addr()[static_cast<std::size_t>(dir ^ 1)],
                key.port()[d],
                key.port()[static_cast<std::size_t>(dir ^ 1)],
                flow.octets[d],
                flow.packets[d],
                flow.flow_start,
                flow.flow_last,
                key.protocol(),
                key.tos(),
                flow.tcp_flags[d],
                &flow.mpls_labels,
            };
            if (dr.src->family == AddressFamily::IPv4) {
                v4.push_back(dr);
            } else {
                v6.push_back(dr);
            }
        }
    }
}

void write_v4_record(ByteWriter& writer, const DirectionalRecord& r,
                      IpfixTimeFormat time_format, std::uint8_t mpls_label_count,
                      TimePoint now, std::chrono::system_clock::time_point wall_now) {
    writer.put_u32(static_cast<std::uint32_t>(
        std::min<std::uint64_t>(r.octets, 0xFFFFFFFFu)));  // octetDeltaCount
    writer.put_u32(static_cast<std::uint32_t>(
        std::min<std::uint64_t>(r.packets, 0xFFFFFFFFu))); // packetDeltaCount
    writer.put_u8(r.protocol);                              // protocolIdentifier
    writer.put_u8(r.tos);                                   // ipClassOfService
    writer.put_u8(r.tcp_flags);                              // tcpControlBits
    writer.put_u16(r.src_port);                              // sourceTransportPort
    writer.put_ipv4(*r.src);                                 // sourceIPv4Address
    writer.put_u16(r.dst_port);                              // destinationTransportPort
    writer.put_ipv4(*r.dst);                                 // destinationIPv4Address
    write_time_values(writer, time_format, now, wall_now, r.first, r.last);
    write_mpls_labels(writer, *r.mpls_labels, mpls_label_count);
}

void write_v6_record(ByteWriter& writer, const DirectionalRecord& r,
                      IpfixTimeFormat time_format, std::uint8_t mpls_label_count,
                      TimePoint now, std::chrono::system_clock::time_point wall_now) {
    writer.put_u32(static_cast<std::uint32_t>(
        std::min<std::uint64_t>(r.octets, 0xFFFFFFFFu)));
    writer.put_u32(static_cast<std::uint32_t>(
        std::min<std::uint64_t>(r.packets, 0xFFFFFFFFu)));
    writer.put_u8(r.protocol);
    writer.put_u8(r.tos);
    writer.put_u8(r.tcp_flags);
    writer.put_u16(r.src_port);
    writer.put_ipv6(*r.src);
    writer.put_u16(r.dst_port);
    writer.put_ipv6(*r.dst);
    write_time_values(writer, time_format, now, wall_now, r.first, r.last);
    write_mpls_labels(writer, *r.mpls_labels, mpls_label_count);
}

// ---- Biflow (-b) record shape: one record per flow, not per direction ----

struct BiflowRecord {
    const IpAddress* src; // FlowKey's canonical addr()[0] -- the "forward" direction
    const IpAddress* dst;
    std::uint16_t src_port;
    std::uint16_t dst_port;
    std::uint8_t protocol;
    std::uint8_t tos;
    std::uint64_t fwd_octets, fwd_packets;
    std::uint8_t fwd_tcp_flags;
    std::uint64_t rev_octets, rev_packets;
    std::uint8_t rev_tcp_flags;
    TimePoint first, last;
    const MplsLabelStack* mpls_labels;
};

void flatten_biflow(std::span<const ExportRecord> records,
                     std::vector<BiflowRecord>& v4, std::vector<BiflowRecord>& v6) {
    for (const auto& record : records) {
        const auto& key = record.key;
        const auto& flow = record.flow;
        if (flow.packets[0] == 0 && flow.packets[1] == 0) {
            continue; // no traffic in either direction; nothing to report
        }
        BiflowRecord br{
            &key.addr()[0], &key.addr()[1], key.port()[0], key.port()[1],
            key.protocol(), key.tos(),
            flow.octets[0], flow.packets[0], flow.tcp_flags[0],
            flow.octets[1], flow.packets[1], flow.tcp_flags[1],
            flow.flow_start, flow.flow_last, &flow.mpls_labels,
        };
        if (br.src->family == AddressFamily::IPv4) {
            v4.push_back(br);
        } else {
            v6.push_back(br);
        }
    }
}

void write_biflow_v4_record(ByteWriter& writer, const BiflowRecord& r,
                             IpfixTimeFormat time_format,
                             std::uint8_t mpls_label_count, TimePoint now,
                             std::chrono::system_clock::time_point wall_now) {
    writer.put_u32(static_cast<std::uint32_t>(
        std::min<std::uint64_t>(r.fwd_octets, 0xFFFFFFFFu)));
    writer.put_u32(static_cast<std::uint32_t>(
        std::min<std::uint64_t>(r.fwd_packets, 0xFFFFFFFFu)));
    writer.put_u8(r.protocol);
    writer.put_u8(r.tos);
    writer.put_u8(r.fwd_tcp_flags);
    writer.put_u16(r.src_port);
    writer.put_ipv4(*r.src);
    writer.put_u16(r.dst_port);
    writer.put_ipv4(*r.dst);
    write_time_values(writer, time_format, now, wall_now, r.first, r.last);
    write_mpls_labels(writer, *r.mpls_labels, mpls_label_count);
    // Reverse Information Elements (RFC 5103): the same three "traffic
    // volume" fields, but for the direction FlowKey's canonical ordering
    // put in slot [1].
    writer.put_u32(static_cast<std::uint32_t>(
        std::min<std::uint64_t>(r.rev_octets, 0xFFFFFFFFu)));
    writer.put_u32(static_cast<std::uint32_t>(
        std::min<std::uint64_t>(r.rev_packets, 0xFFFFFFFFu)));
    writer.put_u8(r.rev_tcp_flags);
}

void write_biflow_v6_record(ByteWriter& writer, const BiflowRecord& r,
                             IpfixTimeFormat time_format,
                             std::uint8_t mpls_label_count, TimePoint now,
                             std::chrono::system_clock::time_point wall_now) {
    writer.put_u32(static_cast<std::uint32_t>(
        std::min<std::uint64_t>(r.fwd_octets, 0xFFFFFFFFu)));
    writer.put_u32(static_cast<std::uint32_t>(
        std::min<std::uint64_t>(r.fwd_packets, 0xFFFFFFFFu)));
    writer.put_u8(r.protocol);
    writer.put_u8(r.tos);
    writer.put_u8(r.fwd_tcp_flags);
    writer.put_u16(r.src_port);
    writer.put_ipv6(*r.src);
    writer.put_u16(r.dst_port);
    writer.put_ipv6(*r.dst);
    write_time_values(writer, time_format, now, wall_now, r.first, r.last);
    write_mpls_labels(writer, *r.mpls_labels, mpls_label_count);
    writer.put_u32(static_cast<std::uint32_t>(
        std::min<std::uint64_t>(r.rev_octets, 0xFFFFFFFFu)));
    writer.put_u32(static_cast<std::uint32_t>(
        std::min<std::uint64_t>(r.rev_packets, 0xFFFFFFFFu)));
    writer.put_u8(r.rev_tcp_flags);
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

void IpfixExporter::write_template_set(ByteWriter& writer) const {
    const std::size_t set_start = writer.size();
    writer.put_u16(2); // Set ID 2 identifies a Template Set (IPFIX; NetFlow v9 uses 0)
    writer.put_u16(0); // Length placeholder, patched by finish_set()

    const auto write_template = [&](std::uint16_t template_id,
                                     std::span<const FieldSpec> fields) {
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
    };

    const auto [end_field, start_field] = time_field_pair(time_format_);

    if (!biflow_) {
        // Field order must exactly match write_v4_record()/write_v6_record().
        std::vector<FieldSpec> v4_fields = {
            {1, 4},   // octetDeltaCount
            {2, 4},   // packetDeltaCount
            {4, 1},   // protocolIdentifier
            {5, 1},   // ipClassOfService
            {6, 1},   // tcpControlBits
            {7, 2},   // sourceTransportPort
            {8, 4},   // sourceIPv4Address
            {11, 2},  // destinationTransportPort
            {12, 4},  // destinationIPv4Address
            end_field, start_field,
        };
        std::vector<FieldSpec> v6_fields = {
            {1, 4},   {2, 4},   {4, 1},   {5, 1},   {6, 1},
            {7, 2},   {27, 16}, // sourceIPv6Address
            {11, 2},  {28, 16}, // destinationIPv6Address
            end_field, start_field,
        };
        for (std::uint8_t i = 0; i < mpls_label_count_; ++i) {
            v4_fields.push_back({static_cast<std::uint16_t>(70 + i), 3});
            v6_fields.push_back({static_cast<std::uint16_t>(70 + i), 3});
        }
        write_template(kIpfixTemplateIdV4, v4_fields);
        write_template(kIpfixTemplateIdV6, v6_fields);
    } else {
        // Field order must exactly match write_biflow_v4_record()/
        // write_biflow_v6_record(): forward fields, time, MPLS, then the
        // three Reverse Information Elements (RFC 5103).
        std::vector<FieldSpec> v4_fields = {
            {1, 4},  {2, 4},  {4, 1},  {5, 1},  {6, 1},
            {7, 2},  {8, 4},  {11, 2}, {12, 4},
            end_field, start_field,
        };
        std::vector<FieldSpec> v6_fields = {
            {1, 4},  {2, 4},  {4, 1},   {5, 1},   {6, 1},
            {7, 2},  {27, 16}, {11, 2}, {28, 16},
            end_field, start_field,
        };
        for (std::uint8_t i = 0; i < mpls_label_count_; ++i) {
            v4_fields.push_back({static_cast<std::uint16_t>(70 + i), 3});
            v6_fields.push_back({static_cast<std::uint16_t>(70 + i), 3});
        }
        const FieldSpec reverse_octets{1, 4, kReversePen};
        const FieldSpec reverse_packets{2, 4, kReversePen};
        const FieldSpec reverse_tcp_flags{6, 1, kReversePen};
        for (auto* fields : {&v4_fields, &v6_fields}) {
            fields->push_back(reverse_octets);
            fields->push_back(reverse_packets);
            fields->push_back(reverse_tcp_flags);
        }
        write_template(kIpfixTemplateIdV4, v4_fields);
        write_template(kIpfixTemplateIdV6, v6_fields);
    }

    finish_set(writer, set_start);
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
    const auto pack = [&](auto& v4, auto& v6, auto write_v4, auto write_v6) {
        std::size_t v4_idx = 0, v6_idx = 0;
        while (v4_idx < v4.size() || v6_idx < v6.size()) {
            ByteWriter body;
            std::uint32_t data_records_in_packet = 0;

            const bool send_template = (packets_since_template_ == 0);
            if (send_template) {
                write_template_set(body);
            }

            if (v4_idx < v4.size()) {
                const std::size_t chunk =
                    std::min(kIpfixMaxV4RecordsPerSet, v4.size() - v4_idx);
                const std::size_t set_start = body.size();
                body.put_u16(kIpfixTemplateIdV4);
                body.put_u16(0);
                for (std::size_t i = 0; i < chunk; ++i) {
                    write_v4(body, v4[v4_idx + i]);
                }
                finish_set(body, set_start);
                data_records_in_packet += static_cast<std::uint32_t>(chunk);
                v4_idx += chunk;
            }

            if (v6_idx < v6.size()) {
                const std::size_t chunk =
                    std::min(kIpfixMaxV6RecordsPerSet, v6.size() - v6_idx);
                const std::size_t set_start = body.size();
                body.put_u16(kIpfixTemplateIdV6);
                body.put_u16(0);
                for (std::size_t i = 0; i < chunk; ++i) {
                    write_v6(body, v6[v6_idx + i]);
                }
                finish_set(body, set_start);
                data_records_in_packet += static_cast<std::uint32_t>(chunk);
                v6_idx += chunk;
            }

            ByteWriter packet;
            const auto message_length =
                static_cast<std::uint16_t>(16 /* header */ + body.size());
            write_header(packet, message_length, wall_now);
            packet.put_bytes(body.bytes());
            packets.push_back(packet.take());

            sequence_ += data_records_in_packet;
            packets_since_template_ = send_template ? 1 : packets_since_template_ + 1;
            if (packets_since_template_ >= kIpfixTemplateResendInterval) {
                packets_since_template_ = 0;
            }
        }
    };

    if (!biflow_) {
        std::vector<DirectionalRecord> v4, v6;
        flatten(records, v4, v6);
        pack(
            v4, v6,
            [&](ByteWriter& w, const DirectionalRecord& r) {
                write_v4_record(w, r, time_format_, mpls_label_count_, now, wall_now);
            },
            [&](ByteWriter& w, const DirectionalRecord& r) {
                write_v6_record(w, r, time_format_, mpls_label_count_, now, wall_now);
            });
    } else {
        std::vector<BiflowRecord> v4, v6;
        flatten_biflow(records, v4, v6);
        pack(
            v4, v6,
            [&](ByteWriter& w, const BiflowRecord& r) {
                write_biflow_v4_record(w, r, time_format_, mpls_label_count_, now,
                                        wall_now);
            },
            [&](ByteWriter& w, const BiflowRecord& r) {
                write_biflow_v6_record(w, r, time_format_, mpls_label_count_, now,
                                        wall_now);
            });
    }

    return packets;
}

} // namespace softflow
