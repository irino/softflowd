#include "softflow/netflow9.hpp"

#include <algorithm>

namespace softflow {

namespace {

std::uint32_t uptime_ms(TimePoint boot_time, TimePoint t) {
    const auto delta = std::chrono::duration_cast<std::chrono::milliseconds>(
        t - boot_time);
    return static_cast<std::uint32_t>(std::max<std::int64_t>(0, delta.count()));
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
    const MplsLabelStack* mpls_labels; // never null; may be empty
};

// Original: ipv4_to_flowrec()/ipv6_to_flowrec() populated one struct FLOW
// per direction. Here, expired flows are split into per-direction,
// per-address-family lists so IPv4 and IPv6 records can go into their own
// FlowSets (a NetFlow v9 Data FlowSet's records must all match a single
// template, and the IPv4/IPv6 templates differ in field length).
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

// Pads `writer` up to a 4-byte boundary measured from `flowset_start`, then
// patches the FlowSet's Length field (the 2 bytes right after its 2-byte
// FlowSet ID, i.e. at flowset_start + 2) to the total FlowSet size
// including that padding, per RFC 3954 section 5.2 ("Padding... included
// in the length of the Set").
void finish_flowset(ByteWriter& writer, std::size_t flowset_start) {
    const std::size_t raw_length = writer.size() - flowset_start;
    const std::size_t pad = (4 - (raw_length % 4)) % 4;
    for (std::size_t i = 0; i < pad; ++i) {
        writer.put_u8(0);
    }
    writer.patch_u16(flowset_start + 2,
                      static_cast<std::uint16_t>(raw_length + pad));
}

// Original: -x number_of_mpls_labels. Writes mpls_label_count 3-octet
// mplsLabelStackSectionN fields (IANA Information Elements 70-79): the top
// 20 bits of a label stack entry's label, its 3-bit EXP field, and its
// bottom-of-stack bit, packed into 3 bytes (dropping the 4th byte, TTL,
// which these particular Information Elements don't carry). Flows with
// fewer labels than mpls_label_count are padded with zeroed sections;
// flows with more are truncated -- both cases keep every record's length
// matching what the template declares, which is required since NetFlow v9
// records carry no per-record length of their own.
void write_mpls_labels(ByteWriter& writer, const MplsLabelStack& labels,
                        std::uint8_t mpls_label_count) {
    for (std::uint8_t i = 0; i < mpls_label_count; ++i) {
        std::uint32_t section = 0;
        if (i < labels.size()) {
            const bool bottom = (static_cast<std::size_t>(i) + 1 == labels.size());
            // The 24-bit field mirrors the top 3 bytes of the original
            // 4-byte shim (bits 31-8: 20-bit label, 3-bit EXP, 1-bit S),
            // i.e. (label << 4) | (exp << 1) | S. EXP is always encoded
            // as 0 -- this project's packet parser only extracts the
            // label value itself, see softflowd.cpp's
            // parse_mpls_label_stack().
            section = (labels[i] << 4) | (bottom ? 0x1u : 0u);
        }
        writer.put_u8(static_cast<std::uint8_t>(section >> 16));
        writer.put_u8(static_cast<std::uint8_t>(section >> 8));
        writer.put_u8(static_cast<std::uint8_t>(section));
    }
}

void write_v4_record(ByteWriter& writer, const DirectionalRecord& r,
                      TimePoint boot_time, std::uint8_t mpls_label_count) {
    // Order and widths must exactly match the IPv4 template written by
    // write_template_flowset() below.
    writer.put_u32(static_cast<std::uint32_t>(
        std::min<std::uint64_t>(r.octets, 0xFFFFFFFFu)));  // IN_BYTES
    writer.put_u32(static_cast<std::uint32_t>(
        std::min<std::uint64_t>(r.packets, 0xFFFFFFFFu))); // IN_PKTS
    writer.put_u8(r.protocol);                              // PROTOCOL
    writer.put_u8(r.tos);                                   // SRC_TOS
    writer.put_u8(r.tcp_flags);                              // TCP_FLAGS
    writer.put_u16(r.src_port);                              // L4_SRC_PORT
    writer.put_ipv4(*r.src);                                 // IPV4_SRC_ADDR
    writer.put_u16(r.dst_port);                              // L4_DST_PORT
    writer.put_ipv4(*r.dst);                                 // IPV4_DST_ADDR
    writer.put_u32(uptime_ms(boot_time, r.last));             // LAST_SWITCHED
    writer.put_u32(uptime_ms(boot_time, r.first));            // FIRST_SWITCHED
    write_mpls_labels(writer, *r.mpls_labels, mpls_label_count);
}

void write_v6_record(ByteWriter& writer, const DirectionalRecord& r,
                      TimePoint boot_time, std::uint8_t mpls_label_count) {
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
    writer.put_u32(uptime_ms(boot_time, r.last));
    writer.put_u32(uptime_ms(boot_time, r.first));
    write_mpls_labels(writer, *r.mpls_labels, mpls_label_count);
}

} // namespace

void Netflow9Exporter::write_header(
    ByteWriter& writer, std::uint16_t record_count, TimePoint now,
    std::chrono::system_clock::time_point wall_now) const {
    const auto unix_time = std::chrono::system_clock::to_time_t(wall_now);

    writer.put_u16(9); // version
    writer.put_u16(record_count);
    writer.put_u32(uptime_ms(boot_time_, now));
    writer.put_u32(static_cast<std::uint32_t>(unix_time));
    writer.put_u32(sequence_);
    writer.put_u32(source_id_);
}

void Netflow9Exporter::write_template_flowset(ByteWriter& writer) const {
    // Original: netflow9.c's NF9_SOFTFLOWD_TEMPLATE definitions --
    // Information Element (type, length) pairs describing one flow
    // record's wire layout. The type numbers below are the standard
    // NetFlow v9 / IPFIX Information Element identifiers (RFC 3954 /
    // IANA's IPFIX Information Elements registry): 1=IN_BYTES,
    // 2=IN_PKTS, 4=PROTOCOL, 5=SRC_TOS, 6=TCP_FLAGS, 7=L4_SRC_PORT,
    // 8=IPV4_SRC_ADDR, 11=L4_DST_PORT, 12=IPV4_DST_ADDR,
    // 21=LAST_SWITCHED, 22=FIRST_SWITCHED, 27=IPV6_SRC_ADDR,
    // 28=IPV6_DST_ADDR, 70-79=MPLS_LABEL_1..10 (mplsLabelStackSection1
    // through mplsLabelStackSection10, each 3 octets).
    //
    // The field order here must exactly match the order fields are
    // *written* in write_v4_record()/write_v6_record() above -- a
    // template only describes field (type, length) pairs, not field
    // names, so the collector decodes purely positionally.
    struct FieldSpec {
        std::uint16_t type;
        std::uint16_t length;
    };

    const std::size_t flowset_start = writer.size();
    writer.put_u16(0); // FlowSet ID 0 identifies a Template FlowSet
    writer.put_u16(0); // Length placeholder, patched by finish_flowset()

    const auto write_template = [&](std::uint16_t template_id,
                                     std::span<const FieldSpec> fields) {
        writer.put_u16(template_id);
        writer.put_u16(static_cast<std::uint16_t>(fields.size() +
                                                    mpls_label_count_));
        for (const auto& f : fields) {
            writer.put_u16(f.type);
            writer.put_u16(f.length);
        }
        // Original: -x. IE 70 is mplsLabelStackSection1, 71 is section2,
        // and so on through 79 (section10) -- mpls_label_count_ is
        // clamped to [0, 10] by the constructor.
        for (std::uint8_t i = 0; i < mpls_label_count_; ++i) {
            writer.put_u16(static_cast<std::uint16_t>(70 + i));
            writer.put_u16(3);
        }
    };

    // Must match write_v4_record()'s write order exactly.
    static constexpr FieldSpec kIpv4Fields[] = {
        {1, 4},   // IN_BYTES
        {2, 4},   // IN_PKTS
        {4, 1},   // PROTOCOL
        {5, 1},   // SRC_TOS
        {6, 1},   // TCP_FLAGS
        {7, 2},   // L4_SRC_PORT
        {8, 4},   // IPV4_SRC_ADDR
        {11, 2},  // L4_DST_PORT
        {12, 4},  // IPV4_DST_ADDR
        {21, 4},  // LAST_SWITCHED
        {22, 4},  // FIRST_SWITCHED
    };
    write_template(kNetflow9TemplateIdV4, kIpv4Fields);

    // Must match write_v6_record()'s write order exactly.
    static constexpr FieldSpec kIpv6Fields[] = {
        {1, 4},   // IN_BYTES
        {2, 4},   // IN_PKTS
        {4, 1},   // PROTOCOL
        {5, 1},   // SRC_TOS
        {6, 1},   // TCP_FLAGS
        {7, 2},   // L4_SRC_PORT
        {27, 16}, // IPV6_SRC_ADDR
        {11, 2},  // L4_DST_PORT
        {28, 16}, // IPV6_DST_ADDR
        {21, 4},  // LAST_SWITCHED
        {22, 4},  // FIRST_SWITCHED
    };
    write_template(kNetflow9TemplateIdV6, kIpv6Fields);

    finish_flowset(writer, flowset_start);
}

std::vector<std::vector<std::uint8_t>>
Netflow9Exporter::build_packets(
    std::span<const ExportRecord> records, TimePoint now,
    std::chrono::system_clock::time_point wall_now) {
    std::vector<DirectionalRecord> v4, v6;
    flatten(records, v4, v6);

    std::vector<std::vector<std::uint8_t>> packets;
    std::size_t v4_idx = 0, v6_idx = 0;

    while (v4_idx < v4.size() || v6_idx < v6.size()) {
        ByteWriter body;
        std::uint16_t record_count = 0;

        const bool send_template = (packets_since_template_ == 0);
        if (send_template) {
            write_template_flowset(body);
            record_count += 2; // two template definitions
        }

        if (v4_idx < v4.size()) {
            const std::size_t chunk =
                std::min(kNetflow9MaxV4RecordsPerFlowSet, v4.size() - v4_idx);
            const std::size_t flowset_start = body.size();
            body.put_u16(kNetflow9TemplateIdV4);
            body.put_u16(0); // length placeholder
            for (std::size_t i = 0; i < chunk; ++i) {
                write_v4_record(body, v4[v4_idx + i], boot_time_,
                                 mpls_label_count_);
            }
            finish_flowset(body, flowset_start);
            record_count += static_cast<std::uint16_t>(chunk);
            v4_idx += chunk;
        }

        if (v6_idx < v6.size()) {
            const std::size_t chunk =
                std::min(kNetflow9MaxV6RecordsPerFlowSet, v6.size() - v6_idx);
            const std::size_t flowset_start = body.size();
            body.put_u16(kNetflow9TemplateIdV6);
            body.put_u16(0);
            for (std::size_t i = 0; i < chunk; ++i) {
                write_v6_record(body, v6[v6_idx + i], boot_time_,
                                 mpls_label_count_);
            }
            finish_flowset(body, flowset_start);
            record_count += static_cast<std::uint16_t>(chunk);
            v6_idx += chunk;
        }

        ByteWriter packet;
        write_header(packet, record_count, now, wall_now);
        packet.put_bytes(body.bytes());
        packets.push_back(packet.take());

        ++sequence_;
        packets_since_template_ =
            send_template ? 1 : packets_since_template_ + 1;
        if (packets_since_template_ >= kNetflow9TemplateResendInterval) {
            packets_since_template_ = 0; // triggers a resend next call
        }
    }

    return packets;
}

} // namespace softflow
