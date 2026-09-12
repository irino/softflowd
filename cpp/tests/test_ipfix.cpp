#include <cassert>
#include <cstdio>

#include "softflow/ipfix.hpp"

using namespace softflow;
using namespace std::chrono_literals;

namespace {

IpAddress make_v4(std::uint8_t a, std::uint8_t b, std::uint8_t c,
                   std::uint8_t d) {
    IpAddress addr;
    addr.family = AddressFamily::IPv4;
    addr.bytes[0] = a;
    addr.bytes[1] = b;
    addr.bytes[2] = c;
    addr.bytes[3] = d;
    return addr;
}

std::uint16_t read_u16(const std::vector<std::uint8_t>& b, std::size_t off) {
    return static_cast<std::uint16_t>((b[off] << 8) | b[off + 1]);
}

std::uint64_t read_u64(const std::vector<std::uint8_t>& b, std::size_t off) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | b[off + static_cast<std::size_t>(i)];
    }
    return v;
}

// Scans Sets starting right after the 16-byte message header and returns
// the body offset (i.e. just past the 4-byte Set header) of the first Set
// whose Set ID equals `target_id`. Every test below needs this: since
// Template Sets, the Options Template Set, and the Options Data Set are
// now each their own Set (see IpfixExporter::write_template_set()/
// write_options_set()), a Data Set is no longer simply "whatever comes
// right after offset 16".
std::size_t find_set(const std::vector<std::uint8_t>& pkt, std::uint16_t target_id) {
    std::size_t offset = 16;
    while (offset + 4 <= pkt.size()) {
        const auto set_id = read_u16(pkt, offset);
        const auto set_len = read_u16(pkt, offset + 2);
        if (set_id == target_id) {
            return offset + 4;
        }
        offset += set_len;
    }
    assert(false && "target Set ID not found in packet");
    return 0;
}

void test_header_version_and_length() {
    const auto boot = Clock::now();
    IpfixExporter exporter;

    const auto a = make_v4(10, 0, 0, 1);
    const auto b = make_v4(10, 0, 0, 2);
    const auto key = FlowKey::make_canonical(a, b, 1, 2, 6, 0, {0, 0});
    Flow flow;
    flow.flow_start = boot;
    flow.flow_last = boot + 1s;
    flow.octets = {100, 0};
    flow.packets = {1, 0};
    ExportRecord record{key, flow};

    auto packets = exporter.build_packets(
        std::span<const ExportRecord>(&record, 1), boot + 2s,
        std::chrono::system_clock::time_point(1700000000s));

    assert(packets.size() == 1);
    const auto& pkt = packets[0];
    assert(read_u16(pkt, 0) == 10); // version
    assert(read_u16(pkt, 2) == pkt.size()); // length field == total message size
    // Set ID 2 (Template Set) must be the first Set after the 16-byte header.
    assert(read_u16(pkt, 16) == 2);

    // Sequence counts Data Records, and exactly one was sent.
    assert(exporter.sequence() == 1);
}

void test_absolute_timestamp_round_trip() {
    const auto boot = Clock::now();
    // Explicit Milliseconds: IpfixExporter's default is now SysUpTime (see
    // IpfixTimeFormat's doc comment), which is relative to boot_time, not
    // absolute epoch time -- this test is specifically about the
    // absolute-epoch-time encodings selectable via -A.
    IpfixExporter exporter(/*observation_domain_id=*/0, /*mpls_label_count=*/0,
                            IpfixTimeFormat::Milliseconds);

    const auto a = make_v4(1, 2, 3, 4);
    const auto b = make_v4(5, 6, 7, 8);
    const auto key = FlowKey::make_canonical(a, b, 10, 20, 6, 0, {0, 0});

    const auto now = boot + 10s;
    Flow flow;
    flow.flow_start = now - 5s; // flow began 5s before "now"
    flow.flow_last = now;
    flow.octets = {1000, 0};
    flow.packets = {1, 0};
    ExportRecord record{key, flow};

    const auto wall_now = std::chrono::system_clock::time_point(1700000000s);
    auto packets = exporter.build_packets(
        std::span<const ExportRecord>(&record, 1), now, wall_now);
    assert(packets.size() == 1);
    const auto& pkt = packets[0];

    const std::size_t record_start = find_set(pkt, kIpfixTemplateIdV4);

    // Field order: sourceIPv4Address(4) destinationIPv4Address(4)
    // flowStartMilliseconds(8) flowEndMilliseconds(8) ...
    const std::size_t start_ms_offset = record_start + 4 + 4;
    const std::size_t end_ms_offset = start_ms_offset + 8;

    const std::uint64_t start_ms = read_u64(pkt, start_ms_offset);
    const std::uint64_t end_ms = read_u64(pkt, end_ms_offset);

    // flow_last == now -> its epoch time should equal wall_now exactly.
    const auto expected_end_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            wall_now.time_since_epoch())
            .count());
    assert(end_ms == expected_end_ms);
    // flow_start was 5s earlier than flow_last -> its epoch time should be
    // exactly 5000ms earlier too.
    assert(expected_end_ms - start_ms == 5000);
}

void test_sequence_counts_data_records_not_templates() {
    const auto boot = Clock::now();
    IpfixExporter exporter;

    std::vector<ExportRecord> records;
    for (int i = 0; i < 3; ++i) {
        const auto a = make_v4(10, 0, 0, static_cast<std::uint8_t>(i));
        const auto b = make_v4(10, 1, 0, static_cast<std::uint8_t>(i));
        const auto key = FlowKey::make_canonical(
            a, b, static_cast<std::uint16_t>(1000 + i), 80, 6, 0, {0, 0});
        Flow flow;
        flow.flow_start = boot;
        flow.flow_last = boot;
        flow.octets = {10, 0};
        flow.packets = {1, 0};
        records.push_back(ExportRecord{key, flow});
    }

    exporter.build_packets(records, boot + 1s,
                            std::chrono::system_clock::time_point(1700000000s));
    // 3 directional data records were sent (the Template Set's 2 template
    // definitions must NOT be counted, unlike NetFlow v9's record_count).
    assert(exporter.sequence() == 3);
}

void test_biflow_combines_both_directions_into_one_record() {
    IpfixExporter exporter(/*observation_domain_id=*/0, /*mpls_label_count=*/0,
                            IpfixTimeFormat::Milliseconds, /*biflow=*/true);

    const auto a = make_v4(10, 0, 0, 1);
    const auto b = make_v4(10, 0, 0, 2);
    const auto key = FlowKey::make_canonical(a, b, 1000, 80, 6, 0, {0, 0});

    Flow flow;
    flow.flow_start = Clock::now();
    flow.flow_last = flow.flow_start + 1s;
    flow.octets = {500, 300};   // forward, reverse
    flow.packets = {5, 3};
    flow.tcp_flags = {0x02, 0x12};
    ExportRecord record{key, flow};

    auto packets = exporter.build_packets(
        std::span<const ExportRecord>(&record, 1), flow.flow_last,
        std::chrono::system_clock::time_point(1700000000s));
    assert(packets.size() == 1);
    const auto& pkt = packets[0];

    // Exactly one Data Record for a bidirectional flow (not two, unlike
    // the default per-direction encoding) -> sequence increments by 1.
    assert(exporter.sequence() == 1);

    // Find the IPv4 Data Set and confirm its record count implies a
    // single, wider record rather than two ordinary ones.
    const std::size_t record_start = find_set(pkt, kIpfixTemplateIdV4);
    const std::size_t v4_set_length = read_u16(pkt, record_start - 2);
    // Forward fields: addr(8) + time(8+8=16 for Milliseconds) +
    // common(18) + transport(8) = 50 bytes, plus the Reverse Information
    // Elements tail: reverse octets(4) + packets(4) + tos(1) +
    // tcpControlBits(1) = 10 bytes -- 4-byte Set header + 60-byte record
    // = 64, already a multiple of 4 (no padding needed).
    assert(v4_set_length == 4 + 60);
}

void test_time_format_seconds_uses_four_byte_fields() {
    IpfixExporter exporter(/*observation_domain_id=*/0, /*mpls_label_count=*/0,
                            IpfixTimeFormat::Seconds);

    const auto a = make_v4(1, 1, 1, 1);
    const auto b = make_v4(2, 2, 2, 2);
    const auto key = FlowKey::make_canonical(a, b, 1, 2, 6, 0, {0, 0});
    Flow flow;
    flow.flow_start = Clock::now();
    flow.flow_last = flow.flow_start;
    flow.octets = {10, 0};
    flow.packets = {1, 0};
    ExportRecord record{key, flow};

    auto packets = exporter.build_packets(
        std::span<const ExportRecord>(&record, 1), flow.flow_last,
        std::chrono::system_clock::time_point(1700000000s));
    assert(packets.size() == 1);
    const auto& pkt = packets[0];

    // The IPv4 Data Set's record is addr(8) + time(4+4=8 for Seconds) +
    // common(18) + transport(8) = 42 bytes -> 4-byte Set header + 42 = 46,
    // padded up to a 4-byte boundary -> 48.
    const std::size_t record_start = find_set(pkt, kIpfixTemplateIdV4);
    const std::size_t set_length = read_u16(pkt, record_start - 2);
    assert(set_length == 48);
}

void test_time_format_microseconds_round_trips_via_ntp64() {
    IpfixExporter exporter(/*observation_domain_id=*/0, /*mpls_label_count=*/0,
                            IpfixTimeFormat::Microseconds);

    const auto a = make_v4(1, 1, 1, 1);
    const auto b = make_v4(2, 2, 2, 2);
    const auto key = FlowKey::make_canonical(a, b, 1, 2, 6, 0, {0, 0});

    const auto now = Clock::now();
    Flow flow;
    flow.flow_start = now;
    flow.flow_last = now;
    flow.octets = {10, 0};
    flow.packets = {1, 0};
    ExportRecord record{key, flow};

    const auto wall_now = std::chrono::system_clock::time_point(1700000000s);
    auto packets = exporter.build_packets(
        std::span<const ExportRecord>(&record, 1), now, wall_now);
    assert(packets.size() == 1);
    const auto& pkt = packets[0];

    const std::size_t record_start = find_set(pkt, kIpfixTemplateIdV4);
    // Field order: sourceIPv4Address(4) destinationIPv4Address(4)
    // flowStartMicroseconds(8, NTP64) flowEndMicroseconds(8, NTP64) ...
    const std::size_t end_field_offset = record_start + 4 + 4 + 8;
    const std::uint64_t ntp64 = read_u64(pkt, end_field_offset);

    // NTP 64-bit format: top 32 bits are seconds since 1900-01-01. Since
    // flow_last == now == wall_now, the NTP seconds field should equal
    // wall_now's Unix time plus the 1900->1970 offset.
    const auto expected_unix_seconds =
        std::chrono::duration_cast<std::chrono::seconds>(wall_now.time_since_epoch())
            .count();
    const std::uint32_t ntp_seconds = static_cast<std::uint32_t>(ntp64 >> 32);
    assert(ntp_seconds == static_cast<std::uint32_t>(expected_unix_seconds) + 2208988800u);
}

void test_mpls_labels_are_included_when_configured() {
    IpfixExporter exporter(/*observation_domain_id=*/0, /*mpls_label_count=*/2);

    const auto a = make_v4(1, 1, 1, 1);
    const auto b = make_v4(2, 2, 2, 2);
    const auto key = FlowKey::make_canonical(a, b, 1, 2, 6, 0, {0, 0});
    Flow flow;
    flow.flow_start = Clock::now();
    flow.flow_last = flow.flow_start;
    flow.octets = {10, 0};
    flow.packets = {1, 0};
    // Raw wire sections (label(20)|EXP(3)|S(1)): label 12345 with EXP=3,
    // not bottom-of-stack; label 999 with EXP=0, bottom-of-stack. Chosen
    // to also exercise EXP pass-through, not just the label number.
    flow.mpls_labels = {(12345u << 4) | (3u << 1) | 0u, (999u << 4) | (0u << 1) | 1u};
    ExportRecord record{key, flow};

    auto packets = exporter.build_packets(
        std::span<const ExportRecord>(&record, 1), flow.flow_last,
        std::chrono::system_clock::time_point(1700000000s));
    assert(packets.size() == 1);
    const auto& pkt = packets[0];

    std::size_t record_start = find_set(pkt, kIpfixTemplateIdV4);
    // addr(8) + time(4+4=8 for the default SysUpTime format) + common(18)
    // + transport(8) = 42 bytes of ordinary fields, then 2 * 3-byte MPLS
    // label sections.
    const std::size_t mpls_offset = record_start + 42;
    const std::uint32_t first_section = (static_cast<std::uint32_t>(pkt[mpls_offset]) << 16) |
                                      (static_cast<std::uint32_t>(pkt[mpls_offset + 1]) << 8) |
                                      pkt[mpls_offset + 2];
    assert((first_section >> 4) == 12345);
    assert(((first_section >> 1) & 0x7) == 3); // EXP, passed through verbatim
    assert((first_section & 0x1) == 0);        // not the last label in the stack

    const std::uint32_t second_section =
        (static_cast<std::uint32_t>(pkt[mpls_offset + 3]) << 16) |
        (static_cast<std::uint32_t>(pkt[mpls_offset + 4]) << 8) |
        pkt[mpls_offset + 5];
    assert((second_section >> 4) == 999);
    assert(((second_section >> 1) & 0x7) == 0);
    assert((second_section & 0x1) != 0); // bottom-of-stack
}

} // namespace

int main() {
    test_header_version_and_length();
    test_absolute_timestamp_round_trip();
    test_sequence_counts_data_records_not_templates();
    test_biflow_combines_both_directions_into_one_record();
    test_time_format_seconds_uses_four_byte_fields();
    test_time_format_microseconds_round_trips_via_ntp64();
    test_mpls_labels_are_included_when_configured();
    std::puts("all ipfix tests passed");
    return 0;
}
