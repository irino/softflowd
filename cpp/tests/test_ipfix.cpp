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

std::uint32_t read_u32(const std::vector<std::uint8_t>& b, std::size_t off) {
    return (static_cast<std::uint32_t>(read_u16(b, off)) << 16) |
           read_u16(b, off + 2);
}

ExportRecord make_record(Clock::time_point boot, int i, bool both_directions) {
    const auto a = make_v4(10, 0, 0, static_cast<std::uint8_t>(i));
    const auto b = make_v4(10, 1, 0, static_cast<std::uint8_t>(i));
    const auto key = FlowKey::make_canonical(
        a, b, static_cast<std::uint16_t>(2000 + i), 80, 6, 0, {0, 0});
    Flow flow;
    flow.flow_start = boot;
    flow.flow_last = boot + 1s;
    flow.octets = {100, both_directions ? 200u : 0u};
    flow.packets = {1, both_directions ? 2u : 0u};
    return ExportRecord{key, flow};
}

void test_netflow9_header_and_sets() {
    const auto boot = Clock::now();
    IpfixExporter exporter(0, 0, IpfixTimeFormat::SysUpTime, false, boot, {},
                           MessageVersion::NetFlow9);
    const auto record = make_record(boot, 1, true);
    auto packets = exporter.build_packets(
        std::span<const ExportRecord>(&record, 1), boot + 2s,
        std::chrono::system_clock::time_point(1700000000s));
    assert(packets.size() == 1);
    const auto& pkt = packets[0];
    assert(read_u16(pkt, 0) == 9);          // version
    assert(read_u16(pkt, 2) == 2);          // data records (one per direction)
    assert(read_u32(pkt, 4) == 2000);       // sysUpTime
    assert(read_u32(pkt, 8) == 1700000000); // unix_secs
    assert(read_u32(pkt, 12) == 1);         // sequence counts packets from 1
    assert(read_u16(pkt, 20) == 0);         // template FlowSet ID
    // The options template FlowSet (ID 1) has the scope Interface, 4 octets.
    std::size_t off = 20;
    while (read_u16(pkt, off) == 0) off += read_u16(pkt, off + 2);
    assert(read_u16(pkt, off) == 1 && read_u16(pkt, off + 2) == 26);
    assert(read_u16(pkt, off + 10) == 2 && read_u16(pkt, off + 12) == 4);
    // Its data record follows, unpadded (29 octets).
    off += 26;
    assert(read_u16(pkt, off) == 256 && read_u16(pkt, off + 2) == 29);
    // The data FlowSet is padded so that the packet ends on a multiple of 4.
    assert(pkt.size() % 4 == 0);

    // The next packet carries the next sequence number and no templates.
    packets = exporter.build_packets(
        std::span<const ExportRecord>(&record, 1), boot + 2s,
        std::chrono::system_clock::time_point(1700000000s));
    assert(read_u32(packets[0], 12) == 2);
    assert(read_u16(packets[0], 20) == 1024);
}

void test_packet_size_includes_header_and_reserves_two_records() {
    const auto boot = Clock::now();
    IpfixExporter exporter;
    std::vector<ExportRecord> records;
    for (int i = 0; i < 60; ++i) records.push_back(make_record(boot, i, false));
    const auto packets = exporter.build_packets(
        records, boot + 2s, std::chrono::system_clock::time_point(1700000000s));
    assert(packets.size() >= 2);
    for (const auto& pkt : packets) {
        assert(pkt.size() <= kIpfixMaxPacketSize);
    }
}

void test_exporter_address_is_reported_in_the_options_record() {
    const auto boot = Clock::now();
    IpfixExporter exporter;
    ExporterAddresses addresses;
    addresses.v4 = std::array<std::uint8_t, 4>{192, 0, 2, 7};
    exporter.set_exporter_addresses(addresses);
    const auto record = make_record(boot, 1, false);
    const auto packets = exporter.build_packets(
        std::span<const ExportRecord>(&record, 1), boot + 2s,
        std::chrono::system_clock::time_point(1700000000s));
    const std::array<std::uint8_t, 4> needle{192, 0, 2, 7};
    std::size_t found = 0;
    const auto& pkt = packets[0];
    for (std::size_t i = 0; i + 4 <= pkt.size(); ++i) {
        if (std::equal(needle.begin(), needle.end(), pkt.begin() + static_cast<std::ptrdiff_t>(i))) ++found;
    }
    // exporterIPv4Address and originalExporterIPv4Address
    assert(found == 2);
}

void
test_template_only_packet_is_reported_separately () {
  const auto boot = Clock::now();
  const auto record = make_record (boot, 1, false);
  const auto wall = std::chrono::system_clock::time_point (1700000000s);
  for (const auto version :
       {MessageVersion::Ipfix, MessageVersion::NetFlow9}) {
    IpfixExporter exporter (0, 0, IpfixTimeFormat::SysUpTime, false, boot,
                            {}, version);
    std::vector<std::size_t> template_only;
    auto packets = exporter.build_packets (
      std::span<const ExportRecord> (&record, 1), boot + 2s, wall,
      &template_only);
    // The first packet has only the templates; the data packet has none.
    assert (packets.size() == 2);
    assert (template_only.size() == 1 && template_only[0] == 0);
    const std::size_t header = version == MessageVersion::Ipfix ? 16 : 20;
    assert (read_u16 (packets[0], header) ==
            (version == MessageVersion::Ipfix ? 2 : 0));
    assert (read_u16 (packets[1], header) == 1024);
    if (version == MessageVersion::NetFlow9) {
      assert (read_u16 (packets[0], 2) == 1);  // count
      assert (read_u32 (packets[0], 12) == 1);
      assert (read_u32 (packets[1], 12) == 2);
    }
    // Without the argument the templates stay in the data packet.
    IpfixExporter plain (0, 0, IpfixTimeFormat::SysUpTime, false, boot, {},
                         version);
    assert (plain.build_packets (std::span<const ExportRecord> (&record, 1),
                                 boot + 2s, wall)
              .size() == 1);
  }
}

void
test_vlan_and_ether_fields_follow_the_tracking_level () {
  const auto boot = Clock::now();
  const auto a = make_v4 (10, 0, 0, 1);
  const auto b = make_v4 (10, 1, 0, 1);
  const std::array<std::array<std::uint8_t, 6>, 2> macs = {
    std::array<std::uint8_t, 6>{2, 0, 0, 0, 0, 0xA1},
    std::array<std::uint8_t, 6>{2, 0, 0, 0, 0, 0xB2}};
  const auto key = FlowKey::make_canonical (a, b, 2000, 80, 6, 0, {7, 9}, macs);
  Flow flow;
  flow.flow_start = boot;
  flow.flow_last = boot + 1s;
  flow.octets = {100, 0};
  flow.packets = {1, 0};
  const ExportRecord record{key, flow};
  const auto wall = std::chrono::system_clock::time_point (1700000000s);

  std::size_t base_len = 0;
  for (const auto level : {TrackLevel::IpProtoPort, TrackLevel::FullVlan,
                           TrackLevel::FullVlanEther}) {
    IpfixExporter exporter (0, 0, IpfixTimeFormat::SysUpTime, false, boot,
                            {}, MessageVersion::Ipfix, 0, 0, level);
    const auto pkts = exporter.build_packets (
      std::span<const ExportRecord> (&record, 1), boot + 2s, wall);
    const auto &pkt = pkts[0];
    const auto has = [&] (const std::array<std::uint8_t, 6> &mac) {
      for (std::size_t i = 0; i + 6 <= pkt.size(); ++i) {
        if (std::equal (mac.begin(), mac.end(),
                        pkt.begin() + static_cast<std::ptrdiff_t> (i)))
          return true;
      }
      return false;
    };
    // sourceMacAddress is the sender's, postDestinationMacAddress the
    // receiver's.
    const bool ether = level == TrackLevel::FullVlanEther;
    assert (has (macs[0]) == ether && has (macs[1]) == ether);
    // The packet also carries the templates, which grow with the fields.
    if (level != TrackLevel::IpProtoPort)
      assert (pkt.size() > base_len);
    base_len = pkt.size();
  }
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
    test_netflow9_header_and_sets();
    test_exporter_address_is_reported_in_the_options_record();
    test_template_only_packet_is_reported_separately();
    test_vlan_and_ether_fields_follow_the_tracking_level();
    test_packet_size_includes_header_and_reserves_two_records();
    std::puts("all ipfix tests passed");
    return 0;
}
