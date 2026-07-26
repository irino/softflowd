#include <cassert>
#include <cstdio>

#include "softflow/netflow9.hpp"

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

IpAddress make_v6(std::uint8_t last_byte) {
    IpAddress addr;
    addr.family = AddressFamily::IPv6;
    addr.bytes[0] = 0x20;
    addr.bytes[1] = 0x01;
    addr.bytes[15] = last_byte;
    return addr;
}

std::uint16_t read_u16(const std::vector<std::uint8_t>& b, std::size_t off) {
    return static_cast<std::uint16_t>((b[off] << 8) | b[off + 1]);
}

void test_no_records_produces_no_packets() {
    const auto boot = Clock::now();
    Netflow9Exporter exporter(boot);
    auto packets = exporter.build_packets(
        {}, boot + 1s, std::chrono::system_clock::time_point(1700000000s));
    assert(packets.empty());
}

void test_first_packet_includes_template_flowset() {
    const auto boot = Clock::now();
    Netflow9Exporter exporter(boot);

    const auto a = make_v4(192, 168, 1, 10);
    const auto b = make_v4(93, 184, 216, 34);
    const auto key = FlowKey::make_canonical(a, b, 54321, 443, 6, 0, {0, 0});

    Flow flow;
    flow.flow_start = boot;
    flow.flow_last = boot + 1s;
    flow.octets = {1500, 0};
    flow.packets = {10, 0};

    ExportRecord record{key, flow};
    auto packets = exporter.build_packets(
        std::span<const ExportRecord>(&record, 1), boot + 2s,
        std::chrono::system_clock::time_point(1700000000s));

    assert(packets.size() == 1);
    const auto& pkt = packets[0];

    // Header: version=9
    assert(read_u16(pkt, 0) == 9);
    // First FlowSet right after the 20-byte header must be the Template
    // FlowSet (FlowSet ID 0).
    assert(read_u16(pkt, 20) == 0);
    assert(exporter.sequence() == 1);
}

void test_second_packet_omits_template_flowset() {
    const auto boot = Clock::now();
    Netflow9Exporter exporter(boot);

    const auto a = make_v4(10, 0, 0, 1);
    const auto b = make_v4(10, 0, 0, 2);
    const auto key = FlowKey::make_canonical(a, b, 1, 2, 6, 0, {0, 0});
    Flow flow;
    flow.flow_start = boot;
    flow.flow_last = boot;
    flow.octets = {10, 0};
    flow.packets = {1, 0};
    ExportRecord record{key, flow};

    auto packets1 = exporter.build_packets(
        std::span<const ExportRecord>(&record, 1), boot + 1s,
        std::chrono::system_clock::time_point(1700000000s));
    assert(packets1.size() == 1);
    assert(read_u16(packets1[0], 20) == 0); // template flowset present

    auto packets2 = exporter.build_packets(
        std::span<const ExportRecord>(&record, 1), boot + 2s,
        std::chrono::system_clock::time_point(1700000000s));
    assert(packets2.size() == 1);
    // The very next FlowSet should now be the IPv4 data FlowSet
    // (FlowSet ID == kNetflow9TemplateIdV4), not another template FlowSet.
    assert(read_u16(packets2[0], 20) == kNetflow9TemplateIdV4);
}

void test_mixed_ipv4_and_ipv6_records() {
    const auto boot = Clock::now();
    Netflow9Exporter exporter(boot);

    const auto a4 = make_v4(172, 16, 0, 1);
    const auto b4 = make_v4(172, 16, 0, 2);
    const auto key4 = FlowKey::make_canonical(a4, b4, 100, 200, 6, 0, {0, 0});
    Flow flow4;
    flow4.flow_start = boot;
    flow4.flow_last = boot;
    flow4.octets = {500, 0};
    flow4.packets = {5, 0};

    const auto a6 = make_v6(1);
    const auto b6 = make_v6(2);
    const auto key6 = FlowKey::make_canonical(a6, b6, 53, 12345, 17, 0, {0, 0});
    Flow flow6;
    flow6.flow_start = boot;
    flow6.flow_last = boot;
    flow6.octets = {300, 0};
    flow6.packets = {3, 0};

    std::vector<ExportRecord> records{{key4, flow4}, {key6, flow6}};
    auto packets =
        exporter.build_packets(records, boot + 1s,
                                std::chrono::system_clock::time_point(1700000000s));

    assert(packets.size() == 1);
    const auto& pkt = packets[0];
    // record_count in the header = 2 templates + 1 ipv4 record + 1 ipv6 record
    assert(read_u16(pkt, 2) == 4);

    // Walk the FlowSets: template (id 0), then ipv4 data (id 256), then
    // ipv6 data (id 257).
    std::size_t offset = 20;
    assert(read_u16(pkt, offset) == 0);
    std::size_t template_len = read_u16(pkt, offset + 2);
    offset += template_len;

    assert(read_u16(pkt, offset) == kNetflow9TemplateIdV4);
    std::size_t v4_len = read_u16(pkt, offset + 2);
    offset += v4_len;

    assert(read_u16(pkt, offset) == kNetflow9TemplateIdV6);
    std::size_t v6_len = read_u16(pkt, offset + 2);
    offset += v6_len;

    assert(offset == pkt.size());
}

} // namespace

int main() {
    test_no_records_produces_no_packets();
    test_first_packet_includes_template_flowset();
    test_second_packet_omits_template_flowset();
    test_mixed_ipv4_and_ipv6_records();
    std::puts("all netflow9 tests passed");
    return 0;
}
