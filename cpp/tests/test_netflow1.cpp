#include <cassert>
#include <cstdio>

#include "softflow/netflow1.hpp"

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

void test_no_records_produces_no_packets() {
    const auto boot = Clock::now();
    Netflow1Exporter exporter(boot);

    const auto now = boot + 5s;
    const auto wall = std::chrono::system_clock::time_point(1700000000s);

    auto packets = exporter.build_packets({}, now, wall);
    assert(packets.empty());
}

void test_single_bidirectional_flow_produces_two_records() {
    const auto boot = Clock::now();
    Netflow1Exporter exporter(boot);

    const auto a = make_v4(192, 168, 1, 10);
    const auto b = make_v4(93, 184, 216, 34);
    const auto key = FlowKey::make_canonical(a, b, 54321, 443, 6, 0, {0, 0});

    Flow flow;
    flow.flow_start = boot + 1s;
    flow.flow_last = boot + 2s;
    flow.octets = {1500, 900};
    flow.packets = {10, 8};
    flow.tcp_flags = {0x02, 0x12};

    ExportRecord record{key, flow};
    const auto now = boot + 3s;
    const auto wall = std::chrono::system_clock::time_point(1700000000s);

    auto packets = exporter.build_packets(
        std::span<const ExportRecord>(&record, 1), now, wall);

    assert(packets.size() == 1);
    const auto& pkt = packets[0];

    // Header: version=1, count=2 (both directions carried traffic)
    assert(pkt.size() == kNetflow1HeaderSize + 2 * kNetflow1RecordSize);
    assert((pkt[0] << 8 | pkt[1]) == 1);   // version
    assert((pkt[2] << 8 | pkt[3]) == 2);   // count

    // First record starts right after the 16-byte header.
    const std::uint8_t* rec0 = pkt.data() + kNetflow1HeaderSize;
    // srcaddr should be one of the two endpoints (the smaller one, per
    // FlowKey's canonical ordering, is addr()[0]).
    assert(rec0[0] == 93 || rec0[0] == 192);
}

void test_zero_traffic_direction_is_not_exported() {
    const auto boot = Clock::now();
    Netflow1Exporter exporter(boot);

    const auto a = make_v4(10, 0, 0, 1);
    const auto b = make_v4(10, 0, 0, 2);
    const auto key = FlowKey::make_canonical(a, b, 1000, 2000, 17, 0, {0, 0});

    Flow flow;
    flow.flow_start = boot + 1s;
    flow.flow_last = boot + 1s;
    flow.octets = {100, 0}; // only direction 0 ever carried traffic
    flow.packets = {1, 0};

    ExportRecord record{key, flow};
    auto packets = exporter.build_packets(
        std::span<const ExportRecord>(&record, 1), boot + 2s,
        std::chrono::system_clock::time_point(1700000000s));

    assert(packets.size() == 1);
    assert(packets[0].size() == kNetflow1HeaderSize + kNetflow1RecordSize);
}

void test_chunking_across_multiple_packets() {
    const auto boot = Clock::now();
    Netflow1Exporter exporter(boot);

    std::vector<ExportRecord> records;
    // 35 unidirectional flows -> exceeds kNetflow1MaxRecordsPerPacket (30),
    // so this must be split into two packets.
    for (int i = 0; i < 35; ++i) {
        const auto a = make_v4(10, 0, 0, static_cast<std::uint8_t>(i));
        const auto b = make_v4(10, 1, 0, static_cast<std::uint8_t>(i));
        const auto key = FlowKey::make_canonical(
            a, b, static_cast<std::uint16_t>(2000 + i), 80, 6, 0, {0, 0});
        Flow flow;
        flow.flow_start = boot;
        flow.flow_last = boot;
        flow.octets = {64, 0};
        flow.packets = {1, 0};
        records.push_back(ExportRecord{key, flow});
    }

    auto packets = exporter.build_packets(
        records, boot + 1s, std::chrono::system_clock::time_point(1700000000s));
    assert(packets.size() == 2);
    assert(packets[0].size() ==
           kNetflow1HeaderSize + kNetflow1MaxRecordsPerPacket * kNetflow1RecordSize);
    assert(packets[1].size() == kNetflow1HeaderSize + 5 * kNetflow1RecordSize);
}

} // namespace

int main() {
    test_no_records_produces_no_packets();
    test_single_bidirectional_flow_produces_two_records();
    test_zero_traffic_direction_is_not_exported();
    test_chunking_across_multiple_packets();
    std::puts("all netflow1 tests passed");
    return 0;
}
