#include <cassert>
#include <cstdio>

#include "softflow/netflow5.hpp"

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

void test_header_version_and_sequence_increments() {
    const auto boot = Clock::now();
    Netflow5Exporter exporter(boot);

    const auto a = make_v4(10, 0, 0, 1);
    const auto b = make_v4(10, 0, 0, 2);
    const auto key = FlowKey::make_canonical(a, b, 1, 2, 6, 0, {0, 0});

    Flow flow;
    flow.flow_start = boot;
    flow.flow_last = boot;
    flow.octets = {100, 0};
    flow.packets = {1, 0};
    ExportRecord record{key, flow};

    const auto wall = std::chrono::system_clock::time_point(1700000000s);

    assert(exporter.flow_sequence() == 0);
    auto packets1 = exporter.build_packets(
        std::span<const ExportRecord>(&record, 1), boot + 1s, wall);
    assert(packets1.size() == 1);
    assert((packets1[0][0] << 8 | packets1[0][1]) == 5); // version
    assert(exporter.flow_sequence() == 1); // one directional record exported

    auto packets2 = exporter.build_packets(
        std::span<const ExportRecord>(&record, 1), boot + 2s, wall);
    // flow_sequence continues to increase across calls, matching the
    // original's single ever-incrementing counter per export destination.
    assert(exporter.flow_sequence() == 2);
    (void)packets2;
}

void test_record_size_and_count() {
    const auto boot = Clock::now();
    Netflow5Exporter exporter(boot);

    const auto a = make_v4(192, 168, 0, 1);
    const auto b = make_v4(8, 8, 8, 8);
    const auto key = FlowKey::make_canonical(a, b, 5000, 53, 17, 0, {0, 0});

    Flow flow;
    flow.flow_start = boot;
    flow.flow_last = boot + 500ms;
    flow.octets = {200, 400};
    flow.packets = {2, 3};
    ExportRecord record{key, flow};

    auto packets = exporter.build_packets(
        std::span<const ExportRecord>(&record, 1), boot + 1s,
        std::chrono::system_clock::time_point(1700000000s));

    assert(packets.size() == 1);
    // Both directions carried traffic -> 2 records.
    assert(packets[0].size() == kNetflow5HeaderSize + 2 * kNetflow5RecordSize);
}

} // namespace

int main() {
    test_header_version_and_sequence_increments();
    test_record_size_and_count();
    std::puts("all netflow5 tests passed");
    return 0;
}
