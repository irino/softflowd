#include <cassert>
#include <cstdio>

#include "softflow/psamp.hpp"

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

void test_no_samples_produces_no_packets() {
    PsampExporter exporter;
    auto packets = exporter.build_packets(
        {}, Clock::now(), std::chrono::system_clock::now());
    assert(packets.empty());
}

void test_make_sampled_packet_copies_fields() {
    ParsedPacket parsed;
    parsed.src = make_v4(1, 2, 3, 4);
    parsed.dst = make_v4(5, 6, 7, 8);
    parsed.src_port = 1111;
    parsed.dst_port = 2222;
    parsed.protocol = 6;
    parsed.tos = 8;

    const auto now = Clock::now();
    auto sample = make_sampled_packet(parsed, 1500, now);
    assert(sample.src == parsed.src);
    assert(sample.dst == parsed.dst);
    assert(sample.src_port == 1111);
    assert(sample.dst_port == 2222);
    assert(sample.protocol == 6);
    assert(sample.tos == 8);
    assert(sample.observed_length == 1500);
    assert(sample.observed_at == now);
}

void test_single_sample_builds_one_packet_with_template() {
    PsampExporter exporter;

    SampledPacket sample;
    sample.src = make_v4(192, 168, 1, 1);
    sample.dst = make_v4(8, 8, 8, 8);
    sample.src_port = 5000;
    sample.dst_port = 53;
    sample.protocol = 17;
    sample.observed_length = 74;
    sample.observed_at = Clock::now();

    auto packets = exporter.build_packets(
        std::span<const SampledPacket>(&sample, 1), sample.observed_at,
        std::chrono::system_clock::now());

    assert(packets.size() == 1);
    const auto& pkt = packets[0];
    assert(read_u16(pkt, 0) == 10); // IPFIX version, reused by PSAMP
    assert(read_u16(pkt, 2) == pkt.size()); // length field matches actual size
    assert(read_u16(pkt, 16) == 2); // Template Set ID
    assert(exporter.sequence() == 1);
}

void test_mixed_families_split_into_separate_sets() {
    PsampExporter exporter;

    SampledPacket v4_sample;
    v4_sample.src = make_v4(10, 0, 0, 1);
    v4_sample.dst = make_v4(10, 0, 0, 2);
    v4_sample.observed_length = 100;
    v4_sample.observed_at = Clock::now();

    SampledPacket v6_sample;
    v6_sample.src.family = AddressFamily::IPv6;
    v6_sample.dst.family = AddressFamily::IPv6;
    v6_sample.observed_length = 120;
    v6_sample.observed_at = v4_sample.observed_at;

    std::vector<SampledPacket> samples{v4_sample, v6_sample};
    auto packets = exporter.build_packets(
        samples, v4_sample.observed_at, std::chrono::system_clock::now());

    assert(packets.size() == 1);
    const auto& pkt = packets[0];

    std::size_t offset = 16;
    assert(read_u16(pkt, offset) == 2); // Template Set
    offset += read_u16(pkt, offset + 2);
    assert(read_u16(pkt, offset) == kPsampTemplateIdV4);
    offset += read_u16(pkt, offset + 2);
    assert(read_u16(pkt, offset) == kPsampTemplateIdV6);
    offset += read_u16(pkt, offset + 2);
    assert(offset == pkt.size());
}

void test_receiver_round_trips_exporter_output() {
    PsampExporter exporter;

    SampledPacket original;
    original.src = make_v4(192, 168, 1, 100);
    original.dst = make_v4(93, 184, 216, 34);
    original.src_port = 51234;
    original.dst_port = 443;
    original.protocol = 6;
    original.tos = 8;
    original.observed_length = 1420;
    original.observed_at = Clock::now();

    const auto wall_now = std::chrono::system_clock::now();
    auto packets = exporter.build_packets(
        std::span<const SampledPacket>(&original, 1), original.observed_at, wall_now);
    assert(packets.size() == 1);

    // A single receiver instance decodes both the Template Set (updating
    // its internal template table) and the Data Set from the same
    // message, exactly as it would from a real UDP datagram.
    PsampReceiver receiver;
    auto decoded = receiver.decode_message(packets[0], Clock::now());
    assert(decoded.size() == 1);

    const auto& sample = decoded[0];
    assert(sample.src == original.src);
    assert(sample.dst == original.dst);
    assert(sample.src_port == original.src_port);
    assert(sample.dst_port == original.dst_port);
    assert(sample.protocol == original.protocol);
    assert(sample.tos == original.tos);
    assert(sample.observed_length == original.observed_length);
}

void test_receiver_handles_template_and_data_across_separate_messages() {
    // Exercises the case where the Template Set arrived in an earlier
    // datagram than the Data Set referencing it (which is exactly what
    // happens after PsampExporter's first packets_since_template_-driven
    // template resend interval elapses) -- the receiver must remember the
    // template across separate decode_message() calls.
    PsampExporter exporter;
    PsampReceiver receiver;

    SampledPacket first;
    first.src = make_v4(10, 0, 0, 1);
    first.dst = make_v4(10, 0, 0, 2);
    first.observed_length = 100;
    first.observed_at = Clock::now();

    auto packets1 = exporter.build_packets(
        std::span<const SampledPacket>(&first, 1), first.observed_at,
        std::chrono::system_clock::now());
    assert(packets1.size() == 1);
    auto decoded1 = receiver.decode_message(packets1[0], Clock::now());
    assert(decoded1.size() == 1);

    SampledPacket second = first;
    second.observed_length = 200;
    auto packets2 = exporter.build_packets(
        std::span<const SampledPacket>(&second, 1), second.observed_at,
        std::chrono::system_clock::now());
    assert(packets2.size() == 1);

    // The second packet's Data Set uses the template the receiver already
    // learned from the first message.
    auto decoded2 = receiver.decode_message(packets2[0], Clock::now());
    assert(decoded2.size() == 1);
    assert(decoded2[0].observed_length == 200);
}

void test_receiver_ignores_garbage_input() {
    PsampReceiver receiver;
    const std::vector<std::uint8_t> garbage{0x00, 0x01, 0x02};
    auto decoded = receiver.decode_message(garbage, Clock::now());
    assert(decoded.empty());

    // A too-short but otherwise-plausible-looking header must not crash
    // either.
    const std::vector<std::uint8_t> short_header{0x00, 0x0a, 0x00, 0x10};
    auto decoded2 = receiver.decode_message(short_header, Clock::now());
    assert(decoded2.empty());
}

void test_receiver_scopes_templates_by_source() {
    // Two independent exporters both happen to use the same numeric
    // template IDs (each starts fresh, so both assign kPsampTemplateIdV4/
    // V6 the same way) -- this is exactly the scenario source-scoping
    // exists to handle: template IDs only need to be unique per exporter,
    // not globally, so a receiver serving multiple senders must not
    // conflate them.
    PsampExporter exporter_a;
    PsampExporter exporter_b;
    PsampReceiver receiver;

    SampledPacket sample_a;
    sample_a.src = make_v4(10, 0, 0, 1);
    sample_a.dst = make_v4(10, 0, 0, 2);
    sample_a.observed_length = 111;
    sample_a.observed_at = Clock::now();

    SampledPacket sample_b;
    sample_b.src = make_v4(172, 16, 0, 1);
    sample_b.dst = make_v4(172, 16, 0, 2);
    sample_b.observed_length = 222;
    sample_b.observed_at = Clock::now();

    auto packets_a = exporter_a.build_packets(
        std::span<const SampledPacket>(&sample_a, 1), sample_a.observed_at,
        std::chrono::system_clock::now());
    auto packets_b = exporter_b.build_packets(
        std::span<const SampledPacket>(&sample_b, 1), sample_b.observed_at,
        std::chrono::system_clock::now());
    assert(packets_a.size() == 1);
    assert(packets_b.size() == 1);

    auto decoded_a =
        receiver.decode_message(packets_a[0], Clock::now(), "10.0.0.100:9000");
    auto decoded_b =
        receiver.decode_message(packets_b[0], Clock::now(), "10.0.0.200:9000");

    assert(decoded_a.size() == 1);
    assert(decoded_b.size() == 1);
    assert(decoded_a[0].observed_length == 111);
    assert(decoded_b[0].observed_length == 222);

    // Each source's (v4, v6) template pair is tracked independently: 2
    // per source * 2 sources = 4 (source, template ID) entries tracked in
    // total, not 2 (which is what sharing a single un-scoped table would
    // have produced).
    assert(receiver.template_count() == 4);
}

} // namespace

int main() {
    test_no_samples_produces_no_packets();
    test_make_sampled_packet_copies_fields();
    test_single_sample_builds_one_packet_with_template();
    test_mixed_families_split_into_separate_sets();
    test_receiver_round_trips_exporter_output();
    test_receiver_handles_template_and_data_across_separate_messages();
    test_receiver_ignores_garbage_input();
    test_receiver_scopes_templates_by_source();
    std::puts("all psamp tests passed");
    return 0;
}
