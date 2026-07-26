#include <cassert>
#include <cstdio>
#include <vector>

#include "softflow/softflowd.hpp"

using namespace softflow;

namespace {

// Builds a minimal 20-byte IPv4 header + a 20-byte TCP header.
std::vector<std::uint8_t> build_ipv4_tcp_packet() {
    std::vector<std::uint8_t> pkt(20 + 20, 0);
    pkt[0] = 0x45; // version 4, IHL 5 (20 bytes)
    pkt[1] = 0x00; // tos
    pkt[9] = 6;    // protocol = TCP
    // src 192.168.1.10
    pkt[12] = 192; pkt[13] = 168; pkt[14] = 1; pkt[15] = 10;
    // dst 93.184.216.34
    pkt[16] = 93; pkt[17] = 184; pkt[18] = 216; pkt[19] = 34;

    // TCP header (starting at offset 20)
    pkt[20] = 0xD4; pkt[21] = 0x31; // src port 54321
    pkt[22] = 0x01; pkt[23] = 0xBB; // dst port 443
    pkt[33] = 0x02; // flags = SYN

    return pkt;
}

void test_parse_ipv4_tcp() {
    const auto pkt = build_ipv4_tcp_packet();
    PacketParser parser(TrackLevel::IpProtoPort);
    auto result = parser.parse(pkt, AddressFamily::IPv4);
    assert(result.has_value());
    assert(result->protocol == 6);
    assert(result->src_port == 54321);
    assert(result->dst_port == 443);
    assert(result->tcp_flags == 0x02);
    assert(result->src.bytes[0] == 192 && result->src.bytes[3] == 10);
    assert(result->dst.bytes[0] == 93 && result->dst.bytes[3] == 34);
}

void test_runt_ipv4_header_rejected() {
    // Fewer than 20 bytes: not a valid IPv4 header. If there were an
    // out-of-bounds read here, ASan would abort right at this call --
    // this test doubles as a memory-safety check.
    std::vector<std::uint8_t> pkt(10, 0);
    pkt[0] = 0x45;
    PacketParser parser(TrackLevel::IpProtoPort);
    auto result = parser.parse(pkt, AddressFamily::IPv4);
    assert(!result.has_value());
}

void test_runt_tcp_after_ip_header_is_safe() {
    // A valid IP header, but only 1 byte follows it for the "TCP header".
    // The original also had a caplen check here, so this should behave the
    // same way -- re-verified under ASan for extra confidence.
    std::vector<std::uint8_t> pkt(21, 0);
    pkt[0] = 0x45;
    pkt[9] = 6; // TCP
    PacketParser parser(TrackLevel::IpProtoPort);
    auto result = parser.parse(pkt, AddressFamily::IPv4);
    assert(result.has_value());
    // The transport layer could not be read, so the ports stay at 0.
    assert(result->src_port == 0);
    assert(result->dst_port == 0);
}

void test_icmp_runt_packet_is_safe() {
    // The original had no caplen check for ICMP and read
    // icmp->icmp_type/icmp_code from a payload as short as 1 byte. Here it
    // should safely fall back to "not extracted" instead.
    std::vector<std::uint8_t> pkt(21, 0);
    pkt[0] = 0x45;
    pkt[9] = 1; // ICMP
    pkt.resize(21); // leave only 1 byte of transport payload
    PacketParser parser(TrackLevel::IpProtoPort);
    auto result = parser.parse(pkt, AddressFamily::IPv4);
    assert(result.has_value());
    assert(result->dst_port == 0);
}

void test_parse_ipv6_with_extension_headers() {
    // IPv6 base header (40) + Hop-by-Hop extension (8) + TCP header (20)
    std::vector<std::uint8_t> pkt(40 + 8 + 20, 0);
    pkt[0] = 0x60; // version 6
    pkt[6] = 0;    // next header = Hop-by-Hop Options
    // src = ::1 (all zero except the last byte)
    pkt[8 + 15] = 1;
    // dst = ::2
    pkt[24 + 15] = 2;

    // Hop-by-Hop extension header (offset 40)
    pkt[40] = 6;    // next header = TCP
    pkt[41] = 0;    // ext len = 0 -> (0+1)*8 = 8 bytes

    // TCP header (offset 48)
    pkt[48] = 0x00; pkt[49] = 0x50; // src port 80
    pkt[50] = 0x1F; pkt[51] = 0x90; // dst port 8080
    pkt[61] = 0x12; // flags SYN+ACK

    PacketParser parser(TrackLevel::IpProtoPort);
    auto result = parser.parse(pkt, AddressFamily::IPv6);
    assert(result.has_value());
    assert(result->protocol == 6);
    assert(result->src_port == 80);
    assert(result->dst_port == 8080);
    assert(result->dst.bytes[15] == 2);
}

void test_ipv6_extension_header_loop_terminates() {
    // A crafted packet whose extension header keeps pointing back at
    // itself still cannot cause an infinite loop, since the loop always
    // requires forward progress before another iteration is considered
    // (a regression test for the latent infinite-loop risk in the
    // original code).
    std::vector<std::uint8_t> pkt(40 + 8, 0);
    pkt[0] = 0x60;
    pkt[6] = 0; // Hop-by-Hop
    pkt[40] = 0; // next header still points at Hop-by-Hop
    pkt[41] = 0; // ext len 0 -> advance by 8 bytes

    PacketParser parser(TrackLevel::IpProtoPort);
    auto result = parser.parse(pkt, AddressFamily::IPv6);
    // The loop always terminates once the data runs out, and returns a
    // result either way.
    assert(result.has_value());
}

} // namespace

int main() {
    test_parse_ipv4_tcp();
    test_runt_ipv4_header_rejected();
    test_runt_tcp_after_ip_header_is_safe();
    test_icmp_runt_packet_is_safe();
    test_parse_ipv6_with_extension_headers();
    test_ipv6_extension_header_loop_terminates();
    std::puts("all packet parser tests passed");
    return 0;
}
