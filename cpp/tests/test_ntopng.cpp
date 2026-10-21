#include <cassert>
#include <cstdio>
#include <vector>

#include "softflow/ntopng.hpp"

using namespace softflow;
using namespace std::chrono_literals;

namespace {

IpAddress
make_v4 (std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
  IpAddress addr{};
  addr.family = AddressFamily::IPv4;
  addr.bytes[0] = a;
  addr.bytes[1] = b;
  addr.bytes[2] = c;
  addr.bytes[3] = d;
  return addr;
}

ExportRecord
make_record (TimePoint boot, int i) {
  const auto key = FlowKey::make_canonical (
    make_v4 (10, 0, 0, static_cast<std::uint8_t> (i)), make_v4 (172, 16, 0, 6),
    static_cast<std::uint16_t> (2000 + i), 80, 6, 0, {0, 0});
  Flow flow;
  flow.flow_start = boot;
  flow.flow_last = boot + 2s;
  flow.octets = {100, 0};
  flow.packets = {1, 0};
  flow.tcp_flags = {0x12, 0};
  return ExportRecord{key, flow};
}

std::uint32_t
be32 (const std::vector<std::uint8_t> &b, std::size_t off) {
  std::uint32_t v = 0;
  for (std::size_t i = 0; i < 4; ++i)
    v = (v << 8) | b[off + i];
  return v;
}

void
test_header_and_tlv_of_one_flow () {
  const auto boot = Clock::now();
  const auto wall = std::chrono::system_clock::time_point (1700000000s);
  NtopngExporter exporter (TrackLevel::IpProtoPort);
  const auto record = make_record (boot, 1);
  auto messages = exporter.build_messages (std::span<const ExportRecord> (&record, 1),
                                           boot + 2s, wall);
  assert (messages.size() == 1);
  const auto &m = messages[0];

  // zmq_msg_hdr_v4: the url, version 4, the TLV flag, the sizes, the message
  // id and the source id.
  assert (m.header.size() == kNtopngHeaderSize);
  assert (std::string (m.header.begin(), m.header.begin() + 4) == "flow");
  assert (m.header[4] == 0 && m.header[16] == 4 && m.header[17] == 2);
  assert (be32 (m.header, 20) == m.payload.size() && be32 (m.header, 24) == m.payload.size());
  assert (be32 (m.header, 28) == 0 && be32 (m.header, 32) == 0);

  // The payload: TLV version and format, the items, the end of record.
  assert (m.payload[0] == 1 && m.payload[1] == 1);
  // L4_SRC_PORT (7) is 2001, a 16 bit value: type bytes 0x23, key 7, value.
  assert (m.payload[2] == 0x23 && m.payload[3] == 7);
  assert (m.payload[4] == 0x07 && m.payload[5] == 0xd1);
  assert (m.payload.back() == 1);
  // The addresses are strings.
  const std::string text (m.payload.begin(), m.payload.end());
  assert (text.find ("10.0.0.1") != std::string::npos);
  assert (text.find ("172.16.0.6") != std::string::npos);
  // FIRST_SWITCHED (22) and LAST_SWITCHED (21) are epoch seconds,
  // 1699999998 and 1700000000: 32 bit values, type bytes 0x24.
  const std::string first ("\x24\x16\x65\x53\xf0\xfe", 6);
  const std::string last ("\x24\x15\x65\x53\xf1\x00", 6);
  assert (text.find (first) != std::string::npos && text.find (last) != std::string::npos);

  // The message id counts the messages.
  messages = exporter.build_messages (std::span<const ExportRecord> (&record, 1), boot + 2s, wall);
  assert (be32 (messages[0].header, 28) == 1);
}

void
test_flows_are_split_into_messages_of_limited_size () {
  const auto boot = Clock::now();
  const auto wall = std::chrono::system_clock::time_point (1700000000s);
  NtopngExporter exporter (TrackLevel::FullVlanEther);
  std::vector<ExportRecord> records;
  for (int i = 0; i < 400; ++i)
    records.push_back (make_record (boot, i % 250));
  const auto messages = exporter.build_messages (records, boot + 2s, wall);
  assert (messages.size() >= 2);
  std::size_t flows = 0;
  for (const auto &m : messages) {
    assert (m.payload.size() <= kNtopngMaxTlvSize);
    // Count the MAC strings of the Ethernet level, two per flow.
    const std::string text (m.payload.begin(), m.payload.end());
    for (std::size_t pos = 0; (pos = text.find ("00:00:00:00:00:00", pos)) != std::string::npos; pos += 17)
      ++flows;
  }
  assert (flows == 800);
}

}  // namespace

int
main () {
  test_header_and_tlv_of_one_flow();
  test_flows_are_split_into_messages_of_limited_size();
  std::puts ("all ntopng tests passed");
  return 0;
}
