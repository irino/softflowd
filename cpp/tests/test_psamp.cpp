#include <cassert>
#include <cstdio>
#include <vector>

#include "softflow/psamp.hpp"

using namespace softflow;
using namespace std::chrono_literals;

namespace {

std::uint16_t read_u16(const std::vector<std::uint8_t>& b, std::size_t off) {
    return static_cast<std::uint16_t>((b[off] << 8) | b[off + 1]);
}

std::uint32_t
read_u32 (const std::vector<std::uint8_t> &b, std::size_t off) {
  return (static_cast<std::uint32_t> (read_u16 (b, off)) << 16) | read_u16 (b, off + 2);
}

std::vector<std::uint8_t>
make_frame (std::size_t n) {
  std::vector<std::uint8_t> frame (n);
  for (std::size_t i = 0; i < n; ++i)
    frame[i] = static_cast<std::uint8_t> (i + 1);
  return frame;
}

const auto kObserved = std::chrono::system_clock::time_point (1700000000s + 250000us);
const auto kNow = std::chrono::system_clock::time_point (1700000100s);

void
test_first_sample_sends_template_then_fixed_size_data () {
  PsampExporter exporter;
  const auto frame = make_frame (60);
  std::vector<std::size_t> template_only;
  const auto packets = exporter.build_packets (
    PsampSample{frame, kObserved, 7}, kNow, false, &template_only);

  // The template message, 16 + 4 + 4 + 4 * 4 = 40 octets, and the data one.
  assert (packets.size() == 2);
  assert (template_only.size() == 1 && template_only[0] == 0);
  assert (packets[0].size() == 40);
  assert (read_u16 (packets[0], 0) == 10 && read_u16 (packets[0], 2) == 40);
  assert (read_u32 (packets[0], 4) == 1700000100);  // export time: now
  assert (read_u32 (packets[0], 8) == 0);           // sequence number
  assert (read_u16 (packets[0], 16) == 2);          // template set
  assert (read_u16 (packets[0], 20) == kPsampTemplateId);
  assert (read_u16 (packets[0], 22) == 4);  // four fields
  assert (read_u16 (packets[0], 24) == 301 && read_u16 (packets[0], 26) == 8);
  assert (read_u16 (packets[0], 36) == 315);
  assert (read_u16 (packets[0], 38) == kPsampFrameSectionSize);

  // The data message always has the size of a full export packet.
  assert (packets[1].size() == kPsampMessageSize);
  assert (read_u16 (packets[1], 2) == kPsampMessageSize);
  assert (read_u32 (packets[1], 8) == 0);  // sequence of this record
  assert (read_u16 (packets[1], 16) == kPsampTemplateId);
  assert (read_u16 (packets[1], 18) == kPsampMessageSize - 16);
  assert (read_u32 (packets[1], 24) == 7);   // selectionSequenceId (low)
  assert (read_u16 (packets[1], 36) == 60);  // sectionExportedOctets
  assert (packets[1][38] == 1 && packets[1][38 + 59] == 60);
  assert (packets[1][38 + 60] == 0);  // padded with zeroes
  assert (exporter.sequence() == 1);
}

void
test_template_is_repeated_every_16_messages () {
  PsampExporter exporter;
  const auto frame = make_frame (20);
  std::size_t templates = 0;
  for (int i = 0; i < 33; ++i) {
    std::vector<std::size_t> t;
    const auto p = exporter.build_packets (PsampSample{frame, kObserved, 1}, kNow,
                                           false, &t);
    templates += t.size();
    assert (p.size() == 1 + t.size());
    if (i == 0 || i == 16 || i == 32)
      assert (t.size() == 1);
    else
      assert (t.empty());
  }
  assert (templates == 3);
  assert (exporter.sequence() == 33);
}

void
test_long_frame_is_cut_and_adjust_time_uses_the_capture_time () {
  PsampExporter exporter;
  const auto frame = make_frame (3000);
  const auto packets = exporter.build_packets (PsampSample{frame, kObserved, 1}, kNow, true);
  assert (read_u32 (packets[0], 4) == 1700000000);  // capture time
  assert (read_u16 (packets[1], 36) == kPsampFrameSectionSize);
  assert (packets[1].size() == kPsampMessageSize);
}

void
test_message_is_decoded_and_the_frame_is_cut_at_what_was_received () {
  PsampExporter exporter;
  const auto frame = make_frame (100);
  const auto packets = exporter.build_packets (PsampSample{frame, kObserved, 1}, kNow, false);

  // The template message is not a data record of softflowd.
  assert (!decode_psamp_message (packets[0]).has_value());

  const auto decoded = decode_psamp_message (packets[1]);
  assert (decoded.has_value());
  assert (decoded->original_length == 100 && decoded->frame == frame);
  const auto us = std::chrono::duration_cast<std::chrono::microseconds> (
                    decoded->observed_at - kObserved)
                    .count();
  assert (us >= -2 && us <= 2);  // NTP fraction rounding

  // A datagram that ends inside the frame section.
  const std::vector<std::uint8_t> shorter (packets[1].begin(), packets[1].begin() + 38 + 30);
  const auto cut = decode_psamp_message (shorter);
  assert (cut.has_value() && cut->frame.size() == 30 && cut->original_length == 100);
}

void
test_malformed_messages_are_rejected () {
  assert (!decode_psamp_message ({}).has_value());
  std::vector<std::uint8_t> shorter (37, 0);
  assert (!decode_psamp_message (shorter).has_value());
  PsampExporter exporter;
  const auto frame = make_frame (10);
  auto packets = exporter.build_packets (PsampSample{frame, kObserved, 1}, kNow, false);
  packets[1][1] = 9;  // not IPFIX
  assert (!decode_psamp_message (packets[1]).has_value());
}

} // namespace

int main() {
  test_first_sample_sends_template_then_fixed_size_data();
  test_template_is_repeated_every_16_messages();
  test_long_frame_is_cut_and_adjust_time_uses_the_capture_time();
  test_message_is_decoded_and_the_frame_is_cut_at_what_was_received();
  test_malformed_messages_are_rejected();
  std::puts ("all PSAMP tests passed");
  return 0;
}
