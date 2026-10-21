// Original files: psamp.c, psamp.h
#include "softflow/psamp.hpp"

#include <algorithm>

namespace softflow {

namespace {

// Original: field_psamp[] -- selectionSequenceId, observationTimeMicroseconds,
// sectionExportedOctets and dataLinkFrameSection, and their IPFIX IDs.
struct FieldSpec {
  std::uint16_t id;
  std::uint16_t length;
};
constexpr FieldSpec kFields[] = {
  {301, 8},
  {324, 8},
  {410, 2},
  {315, static_cast<std::uint16_t> (kPsampFrameSectionSize)},
};
constexpr std::uint16_t kIpfixTemplateSetId = 2;
constexpr std::size_t kHeaderSize = 16;
constexpr std::size_t kSetHeaderSize = 4;

}  // namespace

void
PsampExporter::write_header (
  ByteWriter &writer, std::uint16_t length,
  std::chrono::system_clock::time_point export_time) const {
  writer.put_u16 (10);  // PSAMP uses IPFIX
  writer.put_u16 (length);
  writer.put_u32 (static_cast<std::uint32_t> (
    std::chrono::system_clock::to_time_t (export_time)));
  writer.put_u32 (sequence_);
  writer.put_u32 (observation_domain_id_);
}

std::vector<std::vector<std::uint8_t>>
PsampExporter::build_packets (
  const PsampSample &sample, std::chrono::system_clock::time_point wall_now,
  bool adjust_time, std::vector<std::size_t> *template_only_packets) {
  std::vector<std::vector<std::uint8_t>> packets;
  const auto export_time = adjust_time ? sample.observed_at : wall_now;

  if (messages_until_template_ <= 0) {
    ByteWriter body;
    body.put_u16 (kIpfixTemplateSetId);
    body.put_u16 (static_cast<std::uint16_t> (
      kSetHeaderSize + 4 + 4 * std::size (kFields)));
    body.put_u16 (kPsampTemplateId);
    body.put_u16 (static_cast<std::uint16_t> (std::size (kFields)));
    for (const auto &f : kFields) {
      body.put_u16 (f.id);
      body.put_u16 (f.length);
    }
    ByteWriter message;
    write_header (message, static_cast<std::uint16_t> (kHeaderSize + body.size()),
                  export_time);
    message.put_bytes (body.bytes());
    if (template_only_packets != nullptr) {
      template_only_packets->push_back (packets.size());
    }
    packets.push_back (message.take());
    messages_until_template_ = static_cast<int> (kPsampTemplateResendInterval);
  }

  // The data message always has the size of a full export packet: the
  // frame section is padded with zeroes.
  const std::size_t copy_size = std::min (sample.frame.size(), kPsampFrameSectionSize);
  ByteWriter message;
  write_header (message, static_cast<std::uint16_t> (kPsampMessageSize), export_time);
  message.put_u16 (kPsampTemplateId);
  message.put_u16 (static_cast<std::uint16_t> (kPsampMessageSize - kHeaderSize));
  message.put_u64 (sample.sequence_id);
  const auto us = std::chrono::duration_cast<std::chrono::microseconds> (
    sample.observed_at.time_since_epoch());
  message.put_u64 (unix_us_to_ntp64 (
    static_cast<std::uint64_t> (std::max<std::int64_t> (0, us.count()))));
  message.put_u16 (static_cast<std::uint16_t> (copy_size));
  message.put_bytes (sample.frame.first (copy_size));
  for (std::size_t i = message.size(); i < kPsampMessageSize; ++i) {
    message.put_u8 (0);
  }
  packets.push_back (message.take());

  --messages_until_template_;
  ++sequence_;
  return packets;
}

std::optional<PsampFrame>
decode_psamp_message (std::span<const std::uint8_t> data) {
  constexpr std::size_t kMinimum = kHeaderSize + kSetHeaderSize + kPsampFixedFieldsSize;
  if (data.size() < kMinimum) {
    return std::nullopt;
  }
  const auto u16 = [&] (std::size_t off) {
    return static_cast<std::uint16_t> ((data[off] << 8) | data[off + 1]);
  };
  if (u16 (0) != 10) {
    return std::nullopt;
  }
  if (u16 (kHeaderSize) != kPsampTemplateId) {
    return std::nullopt;  // only the data records of softflowd are decoded
  }
  std::size_t offset = kHeaderSize + kSetHeaderSize + 8;  // selectionSequenceId is not used
  std::uint64_t ntp = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    ntp = (ntp << 8) | data[offset + i];
  }
  offset += 8;
  PsampFrame out;
  out.observed_at = std::chrono::system_clock::time_point (
    std::chrono::microseconds (static_cast<std::int64_t> (ntp64_to_unix_us (ntp))));
  out.original_length = u16 (offset);
  offset += 2;
  // The frame section cannot be longer than what was received.
  const std::size_t caplen = std::min<std::size_t> (out.original_length, data.size() - offset);
  out.frame.assign (data.begin() + static_cast<std::ptrdiff_t> (offset),
                    data.begin() + static_cast<std::ptrdiff_t> (offset + caplen));
  return out;
}

}  // namespace softflow
