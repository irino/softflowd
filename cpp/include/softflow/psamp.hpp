// Original files: psamp.c, psamp.h
//
// PSAMP (RFC 5476, RFC 5477) reports individual packets rather than flows,
// in the framing of IPFIX (RFC 7011). The message of softflowd carries one
// captured packet: its position in the sequence of sampled packets, its
// capture time, the number of octets of the frame that are exported and the
// frame itself, in a record of fixed size so that every data message has the
// size of a full export packet.
#ifndef SOFTFLOW_PSAMP_HPP
#define SOFTFLOW_PSAMP_HPP

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "softflow/ipfix.hpp"
#include "softflow/softflowd.hpp"

namespace softflow {

// Original: PSAMP_SOFTFLOWD_TEMPLATE_ID.
inline constexpr std::uint16_t kPsampTemplateId = 3072;

// Original: IPFIX_SOFTFLOWD_MAX_PACKET_SIZE, the size of every data message,
// and PSAMP_DATALINKFRAME_SIZE, what is left of it after the IPFIX header,
// the set header and the fields that precede the frame section.
inline constexpr std::size_t kPsampMessageSize = kIpfixMaxPacketSize;
inline constexpr std::size_t kPsampFixedFieldsSize = 8 + 8 + 2;
inline constexpr std::size_t kPsampFrameSectionSize =
  kPsampMessageSize - 16 - 4 - kPsampFixedFieldsSize;

// Original: IPFIX_DEFAULT_TEMPLATE_INTERVAL, in data messages.
inline constexpr std::uint32_t kPsampTemplateResendInterval = 16;

// One captured packet to be exported, starting at the link layer.
struct PsampSample {
  std::span<const std::uint8_t> frame;                // the captured bytes (caplen)
  std::chrono::system_clock::time_point observed_at;  // capture time
  std::uint64_t sequence_id{0};                       // number of sampled packets so far
};

class PsampExporter {
public:
  explicit PsampExporter (std::uint32_t observation_domain_id = 0)
      : observation_domain_id_ (observation_domain_id) {
  }

  // Original: send_psamp(). Returns the messages to send for one sampled
  // packet: the template message when it is due (its index is added to
  // *template_only_packets, as it goes to every destination) followed by
  // the data message. adjust_time uses the capture time, and not the
  // current time wall_now, as the export time.
  std::vector<std::vector<std::uint8_t>>
  build_packets (const PsampSample &sample,
                 std::chrono::system_clock::time_point wall_now,
                 bool adjust_time,
                 std::vector<std::size_t> *template_only_packets = nullptr);

  // The IPFIX sequence number of the next message: the number of data
  // messages built so far.
  std::uint32_t
  sequence () const noexcept {
    return sequence_; }

private:
  void
  write_header (ByteWriter &writer, std::uint16_t length,
                std::chrono::system_clock::time_point export_time) const;

  std::uint32_t observation_domain_id_;
  std::uint32_t sequence_{0};
  // Data messages until the template is sent again: -1 = never, 0 or less
  // = with the next message.
  int messages_until_template_{-1};
};

// A packet that was received in a PSAMP message of softflowd.
struct PsampFrame {
  std::vector<std::uint8_t> frame;
  std::uint32_t original_length{0};  // sectionExportedOctets
  std::chrono::system_clock::time_point observed_at;
};

// Original: recv_psamp(). Decodes one received UDP payload, which is fed to
// flow tracking as if it had been captured. Only the data records that
// softflowd itself exports are decoded: nullopt is returned for any other
// set and for a message that is not IPFIX or is too short. The frame is cut
// at what was received. Never throws.
std::optional<PsampFrame>
decode_psamp_message (std::span<const std::uint8_t> data);

} // namespace softflow

#endif // SOFTFLOW_PSAMP_HPP
