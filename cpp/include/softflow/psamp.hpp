/**
 * @file psamp.hpp
 * @brief The export of the packets in PSAMP (RFC 5476, RFC 5477), and its receiver.
 *
 * PSAMP reports individual packets rather than flows, in the framing of IPFIX
 * (RFC 7011). The message of softflowd carries one captured packet: its
 * position in the sequence of sampled packets, its capture time, the number of
 * octets of the frame that are exported and the frame itself, in a record of
 * fixed size so that every data message has the size of a full export packet.
 *
 * @original psamp.c, psamp.h.
 */
#ifndef SOFTFLOW_PSAMP_HPP
#define SOFTFLOW_PSAMP_HPP

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "softflow/export_common.hpp"
#include "softflow/softflowd.hpp"

namespace softflow {

/**
 * @brief The Template ID of the template of the PSAMP data messages.
 *
 * @original PSAMP_SOFTFLOWD_TEMPLATE_ID.
 */
inline constexpr std::uint16_t kPsampTemplateId = 3072;

/**
 * @brief The size in octets of every data message.
 *
 * @original IPFIX_SOFTFLOWD_MAX_PACKET_SIZE.
 */
inline constexpr std::size_t kPsampMessageSize = kIpfixMaxPacketSize;
/** @brief The size in octets of the fields that precede the frame section. */
inline constexpr std::size_t kPsampFixedFieldsSize = 8 + 8 + 2;
/**
 * @brief The size in octets of the frame section: what is left of a message
 * after the IPFIX header, the set header and the fields that precede it.
 *
 * @original PSAMP_DATALINKFRAME_SIZE.
 */
inline constexpr std::size_t kPsampFrameSectionSize =
  kPsampMessageSize - 16 - 4 - kPsampFixedFieldsSize;

/**
 * @brief The number of data messages after which the template is sent again.
 *
 * @original IPFIX_DEFAULT_TEMPLATE_INTERVAL, in data messages.
 */
inline constexpr std::uint32_t kPsampTemplateResendInterval = 16;

/** @brief One captured packet to be exported, starting at the link layer. */
struct PsampSample {
  std::span<const std::uint8_t> frame;                ///< The captured bytes (caplen).
  std::chrono::system_clock::time_point observed_at;  ///< The capture time.
  std::uint64_t sequence_id{0};                       ///< The number of sampled packets so far.
};

/** @brief Builds the PSAMP messages for the sampled packets. */
class PsampExporter {
public:
  /**
   * @brief Creates an exporter.
   * @param observation_domain_id The Observation Domain ID of the messages.
   */
  explicit PsampExporter (std::uint32_t observation_domain_id = 0)
      : observation_domain_id_ (observation_domain_id) {
  }

  /**
   * @brief Builds the messages to send for one sampled packet.
   *
   * The template message comes first when it is due, followed by the data
   * message.
   *
   * @param sample The packet.
   * @param wall_now The current wall clock time.
   * @param adjust_time Use the capture time of the packet, and not
   *        @p wall_now, as the export time.
   * @param template_only_packets When not null, the index of the template
   *        message is added to it, as that message goes to every destination.
   * @return The messages, in the order to send them.
   *
   * @original send_psamp().
   */
  std::vector<std::vector<std::uint8_t>>
  build_packets (const PsampSample &sample,
                 std::chrono::system_clock::time_point wall_now,
                 bool adjust_time,
                 std::vector<std::size_t> *template_only_packets = nullptr);

  /**
   * @brief The IPFIX sequence number of the next message: the number of data
   * messages built so far.
   * @return The sequence number.
   */
  std::uint32_t
  sequence () const noexcept {
    return sequence_; }

private:
  /**
   * @brief Writes the IPFIX message header.
   * @param writer The buffer of the message.
   * @param length The length of the whole message in octets.
   * @param export_time The export time.
   */
  void
  write_header (ByteWriter &writer, std::uint16_t length,
                std::chrono::system_clock::time_point export_time) const;

  std::uint32_t observation_domain_id_;  ///< The Observation Domain ID.
  std::uint32_t sequence_{0};            ///< The sequence number of the next message.
  /// Data messages until the template is sent again: -1 = never, 0 or less = with the next message.
  int messages_until_template_{-1};
};

/** @brief A packet that was received in a PSAMP message of softflowd. */
struct PsampFrame {
  std::vector<std::uint8_t> frame;                    ///< The frame, cut at what was received.
  std::uint32_t original_length{0};                   ///< sectionExportedOctets.
  std::chrono::system_clock::time_point observed_at;  ///< The capture time.
};

/**
 * @brief Decodes one received UDP payload, which is fed to flow tracking as if
 * it had been captured.
 *
 * Only the data records that softflowd itself exports are decoded. The frame
 * is cut at what was received. Never throws.
 *
 * @param data The payload of the UDP datagram.
 * @return The packet, or nullopt for any other set and for a message that is
 *         not IPFIX or is too short.
 *
 * @original recv_psamp().
 */
std::optional<PsampFrame>
decode_psamp_message (std::span<const std::uint8_t> data);

} // namespace softflow

#endif // SOFTFLOW_PSAMP_HPP
