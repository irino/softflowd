/**
 * @file ntopng.hpp
 * @brief The export to ntopng: the TLV format for ntopng 6.0 and later over ZeroMQ.
 *
 * The expired flows are sent to ntopng over ZeroMQ (a PUB socket that
 * connects to the -n destination) in messages of the format of ntopng's
 * zmq_msg_hdr_v4: a 36-octet header followed by the flows in the TLV format
 * of the nDPI serializer. The encoding does not need ZeroMQ and is always
 * built; only the sink that sends the messages is optional
 * (SOFTFLOW_HAVE_ZMQ). The JSON export for ntopng 5.x and earlier belongs to
 * the compatibility code of the original and is not implemented.
 *
 * @original ntopng.c (TLV export for ntopng 6.0 and later).
 */
#ifndef SOFTFLOW_NTOPNG_HPP
#define SOFTFLOW_NTOPNG_HPP

#include <chrono>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "softflow/softflowd.hpp"

namespace softflow {

/**
 * @brief The maximum size in octets of the TLV payload of one message.
 *
 * @original NTOPNG_MAX_TLV_SIZE. ntopng accepts up to 128 KB.
 */
inline constexpr std::size_t kNtopngMaxTlvSize = 16384;
/**
 * @brief The size in octets of the header of a message (ntopng's zmq_msg_hdr_v4).
 *
 * @original sizeof(struct NTOPNG_MSG_HEADER).
 */
inline constexpr std::size_t kNtopngHeaderSize = 36;

/**
 * @brief One message to ntopng.
 *
 * The header and the payload are sent as two ZeroMQ frames.
 */
struct NtopngMessage {
  std::vector<std::uint8_t> header;   ///< The header of kNtopngHeaderSize octets.
  std::vector<std::uint8_t> payload;  ///< The flows in the TLV format.
};

/**
 * @brief Encodes the expired flows into the messages for ntopng.
 *
 * It only builds the messages; NtopngSink sends them.
 */
class NtopngExporter {
public:
  /**
   * @brief Creates an exporter.
   * @param track_level The -T level. The VLAN IDs are exported from the level
   *        "vlan" and the Ethernet addresses from the level "ether".
   */
  explicit NtopngExporter (TrackLevel track_level)
      : track_level_ (track_level) {
  }

  /**
   * @brief Packs the flows, one record each, into as many messages as it takes.
   *
   * A flow that does not fit in a message of its own is skipped (and warned
   * about).
   *
   * @param records The expired flows.
   * @param now The monotonic time that @p wall_now belongs to.
   * @param wall_now The wall clock time at @p now. Together with @p now it
   *        relates the monotonic times of the flows to the clock, for the
   *        seconds that are exported.
   * @return The messages, in the order to send them.
   *
   * @original send_ntopng(); a flow that does not fit in a message of its own
   * is skipped (and warned about) as in the original.
   */
  std::vector<NtopngMessage>
  build_messages (std::span<const ExportRecord> records, TimePoint now,
                  std::chrono::system_clock::time_point wall_now);

private:
  TrackLevel track_level_;   ///< The -T level.
  std::uint32_t msg_id_{0};  ///< The message identifier of the next message, counted up.
};

#ifdef SOFTFLOW_HAVE_ZMQ
/**
 * @brief A ZeroMQ PUB socket that sends the messages to ntopng.
 *
 * The socket connects to tcp://host:port. The destructor waits for the queued
 * messages, at most NTOPNG_LINGER_MS, as the flows that are exported at
 * shutdown would be lost otherwise. It can be moved and not copied.
 *
 * @original connect_ntopng() and close_ntopng().
 */
class NtopngSink {
public:
  /**
   * @brief Creates the socket and connects it.
   * @param host The numeric host of the -n destination.
   * @param port The port of the -n destination.
   * @throw std::runtime_error when the socket cannot be created.
   */
  NtopngSink (const std::string &host, const std::string &port);
  /** @brief Closes the socket after the queued messages are sent, or after the linger time. */
  ~NtopngSink();
  NtopngSink (const NtopngSink &) = delete;
  NtopngSink &
  operator= (const NtopngSink &) = delete;
  /** @brief Takes over the socket of @p other, which is left empty. */
  NtopngSink (NtopngSink &&other) noexcept;

  /**
   * @brief Sends the two frames of a message.
   * @param message The message.
   * @return false (and warns) when a frame could not be sent.
   */
  bool
  send (const NtopngMessage &message);

private:
  void *context_{nullptr};  ///< The ZeroMQ context.
  void *socket_{nullptr};   ///< The PUB socket.
};
#endif

}  // namespace softflow

#endif  // SOFTFLOW_NTOPNG_HPP
