// Original files: ntopng.c (TLV export for ntopng 6.0 and later)
//
// The expired flows are sent to ntopng over ZeroMQ (a PUB socket that
// connects to the -n destination) in messages of the format of ntopng's
// zmq_msg_hdr_v4: a 36-octet header followed by the flows in the TLV format
// of the nDPI serializer. The encoding does not need ZeroMQ and is always
// built; only the sink that sends the messages is optional
// (SOFTFLOW_HAVE_ZMQ). The JSON export for ntopng 5.x and earlier belongs to
// the compatibility code of the original and is not implemented.
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

// Original: NTOPNG_MAX_TLV_SIZE. ntopng accepts up to 128 KB.
inline constexpr std::size_t kNtopngMaxTlvSize = 16384;
// Original: sizeof(struct NTOPNG_MSG_HEADER).
inline constexpr std::size_t kNtopngHeaderSize = 36;

// One message: the header and the payload are sent as two ZeroMQ frames.
struct NtopngMessage {
  std::vector<std::uint8_t> header;
  std::vector<std::uint8_t> payload;
};

class NtopngExporter {
public:
  explicit NtopngExporter (TrackLevel track_level)
      : track_level_ (track_level) {
  }

  // Original: send_ntopng(). Packs the flows, one record each, into as
  // many messages as it takes. A flow that does not fit in a message of
  // its own is skipped (and warned about), as in the original. now and
  // wall_now relate the monotonic times of the flows to the clock for the
  // seconds that are exported.
  std::vector<NtopngMessage>
  build_messages (std::span<const ExportRecord> records, TimePoint now,
                  std::chrono::system_clock::time_point wall_now);

private:
  TrackLevel track_level_;
  std::uint32_t msg_id_{0};
};

#ifdef SOFTFLOW_HAVE_ZMQ
// Original: connect_ntopng() and close_ntopng(). A PUB socket that connects
// to tcp://host:port. The destructor waits for the queued messages, at most
// NTOPNG_LINGER_MS, as the flows that are exported at shutdown would be lost
// otherwise.
class NtopngSink {
public:
  // Throws std::runtime_error when the socket cannot be created.
  NtopngSink (const std::string &host, const std::string &port);
  ~NtopngSink();
  NtopngSink (const NtopngSink &) = delete;
  NtopngSink &
  operator= (const NtopngSink &) = delete;
  NtopngSink (NtopngSink &&other) noexcept;

  // Returns false (and warns) when a frame could not be sent.
  bool
  send (const NtopngMessage &message);

private:
  void *context_{nullptr};
  void *socket_{nullptr};
};
#endif

}  // namespace softflow

#endif  // SOFTFLOW_NTOPNG_HPP
