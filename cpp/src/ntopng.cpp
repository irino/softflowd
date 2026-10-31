// Original files: ntopng.c
#include "softflow/ntopng.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <utility>

#ifdef SOFTFLOW_HAVE_ZMQ
#include <zmq.h>

#include <stdexcept>
#endif

namespace softflow {

namespace {

constexpr std::uint8_t kMsgVersion = 4;      ///< The version in the header of a message; ZMQ_MSG_VERSION in the C version.
constexpr std::uint8_t kFlagIsTlv = 1 << 1;  ///< The header flag that tells that the payload is in the TLV format; NTOPNG_FLAG_IS_TLV in the C version.

// nDPI serializer, TLV format.
constexpr std::uint8_t kTlvVersion = 1;      ///< The version of the TLV format, the first byte of a payload.
constexpr std::uint8_t kTlvFormatTlv = 1;    ///< The format byte that follows the version: TLV.
constexpr std::uint8_t kTlvEndOfRecord = 1;  ///< The marker that ends a record.
constexpr std::uint8_t kTlvUint8 = 2;        ///< The type of an unsigned integer of 1 byte.
constexpr std::uint8_t kTlvUint16 = 3;       ///< The type of an unsigned integer of 2 bytes.
constexpr std::uint8_t kTlvUint32 = 4;       ///< The type of an unsigned integer of 4 bytes.
constexpr std::uint8_t kTlvUint64 = 5;       ///< The type of an unsigned integer of 8 bytes.
constexpr std::uint8_t kTlvString = 11;      ///< The type of a string.

// NetFlow v9 element ids understood by ntopng.
constexpr std::uint32_t kInBytes = 1;         ///< IN_BYTES (1): the octets from the first end to the second.
constexpr std::uint32_t kInPkts = 2;          ///< IN_PKTS (2): the packets from the first end to the second.
constexpr std::uint32_t kProtocol = 4;        ///< PROTOCOL (4): the IP protocol number.
constexpr std::uint32_t kTcpFlags = 6;        ///< TCP_FLAGS (6): the TCP flags seen from the first end.
constexpr std::uint32_t kL4SrcPort = 7;       ///< L4_SRC_PORT (7): the port of the first end.
constexpr std::uint32_t kIpv4SrcAddr = 8;     ///< IPV4_SRC_ADDR (8): the IPv4 address of the first end, as a string.
constexpr std::uint32_t kL4DstPort = 11;      ///< L4_DST_PORT (11): the port of the second end.
constexpr std::uint32_t kIpv4DstAddr = 12;    ///< IPV4_DST_ADDR (12): the IPv4 address of the second end, as a string.
constexpr std::uint32_t kLastSwitched = 21;   ///< LAST_SWITCHED (21): the time of the last packet, in seconds since the epoch.
constexpr std::uint32_t kFirstSwitched = 22;  ///< FIRST_SWITCHED (22): the time of the first packet, in seconds since the epoch.
constexpr std::uint32_t kOutBytes = 23;       ///< OUT_BYTES (23): the octets from the second end to the first.
constexpr std::uint32_t kOutPkts = 24;        ///< OUT_PKTS (24): the packets from the second end to the first.
constexpr std::uint32_t kIpv6SrcAddr = 27;    ///< IPV6_SRC_ADDR (27): the IPv6 address of the first end, as a string.
constexpr std::uint32_t kIpv6DstAddr = 28;    ///< IPV6_DST_ADDR (28): the IPv6 address of the second end, as a string.
constexpr std::uint32_t kInSrcMac = 56;       ///< IN_SRC_MAC (56): the Ethernet address of the first end, as a string.
constexpr std::uint32_t kOutDstMac = 57;      ///< OUT_DST_MAC (57): the Ethernet address of the second end, as a string.
constexpr std::uint32_t kSrcVlan = 58;        ///< SRC_VLAN (58): the VLAN ID of the first end.
constexpr std::uint32_t kDstVlan = 59;        ///< DST_VLAN (59): the VLAN ID of the second end.

/**
 * @brief The payload of one ntopng message, in the TLV format of the nDPI serializer.
 *
 * The payload of a message, a buffer of fixed capacity as in the original.
 */
class Tlv {
public:
  Tlv() {
    buf_.push_back (kTlvVersion);
    buf_.push_back (kTlvFormatTlv);
  }

  /**
   * @brief The number of bytes in the payload so far.
   *
   * @return The size.
   */
  std::size_t
  size () const noexcept {
    return buf_.size();
  }
  /**
   * @brief Cuts the payload back to a size, to drop a record that was written only in part.
   *
   * @param n The number of bytes to keep.
   */
  void
  truncate (std::size_t n) {
    buf_.resize (n);
  }
  /**
   * @brief Moves the payload out; the object is not to be used afterwards.
   *
   * @return The payload.
   */
  std::vector<std::uint8_t>
  take () {
    return std::move (buf_);
  }

  /**
   * @brief Appends an unsigned integer item. The key and the value are each written with the smallest of 1, 2, 4 or 8 bytes that holds them.
   *
   * @param key The element ID.
   * @param value The value.
   * @return false when the item does not fit in kNtopngMaxTlvSize; nothing is appended then.
   */
  bool
  put_uint (std::uint32_t key, std::uint64_t value) {
    const int kb = uint_bytes (key);
    const int vb = uint_bytes (value);
    if (kMaxSize - buf_.size() < static_cast<std::size_t> (1 + kb + vb)) {
      return false;
    }
    buf_.push_back (static_cast<std::uint8_t> ((uint_type (kb) << 4) | uint_type (vb)));
    put_be (key, kb);
    put_be (value, vb);
    return true;
  }

  /**
   * @brief Appends a string item: the key, a 2-byte length and the characters.
   *
   * @param key The element ID.
   * @param value The string; at most 65535 bytes.
   * @return false when the string is too long or the item does not fit in kNtopngMaxTlvSize; nothing is appended then.
   */
  bool
  put_string (std::uint32_t key, const std::string &value) {
    const int kb = uint_bytes (key);
    if (value.size() > 0xffff || kMaxSize - buf_.size() < static_cast<std::size_t> (1 + kb + 2) + value.size()) {
      return false;
    }
    buf_.push_back (static_cast<std::uint8_t> ((uint_type (kb) << 4) | kTlvString));
    put_be (key, kb);
    put_be (value.size(), 2);
    buf_.insert (buf_.end(), value.begin(), value.end());
    return true;
  }

  /**
   * @brief Appends the marker that ends a record.
   *
   * @return false when the payload has no room for the marker.
   */
  bool
  end_record () {
    if (buf_.size() >= kMaxSize) {
      return false;
    }
    buf_.push_back (kTlvEndOfRecord);
    return true;
  }

private:
  static constexpr std::size_t kMaxSize = kNtopngMaxTlvSize;

  void
  put_be (std::uint64_t v, int bytes) {
    for (int i = bytes - 1; i >= 0; --i) {
      buf_.push_back (static_cast<std::uint8_t> ((v >> (8 * i)) & 0xff));
    }
  }

  // The smallest of 1, 2, 4 or 8 bytes that holds v, as the serializer does.
  static int
  uint_bytes (std::uint64_t v) {
    return v <= 0xff ? 1 : v <= 0xffff        ? 2
                         : v <= 0xffffffffULL ? 4
                                              : 8;
  }

  static std::uint8_t
  uint_type (int bytes) {
    return bytes == 1 ? kTlvUint8 : bytes == 2 ? kTlvUint16
                                  : bytes == 4 ? kTlvUint32
                                               : kTlvUint64;
  }

  std::vector<std::uint8_t> buf_;
};

/**
 * @brief Writes an address as text.
 *
 * @param addr The address.
 * @return The address in dotted decimal for IPv4 and in the form of inet_ntop() for IPv6.
 */
std::string
format_address (const IpAddress &addr) {
  std::array<char, INET6_ADDRSTRLEN> text{};
  const bool v4 = addr.family == AddressFamily::IPv4;
  inet_ntop (v4 ? AF_INET : AF_INET6, addr.bytes.data(), text.data(), text.size());
  return text.data();
}

/**
 * @brief Writes an Ethernet address as text.
 *
 * @param mac The address.
 * @return Six pairs of lowercase hexadecimal digits that are separated by colons.
 */
std::string
format_mac (const std::array<std::uint8_t, 6> &mac) {
  char text[3 * 6];
  std::snprintf (text, sizeof (text), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1],
                 mac[2], mac[3], mac[4], mac[5]);
  return text;
}

/**
 * @brief Appends one flow as a record: the ports, the counters, the times, the TCP flags, the protocol and the addresses, and the VLAN IDs and the Ethernet addresses depending on the track level.
 *
 * The first end of the key is the source: IN is from the first end to the second, and OUT is from the second to the first.
 *
 * @param t The payload to append to.
 * @param r The flow and its key.
 * @param level The track level: the VLAN IDs are written from FullVlan, the Ethernet addresses from FullVlanEther.
 * @param now The current time on Clock.
 * @param wall_now The wall-clock time that corresponds to @p now; the times of the flow are made from it.
 * @return false when the record does not fit in the payload; the payload may then hold a part of the record.
 *
 * @original add_tlv_flow(). Ports and counters are plain integers, addresses
 * and MAC addresses are strings. Returns false if the record does not fit.
 */
bool
add_flow (Tlv &t, const ExportRecord &r, TrackLevel level, TimePoint now,
          std::chrono::system_clock::time_point wall_now) {
  const auto &key = r.key;
  const auto &flow = r.flow;
  const auto seconds = [&] (TimePoint p) {
    const auto wall = wall_now - (now - p);
    return static_cast<std::uint64_t> (std::max<std::int64_t> (
      0, std::chrono::duration_cast<std::chrono::seconds> (wall.time_since_epoch()).count()));
  };

  if (!t.put_uint (kL4SrcPort, key.port()[0]) || !t.put_uint (kL4DstPort, key.port()[1]) ||
      // IN is source -> destination, OUT is destination -> source
      !t.put_uint (kInBytes, flow.octets[0]) || !t.put_uint (kInPkts, flow.packets[0]) ||
      !t.put_uint (kOutBytes, flow.octets[1]) || !t.put_uint (kOutPkts, flow.packets[1]) ||
      // epoch seconds
      !t.put_uint (kFirstSwitched, seconds (flow.flow_start)) ||
      !t.put_uint (kLastSwitched, seconds (flow.flow_last)) ||
      !t.put_uint (kTcpFlags, flow.tcp_flags[0]) || !t.put_uint (kProtocol, key.protocol())) {
    return false;
  }

  const bool v4 = key.addr()[0].family == AddressFamily::IPv4;
  if (!t.put_string (v4 ? kIpv4SrcAddr : kIpv6SrcAddr, format_address (key.addr()[0])) ||
      !t.put_string (v4 ? kIpv4DstAddr : kIpv6DstAddr, format_address (key.addr()[1]))) {
    return false;
  }

  if (level >= TrackLevel::FullVlan) {
    if (!t.put_uint (kSrcVlan, key.vlanid()[0]) || !t.put_uint (kDstVlan, key.vlanid()[1])) {
      return false;
    }
  }
  if (level >= TrackLevel::FullVlanEther) {
    if (!t.put_string (kInSrcMac, format_mac (key.ethermac()[0])) ||
        !t.put_string (kOutDstMac, format_mac (key.ethermac()[1]))) {
      return false;
    }
  }
  return t.end_record();
}

}  // namespace

std::vector<NtopngMessage>
NtopngExporter::build_messages (
  std::span<const ExportRecord> records, TimePoint now,
  std::chrono::system_clock::time_point wall_now) {
  std::vector<NtopngMessage> messages;
  std::size_t flow = 0;
  while (flow < records.size()) {
    Tlv t;
    std::size_t added = 0;
    while (flow < records.size()) {
      const std::size_t mark = t.size();
      if (!add_flow (t, records[flow], track_level_, now, wall_now)) {
        t.truncate (mark);  // drop the partial record
        if (added != 0) {
          break;  // continue in the next message
        }
        // A single flow never fits: skip it, or this would not end.
        std::fprintf (stderr, "ntopng: flow too large for a TLV message\n");
      } else {
        ++added;
      }
      ++flow;
    }
    if (added == 0) {
      continue;
    }

    NtopngMessage message;
    ByteWriter header;
    const char url[16] = {'f', 'l', 'o', 'w'};
    header.put_bytes (std::span<const std::uint8_t> (
      reinterpret_cast<const std::uint8_t *> (url), sizeof (url)));
    header.put_u8 (kMsgVersion);
    header.put_u8 (kFlagIsTlv);
    header.put_u16 (0);  // padding
    const auto size = static_cast<std::uint32_t> (t.size());
    header.put_u32 (size);  // uncompressed_size
    header.put_u32 (size);  // compressed_size
    header.put_u32 (msg_id_++);
    header.put_u32 (0);  // source_id, host byte order
    message.header = header.take();
    message.payload = t.take();
    messages.push_back (std::move (message));
  }
  return messages;
}

#ifdef SOFTFLOW_HAVE_ZMQ

namespace {
constexpr int kLingerMs = 3000;  // NTOPNG_LINGER_MS
}  // namespace

NtopngSink::NtopngSink (const std::string &host, const std::string &port) {
  context_ = zmq_ctx_new();
  if (context_ == nullptr) {
    throw std::runtime_error ("zmq_ctx_new failed");
  }
  socket_ = zmq_socket (context_, ZMQ_PUB);
  if (socket_ == nullptr) {
    zmq_ctx_destroy (context_);
    throw std::runtime_error ("zmq_socket failed");
  }
  const std::string endpoint = "tcp://" + host + ":" + port;
  std::fprintf (stderr, "Connecting ZMQ socket '%s'\n", endpoint.c_str());
  if (zmq_connect (socket_, endpoint.c_str()) != 0) {
    const std::string reason = zmq_strerror (zmq_errno());
    zmq_close (socket_);
    zmq_ctx_destroy (context_);
    throw std::runtime_error ("Could not create ZeroMQ socket for " + host + ":" + port +
                              ": " + reason);
  }
}

NtopngSink::NtopngSink (NtopngSink &&other) noexcept
    : context_ (std::exchange (other.context_, nullptr)),
      socket_ (std::exchange (other.socket_, nullptr)) {
}

NtopngSink::~NtopngSink() {
  if (socket_ == nullptr) {
    return;
  }
  int linger = kLingerMs;
  zmq_setsockopt (socket_, ZMQ_LINGER, &linger, sizeof (linger));
  zmq_close (socket_);
  zmq_ctx_destroy (context_);
}

bool
NtopngSink::send (const NtopngMessage &message) {
  if (zmq_send (socket_, message.header.data(), message.header.size(), ZMQ_SNDMORE) < 0 ||
      zmq_send (socket_, message.payload.data(), message.payload.size(), 0) < 0) {
    std::fprintf (stderr, "ntopng: zmq_send failed: %s\n", zmq_strerror (zmq_errno()));
    return false;
  }
  return true;
}

#endif

}  // namespace softflow
