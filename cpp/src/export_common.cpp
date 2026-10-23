// Original files: export_common.c
#include "softflow/export_common.hpp"

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <algorithm>
#include <cstring>

namespace softflow {

// base_offset is the size of what precedes the writer's content in the
// packet (the message header): the original pads the packet offset, not the
// Set length, to a multiple of 4 -- which differs after an unpadded Set.
void
finish_set (ByteWriter &writer, std::size_t set_start, std::size_t base_offset) {
  // Original: IPFIX Sets are padded to a 4-byte boundary the same way as
  // NetFlow v9 FlowSets (RFC 7011 section 3.3.2), and the padding is
  // likewise included in the Set's own Length field. This applies to
  // DATA Sets only -- see finish_set_unpadded() for Template/Options
  // Sets, which the original never pads.
  const std::size_t raw_length = writer.size() - set_start;
  const std::size_t pad = (4 - ((base_offset + writer.size()) % 4)) % 4;
  for (std::size_t i = 0; i < pad; ++i) {
    writer.put_u8 (0);
  }
  writer.patch_u16 (set_start + 2, static_cast<std::uint16_t> (raw_length + pad));
}

// Original: memcpy_template() and the Options Template/Data writes in
// compat/ipfix.c's ipfix_put_templates() (called from send_ipfix_flows() in
// export_common.c) never apply the 4-byte padding logic -- that only
// appears later, scoped to the per-flow DATA Set loop. A Template/Options
// Set's length is therefore its raw (frequently non-multiple-of-4) byte
// count.
void
finish_set_unpadded (ByteWriter &writer, std::size_t set_start) {
  const std::size_t raw_length = writer.size() - set_start;
  writer.patch_u16 (set_start + 2, static_cast<std::uint16_t> (raw_length));
}

std::uint32_t
uptime_ms (TimePoint boot_time, TimePoint t) {
  const auto delta = std::chrono::duration_cast<std::chrono::milliseconds> (
    t - boot_time);
  return static_cast<std::uint32_t> (std::max<std::int64_t> (0, delta.count()));
}

// Original: the uptime-relative encoding of NetFlow v9 and IPFIX --
// milliseconds elapsed between `boot_time` and `t`. Unlike uptime_ms (), a `t`
// before `boot_time` wraps around instead of being clamped to 0.
std::uint32_t
uptime_ms_unclamped (TimePoint boot_time, TimePoint t) {
  return static_cast<std::uint32_t> (
    std::chrono::duration_cast<std::chrono::milliseconds> (t - boot_time).count());
}

// Converts a monotonic Clock timestamp `t` into an absolute
// epoch-millisecond value, using the relationship between the monotonic
// "now" and wall-clock "wall_now" supplied for this export call. This is
// the only place in the codebase that bridges the two clocks -- Flow
// itself never stores wall-clock time (see softflowd.hpp's rationale for
// using a monotonic Clock throughout).
std::uint64_t
epoch_ms (TimePoint now,
          std::chrono::system_clock::time_point wall_now,
          TimePoint t) {
  const auto age = now - t;  // how long ago `t` was, relative to `now`
  const auto wall_t = wall_now - age;
  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds> (
    wall_t.time_since_epoch());
  return static_cast<std::uint64_t> (std::max<std::int64_t> (0, ms.count()));
}

// Epoch microseconds of `t`, like the struct timeval of the original.
std::uint64_t
epoch_us (TimePoint now,
          std::chrono::system_clock::time_point wall_now,
          TimePoint t) {
  const auto wall_t = wall_now - (now - t);
  const auto us = std::chrono::duration_cast<std::chrono::microseconds> (
    wall_t.time_since_epoch());
  return static_cast<std::uint64_t> (std::max<std::int64_t> (0, us.count()));
}

ExporterAddresses
resolve_exporter_addresses (const std::string &host) {
  // Original: getaddrinfo () on the -e argument; the first address of each
  // family is the one that is reported.
  ExporterAddresses out;
  struct addrinfo hints {};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  struct addrinfo *list = nullptr;
  if (getaddrinfo (host.c_str(), nullptr, &hints, &list) != 0) {
    return out;
  }
  for (const struct addrinfo *rp = list; rp != nullptr; rp = rp->ai_next) {
    if (rp->ai_family == AF_INET && !out.v4.has_value()) {
      std::array<std::uint8_t, 4> a;
      std::memcpy (a.data(), &reinterpret_cast<const sockaddr_in *> (rp->ai_addr)->sin_addr, 4);
      out.v4 = a;
    } else if (rp->ai_family == AF_INET6 && !out.v6.has_value()) {
      std::array<std::uint8_t, 16> a;
      std::memcpy (a.data(), &reinterpret_cast<const sockaddr_in6 *> (rp->ai_addr)->sin6_addr, 16);
      out.v6 = a;
    }
  }
  freeaddrinfo (list);
  return out;
}

// Original: conv_unix_to_ntp(). -A micro/nano and PSAMP. RFC 7011 section
// 6.1.9 specifies these as the 64-bit NTP Timestamp format (RFC 5905): 32-bit
// seconds since the NTP epoch (1900-01-01), plus a 32-bit binary fraction of
// a second. The original rounds the fraction up with `tv_usec + 1`.
std::uint64_t
unix_us_to_ntp64 (std::uint64_t epoch_us_value) {
  constexpr std::uint64_t kNtpEpochOffsetSeconds = 2208988800ULL;  // 1900 -> 1970
  const std::uint64_t seconds = epoch_us_value / 1000000;
  const std::uint64_t usec = epoch_us_value % 1000000;
  const auto ntp_seconds = static_cast<std::uint32_t> (seconds + kNtpEpochOffsetSeconds);
  const auto ntp_fraction = static_cast<std::uint32_t> (
    static_cast<double> (usec + 1) * 4294967296.0 * 1.0e-6);
  return (static_cast<std::uint64_t> (ntp_seconds) << 32) | ntp_fraction;
}

// Original: conv_ntp_to_unix().
std::uint64_t
ntp64_to_unix_us (std::uint64_t ntp) {
  constexpr std::uint64_t kNtpEpochOffsetSeconds = 2208988800ULL;
  const auto seconds = static_cast<std::uint32_t> (ntp >> 32);
  const auto fraction = static_cast<std::uint32_t> (ntp);
  const auto usec = static_cast<std::uint32_t> (
    static_cast<double> (fraction) * 1.0e6 / 4294967296.0);
  return (static_cast<std::uint64_t> (seconds) - kNtpEpochOffsetSeconds) * 1000000 + usec;
}

}  // namespace softflow
