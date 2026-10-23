// Original files: export_common.c, export_common.h
//
// What the exporters of NetFlow v1/v5/v9 and IPFIX, and PSAMP, have in common:
// the templates' IDs and the packet size of the IPFIX family, the conversion
// between Unix time and NTP time, the time that is reported relative to the
// boot time or to the epoch, the padding of a Set, and the address that -e
// reports.
#ifndef SOFTFLOW_EXPORT_COMMON_HPP
#define SOFTFLOW_EXPORT_COMMON_HPP

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

#include "softflow/softflowd.hpp"

namespace softflow {

// Original: export_common.h's
// IPFIX_SOFTFLOWD_{V4,ICMPV4,V6,ICMPV6}_TEMPLATE_ID.
// ICMP/ICMPv6 flows use a dedicated template (icmpTypeCode instead of a
// source/destination port pair) and so get their own template IDs.
inline constexpr std::uint16_t kIpfixTemplateIdV4 = 1024;
inline constexpr std::uint16_t kIpfixTemplateIdIcmpV4 = 1025;
inline constexpr std::uint16_t kIpfixTemplateIdV6 = 2048;
inline constexpr std::uint16_t kIpfixTemplateIdIcmpV6 = 2049;
// Original: IPFIX_DEFAULT_TEMPLATE_INTERVAL.
inline constexpr std::uint32_t kIpfixTemplateResendInterval = 16;
// Original: IPFIX_SOFTFLOWD_MAX_PACKET_SIZE -- shared by NetFlow v9 and
// IPFIX in send_ipfix_flows() of export_common.c (the unified sender both
// versions actually use, except in --enable-compat-export=static-separate
// builds); NOT the smaller, unused-by-default 512-byte buffer
// (NETFLOW9_SOFTFLOWD_MAX_PACKET_SIZE) declared separately in
// compat/netflow9.c's own send_netflow_v9(), which only exists in
// --enable-compat-export=static-separate (--enable-legacy) builds.
inline constexpr std::size_t kIpfixMaxPacketSize = 1428;

// Original: conv_unix_to_ntp() and conv_ntp_to_unix(): microseconds since the
// Unix epoch from and to a 64-bit NTP timestamp (seconds since 1900 and a
// binary fraction of a second).
std::uint64_t
unix_us_to_ntp64 (std::uint64_t epoch_us);
std::uint64_t
ntp64_to_unix_us (std::uint64_t ntp);

// Original: option.exporterAddr (-e), the address reported in the exporter
// address fields of the IPFIX options record. The first IPv4 and the first
// IPv6 address that -e resolves to; an absent address is reported as zero.
struct ExporterAddresses {
  std::optional<std::array<std::uint8_t, 4>> v4;
  std::optional<std::array<std::uint8_t, 16>> v6;
};

// Resolves a host name or an address with getaddrinfo (). Returns no
// addresses when it cannot be resolved.
ExporterAddresses
resolve_exporter_addresses (const std::string &host);

// Original: the uptime of the SysUptime, First and Last fields of NetFlow v1
// and v5: milliseconds between `boot_time` and `t`, clamped at 0 in case `t`
// predates `boot_time`, so that an unsigned value cannot wrap around.
std::uint32_t
uptime_ms (TimePoint boot_time, TimePoint t);

// Original: the uptime of NetFlow v9 and IPFIX. Unlike uptime_ms (), a `t`
// before `boot_time` wraps around instead of being clamped to 0.
std::uint32_t
uptime_ms_unclamped (TimePoint boot_time, TimePoint t);

// Converts a monotonic Clock timestamp `t` into an absolute epoch time, using
// the relationship between the monotonic `now` and the wall clock `wall_now`
// of an export call (epoch_ms () in milliseconds, epoch_us () in microseconds).
std::uint64_t
epoch_ms (TimePoint now, std::chrono::system_clock::time_point wall_now, TimePoint t);
std::uint64_t
epoch_us (TimePoint now, std::chrono::system_clock::time_point wall_now, TimePoint t);

// Original: IPFIX Sets are padded to a 4-byte boundary, and the padding is
// included in the length of the Set. `base_offset` is the size of what
// precedes the writer's content in the packet (the message header): the
// original pads the packet offset, not the Set length, to a multiple of 4.
void
finish_set (ByteWriter &writer, std::size_t set_start, std::size_t base_offset = 0);

// Original: the Template and Options Template Sets are never padded; their
// length is the raw byte count.
void
finish_set_unpadded (ByteWriter &writer, std::size_t set_start);

}  // namespace softflow

#endif  // SOFTFLOW_EXPORT_COMMON_HPP
