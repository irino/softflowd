/**
 * @file export_common.hpp
 * @brief What the exporters of NetFlow v1/v5/v9 and IPFIX, and PSAMP, have in common.
 *
 * The templates' IDs and the packet size of the IPFIX family, the conversion
 * between Unix time and NTP time, the time that is reported relative to the
 * boot time or to the epoch, the padding of a Set, and the address that -e
 * reports.
 *
 * @original export_common.c, export_common.h.
 */
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

/**
 * @name Template IDs of the flow templates
 * ICMP/ICMPv6 flows use a dedicated template (icmpTypeCode instead of a
 * source/destination port pair) and so get their own template IDs.
 *
 * @original export_common.h's IPFIX_SOFTFLOWD_{V4,ICMPV4,V6,ICMPV6}_TEMPLATE_ID.
 * @{
 */
inline constexpr std::uint16_t kIpfixTemplateIdV4 = 1024;      ///< IPv4 flows.
inline constexpr std::uint16_t kIpfixTemplateIdIcmpV4 = 1025;  ///< ICMPv4 flows.
inline constexpr std::uint16_t kIpfixTemplateIdV6 = 2048;      ///< IPv6 flows.
inline constexpr std::uint16_t kIpfixTemplateIdIcmpV6 = 2049;  ///< ICMPv6 flows.
/** @} */
/**
 * @brief The number of data messages after which the templates are sent again.
 *
 * @original IPFIX_DEFAULT_TEMPLATE_INTERVAL.
 */
inline constexpr std::uint32_t kIpfixTemplateResendInterval = 16;
/**
 * @brief The size in octets of a NetFlow v9 or IPFIX message.
 *
 * Shared by NetFlow v9 and IPFIX.
 *
 * @original IPFIX_SOFTFLOWD_MAX_PACKET_SIZE -- shared by NetFlow v9 and IPFIX
 * in send_ipfix_flows() of export_common.c (the unified sender both versions
 * actually use, except in --enable-compat-export=static-separate builds); NOT
 * the smaller, unused-by-default 512-byte buffer
 * (NETFLOW9_SOFTFLOWD_MAX_PACKET_SIZE) declared separately in
 * compat/netflow9.c's own send_netflow_v9(), which only exists in
 * --enable-compat-export=static-separate (--enable-legacy) builds.
 */
inline constexpr std::size_t kIpfixMaxPacketSize = 1428;

/**
 * @brief Converts microseconds since the Unix epoch into a 64-bit NTP timestamp.
 *
 * A 64-bit NTP timestamp is the seconds since 1900 and a binary fraction of a
 * second.
 *
 * @param epoch_us Microseconds since the Unix epoch.
 * @return The NTP timestamp.
 *
 * @original conv_unix_to_ntp().
 */
std::uint64_t
unix_us_to_ntp64 (std::uint64_t epoch_us);
/**
 * @brief Converts a 64-bit NTP timestamp into microseconds since the Unix epoch.
 *
 * @param ntp The NTP timestamp.
 * @return Microseconds since the Unix epoch.
 *
 * @original conv_ntp_to_unix().
 */
std::uint64_t
ntp64_to_unix_us (std::uint64_t ntp);

/**
 * @brief The address that -e reports in the exporter address fields of the
 * IPFIX options record.
 *
 * The first IPv4 and the first IPv6 address that -e resolves to; an absent
 * address is reported as zero.
 *
 * @original option.exporterAddr (-e).
 */
struct ExporterAddresses {
  std::optional<std::array<std::uint8_t, 4>> v4;   ///< The first IPv4 address.
  std::optional<std::array<std::uint8_t, 16>> v6;  ///< The first IPv6 address.
};

/**
 * @brief Resolves a host name or an address with getaddrinfo ().
 *
 * @param host The argument of -e.
 * @return The addresses; none when @p host cannot be resolved.
 */
ExporterAddresses
resolve_exporter_addresses (const std::string &host);

/**
 * @brief The uptime of the SysUptime, First and Last fields of NetFlow v1 and v5.
 *
 * Clamped at 0 in case @p t predates @p boot_time, so that an unsigned value
 * cannot wrap around.
 *
 * @param boot_time The reference boot time.
 * @param t The time.
 * @return Milliseconds between @p boot_time and @p t.
 */
std::uint32_t
uptime_ms (TimePoint boot_time, TimePoint t);

/**
 * @brief The uptime of NetFlow v9 and IPFIX.
 *
 * Unlike uptime_ms (), a @p t before @p boot_time wraps around instead of
 * being clamped to 0.
 *
 * @param boot_time The reference boot time.
 * @param t The time.
 * @return Milliseconds between @p boot_time and @p t, modulo 2^32.
 */
std::uint32_t
uptime_ms_unclamped (TimePoint boot_time, TimePoint t);

/**
 * @brief Converts a monotonic Clock timestamp into an absolute epoch time in
 * milliseconds.
 *
 * Uses the relationship between the monotonic @p now and the wall clock
 * @p wall_now of an export call.
 *
 * @param now The monotonic time of the export call.
 * @param wall_now The wall clock time of the export call.
 * @param t The monotonic timestamp to convert.
 * @return Milliseconds since the Unix epoch.
 * @see epoch_us ()
 */
std::uint64_t
epoch_ms (TimePoint now, std::chrono::system_clock::time_point wall_now, TimePoint t);
/**
 * @brief Converts a monotonic Clock timestamp into an absolute epoch time in
 * microseconds.
 *
 * @param now The monotonic time of the export call.
 * @param wall_now The wall clock time of the export call.
 * @param t The monotonic timestamp to convert.
 * @return Microseconds since the Unix epoch.
 * @see epoch_ms ()
 */
std::uint64_t
epoch_us (TimePoint now, std::chrono::system_clock::time_point wall_now, TimePoint t);

/**
 * @brief Closes a data Set: pads it to a 4-byte boundary and writes its length.
 *
 * The padding is included in the length of the Set, which is patched in at
 * @p set_start + 2.
 *
 * @param writer The packet that is being built.
 * @param set_start The offset in @p writer of the Set header.
 * @param base_offset The size of what precedes the content of @p writer in the
 *        packet (the message header).
 *
 * @original IPFIX Sets are padded to a 4-byte boundary, and the padding is
 * included in the length of the Set. The original pads the packet offset, not
 * the Set length, to a multiple of 4, hence @p base_offset.
 * @see finish_set_unpadded ()
 */
void
finish_set (ByteWriter &writer, std::size_t set_start, std::size_t base_offset = 0);

/**
 * @brief Closes a Template or Options Template Set: writes its length, without padding.
 *
 * @param writer The packet that is being built.
 * @param set_start The offset in @p writer of the Set header.
 *
 * @original The Template and Options Template Sets are never padded; their
 * length is the raw byte count.
 * @see finish_set ()
 */
void
finish_set_unpadded (ByteWriter &writer, std::size_t set_start);

}  // namespace softflow

#endif  // SOFTFLOW_EXPORT_COMMON_HPP
