/**
 * @file ipfix.hpp
 * @brief The types of IPFIX and NetFlow v9: the time format of -A, the message
 * version and the field specifier of a template.
 *
 * The exporter is in export.hpp.
 *
 * IPFIX (RFC 7011) is structurally very close to NetFlow v9 -- both are
 * template-based -- but differs in a few concrete ways this implementation
 * follows:
 *   - The message header carries a total byte Length instead of a record
 *     Count, and an absolute export_time (seconds since the epoch) instead
 *     of a device-uptime SysUptime.
 *   - The Sequence Number counts Data Records (RFC 7011 section 3.1),
 *     not export packets the way NetFlow v9's sequence number does.
 *   - The Template Set uses Set ID 2 (NetFlow v9 uses FlowSet ID 0 for the
 *     same purpose).
 *   - Per-record timestamps default to the SAME device-uptime-relative
 *     encoding NetFlow v9 uses (flowStartSysUpTime/flowEndSysUpTime, IE
 *     22/21) -- see IpfixTimeFormat::SysUpTime -- even though the
 *     IPFIX message header (unlike NetFlow v9's) has no SysUpTime field to
 *     carry the reference point. The original compensates for that by
 *     sending an Options Template/Record carrying
 *     systemInitTimeMilliseconds (see write_options_set()); -A can select
 *     one of the absolute-epoch-time encodings instead.
 *
 * @original compat/ipfix.c, ipfix.h.
 */
#ifndef SOFTFLOW_IPFIX_HPP
#define SOFTFLOW_IPFIX_HPP

#include <cstdint>

namespace softflow {

/**
 * @brief The encoding of the flow times in IPFIX and NetFlow v9, selected with -A.
 *
 * SysUpTime is the default: milliseconds elapsed since a reference boot time
 * (flowStartSysUpTime / flowEndSysUpTime, IE 22/21), the SAME encoding NetFlow
 * v9 always uses, just without a SysUpTime field in the IPFIX message header
 * to carry the reference. The other values are absolute times.
 *
 * @original -A time_format. When absent (the default -- see softflowd.c's
 * FLOWTRACKPARAMETERS.time_format, left at its zero-value and never matched by
 * any of 's'/'m'/'M'/'n' in ipfix_init_template_time()), the original falls
 * through to field_timesysup. It compensates for the missing field by sending
 * an Options Template/Record carrying systemInitTimeMilliseconds (see
 * build_packets()'s Options Set), letting a receiver reconstruct absolute time
 * from the two together. SysUpTime is therefore this project's default too,
 * matching the original's actual default behavior; Seconds / Milliseconds /
 * Microseconds / Nanoseconds remain available via -A.
 */
enum class IpfixTimeFormat {
  SysUpTime,     ///< Milliseconds since the reference boot time (the default).
  Seconds,       ///< Seconds since the epoch (-A sec).
  Milliseconds,  ///< Milliseconds since the epoch (-A milli).
  Microseconds,  ///< Microseconds since the epoch, as a 64-bit NTP timestamp (-A micro).
  Nanoseconds    ///< Nanoseconds since the epoch, as a 64-bit NTP timestamp (-A nano).
};

/**
 * @brief The Reverse Information Element Private Enterprise Number of RFC 5103.
 *
 * An enterprise-specific Information Element in a Template with this PEN and
 * the same IE number as a standard field represents "the same field, but for
 * the reverse direction of a biflow". It is assigned by IANA.
 */
inline constexpr std::uint32_t kIpfixReversePen = 29305;

/**
 * @brief One field of a template: the field specifier of RFC 7011 section 3.2.
 *
 * @original IPFIX_FIELD_SPECIFIER.
 */
struct IpfixFieldSpec {
  std::uint16_t type;            ///< The Information Element identifier.
  std::uint16_t length;          ///< The length of the field in octets.
  std::uint32_t enterprise = 0;  ///< 0 = standard IE; nonzero = enterprise-specific.
};

/**
 * @brief The protocol of an export message that is built from templates.
 *
 * NetFlow v9 and IPFIX share the templates, the data records and the packet
 * framing; they differ in the message header, the Set IDs of the template and
 * options template sets, and the options template and data record. NetFlow v9
 * has no biflow and no absolute time formats.
 *
 * @original The `version` argument of send_ipfix_flows().
 */
enum class MessageVersion : std::uint16_t {
  NetFlow9 = 9,  ///< NetFlow v9 (RFC 3954).
  Ipfix = 10     ///< IPFIX (RFC 7011); the version field of its header is 10.
};

} // namespace softflow

#endif // SOFTFLOW_IPFIX_HPP
