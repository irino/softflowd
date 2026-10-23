// Original files: compat/ipfix.c, ipfix.h
//
// The types of IPFIX and NetFlow v9: the time format of -A, the message version
// and the field specifier of a template. The exporter is in export.hpp.
//
// IPFIX (RFC 7011) is structurally very close to NetFlow v9 -- both are
// template-based -- but differs in a few concrete ways this implementation
// follows:
//   - The message header carries a total byte Length instead of a record
//     Count, and an absolute export_time (seconds since the epoch) instead
//     of a device-uptime SysUptime.
//   - The Sequence Number counts Data Records (RFC 7011 section 3.1),
//     not export packets the way NetFlow v9's sequence number does.
//   - The Template Set uses Set ID 2 (NetFlow v9 uses FlowSet ID 0 for the
//     same purpose).
//   - Per-record timestamps default to the SAME device-uptime-relative
//     encoding NetFlow v9 uses (flowStartSysUpTime/flowEndSysUpTime, IE
//     22/21) -- see IpfixTimeFormat::SysUpTime below -- even though the
//     IPFIX message header (unlike NetFlow v9's) has no SysUpTime field to
//     carry the reference point. The original compensates for that by
//     sending an Options Template/Record carrying
//     systemInitTimeMilliseconds (see write_options_set()); -A can select
//     one of the absolute-epoch-time encodings instead.
#ifndef SOFTFLOW_IPFIX_HPP
#define SOFTFLOW_IPFIX_HPP

#include <cstdint>

namespace softflow {

// Original: -A time_format. When absent (the default -- see softflowd.c's
// FLOWTRACKPARAMETERS.time_format, left at its zero-value and never
// matched by any of 's'/'m'/'M'/'n' in ipfix_init_template_time()), the
// original falls through to field_timesysup: flowStartSysUpTime/
// flowEndSysUpTime (IE 22/21), i.e. milliseconds elapsed since a reference
// boot time -- the SAME encoding NetFlow v9 always uses, just without a
// SysUpTime field in the IPFIX message header to carry the reference
// (IPFIX's header has no such field). The original compensates by sending
// an Options Template/Record carrying systemInitTimeMilliseconds (see
// build_packets()'s Options Set), letting a receiver reconstruct absolute
// time from the two together. SysUpTime is therefore this project's
// default too, matching the original's actual default behavior; Seconds/
// Milliseconds/Microseconds/Nanoseconds remain available via -A.
enum class IpfixTimeFormat { SysUpTime, Seconds, Milliseconds, Microseconds, Nanoseconds };

// RFC 5103's IANA-assigned Reverse Information Element Private Enterprise
// Number. An enterprise-specific Information Element in a Template with
// this PEN and the same IE number as a standard field represents "the
// same field, but for the reverse direction of a biflow".
inline constexpr std::uint32_t kIpfixReversePen = 29305;

// Original: IPFIX_FIELD_SPECIFIER, one field of a template.
struct IpfixFieldSpec {
  std::uint16_t type;
  std::uint16_t length;
  std::uint32_t enterprise = 0;  // 0 = standard IE; nonzero = enterprise-specific
};

// Original: the `version` argument of send_ipfix_flows(). NetFlow v9 and
// IPFIX share the templates, the data records and the packet framing; they
// differ in the message header, the Set IDs of the template and options
// template sets, and the options template and data record. NetFlow v9 has no
// biflow and no absolute time formats.
enum class MessageVersion : std::uint16_t { NetFlow9 = 9, Ipfix = 10 };


} // namespace softflow

#endif // SOFTFLOW_IPFIX_HPP
