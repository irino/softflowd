// Original files: ipfix.c, ipfix.h
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
//   - Per-record timestamps are exported as absolute epoch time (original:
//     -A time_format) rather than device-uptime-relative values, since
//     there is no uptime reference to convert from/to at all here (unlike
//     Netflow1Exporter/Netflow5Exporter/Netflow9Exporter, no boot_time is
//     needed).
#ifndef SOFTFLOW_IPFIX_HPP
#define SOFTFLOW_IPFIX_HPP

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <span>
#include <vector>

#include "softflow/softflowd.hpp"

namespace softflow {

inline constexpr std::uint16_t kIpfixTemplateIdV4 = 256;
inline constexpr std::uint16_t kIpfixTemplateIdV6 = 257;
inline constexpr std::size_t kIpfixMaxV4RecordsPerSet = 20;
inline constexpr std::size_t kIpfixMaxV6RecordsPerSet = 10;
inline constexpr std::uint32_t kIpfixTemplateResendInterval = 20;

// Original: -A time_format. dateTimeSeconds (IE 150/151) is a plain 4-byte
// integer; dateTimeMilliseconds (IE 152/153, this project's original
// default and still the default here) is a plain 8-byte integer;
// dateTimeMicroseconds/dateTimeNanoseconds (IE 154/155 and 156/157) both
// use the same 64-bit NTP short-format encoding (RFC 7011 section 6.1.9:
// 32-bit seconds since the NTP epoch of 1900-01-01, plus a 32-bit
// fraction) -- the "nanoseconds" variant is only a difference in which
// Information Element numbers are used, not in the underlying precision
// actually achievable, since both share the same 32-bit fraction field.
enum class IpfixTimeFormat { Seconds, Milliseconds, Microseconds, Nanoseconds };

class IpfixExporter {
public:
    // mpls_label_count: see Netflow9Exporter's constructor (netflow9.hpp)
    // -- the same -x semantics apply here.
    //
    // biflow (original: -b): when true, uses RFC 5103 biflow encoding --
    // one record per flow (not per direction), with the reverse
    // direction's octet/packet/TCP-flags counts carried in Reverse
    // Information Elements (RFC 5103's IANA-assigned Reverse PEN, 29305)
    // alongside the forward direction's ordinary fields.
    explicit IpfixExporter(std::uint32_t observation_domain_id = 0,
                            std::uint8_t mpls_label_count = 0,
                            IpfixTimeFormat time_format = IpfixTimeFormat::Milliseconds,
                            bool biflow = false)
        : observation_domain_id_(observation_domain_id),
          mpls_label_count_(std::min<std::uint8_t>(mpls_label_count, 10)),
          time_format_(time_format), biflow_(biflow) {}

    // now/wall_now are used together to compute each record's absolute
    // timestamp fields: since Flow's timestamps are recorded on the
    // monotonic Clock (see softflowd.hpp), converting one to an epoch
    // time requires knowing how the monotonic "now" and the wall-clock
    // "wall_now" relate at the moment of export.
    std::vector<std::vector<std::uint8_t>>
    build_packets(std::span<const ExportRecord> records, TimePoint now,
                  std::chrono::system_clock::time_point wall_now);

    std::uint32_t sequence() const noexcept { return sequence_; }

private:
    void write_header(ByteWriter& writer, std::uint16_t message_length,
                       std::chrono::system_clock::time_point wall_now) const;
    void write_template_set(ByteWriter& writer) const;

    std::uint32_t observation_domain_id_;
    std::uint8_t mpls_label_count_;
    IpfixTimeFormat time_format_;
    bool biflow_;
    std::uint32_t sequence_{0}; // count of Data Records sent so far
    std::uint32_t packets_since_template_{0};
};

} // namespace softflow

#endif // SOFTFLOW_IPFIX_HPP
