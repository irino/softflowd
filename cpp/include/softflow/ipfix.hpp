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

#include <string>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <span>
#include <vector>

#include "softflow/softflowd.hpp"

namespace softflow {

// Original: ipfix.c's IPFIX_SOFTFLOWD_{V4,ICMPV4,V6,ICMPV6}_TEMPLATE_ID.
// ICMP/ICMPv6 flows use a dedicated template (icmpTypeCode instead of a
// source/destination port pair) and so get their own template IDs.
inline constexpr std::uint16_t kIpfixTemplateIdV4 = 1024;
inline constexpr std::uint16_t kIpfixTemplateIdIcmpV4 = 1025;
inline constexpr std::uint16_t kIpfixTemplateIdV6 = 2048;
inline constexpr std::uint16_t kIpfixTemplateIdIcmpV6 = 2049;
inline constexpr std::size_t kIpfixMaxV4RecordsPerSet = 20;
inline constexpr std::size_t kIpfixMaxV6RecordsPerSet = 10;
// Original: IPFIX_DEFAULT_TEMPLATE_INTERVAL.
inline constexpr std::uint32_t kIpfixTemplateResendInterval = 16;
// Original: IPFIX_SOFTFLOWD_MAX_PACKET_SIZE -- shared by NetFlow v9 and
// IPFIX in send_ipfix_common() (the unified sender both versions actually
// use in a default, non---enable-legacy build); NOT the smaller,
// unused-by-default 512-byte buffer declared separately in netflow9.c's
// own send_netflow_v9(), which only exists in --enable-legacy builds.
inline constexpr std::size_t kIpfixMaxPacketSize = 1428;

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

class IpfixExporter {
public:
    // mpls_label_count: see Netflow9Exporter's constructor (netflow9.hpp)
    // -- the same -x semantics apply here.
    //
    // boot_time/boot_wall_time: reference point for
    // IpfixTimeFormat::SysUpTime's millisecond-elapsed encoding
    // (monotonic) and for the Options Record's systemInitTimeMilliseconds
    // (wall-clock epoch) -- see set_boot_time().
    //
    // biflow (original: -b): when true, uses RFC 5103 biflow encoding --
    // one record per flow (not per direction), with the reverse
    // direction's octet/packet/TCP-flags counts carried in Reverse
    // Information Elements (RFC 5103's IANA-assigned Reverse PEN, 29305)
    // alongside the forward direction's ordinary fields.
    explicit IpfixExporter(std::uint32_t observation_domain_id = 0,
                            std::uint8_t mpls_label_count = 0,
                            IpfixTimeFormat time_format = IpfixTimeFormat::SysUpTime,
                            bool biflow = false, TimePoint boot_time = TimePoint{},
                            std::chrono::system_clock::time_point boot_wall_time = {},
                            std::string interface_name = {})
        : observation_domain_id_(observation_domain_id),
          mpls_label_count_(std::min<std::uint8_t>(mpls_label_count, 10)),
          time_format_(time_format), biflow_(biflow), boot_time_(boot_time),
          boot_wall_time_(boot_wall_time), interface_name_(std::move(interface_name)) {}

    // Original: softflowd.c's `ft->param.system_boot_time`, refreshed from
    // the first packet's own (pcap or wall-clock) timestamp -- see
    // softflowd.cpp's call sites alongside Netflow9Exporter::set_boot_time.
    void set_boot_time(TimePoint boot_time,
                        std::chrono::system_clock::time_point boot_wall_time) noexcept {
        boot_time_ = boot_time;
        boot_wall_time_ = boot_wall_time;
    }

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
    void write_options_set(ByteWriter& writer) const;

    std::uint32_t observation_domain_id_;
    std::uint8_t mpls_label_count_;
    IpfixTimeFormat time_format_;
    bool biflow_;
    TimePoint boot_time_;
    std::chrono::system_clock::time_point boot_wall_time_;
    std::string interface_name_; // Original: -i dev, or capfile in -r mode
    std::uint32_t sequence_{0}; // count of Data Records sent so far
    std::uint32_t packets_since_template_{0};
};

} // namespace softflow

#endif // SOFTFLOW_IPFIX_HPP
