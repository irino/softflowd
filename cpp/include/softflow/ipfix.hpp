// Original files: compat/ipfix.c, ipfix.h, export_common.h
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
#include <array>
#include <optional>
#include <chrono>
#include <cstdint>
#include <span>
#include <vector>

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

// Original: option.exporterAddr (-e), the address reported in the exporter
// address fields of the IPFIX options record. The first IPv4 and the first
// IPv6 address that -e resolves to; an absent address is reported as zero.
struct ExporterAddresses {
  std::optional<std::array<std::uint8_t, 4>> v4;
  std::optional<std::array<std::uint8_t, 16>> v6;
};

// Resolves a host name or an address with getaddrinfo (). Returns no
// addresses when it cannot be resolved.
ExporterAddresses resolve_exporter_addresses (const std::string &host);

// Original: the `version` argument of send_ipfix_flows(). NetFlow v9 and
// IPFIX share the templates, the data records and the packet framing; they
// differ in the message header, the Set IDs of the template and options
// template sets, and the options template and data record. NetFlow v9 has no
// biflow and no absolute time formats.
enum class MessageVersion : std::uint16_t { NetFlow9 = 9, Ipfix = 10 };

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
  explicit IpfixExporter (std::uint32_t observation_domain_id = 0,
                          std::uint8_t mpls_label_count = 0,
                          IpfixTimeFormat time_format = IpfixTimeFormat::SysUpTime,
                          bool biflow = false, TimePoint boot_time = TimePoint{},
                          std::chrono::system_clock::time_point boot_wall_time = {},
                          MessageVersion version = MessageVersion::Ipfix,
                          std::uint32_t if_index = 0,
                          std::uint32_t sampling_rate = 0,
                          TrackLevel track_level = TrackLevel::IpProtoPort)
      : observation_domain_id_ (observation_domain_id),
        mpls_label_count_ (std::min<std::uint8_t> (mpls_label_count, 10)),
        time_format_ (version == MessageVersion::Ipfix
                        ? time_format
                        : IpfixTimeFormat::SysUpTime),
        biflow_ (biflow && version == MessageVersion::Ipfix),
        boot_time_ (boot_time), boot_wall_time_ (boot_wall_time),
        version_ (version),
        if_index_ (if_index), sampling_rate_ (sampling_rate),
        track_level_ (track_level) {
  }

  // Original: -H, flowDirection from the direction MAC. Only meaningful
  // when the flows carry Ethernet addresses (-T ether).
  void
  set_direction_mac (const std::array<std::uint8_t, 6> &mac) {
    direction_mac_ = mac;
  }

    void set_exporter_addresses (const ExporterAddresses &addresses) {
        exporter_addresses_ = addresses;
    }

    // Original: ipfix_resend_template() -- send the templates again with the
    // next export packet.
    void force_template_resend() noexcept {
        if (packets_since_template_ != 0) {
            packets_since_template_ = 0;
        }
    }

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
    //
    // Original: send_ipfix_flows()'s template-only packet. When
    // template_only_packets is not null (-l with several destinations), the
    // templates and the options record are sent in a packet of their own,
    // ahead of the data packet, and the index of that packet in the result
    // is added to *template_only_packets: it has to reach every
    // destination, whereas the other packets are balanced among them.
    std::vector<std::vector<std::uint8_t>>
    build_packets (std::span<const ExportRecord> records, TimePoint now,
                   std::chrono::system_clock::time_point wall_now,
                   std::vector<std::size_t> *template_only_packets = nullptr);

    std::uint32_t sequence() const noexcept { return sequence_; }

private:
    // length_or_count is the message length for IPFIX and the number of data
    // records for NetFlow v9.
    void write_header(ByteWriter& writer, std::uint16_t length_or_count,
                       TimePoint now,
                       std::chrono::system_clock::time_point wall_now) const;
    std::size_t header_size() const noexcept {
        return version_ == MessageVersion::Ipfix ? 16 : 20;
    }
    void write_template_set(ByteWriter& writer) const;
    void write_options_set(ByteWriter& writer) const;

    std::uint32_t observation_domain_id_;
    std::uint8_t mpls_label_count_;
    IpfixTimeFormat time_format_;
    bool biflow_;
    TimePoint boot_time_;
    std::chrono::system_clock::time_point boot_wall_time_;
    MessageVersion version_;
    std::uint32_t if_index_;      // NetFlow v9 options scope (-i if_ndx:dev)
    std::uint32_t sampling_rate_; // -s
    TrackLevel track_level_;      // -T: VLAN and Ethernet fields
    ExporterAddresses exporter_addresses_;
    std::optional<std::array<std::uint8_t, 6>> direction_mac_;
    std::uint32_t v9_sequence_{1};  // NetFlow v9 counts packets, from 1
    std::uint32_t sequence_{0}; // count of Data Records sent so far
    std::uint32_t packets_since_template_{0};
};

} // namespace softflow

#endif // SOFTFLOW_IPFIX_HPP
