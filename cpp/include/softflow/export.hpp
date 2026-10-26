// Original files: export.c, export_common.h
//
// The exporters of NetFlow v1, v5, v9 and IPFIX. The types of the IPFIX family
// are in ipfix.hpp, the sizes of the NetFlow v1 and v5 packets in netflow.hpp,
// and what the exporters share in export_common.hpp.
#ifndef SOFTFLOW_EXPORT_HPP
#define SOFTFLOW_EXPORT_HPP

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "softflow/export_common.hpp"
#include "softflow/ipfix.hpp"
#include "softflow/netflow.hpp"
#include "softflow/softflowd.hpp"

namespace softflow {

// Original: the exporter logic embedded in softflowd.c's
// send_netflow_v1() (in older revisions of softflowd; later revisions
// moved per-version export into separate compat/netflow1.c and similar
// files).
// This class owns none of the actual network I/O -- it only builds the
// wire-format byte buffers, which the caller (softflowd.cpp's main
// export loop, in a later stage) is responsible for sending. Keeping
// packet construction and socket I/O separate makes the construction
// logic trivially unit-testable without a real network.
class Netflow1Exporter {
public:
  // boot_time is the reference point ("device boot") that NetFlow's
  // uptime-based fields are measured from. In the original, this was
  // system_boot_time, computed once at startup via gettimeofday().
  //
  // if_index: the interface index of -i idx:interface, put in the input and
  // output interface fields of the records.
  explicit Netflow1Exporter (TimePoint boot_time, bool debug = false,
                             std::uint16_t if_index = 0)
      : boot_time_ (boot_time), debug_ (debug), if_index_ (if_index) {
  }

    void set_boot_time(TimePoint boot_time) noexcept { boot_time_ = boot_time; }

    // Splits `records` into one or more NetFlow v1 UDP payloads, each
    // containing at most kNetflow1MaxRecordsPerPacket records.
    //   now       - the current monotonic time, used to compute the
    //               header's SysUptime field and (indirectly, via each
    //               flow's already-recorded timestamps) the per-record
    //               First/Last uptime fields.
    //   wall_now  - the current wall-clock time, used for the header's
    //               unix_secs/unix_nsecs fields. Kept as an explicit
    //               parameter (rather than reading std::chrono::system_clock::now()
    //               internally) so tests can supply a fixed value.
    std::vector<std::vector<std::uint8_t>>
    build_packets(std::span<const ExportRecord> records, TimePoint now,
                  std::chrono::system_clock::time_point wall_now) const;

private:
    void write_header(ByteWriter& writer, std::uint16_t count,
                       TimePoint now,
                       std::chrono::system_clock::time_point wall_now) const;

    TimePoint boot_time_;
    bool debug_{false};
    std::uint16_t if_index_{0};
};

class Netflow5Exporter {
public:
  // debug: when true, mirrors the reference C softflowd's -D
  // (verbose_flag) behavior of logging "Sending v5 flow packet len =
  // %d" to stderr right before each UDP packet is handed off to
  // send_multi_destinations().
  //
  // sampling_rate: -s. Above 1 it is put in the sampling_interval field of
  // the header, with the sampling mode 1 (deterministic) in its top 2 bits.
  // if_index: as for Netflow1Exporter.
  explicit Netflow5Exporter (TimePoint boot_time, bool debug = false,
                             std::uint32_t sampling_rate = 0,
                             std::uint16_t if_index = 0)
      : boot_time_ (boot_time), debug_ (debug), sampling_rate_ (sampling_rate),
        if_index_ (if_index) {
  }

    void set_boot_time(TimePoint boot_time) noexcept { boot_time_ = boot_time; }

    // Same time-parameter shape as Netflow1Exporter (see netflow1.hpp) --
    // now/wall_now are passed in explicitly rather than read from the
    // system clock internally, to keep packet construction deterministic
    // and unit-testable.
    //
    // Original: softflowd.c maintained a single, ever-incrementing
    // "flows_exported" counter that became the flow_sequence field. Here
    // that counter lives inside the exporter object itself (flow_seq_),
    // incremented by the number of records in each call -- exactly one
    // exporter instance should be used for the lifetime of a given export
    // destination, matching the original's one-counter-per-destination
    // design.
    std::vector<std::vector<std::uint8_t>>
    build_packets(std::span<const ExportRecord> records, TimePoint now,
                  std::chrono::system_clock::time_point wall_now);

    std::uint32_t flow_sequence() const noexcept { return flow_seq_; }

private:
    void write_header(ByteWriter& writer, std::uint16_t count, TimePoint now,
                       std::chrono::system_clock::time_point wall_now) const;

    TimePoint boot_time_;
    std::uint32_t flow_seq_{0};
    bool debug_{false};
    std::uint32_t sampling_rate_{0};
    std::uint16_t if_index_{0};
};

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

}  // namespace softflow

#endif  // SOFTFLOW_EXPORT_HPP
