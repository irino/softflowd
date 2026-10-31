/**
 * @file export.hpp
 * @brief The exporters of NetFlow v1, v5, v9 and IPFIX.
 *
 * The types of the IPFIX family are in ipfix.hpp, the sizes of the NetFlow v1
 * and v5 packets in netflow.hpp, and what the exporters share in
 * export_common.hpp.
 *
 * @original export.c, export_common.h.
 */
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

/**
 * @brief Builds the packets of NetFlow v1.
 *
 * This class owns none of the actual network I/O -- it only builds the
 * wire-format byte buffers, which the caller (softflowd.cpp's main export
 * loop) is responsible for sending. Keeping packet construction and socket
 * I/O separate makes the construction logic trivially unit-testable without a
 * real network.
 *
 * @original The exporter logic embedded in softflowd.c's send_netflow_v1() (in
 * older revisions of softflowd; later revisions moved per-version export into
 * separate compat/netflow1.c and similar files).
 */
class Netflow1Exporter {
public:
  /**
   * @brief Creates an exporter.
   * @param boot_time The reference point ("device boot") that NetFlow's
   *        uptime-based fields are measured from. In the original, this was
   *        system_boot_time, computed once at startup via gettimeofday().
   * @param debug Log "Sending flow packet len = N" to stderr for each packet,
   *        as -D does in the original (send_multi_destinations() logs every
   *        packet length).
   * @param if_index The interface index of -i idx:interface, put in the input
   *        and output interface fields of the records.
   */
  explicit Netflow1Exporter (TimePoint boot_time, bool debug = false,
                             std::uint16_t if_index = 0)
      : boot_time_ (boot_time), debug_ (debug), if_index_ (if_index) {
  }

  /**
     * @brief Sets the reference point that the uptime-based fields are measured from.
     * @param boot_time The new reference point.
     */
  void
  set_boot_time (TimePoint boot_time) noexcept {
    boot_time_ = boot_time; }

  /**
     * @brief Splits @p records into one or more NetFlow v1 UDP payloads, each
     * containing at most kNetflow1MaxRecordsPerPacket records.
     *
     * @param records The expired flows.
     * @param now The current monotonic time, used to compute the header's
     *        SysUptime field and (indirectly, via each flow's already-recorded
     *        timestamps) the per-record First/Last uptime fields.
     * @param wall_now The current wall-clock time, used for the header's
     *        unix_secs/unix_nsecs fields. Kept as an explicit parameter
     *        (rather than reading std::chrono::system_clock::now() internally)
     *        so tests can supply a fixed value.
     * @return The UDP payloads, in the order to send them.
     */
  std::vector<std::vector<std::uint8_t>>
  build_packets (std::span<const ExportRecord> records, TimePoint now,
                 std::chrono::system_clock::time_point wall_now) const;

private:
  /**
     * @brief Writes the header of a packet.
     * @param writer The buffer of the packet.
     * @param count The number of records in the packet.
     * @param now The current monotonic time.
     * @param wall_now The current wall-clock time.
     */
  void
  write_header (ByteWriter &writer, std::uint16_t count,
                TimePoint now,
                std::chrono::system_clock::time_point wall_now) const;

  TimePoint boot_time_;        ///< The reference point of the uptime fields.
  bool debug_{false};          ///< Log each packet that is built.
  std::uint16_t if_index_{0};  ///< The interface index of the records.
};

/** @brief Builds the packets of NetFlow v5. */
class Netflow5Exporter {
public:
  /**
   * @brief Creates an exporter.
   * @param boot_time The reference point of the uptime-based fields, as for
   *        Netflow1Exporter.
   * @param debug When true, mirrors the reference C softflowd's -D
   *        (verbose_flag) behavior of logging "Sending flow packet len = N" to
   *        stderr for each UDP packet that is built, as the original does
   *        right before it hands the packet off to send_multi_destinations().
   * @param sampling_rate The -s sampling rate. Above 1 it is put in the
   *        sampling_interval field of the header, with the sampling mode 1
   *        (deterministic) in its top 2 bits.
   * @param if_index The interface index of the records, as for
   *        Netflow1Exporter.
   */
  explicit Netflow5Exporter (TimePoint boot_time, bool debug = false,
                             std::uint32_t sampling_rate = 0,
                             std::uint16_t if_index = 0)
      : boot_time_ (boot_time), debug_ (debug), sampling_rate_ (sampling_rate),
        if_index_ (if_index) {
  }

  /**
     * @brief Sets the reference point that the uptime-based fields are measured from.
     * @param boot_time The new reference point.
     */
  void
  set_boot_time (TimePoint boot_time) noexcept {
    boot_time_ = boot_time; }

  /**
     * @brief Splits @p records into one or more NetFlow v5 UDP payloads, each
     * containing at most kNetflow5MaxRecordsPerPacket records.
     *
     * Same time-parameter shape as Netflow1Exporter::build_packets():
     * @p now and @p wall_now are passed in explicitly rather than read from the
     * system clock internally, to keep packet construction deterministic and
     * unit-testable.
     *
     * @param records The expired flows.
     * @param now The current monotonic time.
     * @param wall_now The current wall-clock time.
     * @return The UDP payloads, in the order to send them.
     *
     * @original softflowd.c maintained a single, ever-incrementing
     * "flows_exported" counter that became the flow_sequence field. Here that
     * counter lives inside the exporter object itself (flow_seq_), incremented
     * by the number of records in each call -- exactly one exporter instance
     * should be used for the lifetime of a given export destination, matching
     * the original's one-counter-per-destination design.
     */
  std::vector<std::vector<std::uint8_t>>
  build_packets (std::span<const ExportRecord> records, TimePoint now,
                 std::chrono::system_clock::time_point wall_now);

  /**
     * @brief The flow sequence number of the next packet: the number of flow records built so far.
     * @return The sequence number.
     */
  std::uint32_t
  flow_sequence () const noexcept {
    return flow_seq_; }

private:
  /**
     * @brief Writes the header of a packet.
     * @param writer The buffer of the packet.
     * @param count The number of records in the packet.
     * @param now The current monotonic time.
     * @param wall_now The current wall-clock time.
     */
  void
  write_header (ByteWriter &writer, std::uint16_t count, TimePoint now,
                std::chrono::system_clock::time_point wall_now) const;

  TimePoint boot_time_;             ///< The reference point of the uptime fields.
  std::uint32_t flow_seq_{0};       ///< The flow_sequence field of the next packet.
  bool debug_{false};               ///< Log each packet that is built.
  std::uint32_t sampling_rate_{0};  ///< -s.
  std::uint16_t if_index_{0};       ///< The interface index of the records.
};

/**
 * @brief Builds the messages of IPFIX and of NetFlow v9.
 *
 * The two protocols share the templates, the data records and the packet
 * framing (see MessageVersion), so one class builds both; the constructor
 * selects the protocol.
 */
class IpfixExporter {
public:
  /**
   * @brief Creates an exporter.
   * @param observation_domain_id The Observation Domain ID of IPFIX, which is
   *        the Source ID of the header of NetFlow v9.
   * @param mpls_label_count The number of MPLS labels that are exported (-x),
   *        at most 10.
   * @param time_format The -A time format. NetFlow v9 has no absolute time
   *        formats: for it, IpfixTimeFormat::SysUpTime is used whatever is
   *        given.
   * @param biflow -b: use RFC 5103 biflow encoding -- one record per flow (not
   *        per direction), with the reverse direction's octet/packet/TCP-flags
   *        counts carried in Reverse Information Elements (RFC 5103's
   *        IANA-assigned Reverse PEN, 29305) alongside the forward direction's
   *        ordinary fields. NetFlow v9 has no biflow: it is ignored for it.
   * @param boot_time The reference point for IpfixTimeFormat::SysUpTime's
   *        millisecond-elapsed encoding (monotonic); see set_boot_time().
   * @param boot_wall_time The reference point for the Options Record's
   *        systemInitTimeMilliseconds (wall-clock epoch); see set_boot_time().
   * @param version The protocol to build.
   * @param if_index The interface index (-i if_ndx:dev); the NetFlow v9 options
   *        scope, and the interface fields of the records.
   * @param sampling_rate The -s sampling rate.
   * @param track_level The -T level; the VLAN and Ethernet address fields
   *        belong to the levels "vlan" and "ether".
   */
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

  /**
   * @brief Sets the direction MAC from which flowDirection is derived.
   *
   * Only meaningful when the flows carry Ethernet addresses (-T ether).
   *
   * @param mac The Ethernet address of -H.
   *
   * @original -H, flowDirection from the direction MAC.
   */
  void
  set_direction_mac (const std::array<std::uint8_t, 6> &mac) {
    direction_mac_ = mac;
  }

  /**
     * @brief Sets the exporter addresses that the options record reports (-e).
     * @param addresses The resolved addresses of -e.
     */
  void
  set_exporter_addresses (const ExporterAddresses &addresses) {
    exporter_addresses_ = addresses;
    }

    /**
     * @brief Sends the templates again with the next export packet.
     *
     * @original ipfix_resend_template().
     */
    void force_template_resend() noexcept {
        if (packets_since_template_ != 0) {
            packets_since_template_ = 0;
        }
    }

    /**
     * @brief Sets the reference points of the time fields.
     *
     * @param boot_time The reference point of the millisecond-elapsed encoding
     *        (monotonic).
     * @param boot_wall_time The same instant on the wall clock, for the
     *        Options Record's systemInitTimeMilliseconds.
     *
     * @original softflowd.c's `ft->param.system_boot_time`, refreshed from the
     * first packet's own (pcap or wall-clock) timestamp -- see softflowd.cpp's
     * call sites alongside Netflow9Exporter::set_boot_time.
     */
    void set_boot_time(TimePoint boot_time,
                        std::chrono::system_clock::time_point boot_wall_time) noexcept {
        boot_time_ = boot_time;
        boot_wall_time_ = boot_wall_time;
    }

    /**
     * @brief Builds the messages for the expired flows.
     *
     * @p now and @p wall_now are used together to compute each record's
     * absolute timestamp fields: since Flow's timestamps are recorded on the
     * monotonic Clock (see softflowd.hpp), converting one to an epoch time
     * requires knowing how the monotonic "now" and the wall-clock "wall_now"
     * relate at the moment of export.
     *
     * @param records The expired flows.
     * @param now The current monotonic time.
     * @param wall_now The current wall-clock time.
     * @param template_only_packets When not null (-l with several
     *        destinations), the templates and the options record are sent in a
     *        packet of their own, ahead of the data packet, and the index of
     *        that packet in the result is added to it: it has to reach every
     *        destination, whereas the other packets are balanced among them.
     * @return The messages, in the order to send them.
     *
     * @original send_ipfix_flows()'s template-only packet.
     */
    std::vector<std::vector<std::uint8_t>>
    build_packets (std::span<const ExportRecord> records, TimePoint now,
                   std::chrono::system_clock::time_point wall_now,
                   std::vector<std::size_t> *template_only_packets = nullptr);

    /**
     * @brief The IPFIX sequence number of the next message: the count of Data
     * Records built so far.
     * @return The sequence number.
     */
    std::uint32_t sequence() const noexcept { return sequence_; }

private:
  /**
     * @brief Writes the message header.
     * @param writer The buffer of the message.
     * @param length_or_count The message length for IPFIX and the number of
     *        data records for NetFlow v9.
     * @param now The current monotonic time.
     * @param wall_now The current wall-clock time.
     */
  void
  write_header (ByteWriter &writer, std::uint16_t length_or_count,
                TimePoint now,
                std::chrono::system_clock::time_point wall_now) const;
  /**
     * @brief The size in octets of the message header.
     * @return 16 for IPFIX and 20 for NetFlow v9.
     */
  std::size_t
  header_size () const noexcept {
    return version_ == MessageVersion::Ipfix ? 16 : 20;
    }
    /**
     * @brief Writes the Template Set with the templates of the flow records.
     * @param writer The buffer of the message.
     */
    void write_template_set(ByteWriter& writer) const;
    /**
     * @brief Writes the Options Template Set and the Options Record.
     * @param writer The buffer of the message.
     */
    void write_options_set(ByteWriter& writer) const;

    std::uint32_t observation_domain_id_;                       ///< The Observation Domain ID / Source ID.
    std::uint8_t mpls_label_count_;                             ///< The number of MPLS labels exported (-x), at most 10.
    IpfixTimeFormat time_format_;                               ///< The time format (-A); SysUpTime for NetFlow v9.
    bool biflow_;                                               ///< Biflow encoding (-b); IPFIX only.
    TimePoint boot_time_;                                       ///< The reference point of the SysUpTime encoding.
    std::chrono::system_clock::time_point boot_wall_time_;      ///< The same instant on the wall clock.
    MessageVersion version_;                                    ///< The protocol that is built.
    std::uint32_t if_index_;                                    ///< NetFlow v9 options scope (-i if_ndx:dev).
    std::uint32_t sampling_rate_;                               ///< -s.
    TrackLevel track_level_;                                    ///< -T: VLAN and Ethernet fields.
    ExporterAddresses exporter_addresses_;                      ///< The addresses of -e.
    std::optional<std::array<std::uint8_t, 6>> direction_mac_;  ///< -H.
    std::uint32_t v9_sequence_{1};                              ///< NetFlow v9 counts packets, from 1.
    std::uint32_t sequence_{0};                                 ///< The count of Data Records built so far.
    std::uint32_t packets_since_template_{0};                   ///< Packets since the templates were sent; 0 = send them with the next packet.
};

}  // namespace softflow

#endif  // SOFTFLOW_EXPORT_HPP
