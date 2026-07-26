// Original files: netflow9.c, netflow9.h
//
// Unlike v1/v5, NetFlow v9 (RFC 3954) is template-based: the exporter first
// describes the layout of a record type via a Template FlowSet, then sends
// Data FlowSets whose records the collector decodes according to a
// previously-received template. This implementation defines two fixed
// templates -- one for IPv4 flows, one for IPv6 flows -- and periodically
// re-sends them (since UDP export can be lossy, and a collector that missed
// the original template can't decode any data until it sees one again).
//
// The original tracked template state (when it was last sent, to whom) as
// part of the larger FLOWTRACKPARAMETERS/output-destination bookkeeping.
// Here that state is scoped to one Netflow9Exporter instance, which is
// intended to be constructed once per export destination and reused for
// the daemon's lifetime -- matching the original's one-set-of-templates-
// per-destination model.
#ifndef SOFTFLOW_NETFLOW9_HPP
#define SOFTFLOW_NETFLOW9_HPP

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <span>
#include <vector>

#include "softflow/softflowd.hpp"

namespace softflow {

// Original: netflow9.c used template ID 256 upward for its dynamically
// registered templates. Fixed IDs are used here since only two, unchanging
// record shapes (IPv4 and IPv6 flow records) are exported.
inline constexpr std::uint16_t kNetflow9TemplateIdV4 = 256;
inline constexpr std::uint16_t kNetflow9TemplateIdV6 = 257;

// Conservative per-FlowSet record limits, chosen so that a packet
// containing the template FlowSet plus one of each data FlowSet still
// comfortably fits under a standard 1500-byte Ethernet MTU.
inline constexpr std::size_t kNetflow9MaxV4RecordsPerFlowSet = 20;
inline constexpr std::size_t kNetflow9MaxV6RecordsPerFlowSet = 10;

// Original: softflowd.c resent NetFlow v9/IPFIX templates on a timer
// (independent of data export) so that a collector that missed the first
// template could still eventually decode data. Here, the template is
// resent once every kNetflow9TemplateResendInterval *export packets*
// rather than on a wall-clock timer, which keeps the exporter's behavior a
// pure function of how many packets it has been asked to build (easier to
// unit test) while achieving the same goal.
inline constexpr std::uint32_t kNetflow9TemplateResendInterval = 20;

class Netflow9Exporter {
public:
    // mpls_label_count (original: -x number_of_mpls_labels) fixes how many
    // mplsLabelStackSectionN fields (IANA Information Elements 70-79,
    // clamped here to the registry's defined range of 1-10) are included
    // in both templates for this exporter's lifetime. 0 (the default)
    // omits MPLS fields entirely, matching the original's behavior when
    // -x isn't given.
    explicit Netflow9Exporter(TimePoint boot_time, std::uint32_t source_id = 0,
                               std::uint8_t mpls_label_count = 0)
        : boot_time_(boot_time), source_id_(source_id),
          mpls_label_count_(std::min<std::uint8_t>(mpls_label_count, 10)) {}

    // Returns one export packet per call to this function's internal
    // packing loop; multiple packets are returned when there are more
    // records than fit in a single FlowSet, or when both IPv4 and IPv6
    // records are present. Returns an empty vector if there is nothing to
    // export.
    std::vector<std::vector<std::uint8_t>>
    build_packets(std::span<const ExportRecord> records, TimePoint now,
                  std::chrono::system_clock::time_point wall_now);

    // Original: the "sequence number of this export packet", incremented
    // once per packet sent (RFC 3954 section 5.1) -- unlike NetFlow v5,
    // where flow_sequence counts individual flow *records*.
    std::uint32_t sequence() const noexcept { return sequence_; }

    // Original: softflowctl(8)'s send-template command ("Resend a NetFlow
    // v.9 template record before the next flow export"). The next call to
    // build_packets() will include the Template FlowSet regardless of how
    // recently one was last sent.
    void force_template_resend() noexcept { packets_since_template_ = 0; }

private:
    void write_header(ByteWriter& writer, std::uint16_t record_count,
                       TimePoint now,
                       std::chrono::system_clock::time_point wall_now) const;
    void write_template_flowset(ByteWriter& writer) const;

    TimePoint boot_time_;
    std::uint32_t source_id_;
    std::uint8_t mpls_label_count_;
    std::uint32_t sequence_{0};
    std::uint32_t packets_since_template_{0};
};

} // namespace softflow

#endif // SOFTFLOW_NETFLOW9_HPP
