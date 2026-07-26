// Original files: netflow5.c, netflow5.h
//
// NetFlow v5 extends v1 with a flow sequence number (so a collector can
// detect lost export packets), engine type/id, and BGP-related fields
// (src_as/dst_as/src_mask/dst_mask) that this project's Flow/FlowKey don't
// currently track and so are exported as zero, matching the original's
// behavior when BGP data isn't available.
#ifndef SOFTFLOW_NETFLOW5_HPP
#define SOFTFLOW_NETFLOW5_HPP

#include <atomic>
#include <chrono>
#include <cstdint>
#include <span>
#include <vector>

#include "softflow/softflowd.hpp"

namespace softflow {

// Original: netflow5.c's NF5_MAXFLOWS. (1500 - 24-byte header) / 48-byte
// record = 30.75, rounded down.
inline constexpr std::size_t kNetflow5MaxRecordsPerPacket = 30;
inline constexpr std::size_t kNetflow5HeaderSize = 24;
inline constexpr std::size_t kNetflow5RecordSize = 48;

class Netflow5Exporter {
public:
    explicit Netflow5Exporter(TimePoint boot_time) : boot_time_(boot_time) {}

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
};

} // namespace softflow

#endif // SOFTFLOW_NETFLOW5_HPP
