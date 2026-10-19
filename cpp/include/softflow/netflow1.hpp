// Original files: compat/netflow1.c, netflow.h
//
// NetFlow v1 is Cisco's original, pre-standardization export format: a
// fixed 16-byte header followed by fixed 48-byte records (IPv4 only, no
// templates). It predates any RFC, so this implementation follows the
// widely-documented de facto layout also used by tools like nfdump and
// flow-tools.
//
// See softflowd.hpp for ByteWriter, which this file uses instead of the
// original's `__packed` struct + htons/htonl approach (see the comment
// above ByteWriter's definition for why).
#ifndef SOFTFLOW_NETFLOW1_HPP
#define SOFTFLOW_NETFLOW1_HPP

#include <chrono>
#include <cstdint>
#include <span>
#include <vector>

#include "softflow/softflowd.hpp"

namespace softflow {

// Original: NETFLOW1_MAXFLOWS in netflow.h -- the maximum number of flow
// records in one NetFlow v1 export packet, following Cisco's documentation.
inline constexpr std::size_t kNetflow1MaxRecordsPerPacket = 24;
inline constexpr std::size_t kNetflow1HeaderSize = 16;
inline constexpr std::size_t kNetflow1RecordSize = 48;

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
    explicit Netflow1Exporter(TimePoint boot_time, bool debug = false)
        : boot_time_(boot_time), debug_(debug) {}

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
};

} // namespace softflow

#endif // SOFTFLOW_NETFLOW1_HPP
