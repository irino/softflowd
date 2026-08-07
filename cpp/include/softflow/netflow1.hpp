// Original files: netflow1.c, netflow1.h
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

// Original: netflow1.c's NF1_MAXFLOWS -- the maximum number of flow
// records that fit in one NetFlow v1 export packet without risking IP
// fragmentation. (1500 - 16-byte header) / 48-byte record = 30.9, rounded
// down.
// Original: with the default build (configure.ac's --enable-legacy is
// off by default), softflowd.c's `-v 1` doesn't actually use netflow1.c
// at all -- netflow5.c's `#ifndef ENABLE_LEGACY` branch defines
// send_netflow_v1() as send_netflow_v5_v1(sp, 1), the *same* shared
// function used for v5, which uses NF5_MAXFLOWS (30) as its packing
// threshold regardless of version. netflow1.c's own NF1_MAXFLOWS (24)
// only applies to a --enable-legacy build, which is not the default and
// not what this project matches. So this constant intentionally equals
// NetFlow v5's, not a separately-computed "ideal" value for v1's smaller
// header.
inline constexpr std::size_t kNetflow1MaxRecordsPerPacket = 30;

// Original: netflow1.c's true NF1_MAXFLOWS, matching Cisco's original v1
// specification. Only used by softflowd.c when built with
// --enable-legacy (off by default); see Netflow1Exporter's constructor
// comment. Pass this to Netflow1Exporter's max_records_per_packet
// parameter to reproduce a --enable-legacy build (or a genuine Cisco v1
// collector) instead of a default softflowd build.
inline constexpr std::size_t kNetflow1CiscoMaxRecordsPerPacket = 24;
inline constexpr std::size_t kNetflow1HeaderSize = 16;
inline constexpr std::size_t kNetflow1RecordSize = 48;

// Original: the exporter logic embedded in softflowd.c's
// send_netflow_v1() (in older revisions of softflowd; later revisions
// moved per-version export into separate netflow1.c and similar files).
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
    // max_records_per_packet: softflowd.c's *default* build (configure.ac's
    // --enable-legacy is off by default) doesn't actually use netflow1.c
    // at all -- it reuses netflow5.c's send_netflow_v5_v1() for v1 too,
    // which packs up to NF5_MAXFLOWS (30) records per packet, not
    // netflow1.c's own NF1_MAXFLOWS (24, matching Cisco's original v1
    // specification, only used in a --enable-legacy build). Both record
    // *layouts* are byte-identical either way (send_netflow_v5_v1()
    // reconstructs the same NF1_FLOW tail via fill_netflow_v1_proto_tos_
    // tcp()); only this per-packet count differs. Defaults to 30 to match
    // a default (non-legacy) softflowd build; pass 24 (see
    // kNetflow1CiscoMaxRecordsPerPacket) to match a --enable-legacy build
    // or genuine Cisco v1 collectors instead.
    explicit Netflow1Exporter(
        TimePoint boot_time,
        std::size_t max_records_per_packet = kNetflow1MaxRecordsPerPacket,
        bool debug = false)
        : boot_time_(boot_time),
          max_records_per_packet_(max_records_per_packet), debug_(debug) {}

    void set_boot_time(TimePoint boot_time) noexcept { boot_time_ = boot_time; }

    // Splits `records` into one or more NetFlow v1 UDP payloads, each
    // containing at most max_records_per_packet_ records.
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
    std::size_t max_records_per_packet_;
    bool debug_{false};
};

} // namespace softflow

#endif // SOFTFLOW_NETFLOW1_HPP
