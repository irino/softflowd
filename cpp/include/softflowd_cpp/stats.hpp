/**
 * @file stats.hpp
 * @brief The statistics of the flow table and the debug lines of the expiry scans.
 *
 * Split from softflowd.cpp. The output is that of the original, so that the
 * statistics and the output of -D stay the same.
 *
 * @original statistics () and the verbose_flag output of check_expired () in
 * softflowd.c.
 */
#ifndef SOFTFLOWD_CPP_STATS_HPP
#define SOFTFLOWD_CPP_STATS_HPP

#include "softflowd_cpp/capture.hpp"
#include "softflowd_cpp/export.hpp"
#include "softflowd_cpp/flow.hpp"
#include "softflowd_cpp/softflowd.hpp"

#include <cstddef>
#include <cstdio>
#include <vector>

namespace softflowd_cpp {

/**
 * @brief The mode of the regular scan for expired flows.
 *
 * @original softflowd.c's CE_EXPIRE_NORMAL(0)/CE_EXPIRE_ALL(-1)/
 * CE_EXPIRE_FORCED(1), passed to check_expired() and echoed in its
 * "Starting expiry scan: mode %d" debug line.
 */
constexpr int kCeExpireNormal = 0;
constexpr int kCeExpireAll = -1;    ///< The mode that expires every flow: the expire-all command, and the end of a run.
constexpr int kCeExpireForced = 1;  ///< The mode of the forced scan, which expires the urgent flows and, when the table holds more than -m flows, the oldest ones.

void
print_statistics (const softflowd_cpp::FlowTableStats &s, std::size_t active_flows,
                  softflowd_cpp::FlowLookup lookup,
                  const softflowd_cpp::FlowTableUsage &usage,
                  std::FILE *out, const softflowd_cpp::PcapHandle *handle);

void
log_expiry_debug_start (bool debug, int mode);

void
log_expiry_debug_queued (bool debug, const std::vector<softflowd_cpp::ExportRecord> &expired);

void
log_expiry_debug_sent (bool debug, int packets_sent, std::size_t flows);

void
log_expiry_debug_expired (bool debug, const std::vector<softflowd_cpp::ExportRecord> &expired);

}  // namespace softflowd_cpp

#endif  // SOFTFLOWD_CPP_STATS_HPP
