/**
 * @file run.hpp
 * @brief The two ways softflowd+ collects flows: from a capture file (-r) and from an interface (-i), and what they share.
 *
 * Split from softflowd.cpp. The C version has the loop of both in main () of
 * softflowd.c; run_pcap_file () and run_live_capture () are its two halves.
 *
 * @original main () of softflowd.c.
 */
#ifndef SOFTFLOWD_CPP_RUN_HPP
#define SOFTFLOWD_CPP_RUN_HPP

#include <ctime>
#include <optional>
#include <string>

#include "softflowd_cpp/capture.hpp"
#include "softflowd_cpp/control.hpp"
#include "softflowd_cpp/options.hpp"
#include "softflowd_cpp/sender.hpp"

namespace softflowd_cpp {

/** @brief Reads a capture file (-r), exports the flows, and prints the statistics at the end. See run_file.cpp. */
int
run_pcap_file (const DaemonConfig &config);

/** @brief Captures packets from the interface, exports the flows and answers the control socket, until it is told to stop. See run_live.cpp. */
int
run_live_capture (const DaemonConfig &config,
                  std::optional<PcapHandle> handle,
                  ControlListenerPtr control_socket);

/** @brief Logs that the collection of data starts, and the destinations. See run_common.cpp. */
void
log_start (const DaemonConfig &config, const std::string &source);

/** @brief Logs the CPU clock ticks of the run, and of the export (-g). See run_common.cpp. */
void
report_cpu_clocks (const DaemonConfig &config, std::clock_t cpu_start,
                   const ExportPipeline &exporter);

}  // namespace softflowd_cpp

#endif  // SOFTFLOWD_CPP_RUN_HPP
