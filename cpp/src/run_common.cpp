// Original files: softflowd.c
//
// The two lines that main () logs when it starts collecting, and the report
// of the CPU clocks of -g, which run_pcap_file () and run_live_capture ()
// share. Split from softflowd.cpp. See run.hpp.
#include "softflowd_cpp/run.hpp"
#include "softflowd_cpp/log.hpp"
#include "softflowd_cpp/options.hpp"
#include "softflowd_cpp/sender.hpp"
#include "softflowd_cpp/softflowd.hpp"

#include <ctime>
#include <string>

#include <syslog.h>

// Original: common.h's PROGNAME/PROGVER macros. They are injected by
// CMakeLists.txt; the fallbacks only matter outside that build.
#ifndef SOFTFLOWDPP_NAME
/// The name of the program, which CMakeLists.txt gives.
#define SOFTFLOWDPP_NAME "softflowd+"
#endif
#ifndef SOFTFLOWDPP_VERSION
/// The version of the program, which CMakeLists.txt gives.
#define SOFTFLOWDPP_VERSION "0.0.0"
#endif

namespace softflowd_cpp {

/**
 * @brief Logs that the collection of data starts, and the destinations.
 *
 * @param config The settings.
 * @param source The capture file or the interface.
 *
 * @original the two lines that main () logs when it starts collecting; the
 * capture file or the interface is the first %s of the second.
 */
void
log_start (const DaemonConfig &config, const std::string &source) {
  logit (LOG_NOTICE, "%s v%s starting data collection", SOFTFLOWDPP_NAME,
         SOFTFLOWDPP_VERSION);
  for (const auto &[host, port] : config.destinations) {
    logit (LOG_NOTICE, "Exporting flows from %s to [%s]:%s", source.c_str(),
           host.c_str(), port.c_str());
  }
}

/**
 * @brief Logs the CPU clock ticks of the run, and of the export (-g).
 *
 * @param config The settings.
 * @param cpu_start The value of std::clock () at the start.
 * @param exporter The exporter, which counts its own ticks.
 *
 * @original -g at the exit. The clocks of the export are not counted with the
 * threaded export (-M).
 */
void
report_cpu_clocks (const DaemonConfig &config, std::clock_t cpu_start,
                   const ExportPipeline &exporter) {
  if (!config.gauge_clock) {
    return;
  }
  logit (LOG_INFO, "cpu clocks: %ld\n",
         static_cast<long> (std::clock() - cpu_start));
  if (config.multithread) {
    logit (LOG_INFO, "cpu clocks (export): n/a with threaded export\n");
  } else {
    logit (LOG_INFO, "cpu clocks (export): %ld (%lu calls)\n",
           static_cast<long> (exporter.export_clocks()), exporter.export_calls());
  }
}

}  // namespace softflowd_cpp
