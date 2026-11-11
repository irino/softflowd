// Original files: softflowd.c
//
// What is left of the original softflowd.c: main () and its start-up
// messages. The loop that reads a capture file (-r) is in run_file.cpp, the
// loop of the live capture (-i) in run_live.cpp, and what they share in
// run_common.cpp. The other groups of functions of softflowd.c are in the
// files that follow the C version: flow.cpp (with flow_runtime.cpp),
// packet.cpp, capture.cpp, options.cpp, stats.cpp, format.cpp, log.cpp,
// sender.cpp, netsock.cpp, control.cpp and daemon_setup.cpp. See
// ClaudeOutputDocument.en.md for the table of the files.
//
// Build note: the code of this file is compiled out when SOFTFLOWD_CPP_NO_MAIN
// is defined, so that the tests, which supply their own main(), can link the
// other files without a duplicate-symbol error. See CMakeLists.txt.
#include "softflowd_cpp/capture.hpp"
#include "softflowd_cpp/control.hpp"
#include "softflowd_cpp/daemon.hpp"
#include "softflowd_cpp/flow.hpp"
#include "softflowd_cpp/log.hpp"
#include "softflowd_cpp/netsock.hpp"
#include "softflowd_cpp/options.hpp"
#include "softflowd_cpp/packet.hpp"
#include "softflowd_cpp/run.hpp"

#include <cstdint>
#include <cstdio>
#include <exception>
#include <optional>
#include <utility>

#include <net/if.h>

// Original: common.h's PROGNAME/PROGVER macros. There, they're literal
// #defines that happen to be kept in sync with configure.ac's AC_INIT by
// hand, not actually generated from it. Here, SOFTFLOWDPP_NAME/
// SOFTFLOWDPP_VERSION are genuinely injected by CMakeLists.txt's
// project(softflowd+ VERSION ...) declaration (see target_compile_
// definitions(softflow_core ...)), so there is exactly one place --
// CMakeLists.txt -- that defines this project's version. The fallback
// definitions below only matter if this file is ever compiled outside
// that CMake build (e.g. by a stray IDE indexer).
#ifndef SOFTFLOWDPP_NAME
#define SOFTFLOWDPP_NAME "softflowd+"
#endif
#ifndef SOFTFLOWDPP_VERSION
#define SOFTFLOWDPP_VERSION "0.0.0"
#endif

// =======================================================================
// main() (original: softflowd.c's main())
// =======================================================================
#ifndef SOFTFLOWD_CPP_NO_MAIN

namespace {

using softflowd_cpp::DaemonConfig;
using softflowd_cpp::format_name;
using softflowd_cpp::get_interface_mac;
using softflowd_cpp::loginit;
using softflowd_cpp::open_control_listener;
using softflowd_cpp::open_live_capture;
using softflowd_cpp::parse_command_line;
using softflowd_cpp::run_live_capture;
using softflowd_cpp::run_pcap_file;
using softflowd_cpp::StartupError;
using softflowd_cpp::track_level_name;

}  // namespace

int
main (int argc, char **argv) {
  // A daemon's log output is much more useful flushed promptly than
  // batched up in a large buffer -- especially relevant once stdout is
  // redirected to a file or pipe (as it always is once daemonizing
  // redirects it, and as it commonly is under a supervisor like
  // systemd). This has no effect on interactive/TTY use, where stdout is
  // already line-buffered by default.
  std::setvbuf (stdout, nullptr, _IOLBF, 0);

  DaemonConfig config = parse_command_line (argc, argv);

  if (config.debug) {
    std::printf (
      "[softflowd] debug: interface=%s pcap_file=%s max_flows=%zu "
      "track_level=%s version=%s destinations=%zu flow_lookup=%s\n",
      config.interface.c_str(), config.pcap_file.c_str(),
      config.max_flows, track_level_name (config.track_level),
      format_name (config.export_format), config.destinations.size(),
      softflowd_cpp::flow_lookup_name (config.flow_lookup));
  }

  try {
    if (!config.pcap_file.empty()) {
      loginit (SOFTFLOWDPP_NAME, true);
      return run_pcap_file (config);
    }

    // Original: softflowd defaults to daemonizing (forking into the
    // background) when run against a live interface, unless -d is
    // given.
    // Original: the capture and the control socket are set up before the
    // process forks, so that their errors are seen on the terminal.
    auto live_handle = open_live_capture (config);
    auto control_socket = open_control_listener (config.ctl_sock);
#ifdef __linux__
    // Original: without an index with -i, that of the interface is looked up
    // (SIOCGIFINDEX) once there is a destination to export to.
    if (!config.interface.empty() && !config.user_ifindex &&
        !config.destinations.empty()) {
      const unsigned index = if_nametoindex (config.interface.c_str());
      if (index == 0) {
        std::perror ("ioctl SIOCGIFINDEX");
      } else {
        config.if_index = static_cast<std::uint16_t> (index);
      }
      if (config.debug) {
        std::fprintf (stderr, "Using %s (idx: %d as result of SIOCGIFINDEX)\n",
                      config.interface.c_str(), config.if_index);
      }
    }
#endif
    std::optional<softflowd_cpp::PidFile> pidfile;
    if (config.no_daemonize) {
      loginit (SOFTFLOWDPP_NAME, true);
    } else {
      softflowd_cpp::daemonize();
      loginit (SOFTFLOWDPP_NAME, false);
      pidfile.emplace (config.pidfile);
    }
    // Original: with ethernet tracking and no -H, the MAC address of the
    // capture interface is the direction MAC.
    if (config.track_level >= softflowd_cpp::TrackLevel::FullVlanEther &&
        !config.direction_mac.has_value() && !config.interface.empty()) {
      config.direction_mac = get_interface_mac (config.interface);
      if (config.debug) {
        if (config.direction_mac.has_value()) {
          const auto &m = *config.direction_mac;
          std::fprintf (stderr,
                        "Auto-detected direction MAC "
                        "%02x:%02x:%02x:%02x:%02x:%02x from interface %s\n",
                        m[0], m[1], m[2], m[3], m[4], m[5],
                        config.interface.c_str());
        } else {
          std::fprintf (stderr,
                        "Could not auto-detect MAC address of %s; "
                        "flowDirection will use canonical ordering\n",
                        config.interface.c_str());
        }
      }
    }
    return run_live_capture (config, std::move (live_handle),
                             std::move (control_socket));
  } catch (const softflowd_cpp::PcapError &e) {
    std::fprintf (stderr, "%s\n", e.what());
    return 1;
  } catch (const softflowd_cpp::ExportError &e) {
    std::fprintf (stderr, "%s\n", e.what());
    return 1;
  } catch (const StartupError &e) {
    std::fprintf (stderr, "%s\n", e.what());
    return 1;
  } catch (const std::exception &e) {
    std::fprintf (stderr, "%s: %s\n", argv[0], e.what());
    return 1;
  }
}

#endif  // SOFTFLOWD_CPP_NO_MAIN
