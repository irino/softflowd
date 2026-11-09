// Original files: softflowd.c
//
// What is left of the original softflowd.c: main(), the loop that reads a
// capture file (-r), the loop of the live capture (-i), drop_privs() and the
// start-up messages. The other groups of functions of softflowd.c are in the
// files that follow the C version: flow.cpp (with flow_runtime.cpp),
// packet.cpp, capture.cpp, options.cpp, stats.cpp, format.cpp, log.cpp,
// sender.cpp, netsock.cpp and control.cpp. See ClaudeOutputDocument.en.md for
// the table of the files.
//
// Build note: the code of this file is compiled out when SOFTFLOWD_CPP_NO_MAIN
// is defined, so that the tests, which supply their own main(), can link the
// other files without a duplicate-symbol error. See CMakeLists.txt.
#include "softflowd_cpp/capture.hpp"
#include "softflowd_cpp/control.hpp"
#include "softflowd_cpp/daemon.hpp"
#include "softflowd_cpp/flow.hpp"
#include "softflowd_cpp/format.hpp"
#include "softflowd_cpp/log.hpp"
#include "softflowd_cpp/netsock.hpp"
#include "softflowd_cpp/options.hpp"
#include "softflowd_cpp/packet.hpp"
#include "softflowd_cpp/psamp.hpp"
#include "softflowd_cpp/sender.hpp"
#include "softflowd_cpp/softflowd.hpp"
#include "softflowd_cpp/stats.hpp"

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

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <climits>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <exception>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pwd.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

// =======================================================================
// main() (original: softflowd.c's main())
// =======================================================================
#ifndef SOFTFLOWD_CPP_NO_MAIN

namespace {

// The command line moved to options.hpp; this file keeps using its names
// without the qualifier.
using softflowd_cpp::convtime;
using softflowd_cpp::DaemonConfig;
using softflowd_cpp::die_usage;
using softflowd_cpp::ExportFormat;
using softflowd_cpp::format_name;
using softflowd_cpp::kDefaultIpfixPort;
using softflowd_cpp::parse_destinations;
using softflowd_cpp::parse_mac_address;
using softflowd_cpp::parse_netflow_version;
using softflowd_cpp::parse_time_format;
using softflowd_cpp::parse_track_level;
using softflowd_cpp::parse_transport_protocol;
using softflowd_cpp::print_usage;
using softflowd_cpp::set_timeout;
using softflowd_cpp::should_track_ipv6;
using softflowd_cpp::StartupError;
using softflowd_cpp::TimeFormat;
using softflowd_cpp::to_ipfix_time_format;
using softflowd_cpp::track_level_name;
using softflowd_cpp::TransportProtocol;

// The text of addresses, times and flows moved to format.hpp.
using softflowd_cpp::format_address;
using softflowd_cpp::format_ethermac;
using softflowd_cpp::format_flow;
using softflowd_cpp::format_flow_brief;
using softflowd_cpp::format_time;

// The messages moved to log.hpp.
using softflowd_cpp::loginit;
using softflowd_cpp::logit;

// The statistics and the debug lines of the expiry scans moved to stats.hpp.
using softflowd_cpp::log_expiry_debug_expired;
using softflowd_cpp::log_expiry_debug_queued;
using softflowd_cpp::log_expiry_debug_sent;
using softflowd_cpp::log_expiry_debug_start;
using softflowd_cpp::print_statistics;

// The classification of a frame moved to packet.hpp.
using softflowd_cpp::classify_frame;
using softflowd_cpp::FrameClassification;

// The export of the expired flows moved to sender.hpp.
using softflowd_cpp::ExportPipeline;

// The capture moved to capture.hpp.
using softflowd_cpp::get_interface_mac;
using softflowd_cpp::open_live_capture;
using softflowd_cpp::PacketProcessor;

// The control socket moved to control.hpp, and the modes of the expiry scan to stats.hpp.
using softflowd_cpp::control_listener_fd;
using softflowd_cpp::control_listener_state;
using softflowd_cpp::ControlListener;
using softflowd_cpp::ControlListenerPtr;
using softflowd_cpp::ControlState;
using softflowd_cpp::kCeExpireAll;
using softflowd_cpp::kCeExpireForced;
using softflowd_cpp::kCeExpireNormal;
using softflowd_cpp::open_control_listener;
using softflowd_cpp::serve_control_client;

// run_pcap_file (original: softflowd.c's -r mode -- process a capture
// file in a single pass, then print statistics and exit without forking)
// =======================================================================

// Original: PRIVDROP_USER and PRIVDROP_CHROOT_DIR of softflowd.h.
#ifndef PRIVDROP_USER
#define PRIVDROP_USER "nobody"
#endif
#ifndef PRIVDROP_CHROOT_DIR
#define PRIVDROP_CHROOT_DIR "/var/empty"
#endif

/**
 * @brief Changes the root directory of a daemon to an empty one, and its user to an unprivileged one.
 *
 * It exits with 1 when it fails.
 *
 * @original drop_privs (). A daemon changes its root directory to an empty one
 * and its user to an unprivileged one once it has what it needs from the
 * system: the capture, the sockets and the files. Exits on failure.
 */
void
drop_privs () {
  struct passwd *pw = getpwnam (PRIVDROP_USER);
  if (pw == nullptr) {
    logit (LOG_ERR, "Unable to find unprivileged user \"%s\"", PRIVDROP_USER);
    std::exit (1);
  }
  if (chdir (PRIVDROP_CHROOT_DIR) != 0) {
    logit (LOG_ERR, "Unable to chdir to chroot directory \"%s\": %s",
           PRIVDROP_CHROOT_DIR, std::strerror (errno));
    std::exit (1);
  }
  if (chroot (PRIVDROP_CHROOT_DIR) != 0) {
    logit (LOG_ERR, "Unable to chroot to directory \"%s\": %s",
           PRIVDROP_CHROOT_DIR, std::strerror (errno));
    std::exit (1);
  }
  if (chdir ("/") != 0) {
    logit (LOG_ERR, "Unable to chdir to chroot root: %s", std::strerror (errno));
    std::exit (1);
  }
  if (setgroups (1, &pw->pw_gid) != 0) {
    logit (LOG_ERR, "Couldn't setgroups (%u): %s",
           static_cast<unsigned int> (pw->pw_gid), std::strerror (errno));
    std::exit (1);
  }
#ifdef __linux__
  if (setresgid (pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
#else
  if (setregid (pw->pw_gid, pw->pw_gid) == -1) {
#endif
    logit (LOG_ERR, "Couldn't set gid (%u): %s",
           static_cast<unsigned int> (pw->pw_gid), std::strerror (errno));
    std::exit (1);
  }
#ifdef __linux__
  if (setresuid (pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
#else
  if (setreuid (pw->pw_uid, pw->pw_uid) == -1) {
#endif
    logit (LOG_ERR, "Couldn't set uid (%u): %s",
           static_cast<unsigned int> (pw->pw_uid), std::strerror (errno));
    std::exit (1);
  }
}

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

/**
 * @brief Reads a capture file (-r), exports the flows, and prints the statistics at the end.
 *
 * @param config The settings.
 * @return The exit status: 1 for an unsupported data-link type or when a control command ended the run, otherwise 0.
 *
 * @original softflowd.c's -r mode -- process a capture file in a single
 * pass, then print statistics and exit without forking.
 */
int
run_pcap_file (const DaemonConfig &config) {
  using namespace softflowd_cpp;

  PcapHandle handle = PcapHandle::open_offline (config.pcap_file);
  if (!config.bpf_filter.empty()) {
    handle.set_filter (config.bpf_filter);
  }
  const auto dl_kind = handle.datalink_kind();
  if (dl_kind == DatalinkKind::Unsupported) {
    std::fprintf (stderr, "Unsupported datalink type %d\n", handle.datalink());
    return 1;
  }
  const std::size_t skip = datalink_header_len (dl_kind);

  PacketParser parser (config.track_level, config.full_l4hdr_check);
  FlowTableRuntime table (config.flow_lookup, config.max_flows, config.track_level,
                          config.timeouts);
  const TimePoint boot_time = Clock::now();
  ExportPipeline exporter (config, boot_time);
  ControlListenerPtr control;
  if (config.replay_control) {
    control = open_control_listener (config.ctl_sock);
    control_listener_state (*control).expiry_interval = config.expiry_interval;
  }
  TimePoint system_boot_time = boot_time;       // mutable copy, tracks -I reinit
  const std::clock_t cpu_start = std::clock();  // -g

  // Original: softflowd.c's startup logit() calls (logit(LOG_NOTICE,
  // "%s v%s starting data collection", PROGNAME, PROGVER); plus one
  // "Exporting flows from %s to [%s]:%s" per destination). Mirrored
  // here (full pcap path, not truncated to IFNAMSIZ like the original)
  // so the two implementations' output is easy to diff line-for-line.
  // Original: `logit(LOG_NOTICE, "%s v%s starting data collection",
  // PROGNAME, PROGVER);`
  log_start (config, config.pcap_file);

  bool time_base_established = false;
  TimePoint time_base_mono{};
  std::chrono::system_clock::time_point time_base_wall{};

  // Original: SET_EXPORT_NOW(). With -a the export time is the time of the
  // last packet read from the file instead of this process's clock. The
  // control command expire-all uses it too, so it is kept in the control
  // state (a local one when there is no control socket).
  ControlState no_control;
  ControlState &time_state =
    control ? control_listener_state (*control) : no_control;
  time_state.adjust_time = config.adjust_pcap_time;
  TimePoint &last_packet_mono = time_state.last_packet_mono;
  std::chrono::system_clock::time_point &last_packet_wall =
    time_state.last_packet_wall;

  std::uint64_t total = 0;
  std::uint64_t parsed_ok = 0;
  std::uint64_t sampled_total = 0;  // total_packets of the original
  std::uint64_t non_sampled = 0;

  // Original: softflowd.c's main loop reads a capture file with
  // pcap_dispatch(pcap, max_flows, ...), so the table is checked only after
  // every max_flows packets (and after the last, shorter batch); a table
  // that is over max_flows is then reduced by force-expiring the oldest
  // flows. No time-based expiry happens mid-file.
  std::uint64_t batch_packets = 0;
  bool reached_eof = false;
  const auto force_expire_over_max = [&] () {
    // Original: after each batch, a capture file is checked (CE_EXPIRE_FORCED)
    // when the table holds more than max_flows or the next expiry has come:
    // only the flows that are due at once (and those evicted by a collision)
    // expire. A table over max_flows then loses its oldest flows, which are
    // made due at once and expire in a second scan.
    const auto wall_now = config.adjust_pcap_time
                            ? last_packet_wall
                            : std::chrono::system_clock::now();
    if (table.size() <= table.max_flows() &&
        table.next_expire (wall_now, config.expiry_interval) != 0) {
      return;
    }
    const auto scan = [&] (const std::vector<ExportRecord> &expired) {
      log_expiry_debug_queued (config.debug, expired);
      if (expired.empty()) {
        return;
      }
      const auto outcome =
        config.adjust_pcap_time
          ? exporter.export_flows (expired, last_packet_mono, last_packet_wall)
          : exporter.export_flows (expired, last_packet_mono,
                                   std::chrono::system_clock::now());
      table.record_export_stats (outcome.flows, outcome.records,
                                 outcome.packets, outcome.failures);
      log_expiry_debug_sent (config.debug, static_cast<int> (outcome.packets),
                             expired.size());
      log_expiry_debug_expired (config.debug, expired);
    };
    log_expiry_debug_start (config.debug, kCeExpireForced);
    scan (table.expire_urgent());
    if (table.size() > table.max_flows()) {
      if (config.debug) {
        logit (LOG_INFO, "Forcing expiry of %zu flows",
               table.size() - table.max_flows());
      }
      const auto forced =
        table.force_expire_oldest (table.size() - table.max_flows());
      log_expiry_debug_start (config.debug, kCeExpireForced);
      scan (forced);
    }
  };

  // Original: with a control socket, softflowd.c waits for the capture file
  // and the control socket together, before each pcap_dispatch () of
  // max_flows packets, so that softflowctl (8) is answered even while a file
  // such as a FIFO has no data. stop-gather keeps the file from being read.
  // Returns false when the controller asked to shut down or to exit.
  const int control_fd = control ? control_listener_fd (*control) : -1;
  const int capture_fd = control ? handle.selectable_fd() : -1;
  const auto wait_for_input = [&] () {
    for (;;) {
      struct pollfd fds[2]{};
      fds[0].fd = control_listener_state (*control).capturing ? capture_fd : -1;
      fds[0].events = POLLIN | POLLERR | POLLHUP;
      fds[1].fd = control_fd;
      fds[1].events = POLLIN | POLLERR | POLLHUP;
      if (poll (fds, 2, -1) < 0) {
        if (errno == EINTR) {
          continue;
        }
        throw std::runtime_error (std::string ("poll failed: ") + std::strerror (errno));
      }
      if (fds[1].revents != 0 && serve_control_client (*control, table, exporter, &handle)) {
        return false;
      }
      if (control_listener_state (*control).capturing && fds[0].revents != 0) {
        return true;
      }
    }
  };

  for (;;) {
    if (batch_packets % table.max_flows() == 0) {
      if (batch_packets != 0) {
        force_expire_over_max();
      }
      if (control && !wait_for_input()) {
        break;
      }
    }
    auto pkt = handle.next_packet();
    if (!pkt) {
      reached_eof = true;
      break;
    }
    ++batch_packets;
    ++total;
    // Original: flow_cb () makes the first packet the boot time (-a) before
    // anything else is done with it, and process_packet () *always* sources
    // flow->flow_start/flow->flow_last from phdr->ts (the pcap file's
    // own recorded timestamp) via PCAP_TS_TO_TIMEVAL -- this is not
    // conditional on -a. (-a/adjust_time only affects the separate
    // system_boot_time/last_packet_time fields used for uptime-style
    // export encoding, not per-flow timing.) So effective_time must
    // always be derived from the file's own timestamps here, not from
    // this process's wall clock -- otherwise flow durations reflect
    // how fast this process reads the file instead of the capture's
    // real elapsed time. The very first packet establishes the mapping
    // between the pcap file's timestamps and this process's monotonic
    // clock; every subsequent packet's effective_time is that anchor
    // plus its own delta from the first packet's recorded time.
    if (!time_base_established) {
      time_base_mono = Clock::now();
      time_base_wall = pkt->wall_timestamp;
      time_base_established = true;
      if (config.adjust_pcap_time) {
        // Original: -a makes the first packet's time the boot time.
        system_boot_time = time_base_mono;
        if (control) {
          control_listener_state (*control).boot_wall = pkt->wall_timestamp;
        }
        exporter.reinit_boot_time (time_base_mono, pkt->wall_timestamp);
        last_packet_mono = time_base_mono;
        last_packet_wall = pkt->wall_timestamp;
      }
    }
    const TimePoint effective_time =
      time_base_mono + std::chrono::duration_cast<Clock::duration> (
                         pkt->wall_timestamp - time_base_wall);

    // Original: flow_cb (). -s is tested before the packet is counted, so
    // the first packet is the first one that is kept; a packet that is not
    // IP is taken back out of the count below.
    if (config.sampling_rate > 1 &&
        (sampled_total + non_sampled) % config.sampling_rate > 0) {
      ++non_sampled;
      continue;
    }
    ++sampled_total;
    if (config.export_format == ExportFormat::Psamp) {
      table.count_packet_without_flow();
      exporter.export_psamp (
        PsampSample{pkt->data, pkt->wall_timestamp, sampled_total},
        config.adjust_pcap_time);
      continue;
    }
    // Original: flow_cb () records the time of the packet whatever became of
    // it (not for -v psamp, nor for a packet that sampling left out).
    last_packet_mono = effective_time;
    last_packet_wall = pkt->wall_timestamp;
    if (pkt->data.size() <= skip) {
      table.count_non_ip_packet();
      --sampled_total;
      continue;
    }
    const auto ip_bytes = pkt->data.subspan (skip);

    const auto frame = classify_frame (*pkt, dl_kind, ip_bytes);
    if (!frame.has_value()) {
      table.count_non_ip_packet();
      --sampled_total;
      continue;
    }
    if (frame->af == AddressFamily::IPv6 && !should_track_ipv6 (config)) {
      table.count_non_ip_packet();
      --sampled_total;
      continue;
    }

    auto parsed = parser.parse (ip_bytes.subspan (frame->ip_offset), frame->af);
    if (!parsed.has_value()) {
      table.count_bad_packet();
      continue;
    }
    ++parsed_ok;

    // Original: when a capture file is read, check_expired() runs with
    // CE_EXPIRE_FORCED only, so no flow is expired for being idle mid-file,
    // with or without -a: flows accumulate until EOF, apart from the forced
    // eviction at max_flows (force_expire_over_max below). -a only makes the
    // export and boot times follow the packets' own times.

    const auto key = make_flow_key (*parsed, parser.track_level(),
                                    {frame->vlanid, 0}, frame->ethermac);
    const std::uint8_t direction = flow_direction (key, *parsed);
    // Original: `tmp.octets[ndx] = phdr->len - datalink_size;` --
    // octet counts exclude the L2 (e.g. Ethernet) header. Using the
    // raw on-the-wire length here over-counted every packet by the
    // L2 header size (e.g. +14 bytes/packet for Ethernet).
    const std::size_t size_before = table.size();
    Flow &flow = table.record_packet (key, effective_time, pkt->wall_timestamp,
                                      direction, pkt->original_length - skip - frame->vlan_size,
                                      parsed->tcp_flags, parsed->tos);
    // Original: `if (verbose_flag) logit(LOG_DEBUG, "ADD FLOW %s", ...)`
    // in process_packet(), logged only when a *new* flow entry is
    // created (not on every packet belonging to an existing flow).
    if (config.debug && table.size() != size_before) {
      logit (LOG_DEBUG, "ADD FLOW %s",
             format_flow_brief (flow.flow_seq, key).c_str());
    }
    // Original: -x. Only actually stored (and later exported) when
    // requested, capped both by -x's own argument and by the IPFIX/
    // NetFlow v9 Information Element registry's defined range of 10
    // label-stack-section fields.
    if (config.mpls_labels > 0 && !frame->mpls_labels.empty()) {
      const std::size_t keep = std::min<std::size_t> (
        {frame->mpls_labels.size(),
         static_cast<std::size_t> (config.mpls_labels), 10});
      flow.mpls_labels.assign (frame->mpls_labels.begin(),
                               frame->mpls_labels.begin() +
                                 static_cast<std::ptrdiff_t> (keep));
    }

    // Original: softflowd.c's check_expired() -- if boot_time_reinit
    // (-I) is set and more time than that has elapsed since the last
    // reset, treat the current packet's time as the new reference
    // point that uptime-based export fields are measured from.
    if (config.boot_time_reinit.count() != 0 &&
        effective_time - system_boot_time > config.boot_time_reinit) {
      system_boot_time = effective_time;
      if (control) {
        control_listener_state (*control).boot_wall = pkt->wall_timestamp;
      }
      exporter.reinit_boot_time (system_boot_time);
    }
  }

  force_expire_over_max();

  // Original: softflowd.c's main() -- reaching EOF on a pcap file sets
  // graceful_shutdown_request, which the shared shutdown path then logs
  // as both of these lines (yes, the original really does log "on user
  // request" here too, even though EOF triggered it, not a user signal).
  if (reached_eof) {
    logit (LOG_NOTICE, "Shutting down after pcap EOF");
  }
  logit (LOG_WARNING, control && control_listener_state (*control).immediate_exit
                        ? "Exiting immediately on user request"
                        : "Shutting down on user request");

  const auto now = config.adjust_pcap_time ? last_packet_mono : Clock::now();
  const auto wall_now = config.adjust_pcap_time
                          ? last_packet_wall
                          : std::chrono::system_clock::now();
  log_expiry_debug_start (config.debug, kCeExpireAll);
  // Original: the exit command leaves without expiring the flows.
  const bool immediate_exit =
    control && control_listener_state (*control).immediate_exit;
  const auto expired =
    immediate_exit ? decltype (table.expire_flows (now, true)){}
                   : table.expire_flows (now, /*flush_all=*/true);
  log_expiry_debug_queued (config.debug, expired);
  const auto eof_outcome = exporter.export_flows (expired, now, wall_now);
  table.record_export_stats (eof_outcome.flows, eof_outcome.records,
                             eof_outcome.packets, eof_outcome.failures);
  log_expiry_debug_sent (config.debug, static_cast<int> (eof_outcome.packets),
                         expired.size());
  log_expiry_debug_expired (config.debug, expired);

  // Original: `if (capfile != NULL && dontfork_flag) statistics(...)`.
  // dontfork_flag looks like it depends on -d, but softflowd.c's own
  // `case 'r':` unconditionally sets `dontfork_flag = 1` as a side
  // effect of choosing -r -- so in the original, reading from a pcap
  // file *always* forces foreground mode and this condition is always
  // true, with or without -d. run_pcap_file() here only ever runs for
  // -r, so the equivalent is: always print.
  exporter.wait_idle();
  exporter.sync_stats (table);
  print_statistics (table.stats(), table.size(), table.lookup(), table.usage(),
                    stdout, &handle);
  report_cpu_clocks (config, cpu_start, exporter);
  // Original: main () returns 1 when shutdown or exit stopped it.
  return control && control_listener_state (*control).stopped_by_controller ? 1 : 0;
}

// =======================================================================
// Live capture with daemon control (original: softflowd.c's main loop
// when running against a live interface, plus its control-socket
// handling)
// =======================================================================

/**
 * @brief Captures packets from the interface, exports the flows and answers the control socket, until it is told to stop.
 *
 * It is stopped by the shutdown or exit command, by a signal, or by --max-runtime. The capture and the control socket have been opened by the caller before it forked.
 *
 * The capture and the control socket have been opened by the caller, before
 * it forked.
 *
 * @param config The settings.
 * @param handle The capture; nothing when only PSAMP is received (-R without -i).
 * @param control_socket The control socket.
 * @return The exit status: 1 when a control command ended the run, otherwise 0.
 */
int
run_live_capture (const DaemonConfig &config,
                  std::optional<softflowd_cpp::PcapHandle> handle,
                  ControlListenerPtr control_socket) {
  using namespace softflowd_cpp;

  const std::clock_t cpu_start = std::clock();  // -g
  const auto dl_kind =
    handle.has_value() ? handle->datalink_kind() : DatalinkKind::Ethernet;
  const std::size_t skip = datalink_header_len (dl_kind);

  PacketParser parser (config.track_level, config.full_l4hdr_check);
  FlowTableRuntime table (config.flow_lookup, config.max_flows, config.track_level,
                          config.timeouts);
  const TimePoint boot_time = Clock::now();
  const auto start_time = boot_time;
  ExportPipeline exporter (config, boot_time);

  // Original: softflowd.c bound and listened on /var/run/softflowd.ctl
  // (or -c's argument) for softflowctl(8) connections. RAII (this small
  // guard struct) ensures both the listening socket and its filesystem
  // entry are cleaned up on every return path from this function,
  // including an exception.
  ControlListener &control = *control_socket;
  const int ctl_fd = control.fd();

  // Original: -R receive_port. An additional UDP socket, listened on
  // alongside the pcap capture descriptor, control socket, and signal
  // pipe -- see PsampReceiver (psamp.hpp) for how received datagrams are
  // decoded back into SampledPacket values, which are then fed into
  // FlowTable::record_packet() exactly as if they'd been locally
  // captured.
  int psamp_fd = -1;
  struct PsampSocketGuard {
    int fd;
    ~PsampSocketGuard () {
      if (fd >= 0) {
        ::close (fd);
      }
    }
  } psamp_guard{-1};
  if (config.psamp_receive_port.has_value()) {
    // Prefer a dual-stack IPv6 socket (accepting both IPv4- and
    // IPv6-sourced datagrams); fall back to IPv4-only if the platform
    // or environment doesn't support IPv6 at all (e.g. some
    // containers/sandboxes disable it entirely).
    psamp_fd = socket (AF_INET6, SOCK_DGRAM, 0);
    const bool using_ipv6 = psamp_fd >= 0;
    if (!using_ipv6) {
      psamp_fd = socket (AF_INET, SOCK_DGRAM, 0);
    }
    if (psamp_fd < 0) {
      throw std::runtime_error ("socket() for PSAMP receive port failed");
    }

    int bind_result = -1;
    if (using_ipv6) {
      // Accept both IPv4 and IPv6 senders on one dual-stack socket
      // where the platform supports it; a failure to clear
      // IPV6_V6ONLY is non-fatal (the socket still works for
      // IPv6-only use).
#ifdef IPV6_V6ONLY
      const int v6only = 0;
      setsockopt (psamp_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof (v6only));
#endif
      struct sockaddr_in6 psamp_addr{};
      psamp_addr.sin6_family = AF_INET6;
      psamp_addr.sin6_addr = in6addr_any;
      psamp_addr.sin6_port =
        htons (static_cast<std::uint16_t> (*config.psamp_receive_port));
      bind_result = bind (psamp_fd, reinterpret_cast<struct sockaddr *> (&psamp_addr),
                          sizeof (psamp_addr));
    } else {
      struct sockaddr_in psamp_addr{};
      psamp_addr.sin_family = AF_INET;
      psamp_addr.sin_addr.s_addr = INADDR_ANY;
      psamp_addr.sin_port =
        htons (static_cast<std::uint16_t> (*config.psamp_receive_port));
      bind_result = bind (psamp_fd, reinterpret_cast<struct sockaddr *> (&psamp_addr),
                          sizeof (psamp_addr));
    }
    if (bind_result < 0) {
      ::close (psamp_fd);
      throw std::runtime_error ("failed to bind PSAMP receive port " +
                                std::to_string (*config.psamp_receive_port));
    }
    // Set O_NONBLOCK on the socket itself, rather than relying solely
    // on passing MSG_DONTWAIT to each individual recv() call below --
    // belt-and-braces, matching the same reasoning as SignalPipe's
    // pipe file descriptors (daemon.cpp): a blocking recv() here,
    // even briefly, would stall the entire event loop (control
    // socket, signals, pcap capture) until another PSAMP datagram
    // happened to arrive.
    const int psamp_flags = fcntl (psamp_fd, F_GETFL, 0);
    if (psamp_flags >= 0) {
      fcntl (psamp_fd, F_SETFL, psamp_flags | O_NONBLOCK);
    }
    psamp_guard.fd = psamp_fd;
  }

  SignalPipe signals;
  ControlState state;
  state.expiry_interval = config.expiry_interval;

  std::uint64_t sampled_total = 0;  // total_packets of the original
  std::uint64_t non_sampled = 0;

  // Original: only a daemon drops its privileges (main () does it when it is
  // not told to stay in the foreground), after the capture, the control
  // socket, the sockets of the destinations and the other files are open.
  if (!config.no_daemonize) {
    drop_privs();
  }
  log_start (config, config.interface);

  // Original: with -a, flow_cb () records the time of the last packet in
  // last_packet_time, which next_expire () and check_expired () use as the
  // current time instead of gettimeofday ().
  // The control command expire-all uses it too.
  state.adjust_time = config.adjust_pcap_time;
  TimePoint &last_packet_mono = state.last_packet_mono;
  std::chrono::system_clock::time_point &last_packet_wall =
    state.last_packet_wall;
  const auto current_mono = [&] () {
    return config.adjust_pcap_time ? last_packet_mono : Clock::now();
  };
  const auto current_wall = [&] () {
    return config.adjust_pcap_time ? last_packet_wall
                                   : std::chrono::system_clock::now();
  };

  // The flow tracking of one captured packet. With -M it runs in another
  // thread (see PacketProcessor); the main loop waits for it before it uses
  // the table, the exporter or the samples.
  const auto process_packet = [&] (const softflowd_cpp::CapturedPacket &pkt) {
    // Original: flow_cb (); see the replay loop.
    if (config.sampling_rate > 1 &&
        (sampled_total + non_sampled) % config.sampling_rate > 0) {
      ++non_sampled;
      return;
    }
    ++sampled_total;
    if (config.export_format == ExportFormat::Psamp) {
      table.count_packet_without_flow();
      exporter.export_psamp (
        PsampSample{pkt.data, pkt.wall_timestamp, sampled_total}, false);
      return;
    }
    // Original: the time of the last packet is recorded after the packet has
    // been processed, whatever became of it (it is not for a sampled-out one
    // or with -v psamp).
    struct LastPacket {
      bool adjust;
      const softflowd_cpp::CapturedPacket &pkt;
      TimePoint &mono;
      std::chrono::system_clock::time_point &wall;
      ~LastPacket() {
        if (adjust) {
          mono = pkt.timestamp;
          wall = pkt.wall_timestamp;
        }
      }
    } last_packet{config.adjust_pcap_time, pkt, last_packet_mono,
                  last_packet_wall};
    if (pkt.data.size() <= skip) {
      table.count_non_ip_packet();
      --sampled_total;
      return;
    }
    const auto ip_bytes = pkt.data.subspan (skip);

    const auto frame = classify_frame (pkt, dl_kind, ip_bytes);
    if (!frame.has_value()) {
      table.count_non_ip_packet();
      --sampled_total;
      return;
    }
    if (frame->af == AddressFamily::IPv6 && !should_track_ipv6 (config)) {
      table.count_non_ip_packet();
      --sampled_total;
      return;
    }

    auto parsed =
      parser.parse (ip_bytes.subspan (frame->ip_offset), frame->af);
    if (!parsed.has_value()) {
      table.count_bad_packet();
      return;
    }

    const auto key = make_flow_key (*parsed, parser.track_level(),
                                    {frame->vlanid, 0}, frame->ethermac);
    const std::uint8_t direction = flow_direction (key, *parsed);
    const std::size_t size_before = table.size();
    Flow &flow = table.record_packet (
      key, pkt.timestamp, pkt.wall_timestamp, direction,
      pkt.original_length - skip - frame->vlan_size, parsed->tcp_flags, parsed->tos);
    if (config.debug && table.size() != size_before) {
      logit (LOG_DEBUG, "ADD FLOW %s",
             format_flow_brief (flow.flow_seq, key).c_str());
    }
    if (config.mpls_labels > 0 && !frame->mpls_labels.empty()) {
      const std::size_t keep = std::min<std::size_t> (
        {frame->mpls_labels.size(),
         static_cast<std::size_t> (config.mpls_labels), 10});
      flow.mpls_labels.assign (
        frame->mpls_labels.begin(),
        frame->mpls_labels.begin() + static_cast<std::ptrdiff_t> (keep));
    }
  };
  std::optional<PacketProcessor> processor;
  if (config.multithread) {
    processor.emplace (process_packet);
  }

  // Original: flow_cb () takes the flow times from phdr->ts, the time that
  // libpcap recorded for a packet (for a PSAMP message its
  // observationTimeMicroseconds), and not from the time at which the packet is
  // read. That time is mapped to this process's monotonic clock from one
  // anchor, as the capture file replay does, and with -a the first packet or
  // message is the boot time.
  bool time_anchored = false;
  TimePoint time_base_mono = boot_time;
  auto time_base_wall = std::chrono::system_clock::now();
  const auto packet_time = [&] (std::chrono::system_clock::time_point wall) {
    if (!time_anchored) {
      time_anchored = true;
      if (config.adjust_pcap_time) {
        time_base_mono = Clock::now();
        time_base_wall = wall;
        state.boot_wall = wall;
        exporter.reinit_boot_time (time_base_mono, wall);
      }
    }
    return time_base_mono +
           std::chrono::duration_cast<Clock::duration> (wall - time_base_wall);
  };

  while (!state.shutting_down && !state.immediate_exit) {
    struct pollfd fds[4];
    fds[0] = {signals.read_fd(), POLLIN, 0};
    fds[1] = {ctl_fd, POLLIN, 0};
    const int pcap_fd = handle.has_value() ? handle->selectable_fd() : -1;
    fds[2] = {pcap_fd >= 0 ? pcap_fd : -1, POLLIN, 0};
    fds[3] = {psamp_fd >= 0 ? psamp_fd : -1, POLLIN, 0};

    // Original: poll () waits until the next expiry, clustered by
    // expiry_interval (next_expire ()); without a flow it waits for ever.
    if (processor.has_value()) {
      processor->wait_idle();
    }
    int timeout_ms =
      table.next_expire (current_wall(), config.expiry_interval);
    if (config.max_runtime.has_value() && (timeout_ms < 0 || timeout_ms > 1000)) {
      timeout_ms = 1000;  // --max-runtime needs to look at the clock
    }
    const int ready = poll (fds, 4, timeout_ms);
    if (ready < 0 && errno != EINTR) {
      throw std::runtime_error ("poll() failed");
    }
    if (processor.has_value()) {
      processor->wait_idle();
    }

    for (int sig : signals.drain()) {
      if (sig == SIGTERM || sig == SIGINT) {
        state.shutting_down = true;
      } else if (sig == SIGUSR1) {
        logit (LOG_INFO, "stats: tracked=%zu total_packets=%llu", table.size(),
               static_cast<unsigned long long> (table.stats().total_packets));
      } else if (sig == SIGHUP) {
        logit (LOG_INFO, "SIGHUP received (config reload not implemented)");
      }
    }

    if ((fds[1].revents & POLLIN) != 0) {
      control.serve_client (table, state, exporter,
                            handle.has_value() ? &*handle : nullptr);
    }

    if (pcap_fd >= 0 && (fds[2].revents & POLLIN) != 0 && state.capturing) {
      // Bounded rather than "drain until there is no packet": under
      // sustained traffic, an unbounded drain here could starve the control
      // socket and signal handling below of any chance to run. Packets
      // that are still waiting after this many are picked up on the very
      // next poll () iteration.
      //
      // The handle is not blocking, so next_packet () returns at once when
      // libpcap holds no packet. The descriptor is not asked again between
      // two packets: libpcap hands over several packets that it read in one
      // go, and the descriptor is not readable for those.
      // Original: r = pcap_dispatch (pcap, max_flows, flow_cb, ...), once per
      // wake-up: libpcap hands over the packets of one read, at most max_flows,
      // and the flow table is only checked for being over max_flows after that.
      // Bounded, so that a sustained traffic cannot starve the control socket
      // and the signals; what is left is picked up on the next poll ().
      // The handle is not blocking, so this returns at once when libpcap has
      // no packet.
      const int dispatched = handle->dispatch (
        static_cast<int> (std::min<std::size_t> (table.max_flows(), 0x7fffffff)),
        [&] (const CapturedPacket &captured) {
          CapturedPacket pkt = captured;
          pkt.timestamp = packet_time (captured.wall_timestamp);
          if (processor.has_value()) {
            processor->submit (pkt);
          } else {
            process_packet (pkt);
          }
        });
      if (dispatched == -1) {
        throw std::runtime_error (std::string ("pcap_dispatch failed"));
      }
      if (processor.has_value()) {
        processor->wait_idle();
      }
    }

    if (psamp_fd >= 0 && (fds[3].revents & POLLIN) != 0) {
      // Original: -R. Drains every currently-queued datagram (not
      // just one) each time the socket is readable, the same
      // bounded-batch reasoning as the pcap-draining loop above
      // applies here too, so a burst of incoming PSAMP messages
      // can't starve the control socket or signal handling either.
      // Original: recvloop < max_flows.
      const std::size_t max_datagrams_per_cycle = table.max_flows();
      std::array<std::uint8_t, 65536> buffer;
      for (std::size_t n = 0; n < max_datagrams_per_cycle; ++n) {
        struct sockaddr_storage sender_addr{};
        socklen_t sender_len = sizeof (sender_addr);
        const ssize_t received =
          recvfrom (psamp_fd, buffer.data(), buffer.size(), MSG_DONTWAIT,
                    reinterpret_cast<struct sockaddr *> (&sender_addr),
                    &sender_len);
        if (received <= 0) {
          break;  // no more datagrams queued right now
        }
        // Original: recv_psamp (). The frame of a message of softflowd is
        // processed like a packet that was captured: it goes through the same
        // sampling and flow tracking as one.
        auto frame = decode_psamp_message (std::span<const std::uint8_t> (
          buffer.data(), static_cast<std::size_t> (received)));
        if (!frame.has_value()) {
          continue;
        }
        if (processor.has_value()) {
          processor->wait_idle();
        }
        const CapturedPacket packet{
          std::span<const std::uint8_t> (frame->frame), frame->original_length,
          packet_time (frame->observed_at), frame->observed_at};
        process_packet (packet);
      }
    }

    // Original: the flow table is checked when the next expiry, clustered by
    // -t expint (a larger interval groups more flows into fewer, larger
    // export packets), has come, or when it holds more than max_flows.
    const auto now = current_mono();
    const auto wall_now = current_wall();
    if (table.size() > table.max_flows() ||
        table.next_expire (wall_now, config.expiry_interval) == 0) {
      const auto scan = [&] (const std::vector<ExportRecord> &expired) {
        log_expiry_debug_queued (config.debug, expired);
        const auto outcome = exporter.export_flows (expired, now, wall_now);
        table.record_export_stats (outcome.flows, outcome.records,
                                   outcome.packets, outcome.failures);
        log_expiry_debug_sent (config.debug, static_cast<int> (outcome.packets),
                               expired.size());
        log_expiry_debug_expired (config.debug, expired);
      };
      // Original: expiry_check. A table over max_flows loses its oldest flows,
      // which expire in a second scan.
      log_expiry_debug_start (config.debug, kCeExpireNormal);
      scan (table.expire_flows (now));
      if (table.size() > table.max_flows()) {
        if (config.debug) {
          logit (LOG_INFO, "Forcing expiry of %zu flows",
                 table.size() - table.max_flows());
        }
        const auto forced =
          table.force_expire_oldest (table.size() - table.max_flows());
        log_expiry_debug_start (config.debug, kCeExpireNormal);
        scan (forced);
      }
    }

    if (config.max_runtime.has_value() &&
        Clock::now() - start_time >= *config.max_runtime) {
      state.shutting_down = true;
    }
  }

  // Original: the flags of the signal handlers and of the control socket are
  // logged as these three lines (the last of them is for an internal error,
  // which this version has no case of).
  if (state.shutting_down) {
    logit (LOG_WARNING, "Shutting down on user request");
    // Original: "receipt of a SIGTERM or SIGINT will cause softflowd
    // to exit, after expiring all flows (and thus sending flow export
    // packets if -n was specified)".
    const auto now = current_mono();
    const auto wall_now = current_wall();
    log_expiry_debug_start (config.debug, kCeExpireAll);
    const auto expired = table.expire_flows (now, /*flush_all=*/true);
    log_expiry_debug_queued (config.debug, expired);
    const auto outcome = exporter.export_flows (expired, now, wall_now);
    table.record_export_stats (outcome.flows, outcome.records,
                               outcome.packets, outcome.failures);
    log_expiry_debug_sent (config.debug, static_cast<int> (outcome.packets),
                           expired.size());
    log_expiry_debug_expired (config.debug, expired);
  }

  if (!state.shutting_down) {
    logit (LOG_WARNING, "Exiting immediately on user request");
  }
  exporter.wait_idle();
  report_cpu_clocks (config, cpu_start, exporter);
  // Original: main () returns 1 when shutdown or exit stopped it.
  return state.stopped_by_controller ? 1 : 0;
}

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

  DaemonConfig config;

  // This project's own additions are exposed as GNU-style long options
  // via getopt_long(). Every existing short option keeps its exact
  // original letter and argument-taking behavior (the optstring below is
  // unchanged), so any script or invocation built against the original
  // softflowd's short-option grammar continues to work unmodified;
  // getopt_long() simply also accepts these long forms alongside them.
  enum {
    kOptExportOut = 1000,
    kOptMaxRuntime,
    kOptIcmpTypecodeOnly,
    kOptExpirySecondGranularity,
    kOptNoExpirySecondGranularity,
  };
  static const struct option long_options[] = {
    {"track-ipv6", no_argument, nullptr, '6'},
    {"adjust-time", no_argument, nullptr, 'a'},
    {"absolute-time", required_argument, nullptr, 'A'},
    {"bidirectional", no_argument, nullptr, 'b'},
    {"pcap-buffer-size", required_argument, nullptr, 'B'},
    {"control-socket", required_argument, nullptr, 'c'},
    {"snaplen", required_argument, nullptr, 'C'},
    {"foreground", no_argument, nullptr, 'd'},
    {"debug", no_argument, nullptr, 'D'},
    {"exporter-ip", required_argument, nullptr, 'e'},
    {"full-transport-header-check", no_argument, nullptr, 'f'},
    {"flow-lookup", required_argument, nullptr, 'F'},
    {"gauge-cpu-clock", no_argument, nullptr, 'g'},
    {"help", no_argument, nullptr, 'h'},
    {"direction-mac", required_argument, nullptr, 'H'},
    {"interface", required_argument, nullptr, 'i'},
    {"reinit-interval", required_argument, nullptr, 'I'},
    {"load-balance", no_argument, nullptr, 'l'},
    {"hoplimit", required_argument, nullptr, 'L'},
    {"max-flows", required_argument, nullptr, 'm'},
    {"multithread", no_argument, nullptr, 'M'},
    {"netflow-dest", required_argument, nullptr, 'n'},
    {"no-promisc", no_argument, nullptr, 'N'},
    {"pidfile", required_argument, nullptr, 'p'},
    {"export-protocol", required_argument, nullptr, 'P'},
    {"read", required_argument, nullptr, 'r'},
    {"psamp-port", required_argument, nullptr, 'R'},
    {"sampling-rate", required_argument, nullptr, 's'},
    {"send-interface", required_argument, nullptr, 'S'},
    {"timeout", required_argument, nullptr, 't'},
    {"track", required_argument, nullptr, 'T'},
    {"netflow-version", required_argument, nullptr, 'v'},
    {"mpls-labels", required_argument, nullptr, 'x'},
    // Additions of the C++ version.
    {"export-out", required_argument, nullptr, kOptExportOut},
    {"max-runtime", required_argument, nullptr, kOptMaxRuntime},
    {"icmp-typecode-only", no_argument, nullptr, kOptIcmpTypecodeOnly},
    {"expiry-second-granularity", no_argument, nullptr,
     kOptExpirySecondGranularity},
    {"no-expiry-second-granularity", no_argument, nullptr,
     kOptNoExpirySecondGranularity},
    {nullptr, 0, nullptr, 0},
  };

  const int fargc = argc;
  char **fargv = argv;
  bool export_format_explicit = false;

  ::optind = 1;
  int opt;
  try {
    while ((opt = getopt_long (
              fargc, fargv,
              "n:Ni:r:p:c:m:t:d6DhL:T:v:P:A:s:C:R:S:e:x:B:bfF:alI:gH:M",
              long_options, nullptr)) != -1) {
      switch (opt) {
        case 'F':
          // Original: -F flow-lookup, tree | hash | hash-tree.
          if (std::string (optarg) == "tree") {
            config.flow_lookup = softflowd_cpp::FlowLookup::Tree;
          } else if (std::string (optarg) == "hash") {
            config.flow_lookup = softflowd_cpp::FlowLookup::Hash;
          } else if (std::string (optarg) == "hash-tree") {
            config.flow_lookup = softflowd_cpp::FlowLookup::HashTree;
          } else {
            die_usage ("Invalid flow lookup mode\n\n");
          }
          break;
        case kOptExportOut:
          config.export_out = optarg;
          break;
        case kOptMaxRuntime:
          config.max_runtime = std::chrono::seconds (std::stol (optarg));
          break;
        case kOptIcmpTypecodeOnly:
          // Now the default: only the bytes that are read (ICMP type
          // and code) are required. Kept as a no-op so existing
          // invocations still work; -f requires the whole header.
          break;
        case 'f':
          config.full_l4hdr_check = true;
          break;
        case 'M':
          config.multithread = true;
          break;
        case kOptExpirySecondGranularity:
          // See FlowTimeouts::second_granularity's comment. This is
          // now the default (matching the original's only actual
          // behavior); the flag is kept as a harmless no-op so
          // existing invocations that pass it explicitly still work.
          config.timeouts.second_granularity = true;
          break;
        case kOptNoExpirySecondGranularity:
          // Opts into full sub-second expiry-scheduling precision,
          // deviating from the original's whole-second `time_t`
          // expires_at (and, as a result, its expiry queue/export
          // ordering) in exchange for more precise expiry timing.
          config.timeouts.second_granularity = false;
          break;
        case 'n':
          // Original: the destinations of a later -n replace those of an
          // earlier one.
          config.destinations = parse_destinations (optarg);
          break;
        case 'N':
          config.no_promiscuous = true;
          break;
        case 'i':
          if (!config.pcap_file.empty() || !config.interface.empty()) {
            die_usage ("Packet source already specified.\n\n");
          }
          {
            // Original: -i [idx:]interface. The index is that of the interface
            // in the options of NetFlow v9 and IPFIX; without it the index of
            // the interface is looked up when the daemon starts.
            std::string name = optarg;
            const auto colon = name.find (':');
            if (colon != std::string::npos) {
              if (colon > 0) {
                config.if_index = static_cast<std::uint16_t> (
                  std::atoi (name.substr (0, colon).c_str()));
              }
              name.erase (0, colon + 1);
              config.user_ifindex = true;
            }
            if (name.empty()) {
              die_usage ("Wrong interface is specified.\n\n");
            }
            if (config.debug) {
              std::fprintf (stderr, "Using %s (idx: %d)\n", name.c_str(),
                            config.if_index);
            }
            config.interface = name;
          }
          break;
        case 'r':
          if (!config.pcap_file.empty() || !config.interface.empty()) {
            die_usage ("Packet source already specified.\n\n");
          }
          config.pcap_file = optarg;
          config.replay_control = false;
          break;
        case 'p':
          config.pidfile = optarg;
          break;
        case 'c':
          // Original: "none" is no control socket.
          config.ctl_sock = std::strcmp (optarg, "none") == 0 ? "" : optarg;
          // Original: -r clears the control socket path and a -c after it
          // sets it again, so a capture file is controlled only then.
          config.replay_control = !config.ctl_sock.empty();
          break;
        case 'm': {
          // Range check on an int, as in the C version: 0, negative
          // values and non-numeric arguments are rejected.
          const int max_flows = std::atoi (optarg);
          if (max_flows < 1) {
            die_usage ("Invalid maximum flows\n\n");
          }
          config.max_flows = static_cast<std::size_t> (max_flows);
          break;
        }
        case 't':
          set_timeout (config, optarg);
          break;
        case 'd':
          config.no_daemonize = true;
          break;
        case '6':
          config.force_ipv6 = true;
          break;
        case 'D':
          config.debug = true;
          config.no_daemonize = true;
          config.force_ipv6 = true;
          break;
        case 'h':
          print_usage();
          return 0;
        case 'L': {
          // Original: atoi (), then a range check.
          const int hoplimit = std::atoi (optarg);
          if (hoplimit < 0 || hoplimit > 255) {
            die_usage ("Invalid hop limit\n\n");
          }
          config.ttl = hoplimit;
          break;
        }
        case 'T': {
          const auto level = parse_track_level (optarg);
          if (!level.has_value()) {
            die_usage ("Unknown flow tracking level\n");
          }
          config.track_level = *level;
          break;
        }
        case 'v': {
          const auto format = parse_netflow_version (optarg);
          if (!format.has_value()) {
            std::fprintf (stderr, "Invalid NetFlow version\n");
            return 1;
          }
          config.export_format = *format;
          export_format_explicit = true;
          break;
        }
        case 'P': {
          const auto transport = parse_transport_protocol (optarg);
          if (!transport.has_value()) {
            die_usage ("Unknown transport layer protocol\n");
          }
          config.transport = *transport;
          break;
        }
        case 'A': {
          const auto format = parse_time_format (optarg);
          if (!format.has_value()) {
            die_usage ("Unknown time format\n");
          }
          config.time_format = *format;
          break;
        }
        case 's': {
          // Original: atoi (); a rate below 2 is no sampling.
          const int rate = std::atoi (optarg);
          config.sampling_rate = rate < 2 ? 0 : static_cast<std::uint32_t> (rate);
          break;
        }
        case 'C':
          // Original: atoi ().
          config.snaplen = std::atoi (optarg);
          break;
        case 'R': {
          // Original: atoi (); a port that does not fit 16 bits is reported with
          // the usage, and the default port (IPFIX_PORT of ipfix.h) is used.
          int port = std::atoi (optarg);
          if (port < 0 || port > 65535) {
            std::fprintf (stderr, "Invalid -R port, using the default %d.\n",
                          kDefaultIpfixPort);
            print_usage();
            port = kDefaultIpfixPort;
          }
          config.psamp_receive_port = static_cast<std::uint16_t> (port);
          break;
        }
        case 'S':
          config.send_interface = optarg;
          break;
        case 'e': {
          // Original: the address is resolved when the option is read; one
          // that cannot be is reported and not used. (The original reports
          // it with the reason of getaddrinfo (), as it is printed here.)
          struct addrinfo hints;
          std::memset (&hints, 0, sizeof (hints));
          struct addrinfo *res = nullptr;
          const int err = getaddrinfo (optarg, nullptr, &hints, &res);
          if (err != 0) {
            std::fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (err));
            break;
          }
          freeaddrinfo (res);
          config.source_address = optarg;
          break;
        }
        case 'x': {
          const int num_label = std::atoi (optarg);
          if (num_label < 1 || num_label > 10) {
            die_usage ("Invalid number of MPLS label (1 to 10)\n\n");
          }
          config.mpls_labels = num_label;
          break;
        }
        case 'B': {
          // Original: atoi (); only a positive size is a size.
          const int size = std::atoi (optarg);
          config.buffer_bytes = size > 0 ? static_cast<std::size_t> (size) : 0;
          break;
        }
        case 'b':
          config.bidirectional_ipfix = true;
          break;
        case 'a':
          config.adjust_pcap_time = true;
          break;
        case 'l':
          config.load_balance = true;
          break;
        case 'I': {
          // Original: BOOTTIME_MAX_DAY/HOUR/MIN/SEC clamps in
          // softflowd.c's -I parsing.
          constexpr long kBoottimeMaxDay = 49;
          constexpr long kBoottimeMaxHour = 1193;
          constexpr long kBoottimeMaxMin = 71582;
          constexpr long kBoottimeMaxSec = 4294944;

          char *timeunit = nullptr;
          errno = 0;
          long sec = std::strtol (optarg, &timeunit, 10);
          if ((errno == ERANGE && (sec == LONG_MAX || sec == LONG_MIN)) ||
              (errno != 0 && sec == 0)) {
            std::perror ("strtol");
            print_usage();
            return 1;
          }
          if (timeunit == optarg) {
            die_usage ("No digits were found in boot_time_reinit\n");
          }
          if (*timeunit == 'd' || *timeunit == 'D') {
            if (sec > kBoottimeMaxDay)
              sec = kBoottimeMaxDay;
            sec *= 24 * 60 * 60;
          } else if (*timeunit == 'h' || *timeunit == 'H') {
            if (sec > kBoottimeMaxHour)
              sec = kBoottimeMaxHour;
            sec *= 60 * 60;
          } else if (*timeunit == 'm' || *timeunit == 'M') {
            if (sec > kBoottimeMaxMin)
              sec = kBoottimeMaxMin;
            sec *= 60;
          } else {
            if (sec > kBoottimeMaxSec)
              sec = kBoottimeMaxSec;
          }
          config.boot_time_reinit = std::chrono::seconds (sec);
          break;
        }
        case 'g':
          config.gauge_clock = true;
          break;
        case 'H': {
          std::array<std::uint8_t, 6> mac;
          if (!parse_mac_address (optarg, mac)) {
            std::fprintf (stderr, "Invalid MAC address %s\n", optarg);
            return 1;
          }
          config.direction_mac = mac;
          break;
        }
        case '?':
        default:
          die_usage ("Invalid commandline option.\n");
      }
    }
  } catch (const std::exception &e) {
    std::fprintf (stderr, "%s: %s\n", argv[0], e.what());
    return 1;
  }
  (void) export_format_explicit;  // Netflow5 is already config's default

  std::string bpf;
  for (int i = optind; i < fargc; ++i) {
    if (!bpf.empty()) {
      bpf += " ";
    }
    bpf += fargv[i];
  }
  config.bpf_filter = bpf;

  if (config.interface.empty() && config.pcap_file.empty() &&
      !config.psamp_receive_port.has_value()) {
    die_usage ("-i, -r or -R option not specified.\n");
  }
  // Original: -R with -r is not an error, and has no effect.
  if (config.psamp_receive_port.has_value() && !config.pcap_file.empty()) {
    config.psamp_receive_port.reset();
  }
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
