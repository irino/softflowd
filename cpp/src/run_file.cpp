// Original files: softflowd.c
//
// The -r mode: reads a capture file, exports the flows and prints the
// statistics. Split from softflowd.cpp. See run.hpp.
//
// Like control.cpp, the code is compiled out when SOFTFLOWD_CPP_NO_MAIN is
// defined: it uses softflowctl_lib, which softflow_core, which the tests link,
// does not have. See CMakeLists.txt.
#ifndef SOFTFLOWD_CPP_NO_MAIN
#include "softflowd_cpp/run.hpp"
#include "softflowd_cpp/capture.hpp"
#include "softflowd_cpp/control.hpp"
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

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <stdexcept>
#include <string>
#include <vector>

#include <poll.h>
#include <syslog.h>

namespace softflowd_cpp {

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

}  // namespace softflowd_cpp

#endif  // SOFTFLOWD_CPP_NO_MAIN
