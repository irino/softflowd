// Original files: softflowd.c
//
// The -i mode: captures from an interface, exports the flows and serves the
// control socket. Split from softflowd.cpp. See run.hpp.
//
// Like control.cpp, the code is compiled out when SOFTFLOWD_CPP_NO_MAIN is
// defined: it uses softflowctl_lib, which softflow_core, which the tests link,
// does not have. See CMakeLists.txt.
#ifndef SOFTFLOWD_CPP_NO_MAIN
#include "softflowd_cpp/run.hpp"
#include "softflowd_cpp/capture.hpp"
#include "softflowd_cpp/control.hpp"
#include "softflowd_cpp/daemon.hpp"
#include "softflowd_cpp/daemon_setup.hpp"
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
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

namespace softflowd_cpp {

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
      ~LastPacket () {
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

}  // namespace softflowd_cpp

#endif  // SOFTFLOWD_CPP_NO_MAIN
