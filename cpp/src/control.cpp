/**
 * @file control.cpp
 * @brief The control socket of softflowd+: the commands of softflowctl and the listener.
 *
 * Split from softflowd.cpp. See control.hpp.
 */

// The control socket belongs to the daemon only, as it did when this code was
// in the part of softflowd.cpp that SOFTFLOWD_CPP_NO_MAIN compiles out:
// softflow_core, which the tests link, does not have softflowctl_lib, whose
// read_command () and write_all () this file uses.
#ifndef SOFTFLOWD_CPP_NO_MAIN
#include "softflowd_cpp/capture.hpp"
#include "softflowd_cpp/control.hpp"

#include "softflowd_cpp/flow.hpp"
#include "softflowd_cpp/format.hpp"
#include "softflowd_cpp/log.hpp"
#include "softflowd_cpp/options.hpp"
#include "softflowd_cpp/softflowctl.hpp"
#include "softflowd_cpp/stats.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <exception>
#include <iterator>
#include <string>
#include <vector>

#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace softflowd_cpp {

namespace {

/**
 * @brief Executes one control command and makes its reply.
 *
 * @param command The command word of softflowctl.
 * @param table The flow table.
 * @param state The state that the command changes.
 * @param exporter The exporter.
 * @param handle The capture, for the counters of libpcap; null when there is none.
 * @return The text that the client prints.
 *
 * @original accept_control ()'s replies, byte for byte. The reply is the text
 * the control client copies to its stdout. Every reply except the one for
 * help and for an unknown command starts with "softflowd[pid]: ".
 */
std::string
handle_control_command (const std::string &command,
                        softflowd_cpp::FlowTableRuntime &table,
                        ControlState &state, ExportPipeline &exporter,
                        const softflowd_cpp::PcapHandle *handle) {
  using namespace softflowd_cpp;
  using namespace control_commands;

  const char *const words[] = {kHelp, kShutdown, kExit,
                               kExpireAll, kSendTemplate, kDeleteAll,
                               kStatistics, kDebugPlus, kDebugMinus,
                               kStopGather, kStartGather, kDumpFlows,
                               kTimeouts};
  if (std::none_of (std::begin (words), std::end (words),
                    [&] (const char *w) { return command == w; })) {
    return "Unknown control command \"" + command + "\"\n";
  }
  if (command == kHelp) {
    return "Valid control words are:\n"
           "\tdebug+ debug- delete-all dump-flows exit expire-all\n"
           "\tshutdown start-gather statistics stop-gather timeouts\n"
           "\tsend-template\n";
  }
  const std::string prefix =
    "softflowd[" + std::to_string (static_cast<unsigned int> (getpid())) + "]: ";

  if (command == kExpireAll || command == kSendTemplate) {
    exporter.resend_template();
  }
  if (command == kShutdown) {
    state.shutting_down = true;
    state.stopped_by_controller = true;
    return prefix + "Shutting down gracefully...\n";
  }
  if (command == kExit) {
    state.immediate_exit = true;
    state.stopped_by_controller = true;
    return prefix + "Exiting now...\n";
  }
  if (command == kExpireAll) {
    const bool debug = state.debug_level > 0;
    log_expiry_debug_start (debug, kCeExpireAll);
    // Original: the flows of a collision (expires_at 0) come first.
    auto expired = table.expire_collisions();
    const auto now = state.adjust_time ? state.last_packet_mono : Clock::now();
    const auto wall_now = state.adjust_time ? state.last_packet_wall
                                            : std::chrono::system_clock::now();
    auto rest = table.expire_flows (now, /*flush_all=*/true);
    expired.insert (expired.end(), std::make_move_iterator (rest.begin()),
                    std::make_move_iterator (rest.end()));
    log_expiry_debug_queued (debug, expired);
    const auto outcome = exporter.export_flows (expired, now, wall_now);
    table.record_export_stats (outcome.flows, outcome.records,
                               outcome.packets, outcome.failures);
    log_expiry_debug_sent (debug, static_cast<int> (outcome.packets),
                           expired.size());
    log_expiry_debug_expired (debug, expired);
    return prefix + "Expired " + std::to_string (expired.size()) + " flows.\n";
  }
  if (command == kSendTemplate) {
    return prefix + "Template will be sent at next flow export\n";
  }
  if (command == kDeleteAll) {
    return prefix + "Deleted " + std::to_string (table.delete_all()) +
           " flows.\n";
  }
  if (command == kStatistics) {
    exporter.sync_stats (table);
    char *body = nullptr;
    std::size_t body_size = 0;
    std::FILE *out = open_memstream (&body, &body_size);
    if (out == nullptr) {
      return prefix + "Accumulated statistics since " +
             format_time (state.boot_wall) + " UTC:\n";
    }
    print_statistics (table.stats(), table.size(), table.lookup(),
                      table.usage(), out, handle);
    std::fclose (out);
    const std::string text (body, body_size);
    std::free (body);
    return prefix + "Accumulated statistics since " +
           format_time (state.boot_wall) + " UTC:\n" + text;
  }
  if (command == kDebugPlus) {
    state.debug_level = 1;
    return prefix + "Debug level increased.\n";
  }
  if (command == kDebugMinus) {
    state.debug_level = 0;
    return prefix + "Debug level decreased.\n";
  }
  if (command == kStopGather) {
    state.capturing = false;
    return prefix + "Data collection stopped.\n";
  }
  if (command == kStartGather) {
    state.capturing = true;
    return prefix + "Data collection resumed.\n";
  }
  if (command == kDumpFlows) {
    // Original: dump_flows () walks the expiry tree, which is ordered by
    // expires_at (whole seconds) and then by the flow sequence. A flow that
    // is over 2 GiB or over its maximum lifetime has expires_at 0.
    struct Dumped {
      ExpiryEntry entry;
      long long expires_at;
    };
    std::vector<Dumped> dumped;
    for (auto &entry : table.expiry_snapshot()) {
      const auto &flow = entry.record.flow;
      const long long expires_at = expiry_epoch_seconds (flow, entry.expires_at);
      dumped.push_back (Dumped{std::move (entry), expires_at});
    }
    std::stable_sort (dumped.begin(), dumped.end(),
                      [] (const Dumped &x, const Dumped &y) {
                        if (x.expires_at != y.expires_at) {
                          return x.expires_at < y.expires_at;
                        }
                        return x.entry.record.flow.flow_seq <
                               y.entry.record.flow.flow_seq;
                      });
    const long long now = static_cast<long long> (std::time (nullptr));
    std::string text = prefix + "Dumping flow data:\n";
    for (const auto &d : dumped) {
      const auto &record = d.entry.record;
      text += "ACTIVE " + format_flow (record.key, record.flow) + "\n";
      char line[128];
      if (d.expires_at - now < 0) {
        std::snprintf (line, sizeof (line), "EXPIRY EVENT for flow %llu now%s\n",
                       static_cast<unsigned long long> (record.flow.flow_seq),
                       d.expires_at == 0 ? " (FORCED)" : "");
      } else {
        std::snprintf (line, sizeof (line),
                       "EXPIRY EVENT for flow %llu in %lld seconds\n",
                       static_cast<unsigned long long> (record.flow.flow_seq),
                       d.expires_at - now);
      }
      text += line;
      text += "\n";
    }
    return text;
  }
  // kTimeouts
  const auto &t = table.timeouts();
  char text[512];
  std::snprintf (text, sizeof (text),
                 "Printing timeouts:\n"
                 "           TCP timeout: %lds\n"
                 "  TCP post-RST timeout: %lds\n"
                 "  TCP post-FIN timeout: %lds\n"
                 "           UDP timeout: %lds\n"
                 "          ICMP timeout: %lds\n"
                 "       General timeout: %lds\n"
                 "      Maximum lifetime: %lds\n"
                 "       Expiry interval: %lds\n",
                 static_cast<long> (t.tcp.count()),
                 static_cast<long> (t.tcp_rst.count()),
                 static_cast<long> (t.tcp_fin.count()),
                 static_cast<long> (t.udp.count()),
                 static_cast<long> (t.icmp.count()),
                 static_cast<long> (t.general.count()),
                 static_cast<long> (t.maximum_lifetime.count()),
                 static_cast<long> (state.expiry_interval.count()));
  return prefix + text;
}

}  // namespace

ControlListener::ControlListener (const std::string &path) : path_ (path) {
  if (path.empty()) {
    return;
  }
  struct sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (path.size() >= sizeof (addr.sun_path)) {
    throw StartupError ("control socket path too long");
  }
  std::strncpy (addr.sun_path, path.c_str(), sizeof (addr.sun_path) - 1);
  ::unlink (path.c_str());
  fd_ = socket (AF_UNIX, SOCK_STREAM, 0);
  if (fd_ < 0) {
    throw StartupError (std::string ("unix domain socket() error: ") +
                        std::strerror (errno));
  }
  if (bind (fd_, reinterpret_cast<struct sockaddr *> (&addr), sizeof (addr)) < 0) {
    const std::string err = std::strerror (errno);
    ::close (fd_);
    throw StartupError ("unix domain bind(\"" + path + "\") error: " + err);
  }
  if (listen (fd_, 5) < 0) {
    const std::string err = std::strerror (errno);
    ::close (fd_);
    ::unlink (path.c_str());
    throw StartupError ("unix domain listen() error: " + err);
  }
}

ControlListener::~ControlListener () {
  if (fd_ >= 0) {
    ::close (fd_);
    ::unlink (path_.c_str());
  }
}

void
ControlListener::serve_client (softflowd_cpp::FlowTableRuntime &table, ControlState &ctl_state,
                               ExportPipeline &exporter, const softflowd_cpp::PcapHandle *handle) {
  const int client_fd = accept (fd_, nullptr, nullptr);
  if (client_fd < 0) {
    return;
  }
  struct ClientCloser {
    int fd;
    ~ClientCloser () {
      ::close (fd);
    }
  } client_closer{client_fd};

  try {
    std::string command;
    if (!softflowd_cpp::read_command (client_fd, command)) {
      return;  // Original: "Control socket yielded no data"
    }
    softflowd_cpp::write_all (client_fd, handle_control_command (command, table, ctl_state,
                                                                 exporter, handle));
  } catch (const std::exception &) {
    // A malformed client is not the daemon's problem;
    // just drop the connection.
  }
}

void
ControlListenerDeleter::operator() (ControlListener *listener) const {
  delete listener;
}

ControlListenerPtr
open_control_listener (const std::string &path) {
  return ControlListenerPtr (new ControlListener (path));
}

int
control_listener_fd (const ControlListener &listener) {
  return listener.fd();
}

bool
serve_control_client (ControlListener &listener, softflowd_cpp::FlowTableRuntime &table,
                      ExportPipeline &exporter, const softflowd_cpp::PcapHandle *handle) {
  listener.serve_client (table, listener.replay_state, exporter, handle);
  return listener.replay_state.shutting_down ||
         listener.replay_state.immediate_exit;
}

ControlState &
control_listener_state (ControlListener &listener) {
  return listener.replay_state;
}

}  // namespace softflowd_cpp

#endif  // SOFTFLOWD_CPP_NO_MAIN
