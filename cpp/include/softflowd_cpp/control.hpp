/**
 * @file control.hpp
 * @brief The control socket of softflowd+: the state that the commands of softflowctl change, and the listener.
 *
 * Split from softflowd.cpp. The functions that come before the class are the
 * ones that the loop of the capture file uses; the live loop uses the
 * members of ControlListener.
 *
 * @original accept_control () and unix_listener () of softflowd.c, and the
 * commands that softflowctl(8) sends to them.
 */
#ifndef SOFTFLOWD_CPP_CONTROL_HPP
#define SOFTFLOWD_CPP_CONTROL_HPP

#include "softflowd_cpp/sender.hpp"
#include "softflowd_cpp/softflowd.hpp"

#include <chrono>
#include <memory>
#include <string>

namespace softflowd_cpp {

/**
 * @brief What the control commands read and change.
 */
struct ControlState {
  bool capturing = true;        ///< true while packets are taken from the capture; stop-gather clears it and start-gather sets it again.
  bool shutting_down = false;   ///< true when the run is to end gracefully; the shutdown command sets it.
  bool immediate_exit = false;  ///< true when the run is to end at once, without exporting the flows that are left; the exit command sets it.
  /**
   * @brief true when a control command ended the run, so that the exit status is 1.
   *
   * @original the shutdown and exit commands make main () return 1.
   */
  bool stopped_by_controller = false;
  int debug_level = 0;  ///< The debug level: debug+ sets it to 1 and debug- to 0; it is verbose_flag of the C version.
  /**
   * @brief The wall-clock time when the exporter started, which the statistics command shows.
   *
   * @original ft-\>param.system_boot_time, shown by statistics.
   */
  std::chrono::system_clock::time_point boot_wall = std::chrono::system_clock::now();
  /**
   * @brief The interval between the scans for expired flows, which the timeouts command shows.
   *
   * @original ft-\>param.expiry_interval, shown by timeouts.
   */
  std::chrono::seconds expiry_interval{0};
  /**
   * @brief true with -a: expire-all then takes the time of the last packet as the current time.
   *
   * @original with -a (adjust_time), the time of the last packet is the
   * current time of the expire-all command instead of gettimeofday ().
   */
  bool adjust_time = false;
  softflowd_cpp::TimePoint last_packet_mono{};               ///< The time of the last packet on Clock.
  std::chrono::system_clock::time_point last_packet_wall{};  ///< The wall-clock time of the last packet.
};

// The control socket of softflowctl(8) for a capture file; defined below
// with the control commands. serve_control_client() answers one client and
// returns true when it asked to shut down or to exit.
class ControlListener;
/**
 * @brief Deletes a ControlListener; it is the deleter of ControlListenerPtr.
 */
struct ControlListenerDeleter {
  /**
   * @brief Deletes the listener, which closes and removes the control socket.
   *
   * @param listener The listener.
   */
  void
  operator() (ControlListener *listener) const;
};
/**
 * @brief Owns a ControlListener; the control socket is closed and removed when the pointer goes.
 */
using ControlListenerPtr = std::unique_ptr<ControlListener, ControlListenerDeleter>;
/**
 * @brief Creates the control socket.
 *
 * @param path The path of the socket; an empty path is no socket (-c none).
 * @return The listener.
 */
ControlListenerPtr
open_control_listener (const std::string &path);
/**
 * @brief Gives the descriptor to wait on.
 *
 * @param listener The listener.
 * @return The descriptor of the listening socket, or -1 when there is no socket.
 */
int
control_listener_fd (const ControlListener &listener);
/**
 * @brief Gives the state that the clients of a listener change.
 *
 * @param listener The listener.
 * @return The state.
 */
ControlState &
control_listener_state (ControlListener &listener);
/**
 * @brief Answers one client of the control socket while a capture file is read.
 *
 * @param listener The listener.
 * @param table The flow table.
 * @param exporter The exporter.
 * @param handle The capture, for the counters of libpcap.
 * @return true when the client asked to shut down or to exit.
 */
bool
serve_control_client (ControlListener &listener,
                      softflowd_cpp::FlowTableRuntime &table,
                      ExportPipeline &exporter,
                      const softflowd_cpp::PcapHandle *handle);

/**
 * @brief Listens on the control socket of softflowctl, and answers its clients.
 *
 * @original the control socket that softflowctl(8) connects to. The
 * listening socket and its filesystem entry are removed on every return path,
 * including an exception.
 */
class ControlListener {
public:
  /**
   * @brief Creates the listening socket, after it removes a file that is in its place.
   *
   * An empty path is no control socket (-c none): there is nothing to listen
   * on, and poll () skips the descriptor -1.
   *
   * @param path The path of the socket.
   * @throw StartupError when the path is too long, or the socket cannot be made, bound or put to listen.
   */
  explicit ControlListener (const std::string &path);

  ControlListener (const ControlListener &) = delete;
  ControlListener &
  operator= (const ControlListener &) = delete;

  ~ControlListener ();

  /**
   * @brief Gives the descriptor of the listening socket.
   *
   * @return The descriptor, or -1 when there is no socket.
   */
  int
  fd () const noexcept {
    return fd_;
  }

  /**
   * @brief Accepts one client, reads its command and writes the reply.
   *
   * A client that sends nothing or something malformed is dropped.
   *
   * @param table The flow table.
   * @param ctl_state The state that the command changes.
   * @param exporter The exporter.
   * @param handle The capture, for the counters of libpcap.
   *
   * @original accept_control (). Accepts one client and answers its command.
   */
  void
  serve_client (softflowd_cpp::FlowTableRuntime &table, ControlState &ctl_state,
                ExportPipeline &exporter, const softflowd_cpp::PcapHandle *handle);

  ControlState replay_state;  ///< What the controller of a capture file has asked for.

private:
  int fd_ = -1;
  std::string path_;
};

}  // namespace softflowd_cpp

#endif  // SOFTFLOWD_CPP_CONTROL_HPP
