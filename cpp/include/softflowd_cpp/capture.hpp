/**
 * @file capture.hpp
 * @brief The capture of packets: PcapHandle, which wraps libpcap, the live capture handle, the MAC address of the interface and the thread of -M.
 *
 * Split from softflowd.hpp and softflowd.cpp. The member functions of
 * PcapHandle and PacketProcessor are defined in capture.cpp.
 *
 * @original setup_packet_capture (), get_interface_mac (), pcap_memcpy (),
 * process_packet_loop () and wait_for_packet_loop_idle () of softflowd.c, and
 * capture.h of the C version.
 */
#ifndef SOFTFLOWD_CPP_CAPTURE_HPP
#define SOFTFLOWD_CPP_CAPTURE_HPP

#include "softflowd_cpp/options.hpp"
#include "softflowd_cpp/packet.hpp"
#include "softflowd_cpp/softflowd.hpp"

#include <array>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

extern "C" {
#include <pcap/pcap.h>
}

namespace softflowd_cpp {

/**
 * @brief An error of libpcap: a device or file that cannot be opened, a filter that does not compile.
 */
class PcapError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

/**
 * @brief A libpcap capture, live or from a file, that closes itself.
 *
 * The original declared `pcap_t *pcap;` in main() and reused it across
 * several exit paths (an error exit(1), a signal-driven shutdown, etc.),
 * risking a forgotten pcap_close() on at least one path.
 *
 * Here, ownership of the pcap_t is expressed with std::unique_ptr and a
 * custom deleter. Regardless of which function returns, or whether an
 * exception propagates, the destructor is guaranteed to call pcap_close()
 * exactly once when the handle goes out of scope -- eliminating the whole
 * class of "forgot to close it" bugs. This is the most basic application of
 * RAII, and mirrors the article's SocketHandle example.
 *
 * Original: PcapHandle (original: softflowd.c's main(), where pcap_t* was managed by hand across several possible exit paths)
 */
class PcapHandle {
public:
  /**
     * @brief Opens a live capture.
     *
     * @param device The interface.
     * @param snaplen The bytes of a packet that are captured.
     * @param promiscuous Open the interface in promiscuous mode.
     * @param read_timeout How long a read waits for packets.
     * @param buffer_bytes The capture buffer size (-B); 0 for the default.
     * @return The handle.
     * @throw PcapError when the device cannot be opened.
     *
     * @original softflowd.c called pcap_open_live() directly, which offers
     * no control over the capture buffer size or "immediate mode" (how
     * promptly a captured packet is handed to the application versus
     * waiting for internal buffering/timeout). This project instead uses
     * the pcap_create()/pcap_activate() sequence, which allows setting
     * both -- buffer_bytes maps to the original's -B option, and
     * immediate mode (always enabled here) meaningfully improves how
     * quickly a live-captured packet becomes visible to next_packet(),
     * which in turn keeps the control-socket/signal-handling side of the
     * daemon's event loop responsive under load (see run_live_capture()
     * in run_live.cpp).
     */
  static PcapHandle
  open_live (const std::string &device, int snaplen,
             bool promiscuous,
             std::chrono::milliseconds read_timeout,
             std::size_t buffer_bytes = 0);
  /**
     * @brief Opens a capture file.
     *
     * @param path The file.
     * @return The handle.
     * @throw PcapError when the file cannot be opened.
     */
  static PcapHandle
  open_offline (const std::string &path);

  /**
     * @brief A handle cannot be copied.
     */
  PcapHandle (const PcapHandle &) = delete;
  /**
     * @brief A handle cannot be copied.
     */
  PcapHandle &
  operator= (const PcapHandle &) = delete;
  /**
     * @brief Moves a handle.
     */
  PcapHandle (PcapHandle &&) noexcept = default;
  /**
     * @brief Moves a handle.
     */
  PcapHandle &
  operator= (PcapHandle &&) noexcept = default;
  /**
     * @brief Closes the capture.
     */
  ~PcapHandle () = default;  // the unique_ptr's deleter calls pcap_close()

  /**
     * @brief The link-layer type of the capture.
     *
     * @return The DLT_ value.
     */
  int
  datalink () const noexcept {
    return pcap_datalink (handle_.get());
  }
  /**
     * @brief The kind of the link-layer type.
     *
     * @return The kind.
     */
  DatalinkKind
  datalink_kind () const {
    return classify_datalink (datalink());
  }

  /**
     * @brief The file descriptor to poll for packets.
     *
     * @return The descriptor; -1 when it is not supported (offline files).
     *
     * @original softflowd.c's main loop polled/selected on pcap's file
     * descriptor (via pcap_get_selectable_fd()) alongside its control
     * socket so it could react promptly to both packets and control
     * commands without a busy-wait. Exposed here so a live daemon loop can
     * add this fd to the same poll() set as the control socket and signal
     * pipe. Returns -1 if the platform/capture mode doesn't support a
     * selectable descriptor (notably, this is generally not meaningful
     * for offline pcap files, only live captures).
     */
  int
  selectable_fd () const noexcept {
    return pcap_get_selectable_fd (handle_.get());
  }

  /**
     * @brief Compiles and sets the packet filter.
     *
     * @param bpf_expression The BPF expression.
     * @throw PcapError when it does not compile.
     *
     * @original softflowd.c's pcap_compile()/pcap_setfilter() calls. The
     * original only passed pcap_geterr()'s string to logit() on a compile
     * failure, which the caller had no way to observe. Here it's an
     * exception, so it cannot be silently ignored.
     */
  void
  set_filter (const std::string &bpf_expression);

  /**
     * @brief The capture statistics of libpcap.
     *
     * @return The statistics; nullopt when they are not available (offline files).
     *
     * @original softflowd.c's statistics() called pcap_stats() directly on
     * its pcap_t*. Returns std::nullopt if the stats are unavailable for
     * this capture mode (notably, offline pcap files -- pcap_stats() only
     * reports meaningful numbers for live captures).
     */
  std::optional<struct pcap_stat>
  stats () const noexcept {
    struct pcap_stat ps{};
    if (pcap_stats (handle_.get(), &ps) != 0) {
      return std::nullopt;
    }
    return ps;
  }

  /**
     * @brief Reads the next packet; the data are valid until the next call.
     *
     * @return The packet; nullopt on a read timeout (live) or at the end of the file.
     *
     * @original a thin wrapper over pcap_next_ex().
     * Returns: a CapturedPacket if one was available; std::nullopt on a
     * read timeout (live capture) or EOF (offline file).
     */
  std::optional<CapturedPacket>
  next_packet ();

  /**
     * @brief Hands the packets that libpcap has to a callback.
     *
     * @param max_packets The most packets to hand over.
     * @param callback Called for each packet.
     * @return The number of packets; -2 when the callback threw (the exception is rethrown); -1 on an error.
     *
     * @original pcap_dispatch (pcap, max_packets, callback, ...). Hands the
     * packets that libpcap has (those of one read for a live capture, at most
     * max_packets) to `callback` and returns how many there were; -2 when the
     * loop was ended by an exception of the callback, which is rethrown, and
     * -1 on an error.
     */
  int
  dispatch (int max_packets, const std::function<void (const CapturedPacket &)> &callback);

private:
  /**
     * @brief Takes over a libpcap handle.
     *
     * @param handle The handle.
     */
  explicit PcapHandle (pcap_t *handle)
      : handle_ (handle) {
  }

  /**
     * @brief Closes a libpcap handle.
     */
  struct PcapCloser {
    /**
         * @brief Closes the handle, if there is one.
         *
         * @param p The handle.
         */
    void
    operator() (pcap_t *p) const noexcept {
      if (p != nullptr) {
        pcap_close (p);
      }
    }
  };
  /**
     * @brief The libpcap handle.
     */
  std::unique_ptr<pcap_t, PcapCloser> handle_;
};

/**
 * @brief Tracks flows on another thread for -M, one packet at a time.
 *
 * @original pcap_memcpy () and process_packet_loop () with -M. The capture
 * loop hands one packet at a time to another thread, which does the flow
 * tracking, and waits for it to be finished with the previous packet first.
 * The packet is copied because libpcap reuses its buffer.
 */
class PacketProcessor {
public:
  /**
   * @brief Starts the thread that processes the packets.
   *
   * @param process The function that tracks one packet; it runs on the new thread.
   */
  explicit PacketProcessor (
    std::function<void (const softflowd_cpp::CapturedPacket &)> process)
      : process_ (std::move (process)), thread_ ([this] { run(); }) {
  }

  PacketProcessor (const PacketProcessor &) = delete;
  PacketProcessor &
  operator= (const PacketProcessor &) = delete;

  ~PacketProcessor ();

  /**
   * @brief Hands one packet over to the thread.
   *
   * It waits until the thread is done with the previous packet, and copies the data of the packet. An exception that the processing of the previous packet threw is thrown again here.
   *
   * @param pkt The packet.
   */
  void
  submit (const softflowd_cpp::CapturedPacket &pkt);

  /**
   * @brief Waits until the thread has finished the packet that it was given.
   *
   * An exception that the processing threw is thrown again here.
   *
   * @original wait_for_packet_loop_idle (). What the processing thread
   * shares with the main thread may be used again after this returns.
   */
  void
  wait_idle () {
    std::unique_lock<std::mutex> lock (mutex_);
    idle_cv_.wait (lock, [&] { return !ready_; });
    rethrow();
  }

private:
  void
  rethrow () {
    if (error_) {
      std::rethrow_exception (std::exchange (error_, nullptr));
    }
  }

  void
  run ();

  std::function<void (const softflowd_cpp::CapturedPacket &)> process_;
  std::mutex mutex_;
  std::condition_variable cv_;
  std::condition_variable idle_cv_;
  std::vector<std::uint8_t> storage_;
  softflowd_cpp::CapturedPacket packet_{};
  std::exception_ptr error_;
  bool ready_ = false;
  bool stop_ = false;
  std::thread thread_;  // last: it starts using the members above
};

std::optional<softflowd_cpp::PcapHandle>
open_live_capture (const DaemonConfig &config);

std::optional<std::array<std::uint8_t, 6>>
get_interface_mac (const std::string &ifname);

}  // namespace softflowd_cpp

#endif  // SOFTFLOWD_CPP_CAPTURE_HPP
