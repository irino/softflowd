/**
 * @file capture.hpp
 * @brief The capture of packets: the live capture handle, the MAC address of the interface and the thread of -M.
 *
 * Split from softflowd.cpp. PcapHandle, which wraps libpcap, is in softflowd.hpp.
 *
 * @original setup_packet_capture (), get_interface_mac (), pcap_memcpy (),
 * process_packet_loop () and wait_for_packet_loop_idle () of softflowd.c.
 */
#ifndef SOFTFLOWD_CPP_CAPTURE_HPP
#define SOFTFLOWD_CPP_CAPTURE_HPP

#include "softflowd_cpp/options.hpp"
#include "softflowd_cpp/softflowd.hpp"

#include <array>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <functional>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace softflowd_cpp {

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
