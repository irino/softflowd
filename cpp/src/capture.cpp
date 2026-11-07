/**
 * @file capture.cpp
 * @brief The capture of packets: PcapHandle, which wraps libpcap, the live capture handle, the MAC address of the interface and the thread of -M.
 *
 * Split from softflowd.cpp. PcapHandle is declared in softflowd.hpp, and the
 * rest in capture.hpp.
 */
#include "softflowd_cpp/capture.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <functional>
#include <mutex>
#include <optional>
#include <span>
#include <string>

#include <ifaddrs.h>
#include <net/if.h>
#ifdef __linux__
#include <net/if_arp.h>
#else
#include <net/if_dl.h>
#include <net/if_types.h>
#endif
#include <pcap/pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace softflowd_cpp {

// =======================================================================
// PcapHandle (original: softflowd.c's main(), which managed pcap_t* by
//             hand)
// =======================================================================

DatalinkKind
classify_datalink (int pcap_dlt) {
  switch (pcap_dlt) {
    case DLT_EN10MB:
      return DatalinkKind::Ethernet;
#ifdef DLT_LINUX_SLL
    case DLT_LINUX_SLL:
      return DatalinkKind::LinuxSll;
#endif
    case DLT_RAW:
      return DatalinkKind::Raw;
    case DLT_NULL:
      return DatalinkKind::NullLoop;
#ifdef DLT_LOOP
    case DLT_LOOP:
      return DatalinkKind::NullLoop;
#endif
    default:
      return DatalinkKind::Unsupported;
  }
}

std::size_t
datalink_header_len (DatalinkKind kind) {
  // Original: the DATALINK table's skiplen field.
  switch (kind) {
    case DatalinkKind::Ethernet:
      return 14;
    case DatalinkKind::LinuxSll:
      return 16;
    case DatalinkKind::Raw:
      return 0;
    case DatalinkKind::NullLoop:
      return 4;
    case DatalinkKind::Unsupported:
      return 0;
  }
  return 0;
}

PcapHandle
PcapHandle::open_live (const std::string &device, int snaplen,
                       bool promiscuous,
                       std::chrono::milliseconds read_timeout,
                       std::size_t buffer_bytes) {
  std::array<char, PCAP_ERRBUF_SIZE> errbuf{};
  pcap_t *handle = pcap_create (device.c_str(), errbuf.data());
  if (handle == nullptr) {
    throw PcapError (std::string ("pcap_create: ") + errbuf.data());
  }
  // pcap_create()/pcap_activate() is used instead of the legacy
  // pcap_open_live() specifically so buffer_bytes (original: -B) and
  // immediate mode can both be configured; pcap_open_live() offers
  // neither. Original: `logit(LOG_ERR, "pcap_open_live: %s", ebuf);
  // exit(1);` -- here every setup step below throws instead of exiting,
  // matching the rest of this project's RAII/exception-based error
  // handling.
  // Original: setup_packet_capture () checks the result of each of them.
  const auto check = [&] (int result, const char *name) {
    if (result != 0) {
      const std::string err = pcap_geterr (handle);
      pcap_close (handle);
      throw PcapError (std::string (name) + ": " + err);
    }
  };
  check (pcap_set_snaplen (handle, snaplen), "pcap_set_snaplen");
  check (pcap_set_promisc (handle, promiscuous ? 1 : 0), "pcap_set_promisc");
  check (pcap_set_timeout (handle, static_cast<int> (read_timeout.count())),
         "pcap_set_timeout");
  // Immediate mode delivers each packet to the application as soon as
  // it's captured, rather than waiting for libpcap's internal buffer to
  // fill or its timeout to elapse. Without this, next_packet() can take
  // up to the full read_timeout to return even when poll() has already
  // reported the underlying descriptor readable -- exactly the kind of
  // latency that would make a live daemon sluggish to react to control
  // commands and signals interleaved with packet processing (see
  // run_live_capture() in softflowd.cpp).
  check (pcap_set_immediate_mode (handle, 1), "pcap_set_immediate_mode");
  if (buffer_bytes > 0) {
    check (pcap_set_buffer_size (handle, static_cast<int> (buffer_bytes)),
           "pcap_set_buffer_size");
  }

  const int activate_result = pcap_activate (handle);
  if (activate_result < 0) {
    const std::string err = pcap_geterr (handle);
    pcap_close (handle);
    throw PcapError ("pcap_activate: " + err);
  }
  // next_packet() must return at once when libpcap holds no packet: a
  // descriptor that is not readable does not mean that libpcap has handed over
  // every packet that it read in one go (pcap_dispatch () of the original
  // drains them), so run_live_capture() reads until there is none.
  std::array<char, PCAP_ERRBUF_SIZE> nonblock_error{};
  if (pcap_setnonblock (handle, 1, nonblock_error.data()) < 0) {
    pcap_close (handle);
    throw PcapError (std::string ("pcap_setnonblock failed for '") + device +
                     "': " + nonblock_error.data());
  }
  return PcapHandle (handle);
}

PcapHandle
PcapHandle::open_offline (const std::string &path) {
  std::array<char, PCAP_ERRBUF_SIZE> errbuf{};
  pcap_t *handle = pcap_open_offline (path.c_str(), errbuf.data());
  if (handle == nullptr) {
    throw PcapError ("pcap_open_offline(" + path + "): " + errbuf.data());
  }
  return PcapHandle (handle);
}

void
PcapHandle::set_filter (const std::string &bpf_expression) {
  struct bpf_program program{};
  if (pcap_compile (handle_.get(), &program, bpf_expression.c_str(), 1,
                    PCAP_NETMASK_UNKNOWN) < 0) {
    throw PcapError ("pcap_compile(\"" + bpf_expression + "\"): " +
                     pcap_geterr (handle_.get()));
  }
  // Original: forgetting to call `pcap_freecode(&program)` is a
  // low-impact leak, but easy to miss especially on an exception path.
  // A tiny RAII guard makes sure it always runs.
  struct ProgramGuard {
    struct bpf_program *p;
    ~ProgramGuard () {
      pcap_freecode (p);
    }
  } guard{&program};

  if (pcap_setfilter (handle_.get(), &program) < 0) {
    throw PcapError (std::string ("pcap_setfilter: ") +
                     pcap_geterr (handle_.get()));
  }
}

std::optional<CapturedPacket>
PcapHandle::next_packet () {
  struct pcap_pkthdr *header = nullptr;
  const u_char *data = nullptr;
  const int result = pcap_next_ex (handle_.get(), &header, &data);

  if (result == 1) {
    CapturedPacket packet;
    // Original: `const u_int8_t *pkt = frame + datalink_size + ...`,
    // always carried alongside a separate `phdr->caplen` variable.
    // std::span combines the two into a single value.
    packet.data = std::span<const std::uint8_t> (
      reinterpret_cast<const std::uint8_t *> (data), header->caplen);
    packet.original_length = header->len;
    packet.timestamp = Clock::now();
    // Original: -a ("adjust time for reading pcap file") switches
    // between using libpcap's own recorded timestamp (phdr->ts, this
    // process's wall clock otherwise) as the reference time for flow
    // expiry when replaying a capture file. Both this process's
    // current time and libpcap's recorded time are always captured
    // here; run_pcap_file()/run_live_capture() (softflowd.cpp) decide
    // which one to actually use based on whether -a was given.
    packet.wall_timestamp = std::chrono::system_clock::from_time_t (header->ts.tv_sec) +
                            std::chrono::microseconds (header->ts.tv_usec);
    return packet;
  }
  if (result == 0) {
    return std::nullopt;  // live-capture read timeout
  }
  if (result == -2) {
    return std::nullopt;  // EOF on an offline file
  }
  // result == -1: an error occurred
  throw PcapError (std::string ("pcap_next_ex failed: ") +
                   pcap_geterr (handle_.get()));
}

int
PcapHandle::dispatch (int max_packets,
                      const std::function<void (const CapturedPacket &)> &callback) {
  struct Context {
    const std::function<void (const CapturedPacket &)> *callback;
    pcap_t *handle;
    std::exception_ptr error;
  } context{&callback, handle_.get(), nullptr};

  const auto trampoline = [] (u_char *user, const struct pcap_pkthdr *header,
                              const u_char *data) {
    auto *ctx = reinterpret_cast<Context *> (user);
    try {
      CapturedPacket packet;
      packet.data = std::span<const std::uint8_t> (
        reinterpret_cast<const std::uint8_t *> (data), header->caplen);
      packet.original_length = header->len;
      packet.timestamp = Clock::now();
      packet.wall_timestamp =
        std::chrono::system_clock::from_time_t (header->ts.tv_sec) +
        std::chrono::microseconds (header->ts.tv_usec);
      (*ctx->callback) (packet);
    } catch (...) {
      // An exception must not unwind through libpcap's C frames.
      ctx->error = std::current_exception();
      pcap_breakloop (ctx->handle);
    }
  };
  const int result = pcap_dispatch (handle_.get(), max_packets, trampoline,
                                    reinterpret_cast<u_char *> (&context));
  if (context.error) {
    std::rethrow_exception (context.error);
  }
  return result;
}

PacketProcessor::~PacketProcessor () {
  {
    std::lock_guard<std::mutex> lock (mutex_);
    stop_ = true;
  }
  cv_.notify_all();
  thread_.join();
}

void
PacketProcessor::submit (const softflowd_cpp::CapturedPacket &pkt) {
  std::unique_lock<std::mutex> lock (mutex_);
  idle_cv_.wait (lock, [&] { return !ready_; });
  rethrow();
  storage_.assign (pkt.data.begin(), pkt.data.end());
  packet_ = pkt;
  packet_.data = std::span<const std::uint8_t> (storage_);
  ready_ = true;
  cv_.notify_one();
}

void
PacketProcessor::run () {
  std::unique_lock<std::mutex> lock (mutex_);
  for (;;) {
    cv_.wait (lock, [&] { return ready_ || stop_; });
    if (!ready_) {
      return;
    }
    try {
      process_ (packet_);
    } catch (...) {
      error_ = std::current_exception();
    }
    ready_ = false;
    idle_cv_.notify_all();
  }
}

/**
 * @brief Opens the capture of the interface (-i), before the process forks, so that its errors are seen on the terminal.
 *
 * The snapshot length is -C, or else 160 bytes when IPv6 flows are tracked and 96 bytes when not. The capture takes the packets in immediate mode, with a read timeout of 100 milliseconds.
 *
 * @param config The settings.
 * @return The capture, or nothing when there is no interface (-R alone).
 * @throw StartupError when the data-link type is not supported.
 *
 * @original setup_packet_capture () for a live capture. It is done before the
 * process forks, so that its errors are seen on the terminal.
 */
std::optional<softflowd_cpp::PcapHandle>
open_live_capture (const DaemonConfig &config) {
  using namespace softflowd_cpp;

  // A short read timeout plus immediate mode (see PcapHandle::open_live)
  // keeps this daemon responsive to control-socket commands and signals
  // even under sustained traffic -- see the packet-draining loop below
  // for the other half of this responsiveness story (it also caps how
  // many packets it drains per poll() cycle).
  // Original: with -R and without -i there is no capture at all, and the
  // frames that are received are Ethernet frames (linktype = 1).
  if (config.interface.empty()) {
    return std::nullopt;
  }
  PcapHandle handle = PcapHandle::open_live (
    config.interface,
    // Original: LIBPCAP_SNAPLEN_V4 (96) or, when IPv6 flows are tracked,
    // LIBPCAP_SNAPLEN_V6 (160). A larger snaplen makes every frame of the
    // capture ring larger, so a burst of packets overruns the ring.
    config.snaplen != 0 ? config.snaplen : (should_track_ipv6 (config) ? 160 : 96),
    !config.no_promiscuous, std::chrono::milliseconds (100), config.buffer_bytes);
  if (handle.datalink_kind() == DatalinkKind::Unsupported) {
    throw StartupError ("Unsupported datalink type " +
                        std::to_string (handle.datalink()));
  }
  if (!config.bpf_filter.empty()) {
    handle.set_filter (config.bpf_filter);
  }
  return handle;
}

/**
 * @brief Gives the Ethernet address of an interface.
 *
 * @param ifname The name of the interface.
 * @return The address, or nothing when the interface has none that can be found.
 *
 * @original get_interface_mac(). The Ethernet address of a capture
 * interface, used as the direction MAC when -H is not given.
 */
std::optional<std::array<std::uint8_t, 6>>
get_interface_mac (const std::string &ifname) {
  std::array<std::uint8_t, 6> mac{};
#ifdef __linux__
  const int fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    return std::nullopt;
  }
  struct ifreq ifr{};
  std::strncpy (ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
  const bool ok = ioctl (fd, SIOCGIFHWADDR, &ifr) == 0 &&
                  ifr.ifr_hwaddr.sa_family == ARPHRD_ETHER;
  ::close (fd);
  if (!ok) {
    return std::nullopt;
  }
  std::memcpy (mac.data(), ifr.ifr_hwaddr.sa_data, 6);
  return mac;
#else
  struct ifaddrs *list = nullptr;
  if (getifaddrs (&list) != 0) {
    return std::nullopt;
  }
  bool found = false;
  for (const struct ifaddrs *p = list; p != nullptr; p = p->ifa_next) {
    if (p->ifa_addr == nullptr || p->ifa_addr->sa_family != AF_LINK ||
        ifname != p->ifa_name) {
      continue;
    }
    const auto *sdl = reinterpret_cast<const struct sockaddr_dl *> (p->ifa_addr);
    if (sdl->sdl_alen == 6) {
      std::memcpy (mac.data(), LLADDR (sdl), 6);
      found = true;
      break;
    }
  }
  freeifaddrs (list);
  return found ? std::optional (mac) : std::nullopt;
#endif
}

}  // namespace softflowd_cpp
