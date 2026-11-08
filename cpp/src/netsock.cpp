/**
 * @file netsock.cpp
 * @brief The sockets that the export packets go through: one destination, and the destinations of -n.
 *
 * Split from softflowd.cpp. ExportDestination, which is a socket connected to
 * one collector over UDP, TCP or SCTP, and ExportDestinationSet, which holds the
 * destinations of -n and chooses among them with -l, are declared in
 * netsock.hpp.
 *
 * @original connsock () of netsock.c and the destination handling of
 * send_multi_destinations () of sender.c in the C version.
 */
#include "softflowd_cpp/netsock.hpp"
#include "softflowd_cpp/softflowd.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace softflowd_cpp {

// =======================================================================
// ExportDestination / ExportDestinationSet (original: softflowd.c's -n /
// -l / -L / -e / -S handling)
// =======================================================================

ExportDestination::ExportDestination (const std::string &host,
                                      const std::string &port,
                                      TransportKind transport,
                                      std::optional<int> ttl,
                                      const std::string &source_address,
                                      const std::string &send_interface) {
  struct addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  switch (transport) {
    case TransportKind::Udp:
      hints.ai_socktype = SOCK_DGRAM;
      hints.ai_protocol = IPPROTO_UDP;
      break;
    case TransportKind::Tcp:
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_protocol = IPPROTO_TCP;
      stream_oriented_ = true;
      break;
    case TransportKind::Sctp:
#ifdef IPPROTO_SCTP
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_protocol = IPPROTO_SCTP;
      stream_oriented_ = true;
      break;
#else
      throw ExportError (
        "SCTP is not available on this platform (IPPROTO_SCTP is not "
        "declared)");
#endif
  }

  struct addrinfo *result = nullptr;
  if (getaddrinfo (host.c_str(), port.c_str(), &hints, &result) != 0) {
    throw ExportError ("No addresses found for [" + host + "]:" + port);
  }
  struct AddrinfoGuard {
    struct addrinfo *p;
    ~AddrinfoGuard () {
      freeaddrinfo (p);
    }
  } addrinfo_guard{result};

  fd_ = socket (result->ai_family, result->ai_socktype, result->ai_protocol);
  if (fd_ < 0) {
    throw ExportError (std::string ("socket() error: ") + std::strerror (errno));
  }

  if (!source_address.empty()) {
    // Original: -e. Resolve the requested source address in the same
    // family as the destination and bind() to it before connect()ing,
    // so the OS picks the requested address rather than whatever
    // routing would otherwise select.
    struct addrinfo src_hints{};
    src_hints.ai_family = result->ai_family;
    src_hints.ai_socktype = result->ai_socktype;
    struct addrinfo *src_result = nullptr;
    const int src_err = getaddrinfo (source_address.c_str(), nullptr,
                                     &src_hints, &src_result);
    if (src_err == 0) {
      struct AddrinfoGuard src_guard{src_result};
      bind (fd_, src_result->ai_addr, src_result->ai_addrlen);
      // A failed bind() here is intentionally non-fatal: falling
      // back to default source-address selection is preferable to
      // refusing to export at all.
    }
  }

  if (!send_interface.empty()) {
#ifdef SO_BINDTODEVICE
    // Original: -S. Linux-only, as the man page notes.
    // Original: bind_device (), whose failure is reported and not fatal.
    if (setsockopt (fd_, SOL_SOCKET, SO_BINDTODEVICE, send_interface.c_str(),
                    static_cast<socklen_t> (send_interface.size())) < 0) {
      std::perror ("SO_BINDTODEVICE failed");
    }
#endif
  }

  if (ttl.has_value()) {
    // Original: -L. IPv4 and IPv6 use different setsockopt levels/
    // names for the equivalent setting.
    if (result->ai_family == AF_INET) {
      const int ttl_value = *ttl;
      setsockopt (fd_, IPPROTO_IP, IP_TTL, &ttl_value, sizeof (ttl_value));
      setsockopt (fd_, IPPROTO_IP, IP_MULTICAST_TTL, &ttl_value,
                  sizeof (ttl_value));
    } else if (result->ai_family == AF_INET6) {
      const int ttl_value = *ttl;
      setsockopt (fd_, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl_value,
                  sizeof (ttl_value));
      setsockopt (fd_, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl_value,
                  sizeof (ttl_value));
    }
  }

  // Original: with tcp/sctp, this connect() actually establishes the
  // long-lived connection the destination is streamed over for the
  // exporter's entire lifetime (matching the original's own behavior);
  // with udp, connect() on a datagram socket just fixes the peer address
  // so later calls can use send() instead of sendto().
  if (connect (fd_, result->ai_addr, result->ai_addrlen) < 0) {
    const std::string err = std::strerror (errno);
    close (fd_);
    fd_ = -1;
    throw ExportError ("connect() error: " + err);
  }

  description_ = host + ":" + port;
}

ExportDestination::~ExportDestination () {
  if (fd_ >= 0) {
    close (fd_);
  }
}

ExportDestination::ExportDestination (ExportDestination &&other) noexcept
    : fd_ (other.fd_), stream_oriented_ (other.stream_oriented_),
      description_ (std::move (other.description_)) {
  other.fd_ = -1;
}

ExportDestination &
ExportDestination::operator= (ExportDestination &&other) noexcept {
  if (this != &other) {
    if (fd_ >= 0) {
      close (fd_);
    }
    fd_ = other.fd_;
    stream_oriented_ = other.stream_oriented_;
    description_ = std::move (other.description_);
    other.fd_ = -1;
  }
  return *this;
}

void
ExportDestination::send_packet (const std::vector<std::uint8_t> &packet) const {
  if (fd_ < 0) {
    return;
  }
  if (!stream_oriented_) {
    // A single UDP datagram send either succeeds atomically or fails;
    // there is no partial-send loop to write here the way there is
    // below for tcp/sctp (or for the control socket's
    // read_line()/write_line() in softflowctl.cpp).
    static_cast<void> (send (fd_, packet.data(), packet.size(), 0));
    return;
  }
  // tcp/sctp are stream-oriented: a single send() is not guaranteed to
  // consume the entire buffer, so this loops until it has, the same
  // pattern softflowctl.cpp's write_line() uses for the control socket.
  std::size_t offset = 0;
  while (offset < packet.size()) {
    const ssize_t n =
      send (fd_, packet.data() + offset, packet.size() - offset, 0);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;  // give up silently; a dead collector shouldn't crash the daemon
    }
    offset += static_cast<std::size_t> (n);
  }
}

void
ExportDestinationSet::add (ExportDestination destination) {
  destinations_.push_back (std::move (destination));
}

void
ExportDestinationSet::send_packet (const std::vector<std::uint8_t> &packet,
                                   bool load_balance) {
  if (destinations_.empty()) {
    return;
  }
  if (load_balance) {
    // Original: -l. Successive *export packets* (not individual flow
    // records within a packet) rotate through the configured
    // destinations.
    destinations_[sent_ % destinations_.size()].send_packet (packet);
  } else {
    for (const auto &destination : destinations_) {
      destination.send_packet (packet);
    }
  }
  // Original: send_multi_destinations() counts every packet, so a packet
  // that went to all destinations also advances the rotation.
  ++sent_;
}

}  // namespace softflowd_cpp
