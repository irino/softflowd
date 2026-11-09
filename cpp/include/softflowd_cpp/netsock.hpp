/**
 * @file netsock.hpp
 * @brief The sockets that the export packets go through: one destination, and the destinations of -n.
 *
 * Split from softflowd.hpp. ExportDestination is a socket connected to one
 * collector over UDP, TCP or SCTP, and ExportDestinationSet holds the
 * destinations of -n and chooses among them with -l. The member functions are
 * defined in netsock.cpp.
 *
 * @original netsock.h of the C version, and the destination handling of
 * send_multi_destinations () of sender.c.
 */
#ifndef SOFTFLOWD_CPP_NETSOCK_HPP
#define SOFTFLOWD_CPP_NETSOCK_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace softflowd_cpp {

/**
 * @brief An error of an export destination: it cannot be resolved, opened or written.
 */
class ExportError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

/**
 * @brief The transport of the export, selected with -P.
 *
 * @original -P transport_protocol. udp and tcp are both fully implemented
 * here; sctp is attempted using IPPROTO_SCTP if the platform's headers
 * declare it (Linux with the kernel SCTP module loaded typically does),
 * and otherwise ExportDestination's constructor throws ExportError, which
 * ExportPipeline reports as a fallback-to-udp warning rather than a hard
 * failure -- see sender.cpp.
 */
enum class TransportKind {
  Udp,   ///< UDP.
  Tcp,   ///< TCP.
  Sctp,  ///< SCTP, when the platform has it.
};

/**
 * @brief A socket to one collector, connected up front and closed by the destructor.
 *
 * Original: ExportDestination / ExportDestinationSet (original: softflowd.c's -n destination handling and send_multi_destinations())
 *
 * softflowd.c resolved each -n host:port with getaddrinfo(),
 * opened a UDP socket per destination, and sent each export packet with
 * sendto(). The socket file descriptors lived for the daemon's entire
 * runtime as plain ints in a global-ish destinations array; nothing
 * enforced that every one of them got closed on every exit path.
 *
 * ExportDestination wraps one such socket in RAII (closed by the
 * destructor, matching PcapHandle and PidFile elsewhere in this project).
 * The socket is connect()-ed to its destination up front, which both
 * simplifies sending (plain send() instead of sendto() + a sockaddr each
 * time) and lets the kernel report certain errors (e.g. ICMP port
 * unreachable for a UDP send to a closed collector port) back to this
 * process instead of silently discarding them.
 */
class ExportDestination {
public:
  /**
     * @brief Resolves and connects a destination.
     *
     * host/port are resolved via getaddrinfo(), so host may be a hostname
     * or a numeric IPv4/IPv6 address, and port may be a numeric port or a
     * services(5) name. ttl, if set, configures the original's -L
     * (IPv4 TTL / IPv6 hop limit). source_address and send_interface
     * correspond to the original's -e and -S respectively.
     *
     * Original: with tcp or sctp, the original opened one long-lived
     * connection per destination and streamed export packets over it
     * back-to-back with no additional framing -- the same approach taken
     * here, since every one of this project's export formats already
     * carries its own self-describing length in its header (a NetFlow v9/
     * IPFIX collector reading a TCP stream reads that header, learns the
     * message's length, reads that many bytes, and repeats).
     *
     * @param host A host name or a numeric address.
     * @param port A numeric port or a service name.
     * @param transport The transport (-P).
     * @param ttl The IPv4 TTL / IPv6 hop limit (-L).
     * @param source_address The address to send from (-e).
     * @param send_interface The interface to send on (-S).
     * @throw ExportError when it cannot be set up.
     */
  ExportDestination (const std::string &host, const std::string &port,
                     TransportKind transport = TransportKind::Udp,
                     std::optional<int> ttl = std::nullopt,
                     const std::string &source_address = "",
                     const std::string &send_interface = "");
  /**
     * @brief Closes the socket.
     */
  ~ExportDestination ();

  /**
     * @brief A destination cannot be copied.
     */
  ExportDestination (const ExportDestination &) = delete;
  /**
     * @brief A destination cannot be copied.
     */
  ExportDestination &
  operator= (const ExportDestination &) = delete;
  /**
     * @brief Moves a destination.
     */
  ExportDestination (ExportDestination &&) noexcept;
  /**
     * @brief Moves a destination.
     */
  ExportDestination &
  operator= (ExportDestination &&) noexcept;

  /**
     * @brief Sends one export packet to the destination.
     *
     * Sends one already-serialized export packet (e.g. from
     * Netflow5Exporter::build_packets()) to this destination. For
     * stream-oriented transports (tcp, sctp), this loops until every byte
     * is written, since a single send()/write() call over a stream socket
     * is not guaranteed to consume the whole buffer at once the way a UDP
     * datagram send is.
     *
     * @param packet The serialized packet.
     * @throw ExportError when it cannot be sent.
     */
  void
  send_packet (const std::vector<std::uint8_t> &packet) const;

  /**
     * @brief A description of the destination, for messages.
     *
     * @return The description.
     */
  const std::string &
  description () const noexcept {
    return description_;
  }

private:
  int fd_{-1};                   ///< The socket.
  bool stream_oriented_{false};  ///< Whether the transport is a stream (TCP, SCTP).
  std::string description_;      ///< The description of the destination.
};

/**
 * @brief The destinations of -n, with the choice of -l.
 *
 * @original softflowd.c's -n (comma-separated multiple destinations) and
 * -l (load-balance across them, sending each successive export packet to
 * the next destination in round-robin order, instead of the default of
 * sending every packet to every destination).
 */
class ExportDestinationSet {
public:
  /**
     * @brief Adds a destination.
     *
     * @param destination The destination, which the set takes over.
     */
  void
  add (ExportDestination destination);

  /**
     * @brief Whether there is no destination.
     *
     * @return true when there is none.
     */
  bool
  empty () const noexcept {
    return destinations_.empty();
  }
  /**
     * @brief The number of destinations.
     *
     * @return The number.
     */
  std::size_t
  size () const noexcept {
    return destinations_.size();
  }

  /**
     * @brief Sends a packet to every destination, or to the next one in turn.
     *
     * Sends `packet` according to `load_balance`: to every configured
     * destination if false (the original's default), or to just the next
     * destination in round-robin order if true (the original's -l).
     *
     * @param packet The serialized packet.
     * @param load_balance Send it to the next destination only (-l).
     */
  void
  send_packet (const std::vector<std::uint8_t> &packet, bool load_balance);

private:
  std::vector<ExportDestination> destinations_;  ///< The destinations.
  std::uint64_t sent_ = 0;                       ///< The packets sent, which picks the next destination with -l.
};

}  // namespace softflowd_cpp

#endif  // SOFTFLOWD_CPP_NETSOCK_HPP
