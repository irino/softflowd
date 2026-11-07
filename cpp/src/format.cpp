/**
 * @file format.cpp
 * @brief Text of addresses, times and flows, for the debug output and the dump of the flows.
 *
 * Split from softflowd.cpp. See format.hpp.
 */
#include "softflowd_cpp/format.hpp"

#include <array>
#include <chrono>
#include <cstdio>
#include <ctime>

#include <arpa/inet.h>
#include <sys/socket.h>

namespace softflowd_cpp {

/**
 * @brief Writes an Ethernet address as text.
 *
 * @param mac The address.
 * @return Six pairs of lowercase hexadecimal digits that are separated by colons.
 *
 * @original softflowd.c's format_ethermac().
 */
std::string
format_ethermac (const std::array<std::uint8_t, 6> &mac) {
  char buf[32];
  std::snprintf (buf, sizeof (buf), "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac[0],
                 mac[1], mac[2], mac[3], mac[4], mac[5]);
  return buf;
}

/**
 * @brief Writes a time in UTC.
 *
 * @param t The time.
 * @return The time as YYYY-MM-DDTHH:MM:SS.
 *
 * @original softflowd.c's format_time() -- gmtime + "%Y-%m-%dT%H:%M:%S".
 */
std::string
format_time (std::chrono::system_clock::time_point t) {
  const std::time_t tt = std::chrono::system_clock::to_time_t (t);
  struct tm tm_buf{};
  gmtime_r (&tt, &tm_buf);
  char buf[32];
  std::strftime (buf, sizeof (buf), "%Y-%m-%dT%H:%M:%S", &tm_buf);
  return buf;
}

/**
 * @brief Writes an address as text.
 *
 * @param addr The address.
 * @return The address in dotted decimal for IPv4, and in the compressed form of inet_ntop () for IPv6.
 *
 * @original inet_ntop () for the addresses that softflowd.c's debug lines and
 * its dump-flows output print: IPv6 in the compressed form ("::1").
 */
std::string
format_address (const softflowd_cpp::IpAddress &addr) {
  using namespace softflowd_cpp;
  std::array<char, INET6_ADDRSTRLEN> text{};
  const bool v4 = addr.family == AddressFamily::IPv4;
  inet_ntop (v4 ? AF_INET : AF_INET6, addr.bytes.data(), text.data(), text.size());
  return text.data();
}

/**
 * @brief Writes the key of a flow in one line, for the ADD FLOW line of -D.
 *
 * @param flow_seq The sequence number of the flow.
 * @param key The key of the flow.
 * @return The line.
 *
 * @original softflowd.c's format_flow_brief() -- used by the "ADD FLOW"
 * debug log line (-D).
 */
std::string
format_flow_brief (std::uint64_t flow_seq,
                   const softflowd_cpp::FlowKey &key) {
  char buf[256];
  std::snprintf (
    buf, sizeof (buf),
    "seq:%llu [%s]:%hu <> [%s]:%hu proto:%u vlan>:%u vlan<:%u  ether:%s <> %s ",
    static_cast<unsigned long long> (flow_seq),
    format_address (key.addr()[0]).c_str(), key.port()[0],
    format_address (key.addr()[1]).c_str(), key.port()[1],
    static_cast<unsigned> (key.protocol()), key.vlanid()[0], key.vlanid()[1],
    format_ethermac (key.ethermac()[0]).c_str(),
    format_ethermac (key.ethermac()[1]).c_str());
  return buf;
}

/**
 * @brief Writes a flow and its key in one line, for the EXPIRED line of -D and for dump-flows.
 *
 * @param key The key of the flow.
 * @param flow The flow.
 * @return The line.
 *
 * @original softflowd.c's format_flow() -- used by the "EXPIRED" debug
 * log line (-D). Note flow_start.tv_usec/flow_last.tv_usec in the
 * original are rounded to milliseconds via `(usec + 500) / 1000`; this
 * project's TimePoint doesn't retain sub-millisecond precision from the
 * pcap timestamp the same way internally, so milliseconds are derived
 * from the TimePoint's own duration instead of a separate usec field.
 */
std::string
format_flow (const softflowd_cpp::FlowKey &key,
             const softflowd_cpp::Flow &flow) {
  using namespace std::chrono;
  const auto start_wall = flow.wall_start;
  const auto last_wall = flow.wall_last;
  // Original: `(flow->flow_start.tv_usec + 500) / 1000` -- round to the
  // nearest millisecond (not truncate), matching this exactly.
  const auto start_usec =
    duration_cast<microseconds> (start_wall.time_since_epoch()).count() % 1000000;
  const auto last_usec =
    duration_cast<microseconds> (last_wall.time_since_epoch()).count() % 1000000;
  const auto start_ms = (start_usec + 500) / 1000;
  const auto last_ms = (last_usec + 500) / 1000;

  char buf[512];
  std::snprintf (
    buf, sizeof (buf),
    "seq:%llu [%s]:%hu <> [%s]:%hu proto:%u "
    "octets>:%llu packets>:%llu octets<:%llu packets<:%llu "
    "start:%s.%03lld finish:%s.%03lld tcp>:%02x tcp<:%02x "
    "flowlabel>:%08x flowlabel<:%08x "
    "vlan>:%u vlan<:%u ether:%s <> %s",
    static_cast<unsigned long long> (flow.flow_seq),
    format_address (key.addr()[0]).c_str(), key.port()[0],
    format_address (key.addr()[1]).c_str(), key.port()[1],
    static_cast<unsigned> (key.protocol()),
    static_cast<unsigned long long> (flow.octets[0]),
    static_cast<unsigned long long> (flow.packets[0]),
    static_cast<unsigned long long> (flow.octets[1]),
    static_cast<unsigned long long> (flow.packets[1]),
    format_time (start_wall).c_str(), static_cast<long long> (start_ms),
    format_time (last_wall).c_str(), static_cast<long long> (last_ms),
    flow.tcp_flags[0], flow.tcp_flags[1], flow.ip6_flowlabel_a,
    flow.ip6_flowlabel_b, key.vlanid()[0], key.vlanid()[1],
    format_ethermac (key.ethermac()[0]).c_str(),
    format_ethermac (key.ethermac()[1]).c_str());
  return buf;
}

}  // namespace softflowd_cpp
