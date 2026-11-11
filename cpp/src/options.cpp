/**
 * @file options.cpp
 * @brief The command line of softflowd+: the values of the options and the usage.
 *
 * Split from softflowd.cpp. See options.hpp.
 */
#include "softflowd_cpp/flow.hpp"
#include "softflowd_cpp/options.hpp"

// Original: common.h's PROGNAME/PROGVER macros. They are injected by
// CMakeLists.txt; the fallbacks only matter outside that build.
#ifndef SOFTFLOWDPP_NAME
/// The name of the program, which CMakeLists.txt gives.
#define SOFTFLOWDPP_NAME "softflowd+"
#endif
#ifndef SOFTFLOWDPP_VERSION
/// The version of the program, which CMakeLists.txt gives.
#define SOFTFLOWDPP_VERSION "0.0.0"
#endif

#include <cerrno>
#include <climits>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>

#include <getopt.h>
#include <netdb.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>

namespace softflowd_cpp {

// =======================================================================
// Configuration parsing (original: softflowd.c's getopt() loop)
// =======================================================================
//
// Everything in this section exists to give softflowd_cpp the exact same
// command-line grammar as the original softflowd(8) -- same option
// letters, same argument syntax, same defaults -- so that existing
// deployment scripts, init files, and muscle memory keep working
// unchanged. A handful of options are accepted for compatibility but only
// partially implemented (noted where they're parsed, below); this project
// prints a clear warning rather than silently ignoring them.
//
// This project's own additions (the ability to choose the flow-tracking
// data structure, and a couple of testing/debugging conveniences) use
// GNU-style `--long-options` specifically so they cannot collide with any
// of the original's single-letter flags, and are filtered out of argv
// before the original's getopt()-based option string is parsed.

/**
 * @brief Converts a time format to the one of the exporters.
 *
 * @param format The time format of -A.
 * @return The same format as an IpfixTimeFormat.
 */
softflowd_cpp::IpfixTimeFormat
to_ipfix_time_format (TimeFormat format) {
  switch (format) {
    case TimeFormat::SysUpTime:
      return softflowd_cpp::IpfixTimeFormat::SysUpTime;
    case TimeFormat::Seconds:
      return softflowd_cpp::IpfixTimeFormat::Seconds;
    case TimeFormat::Milliseconds:
      return softflowd_cpp::IpfixTimeFormat::Milliseconds;
    case TimeFormat::Microseconds:
      return softflowd_cpp::IpfixTimeFormat::Microseconds;
    case TimeFormat::Nanoseconds:
      return softflowd_cpp::IpfixTimeFormat::Nanoseconds;
  }
  return softflowd_cpp::IpfixTimeFormat::SysUpTime;
}

/**
 * @brief Gives the name of an export format.
 *
 * @param format The format.
 * @return The name: "none", "netflow1", "netflow5", "netflow9", "ipfix", "psamp" or "ntopng".
 */
const char *
format_name (ExportFormat format) {
  switch (format) {
    case ExportFormat::None:
      return "none";
    case ExportFormat::Netflow1:
      return "netflow1";
    case ExportFormat::Netflow5:
      return "netflow5";
    case ExportFormat::Netflow9:
      return "netflow9";
    case ExportFormat::Ipfix:
      return "ipfix";
    case ExportFormat::Psamp:
      return "psamp";
    case ExportFormat::Ntopng:
      return "ntopng";
  }
  return "unknown";
}

/**
 * @brief Gives the name of a track level, as -T takes it.
 *
 * @param level The track level.
 * @return The name: "ip", "proto", "port", "full", "full-tos", "vlan" or "ether".
 */
const char *
track_level_name (softflowd_cpp::TrackLevel level) {
  using softflowd_cpp::TrackLevel;
  switch (level) {
    case TrackLevel::IpOnly:
      return "ip";
    case TrackLevel::IpProto:
      return "proto";
    case TrackLevel::Port:
      return "port";
    case TrackLevel::IpProtoPort:
      return "full";
    case TrackLevel::FullTos:
      return "full-tos";
    case TrackLevel::FullVlan:
      return "vlan";
    case TrackLevel::FullVlanEther:
      return "ether";
  }
  return "full";
}

/**
 * @brief Prints a message and the usage to the standard error, and exits with 1.
 *
 * @param fmt The format of the message, as for printf().
 * @param ... The values for the format.
 *
 * @original die_usage (). Prints the message and the usage, then exits.
 */
[[noreturn]] void
die_usage (const char *fmt, ...) {
  va_list ap;
  va_start (ap, fmt);
  std::vfprintf (stderr, fmt, ap);
  va_end (ap);
  print_usage();
  std::exit (1);
}

/**
 * @brief Reads a time with qualifiers, such as "90", "10m" or "1h30m".
 *
 * The qualifiers are s, m, h, d and w (seconds, minutes, hours, days and weeks), in either case; a number without one is seconds.
 *
 * @param s The text.
 * @return The number of seconds, or -1 when the text is empty, has a negative number or an unknown qualifier, or does not fit.
 *
 * @original convtime.c. A time of the form time[qualifier][time[qualifier]...],
 * e.g. "10m", "1h30m", or a bare number of seconds like "600"; each term is
 * summed. Returns -1 for an invalid time. The original does not check the
 * products for an overflow, which is not defined for it; -1 is returned here.
 */
long
convtime (const char *s) {
  errno = 0;
  long total = 0;
  const char *p = s;

  if (p == nullptr || *p == '\0') {
    return -1;
  }
  while (*p) {
    char *endp;
    long secs = std::strtol (p, &endp, 10);
    if (p == endp || (errno == ERANGE && (secs == LONG_MIN || secs == LONG_MAX)) ||
        secs < 0) {
      return -1;
    }
    long multiplier = 1;
    switch (*endp++) {
      case '\0':
        --endp;
        break;
      case 's':
      case 'S':
        break;
      case 'm':
      case 'M':
        multiplier = 60;
        break;
      case 'h':
      case 'H':
        multiplier = 60 * 60;
        break;
      case 'd':
      case 'D':
        multiplier = 24 * 60 * 60;
        break;
      case 'w':
      case 'W':
        multiplier = 7 * 24 * 60 * 60;
        break;
      default:
        return -1;
    }
    if (__builtin_mul_overflow (secs, multiplier, &secs) ||
        __builtin_add_overflow (total, secs, &total) || total < 0) {
      return -1;
    }
    p = endp;
  }
  return total;
}

/**
 * @brief Applies one -t option, "name=time".
 *
 * It prints the usage and exits for a bad name or time, and exits with 1 when the general timeout would be 0.
 *
 * @param config The settings to change; expint sets expiry_interval, the others set timeouts.
 * @param to_spec The text of the option.
 *
 * @original set_timeout (). -t timeout_name=time. Named timeouts are:
 * general, tcp, tcp.rst, tcp.fin, udp, icmp, maxlife, expint (see
 * softflowd(8)'s "Timeouts" section). As in the original, the time is kept in
 * an int, so a longer one is rejected.
 */
void
set_timeout (DaemonConfig &config, const char *to_spec) {
  const std::string spec = to_spec;
  const auto eq = spec.find ('=');
  if (eq == std::string::npos || eq + 1 == spec.size()) {
    die_usage ("Invalid -t option \"%s\".\n", spec.c_str());
  }
  const std::string name = spec.substr (0, eq);
  const long timeout = convtime (spec.c_str() + eq + 1);
  if (timeout < 0 || timeout > std::numeric_limits<int>::max()) {
    die_usage ("Invalid -t timeout.\n");
  }
  const std::chrono::seconds value (timeout);

  if (name == "general") {
    config.timeouts.general = value;
  } else if (name == "tcp") {
    config.timeouts.tcp = value;
  } else if (name == "tcp.rst") {
    config.timeouts.tcp_rst = value;
  } else if (name == "tcp.fin") {
    config.timeouts.tcp_fin = value;
  } else if (name == "udp") {
    config.timeouts.udp = value;
  } else if (name == "icmp") {
    config.timeouts.icmp = value;
  } else if (name == "maxlife") {
    config.timeouts.maximum_lifetime = value;
  } else if (name == "expint") {
    config.expiry_interval = value;
  } else {
    die_usage ("Invalid -t name.\n");
  }

  // Original: the general timeout may not be 0, as the check of an idle flow
  // would then never find anything idle.
  if (config.timeouts.general.count() == 0) {
    std::fprintf (stderr, "\"general\" flow timeout must be greater than zero\n");
    std::exit (1);
  }
}

/**
 * @brief Reads the name of a track level of -T.
 *
 * @param s The name, in either case.
 * @return The level, or nothing for an unknown name.
 *
 * @original -T track_level (the name is not case sensitive). Returns nothing
 * for an unknown name.
 */
std::optional<softflowd_cpp::TrackLevel>
parse_track_level (const char *s) {
  using softflowd_cpp::TrackLevel;
  if (strcasecmp (s, "ip") == 0)
    return TrackLevel::IpOnly;
  if (strcasecmp (s, "proto") == 0)
    return TrackLevel::IpProto;
  if (strcasecmp (s, "port") == 0)
    return TrackLevel::Port;
  if (strcasecmp (s, "full") == 0)
    return TrackLevel::IpProtoPort;
  if (strcasecmp (s, "full-tos") == 0)
    return TrackLevel::FullTos;
  if (strcasecmp (s, "vlan") == 0)
    return TrackLevel::FullVlan;
  if (strcasecmp (s, "ether") == 0)
    return TrackLevel::FullVlanEther;
  return std::nullopt;
}

/**
 * @brief Reads the argument of -v.
 *
 * "ntopng" is known only when softflowd is built with ZeroMQ (SOFTFLOWD_CPP_HAVE_ZMQ).
 *
 * @param s A version number, "psamp" or "ntopng".
 * @return The format, or nothing for an unknown one.
 *
 * @original -v netflow_version. As in the original, a number is read by
 * atoi (), so that "5x" is version 5. Returns nothing for an unknown version.
 */
std::optional<ExportFormat>
parse_netflow_version (const char *s) {
  if (std::strcmp (s, "psamp") == 0)
    return ExportFormat::Psamp;
#ifdef SOFTFLOWD_CPP_HAVE_ZMQ
  if (std::strcmp (s, "ntopng") == 0)
    return ExportFormat::Ntopng;
#endif
  switch (std::atoi (s)) {
    case 1:
      return ExportFormat::Netflow1;
    case 5:
      return ExportFormat::Netflow5;
    case 9:
      return ExportFormat::Netflow9;
    case 10:
      return ExportFormat::Ipfix;
    default:
      return std::nullopt;
  }
}

/**
 * @brief Reads the argument of -P.
 *
 * @param s The name, in either case.
 * @return The protocol, or nothing for an unknown name.
 *
 * @original -P transport_protocol (the name is not case sensitive). Returns
 * nothing for an unknown name.
 */
std::optional<TransportProtocol>
parse_transport_protocol (const char *s) {
  if (strcasecmp (s, "udp") == 0)
    return TransportProtocol::Udp;
  if (strcasecmp (s, "tcp") == 0)
    return TransportProtocol::Tcp;
  if (strcasecmp (s, "sctp") == 0)
    return TransportProtocol::Sctp;
  return std::nullopt;
}

/**
 * @brief Reads the argument of -A.
 *
 * @param s The name ("sec", "milli", "micro" or "nano"), in either case.
 * @return The format, or nothing for an unknown name.
 *
 * @original -A time_format (the name is not case sensitive). Returns nothing
 * for an unknown name.
 */
std::optional<TimeFormat>
parse_time_format (const char *s) {
  if (strcasecmp (s, "sec") == 0)
    return TimeFormat::Seconds;
  if (strcasecmp (s, "milli") == 0)
    return TimeFormat::Milliseconds;
  if (strcasecmp (s, "micro") == 0)
    return TimeFormat::Microseconds;
  if (strcasecmp (s, "nano") == 0)
    return TimeFormat::Nanoseconds;
  return std::nullopt;
}

/**
 * @brief Reads the argument of -n: destinations of the form host:port, separated by commas.
 *
 * It prints the usage and exits for a bad argument, and exits with 1 for a destination that cannot be resolved.
 *
 * @param spec The argument.
 * @return The (host, port) pairs, without the brackets of an IPv6 host.
 *
 * @original parse_hostport () and parse_hostports (). -n host:port[,host:port...].
 * A numeric IPv6 address is bracketed (e.g. "[::1]:4432") so that its colons
 * are not taken for the port separator. Each destination is resolved here, as
 * the original does, so that one that cannot be is reported when softflowd
 * starts. The original takes no more than 16 destinations and ignores the
 * rest.
 */
std::vector<std::pair<std::string, std::string>>
parse_destinations (const std::string &spec) {
  constexpr std::size_t kMaxDestinations = 16;
  std::vector<std::pair<std::string, std::string>> result;
  std::size_t pos = 0;
  while (result.size() < kMaxDestinations) {
    const auto comma = spec.find (',', pos);
    const std::string token =
      spec.substr (pos, comma == std::string::npos ? std::string::npos
                                                   : comma - pos);
    const auto colon = token.rfind (':');
    // Original: only a missing or an empty port, or an empty argument, is
    // "Invalid -n argument."; an empty host is one that cannot be resolved.
    if (colon == std::string::npos || colon + 1 == token.size() ||
        token.empty()) {
      die_usage ("Invalid -n argument.\n");
    }
    std::string host = token.substr (0, colon);
    const std::string port = token.substr (colon + 1);
    // Original: a numeric port above 65535 is refused (getaddrinfo () would
    // cut it to 16 bits).
    if (port.front() >= '0' && port.front() <= '9') {
      char *end = nullptr;
      errno = 0;
      const unsigned long number = std::strtoul (port.c_str(), &end, 10);
      if (*end == '\0' && (errno == ERANGE || number > 65535)) {
        die_usage ("Invalid -n argument.\n");
      }
    }
    if (!host.empty() && host.front() == '[' && host.back() == ']') {
      host = host.substr (1, host.size() - 2);
    }

    struct addrinfo hints;
    std::memset (&hints, 0, sizeof (hints));
    hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo *res = nullptr;
    if (getaddrinfo (host.c_str(), port.c_str(), &hints, &res) != 0 ||
        res == nullptr) {
      std::fprintf (stderr, "No addresses found for [%s]:%s\n", host.c_str(),
                    port.c_str());
      std::exit (1);
    }
    freeaddrinfo (res);
    result.emplace_back (std::move (host), port);

    if (comma == std::string::npos) {
      break;
    }
    pos = comma + 1;
  }
  return result;
}

/**
 * @brief Tells whether IPv6 flows are tracked.
 *
 * @param config The settings.
 * @return true with -6, and otherwise unless the format is NetFlow v1 or v5, which have no IPv6 record.
 *
 * @original -6's documented purpose ("force softflowd to track IPv6 flows
 * even if the NetFlow export protocol does not support reporting them").
 * NetFlow v1 and v5 have no IPv6 record format at all; v9, IPFIX, and
 * PSAMP all support IPv6 natively (see netflow9.hpp/ipfix.hpp/psamp.hpp).
 */
bool
should_track_ipv6 (const DaemonConfig &config) {
  if (config.force_ipv6) {
    return true;
  }
  switch (config.export_format) {
    case ExportFormat::Netflow1:
    case ExportFormat::Netflow5:
      return false;
    default:
      return true;
  }
}

/**
 * @brief Reads an Ethernet address of the form xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx.
 *
 * @param str The text.
 * @param mac The address; it is set only when the text is read.
 * @return true when six values were read.
 *
 * @original parse_mac_address(). "xx:xx:xx:xx:xx:xx" or "xx-xx-xx-xx-xx-xx".
 */
bool
parse_mac_address (const char *str, std::array<std::uint8_t, 6> &mac) {
  unsigned int b[6];
  if (std::sscanf (str, "%2x:%2x:%2x:%2x:%2x:%2x", &b[0], &b[1], &b[2], &b[3],
                   &b[4], &b[5]) != 6 &&
      std::sscanf (str, "%2x-%2x-%2x-%2x-%2x-%2x", &b[0], &b[1], &b[2], &b[3],
                   &b[4], &b[5]) != 6) {
    return false;
  }
  for (std::size_t i = 0; i < 6; ++i) {
    mac[i] = static_cast<std::uint8_t> (b[i]);
  }
  return true;
}

/**
 * @brief Prints the usage to the standard error, with the defaults of DaemonConfig.
 *
 * @original usage (). The text is that of the original; the additions of
 * this project follow it.
 */
void
print_usage () {
  const DaemonConfig defaults;
  const softflowd_cpp::FlowTimeouts &t = defaults.timeouts;
  std::fprintf (
    stderr,
    "Usage: %s [options] [bpf_program]\n"
    "This is %s version %s. Valid commandline options:\n"
    "  -i, --interface [idx:]interface\n"
    "                          Specify interface to listen on\n"
    "  -r, --read pcap_file    Specify packet capture file to read\n"
    "  -t, --timeout timeout=time\n"
    "                          Specify named timeout\n"
    "  -m, --max-flows max_flows\n"
    "                          Specify maximum number of flows to track (1 "
    "or more, default %d)\n"
    "  -n, --netflow-dest host:port\n"
    "                          Send Cisco NetFlow(tm)-compatible packets to "
    "host:port\n"
    "  -p, --pidfile pidfile   Record pid in specified file\n"
    "                          (default: %s)\n"
    "  -c, --control-socket socketfile\n"
    "                          Location of control socket\n"
    "                          (default: %s)\n"
    "  -v, --netflow-version 1|5|9|10|psamp\n"
    "                          NetFlow export packet version\n"
    "                          10 means IPFIX and psamp means PSAMP (packet "
    "sampling)\n"
#ifdef SOFTFLOWD_CPP_HAVE_ZMQ
    "     ntopng               ntopng means direct injection to NTOPNG (if "
    "supported, ntopng 6.0 or later).\n"
#endif
    "  -L, --hoplimit hoplimit Set TTL/hoplimit for export datagrams\n"
    "  -T, --track full|port|proto|ip|\n"
    "                          Set flow tracking level (default: full)\n"
    "                          vlan                 (\"vlan\" tracking means "
    "\"full\" tracking with vlanid)\n"
    "                          ether                (\"ether\" tracking "
    "means \"vlan\" tracking with ether header)\n"
    "  -H, --direction-mac MAC Specify MAC Address to determine direction "
    "(requires -T ether)\n"
    "  -6, --track-ipv6        Track IPv6 flows, regardless of whether "
    "selected \n"
    "                          NetFlow export protocol supports it\n"
    "  -d, --foreground        Don't daemonise (run in foreground)\n"
    "  -D, --debug             Debug mode: foreground + verbosity + track v6 "
    "flows\n"
    "  -P, --export-protocol udp|tcp|sctp\n"
    "                          Specify transport layer protocol for "
    "exporting packets\n"
    "  -A, --absolute-time sec|milli|micro|nano\n"
    "                          Specify absolute time format form exporting "
    "records\n"
    "  -s, --sampling-rate rate\n"
    "                          Specify periodical sampling rate "
    "(denominator)\n"
    "  -B, --pcap-buffer-size bytes\n"
    "                          Libpcap buffer size in bytes\n"
    "  -b, --bidirectional     Bidirectional mode in IPFIX (-b work with -v "
    "10)\n"
    "  -a, --adjust-time       Adjusting time for reading pcap file (-a work "
    "with -r)\n"
    "  -C, --snaplen capture_length\n"
    "                          Specify length for packet capture (snaplen)\n"
    "  -l, --load-balance      Load balancing mode for multiple "
    "destinations\n"
    "  -R, --psamp-port receive_port\n"
    "                          Specify port number for PSAMP receive mode\n"
    "  -M, --multithread       Enable multithread\n"
    "  -N, --no-promisc        Disable promiscuous mode\n"
#ifdef __linux__
    "  -S, --send-interface send_interface_name\n"
    "                          Specify send interface name\n"
#endif
    "  -x, --mpls-labels labels\n"
    "                          Specify number of MPLS labels (1 to 10)\n"
    "  -I, --reinit-interval seconds\n"
    "                          Specify seconds for reinitialize boot time\n"
    "  -g, --gauge-cpu-clock   Gauge cpu clock (total and export) for "
    "benchmark\n"
    "  -e, --exporter-ip address\n"
    "                          Specify Exporter IP (IPv4 or IPv6) address\n"
    "  -f, --full-transport-header-check\n"
    "                          Require the whole TCP/UDP/ICMP header instead "
    "of\n"
    "                          only the fields used (ports, TCP flags, ICMP "
    "type/code)\n"
    "  -F, --flow-lookup mode  Flow table lookup: tree, hash-tree (default) "
    "or hash\n"
    "                          (hash: a colliding flow expires the resident "
    "one)\n"
    "  -h, --help              Display this help\n"
    "\n"
    "Valid timeout names and default values:\n"
    "  tcp     (default %6d)"
    "  tcp.rst (default %6d)"
    "  tcp.fin (default %6d)\n"
    "  udp     (default %6d)"
    "  icmp    (default %6d)"
    "  general (default %6d)\n"
    "  maxlife (default %6d)"
    "  expint  (default %6d)\n"
    "\n"
    "This project's own additions (not part of the original softflowd):\n"
    "  -T full-tos           track the ToS as part of the flow as well\n"
    "  --export-out=PATH     additionally write export packets to a file,\n"
    "                        each length-prefixed with 4 big-endian bytes\n"
    "  --max-runtime=SECONDS shut down automatically after SECONDS (testing)\n",
    SOFTFLOWDPP_NAME, SOFTFLOWDPP_NAME, SOFTFLOWDPP_VERSION,
    static_cast<int> (defaults.max_flows), softflowd_cpp::kDefaultPidFilePath,
    softflowd_cpp::kDefaultControlSocketPath, static_cast<int> (t.tcp.count()),
    static_cast<int> (t.tcp_rst.count()), static_cast<int> (t.tcp_fin.count()),
    static_cast<int> (t.udp.count()), static_cast<int> (t.icmp.count()),
    static_cast<int> (t.general.count()),
    static_cast<int> (t.maximum_lifetime.count()),
    static_cast<int> (defaults.expiry_interval.count()));
}

DaemonConfig
parse_command_line (int argc, char **argv) {
  DaemonConfig config;

  // This project's own additions are exposed as GNU-style long options
  // via getopt_long(). Every existing short option keeps its exact
  // original letter and argument-taking behavior (the optstring below is
  // unchanged), so any script or invocation built against the original
  // softflowd's short-option grammar continues to work unmodified;
  // getopt_long() simply also accepts these long forms alongside them.
  enum {
    kOptExportOut = 1000,
    kOptMaxRuntime,
    kOptIcmpTypecodeOnly,
    kOptExpirySecondGranularity,
    kOptNoExpirySecondGranularity,
  };
  static const struct option long_options[] = {
    {"track-ipv6", no_argument, nullptr, '6'},
    {"adjust-time", no_argument, nullptr, 'a'},
    {"absolute-time", required_argument, nullptr, 'A'},
    {"bidirectional", no_argument, nullptr, 'b'},
    {"pcap-buffer-size", required_argument, nullptr, 'B'},
    {"control-socket", required_argument, nullptr, 'c'},
    {"snaplen", required_argument, nullptr, 'C'},
    {"foreground", no_argument, nullptr, 'd'},
    {"debug", no_argument, nullptr, 'D'},
    {"exporter-ip", required_argument, nullptr, 'e'},
    {"full-transport-header-check", no_argument, nullptr, 'f'},
    {"flow-lookup", required_argument, nullptr, 'F'},
    {"gauge-cpu-clock", no_argument, nullptr, 'g'},
    {"help", no_argument, nullptr, 'h'},
    {"direction-mac", required_argument, nullptr, 'H'},
    {"interface", required_argument, nullptr, 'i'},
    {"reinit-interval", required_argument, nullptr, 'I'},
    {"load-balance", no_argument, nullptr, 'l'},
    {"hoplimit", required_argument, nullptr, 'L'},
    {"max-flows", required_argument, nullptr, 'm'},
    {"multithread", no_argument, nullptr, 'M'},
    {"netflow-dest", required_argument, nullptr, 'n'},
    {"no-promisc", no_argument, nullptr, 'N'},
    {"pidfile", required_argument, nullptr, 'p'},
    {"export-protocol", required_argument, nullptr, 'P'},
    {"read", required_argument, nullptr, 'r'},
    {"psamp-port", required_argument, nullptr, 'R'},
    {"sampling-rate", required_argument, nullptr, 's'},
    {"send-interface", required_argument, nullptr, 'S'},
    {"timeout", required_argument, nullptr, 't'},
    {"track", required_argument, nullptr, 'T'},
    {"netflow-version", required_argument, nullptr, 'v'},
    {"mpls-labels", required_argument, nullptr, 'x'},
    // Additions of the C++ version.
    {"export-out", required_argument, nullptr, kOptExportOut},
    {"max-runtime", required_argument, nullptr, kOptMaxRuntime},
    {"icmp-typecode-only", no_argument, nullptr, kOptIcmpTypecodeOnly},
    {"expiry-second-granularity", no_argument, nullptr,
     kOptExpirySecondGranularity},
    {"no-expiry-second-granularity", no_argument, nullptr,
     kOptNoExpirySecondGranularity},
    {nullptr, 0, nullptr, 0},
  };

  const int fargc = argc;
  char **fargv = argv;
  bool export_format_explicit = false;

  ::optind = 1;
  int opt;
  try {
    while ((opt = getopt_long (
              fargc, fargv,
              "n:Ni:r:p:c:m:t:d6DhL:T:v:P:A:s:C:R:S:e:x:B:bfF:alI:gH:M",
              long_options, nullptr)) != -1) {
      switch (opt) {
        case 'F':
          // Original: -F flow-lookup, tree | hash | hash-tree.
          if (std::string (optarg) == "tree") {
            config.flow_lookup = softflowd_cpp::FlowLookup::Tree;
          } else if (std::string (optarg) == "hash") {
            config.flow_lookup = softflowd_cpp::FlowLookup::Hash;
          } else if (std::string (optarg) == "hash-tree") {
            config.flow_lookup = softflowd_cpp::FlowLookup::HashTree;
          } else {
            die_usage ("Invalid flow lookup mode\n\n");
          }
          break;
        case kOptExportOut:
          config.export_out = optarg;
          break;
        case kOptMaxRuntime:
          config.max_runtime = std::chrono::seconds (std::stol (optarg));
          break;
        case kOptIcmpTypecodeOnly:
          // Now the default: only the bytes that are read (ICMP type
          // and code) are required. Kept as a no-op so existing
          // invocations still work; -f requires the whole header.
          break;
        case 'f':
          config.full_l4hdr_check = true;
          break;
        case 'M':
          config.multithread = true;
          break;
        case kOptExpirySecondGranularity:
          // See FlowTimeouts::second_granularity's comment. This is
          // now the default (matching the original's only actual
          // behavior); the flag is kept as a harmless no-op so
          // existing invocations that pass it explicitly still work.
          config.timeouts.second_granularity = true;
          break;
        case kOptNoExpirySecondGranularity:
          // Opts into full sub-second expiry-scheduling precision,
          // deviating from the original's whole-second `time_t`
          // expires_at (and, as a result, its expiry queue/export
          // ordering) in exchange for more precise expiry timing.
          config.timeouts.second_granularity = false;
          break;
        case 'n':
          // Original: the destinations of a later -n replace those of an
          // earlier one.
          config.destinations = parse_destinations (optarg);
          break;
        case 'N':
          config.no_promiscuous = true;
          break;
        case 'i':
          if (!config.pcap_file.empty() || !config.interface.empty()) {
            die_usage ("Packet source already specified.\n\n");
          }
          {
            // Original: -i [idx:]interface. The index is that of the interface
            // in the options of NetFlow v9 and IPFIX; without it the index of
            // the interface is looked up when the daemon starts.
            std::string name = optarg;
            const auto colon = name.find (':');
            if (colon != std::string::npos) {
              if (colon > 0) {
                config.if_index = static_cast<std::uint16_t> (
                  std::atoi (name.substr (0, colon).c_str()));
              }
              name.erase (0, colon + 1);
              config.user_ifindex = true;
            }
            if (name.empty()) {
              die_usage ("Wrong interface is specified.\n\n");
            }
            if (config.debug) {
              std::fprintf (stderr, "Using %s (idx: %d)\n", name.c_str(),
                            config.if_index);
            }
            config.interface = name;
          }
          break;
        case 'r':
          if (!config.pcap_file.empty() || !config.interface.empty()) {
            die_usage ("Packet source already specified.\n\n");
          }
          config.pcap_file = optarg;
          config.replay_control = false;
          break;
        case 'p':
          config.pidfile = optarg;
          break;
        case 'c':
          // Original: "none" is no control socket.
          config.ctl_sock = std::strcmp (optarg, "none") == 0 ? "" : optarg;
          // Original: -r clears the control socket path and a -c after it
          // sets it again, so a capture file is controlled only then.
          config.replay_control = !config.ctl_sock.empty();
          break;
        case 'm': {
          // Range check on an int, as in the C version: 0, negative
          // values and non-numeric arguments are rejected.
          const int max_flows = std::atoi (optarg);
          if (max_flows < 1) {
            die_usage ("Invalid maximum flows\n\n");
          }
          config.max_flows = static_cast<std::size_t> (max_flows);
          break;
        }
        case 't':
          set_timeout (config, optarg);
          break;
        case 'd':
          config.no_daemonize = true;
          break;
        case '6':
          config.force_ipv6 = true;
          break;
        case 'D':
          config.debug = true;
          config.no_daemonize = true;
          config.force_ipv6 = true;
          break;
        case 'h':
          print_usage();
          std::exit (0);
        case 'L': {
          // Original: atoi (), then a range check.
          const int hoplimit = std::atoi (optarg);
          if (hoplimit < 0 || hoplimit > 255) {
            die_usage ("Invalid hop limit\n\n");
          }
          config.ttl = hoplimit;
          break;
        }
        case 'T': {
          const auto level = parse_track_level (optarg);
          if (!level.has_value()) {
            die_usage ("Unknown flow tracking level\n");
          }
          config.track_level = *level;
          break;
        }
        case 'v': {
          const auto format = parse_netflow_version (optarg);
          if (!format.has_value()) {
            std::fprintf (stderr, "Invalid NetFlow version\n");
            std::exit (1);
          }
          config.export_format = *format;
          export_format_explicit = true;
          break;
        }
        case 'P': {
          const auto transport = parse_transport_protocol (optarg);
          if (!transport.has_value()) {
            die_usage ("Unknown transport layer protocol\n");
          }
          config.transport = *transport;
          break;
        }
        case 'A': {
          const auto format = parse_time_format (optarg);
          if (!format.has_value()) {
            die_usage ("Unknown time format\n");
          }
          config.time_format = *format;
          break;
        }
        case 's': {
          // Original: atoi (); a rate below 2 is no sampling.
          const int rate = std::atoi (optarg);
          config.sampling_rate = rate < 2 ? 0 : static_cast<std::uint32_t> (rate);
          break;
        }
        case 'C':
          // Original: atoi ().
          config.snaplen = std::atoi (optarg);
          break;
        case 'R': {
          // Original: atoi (); a port that does not fit 16 bits is reported with
          // the usage, and the default port (IPFIX_PORT of ipfix.h) is used.
          int port = std::atoi (optarg);
          if (port < 0 || port > 65535) {
            std::fprintf (stderr, "Invalid -R port, using the default %d.\n",
                          kDefaultIpfixPort);
            print_usage();
            port = kDefaultIpfixPort;
          }
          config.psamp_receive_port = static_cast<std::uint16_t> (port);
          break;
        }
        case 'S':
          config.send_interface = optarg;
          break;
        case 'e': {
          // Original: the address is resolved when the option is read; one
          // that cannot be is reported and not used. (The original reports
          // it with the reason of getaddrinfo (), as it is printed here.)
          struct addrinfo hints;
          std::memset (&hints, 0, sizeof (hints));
          struct addrinfo *res = nullptr;
          const int err = getaddrinfo (optarg, nullptr, &hints, &res);
          if (err != 0) {
            std::fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (err));
            break;
          }
          freeaddrinfo (res);
          config.source_address = optarg;
          break;
        }
        case 'x': {
          const int num_label = std::atoi (optarg);
          if (num_label < 1 || num_label > 10) {
            die_usage ("Invalid number of MPLS label (1 to 10)\n\n");
          }
          config.mpls_labels = num_label;
          break;
        }
        case 'B': {
          // Original: atoi (); only a positive size is a size.
          const int size = std::atoi (optarg);
          config.buffer_bytes = size > 0 ? static_cast<std::size_t> (size) : 0;
          break;
        }
        case 'b':
          config.bidirectional_ipfix = true;
          break;
        case 'a':
          config.adjust_pcap_time = true;
          break;
        case 'l':
          config.load_balance = true;
          break;
        case 'I': {
          // Original: BOOTTIME_MAX_DAY/HOUR/MIN/SEC clamps in
          // softflowd.c's -I parsing.
          constexpr long kBoottimeMaxDay = 49;
          constexpr long kBoottimeMaxHour = 1193;
          constexpr long kBoottimeMaxMin = 71582;
          constexpr long kBoottimeMaxSec = 4294944;

          char *timeunit = nullptr;
          errno = 0;
          long sec = std::strtol (optarg, &timeunit, 10);
          if ((errno == ERANGE && (sec == LONG_MAX || sec == LONG_MIN)) ||
              (errno != 0 && sec == 0)) {
            std::perror ("strtol");
            print_usage();
            std::exit (1);
          }
          if (timeunit == optarg) {
            die_usage ("No digits were found in boot_time_reinit\n");
          }
          if (*timeunit == 'd' || *timeunit == 'D') {
            if (sec > kBoottimeMaxDay)
              sec = kBoottimeMaxDay;
            sec *= 24 * 60 * 60;
          } else if (*timeunit == 'h' || *timeunit == 'H') {
            if (sec > kBoottimeMaxHour)
              sec = kBoottimeMaxHour;
            sec *= 60 * 60;
          } else if (*timeunit == 'm' || *timeunit == 'M') {
            if (sec > kBoottimeMaxMin)
              sec = kBoottimeMaxMin;
            sec *= 60;
          } else {
            if (sec > kBoottimeMaxSec)
              sec = kBoottimeMaxSec;
          }
          config.boot_time_reinit = std::chrono::seconds (sec);
          break;
        }
        case 'g':
          config.gauge_clock = true;
          break;
        case 'H': {
          std::array<std::uint8_t, 6> mac;
          if (!parse_mac_address (optarg, mac)) {
            std::fprintf (stderr, "Invalid MAC address %s\n", optarg);
            std::exit (1);
          }
          config.direction_mac = mac;
          break;
        }
        case '?':
        default:
          die_usage ("Invalid commandline option.\n");
      }
    }
  } catch (const std::exception &e) {
    std::fprintf (stderr, "%s: %s\n", argv[0], e.what());
    std::exit (1);
  }
  (void) export_format_explicit;  // Netflow5 is already config's default

  std::string bpf;
  for (int i = optind; i < fargc; ++i) {
    if (!bpf.empty()) {
      bpf += " ";
    }
    bpf += fargv[i];
  }
  config.bpf_filter = bpf;

  if (config.interface.empty() && config.pcap_file.empty() &&
      !config.psamp_receive_port.has_value()) {
    die_usage ("-i, -r or -R option not specified.\n");
  }
  // Original: -R with -r is not an error, and has no effect.
  if (config.psamp_receive_port.has_value() && !config.pcap_file.empty()) {
    config.psamp_receive_port.reset();
  }

  return config;
}

}  // namespace softflowd_cpp
