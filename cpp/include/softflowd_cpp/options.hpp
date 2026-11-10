/**
 * @file options.hpp
 * @brief The command line of softflowd+: the settings, the values of the options and the usage.
 *
 * Split from softflowd.cpp. The grammar of the command line is that of the
 * original softflowd(8); see options.cpp. DaemonConfig holds what the options
 * set, and the functions read the values of the options that are not plain
 * numbers or strings, such as a time with qualifiers or a destination.
 *
 * @original The getopt() loop of softflowd.c's main(), usage(), die_usage(),
 * set_timeout() and parse_mac_address() of softflowd.c, and convtime.c.
 */
#ifndef SOFTFLOWD_CPP_OPTIONS_HPP
#define SOFTFLOWD_CPP_OPTIONS_HPP

#include "softflowd_cpp/flow.hpp"
#include "softflowd_cpp/ipfix.hpp"
#include "softflowd_cpp/softflowctl.hpp"
#include "softflowd_cpp/softflowd.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace softflowd_cpp {

/**
 * @brief The format of the export, which -v chooses.
 */
enum class ExportFormat {
  None,      ///< No exporter; no option of the command line gives this format.
  Netflow1,  ///< NetFlow version 1.
  Netflow5,  ///< NetFlow version 5, the default.
  Netflow9,  ///< NetFlow version 9.
  Ipfix,     ///< IPFIX (-v 10).
  Psamp,     ///< PSAMP (-v psamp).
  Ntopng     ///< ntopng messages (-v ntopng); only with ZeroMQ.
};

/**
 * @brief The transport protocol of the export, which -P chooses.
 */
enum class TransportProtocol {
  Udp,  ///< UDP.
  Tcp,  ///< TCP.
  Sctp  ///< SCTP; see the README for what is supported.
};

/**
 * @brief The format of the times in IPFIX and PSAMP records, which -A chooses.
 */
enum class TimeFormat {
  SysUpTime,     ///< Milliseconds since the start of the exporter; the default.
  Seconds,       ///< Seconds since the epoch.
  Milliseconds,  ///< Milliseconds since the epoch.
  Microseconds,  ///< Microseconds since the epoch.
  Nanoseconds    ///< Nanoseconds since the epoch; written like Microseconds (see write_time_values() in export_record.cpp).
};

softflowd_cpp::IpfixTimeFormat
to_ipfix_time_format (TimeFormat format);

const char *
format_name (ExportFormat format);

const char *
track_level_name (softflowd_cpp::TrackLevel level);

/**
 * @brief The settings of a run: what the command line gave, and the defaults of the original for the rest.
 *
 * @original softflowd.c's -n / -p / -c / -m / -t / -T / -v / -L / etc.
 * gathered into one struct rather than threaded through main() as
 * individual local variables, since there are simply too many of them for
 * that to stay readable. Field-by-field comments note the corresponding
 * original option letter.
 */
struct DaemonConfig {
  std::string interface;        ///< The interface to capture from (-i).
  std::uint16_t if_index = 0;   ///< The interface index of the records: the one that -i idx:interface gave, or otherwise looked up at the start.
  bool user_ifindex = false;    ///< true when -i gave the index.
  std::string pcap_file;        ///< The file to read packets from (-r).
  bool no_promiscuous = false;  ///< true when the interface is not put into promiscuous mode (-N).

  std::vector<std::pair<std::string, std::string>> destinations;  ///< The destinations as (host, port) pairs (-n).
  bool load_balance = false;                                      ///< true when the destinations take turns (-l).
  std::optional<int> ttl;                                         ///< The TTL of the export packets (-L), if given.
  std::string source_address;                                     ///< The source address of the export packets (-e).
  std::string send_interface;                                     ///< The interface to send the export packets from (-S).

  std::string pidfile = softflowd_cpp::kDefaultPidFilePath;         ///< The path of the pid file (-p).
  std::string ctl_sock = softflowd_cpp::kDefaultControlSocketPath;  ///< The path of the control socket (-c).
  bool replay_control = false;                                      ///< true when -c came after -r, so that the control socket is served while a file is read.

  std::size_t max_flows = 8192;  ///< The number of flows that are tracked at most (-m).

  softflowd_cpp::FlowTimeouts timeouts;      ///< The timeouts of the flows (-t).
  std::chrono::seconds expiry_interval{60};  ///< The interval between the checks for expired flows (-t expint).

  bool no_daemonize = false;  ///< true when softflowd stays in the foreground (-d).
  bool force_ipv6 = false;    ///< true when IPv6 flows are tracked for every format (-6).
  bool debug = false;         ///< true for the debug output (-D, which implies -d and -6).

  softflowd_cpp::TrackLevel track_level = softflowd_cpp::TrackLevel::IpProtoPort;  ///< What a flow is identified by (-T).

  ExportFormat export_format = ExportFormat::Netflow5;  ///< The export format (-v).

  TransportProtocol transport = TransportProtocol::Udp;      ///< The transport protocol of the export (-P).
  TimeFormat time_format = TimeFormat::SysUpTime;            ///< The format of the times (-A); for IPFIX and PSAMP only.
  std::uint32_t sampling_rate = 1;                           ///< One packet of every this many is tracked (-s); 1 tracks every packet.
  int snaplen = 0;                                           ///< The snapshot length (-C); 0 for the default of 96 bytes, or 160 bytes with IPv6.
  std::size_t buffer_bytes = 0;                              ///< The size of the capture buffer (-B); 0 for the size libpcap chooses.
  bool bidirectional_ipfix = false;                          ///< true for biflow records (-b).
  int mpls_labels = 0;                                       ///< The number of MPLS labels in a record (-x); for NetFlow v9 and IPFIX.
  std::optional<int> psamp_receive_port;                     ///< The port to receive PSAMP on (-R), if given.
  bool adjust_pcap_time = false;                             ///< true to use the times of the packets as the current time (-a).
  std::chrono::seconds boot_time_reinit{0};                  ///< The interval at which the boot time is reset (-I); 0 for never.
  bool gauge_clock = false;                                  ///< true to report the time that the export takes (-g).
  bool full_l4hdr_check = false;                             ///< true to check the size of the whole transport header (-f).
  bool multithread = false;                                  ///< true to export on another thread (-M).
  std::optional<std::array<std::uint8_t, 6>> direction_mac;  ///< The Ethernet address that decides flowDirection (-H), if given.

  std::string bpf_filter;  ///< The BPF expression at the end of the command line.

  // --- This project's own additions (not part of the original grammar) ---
  softflowd_cpp::FlowLookup flow_lookup = softflowd_cpp::FlowLookup::HashTree;  ///< How flows are looked up (-F).
  std::string export_out;                                                       ///< The file to write the export packets to (--export-out), if given.
  std::optional<std::chrono::seconds> max_runtime;                              ///< The time after which softflowd stops (--max-runtime), if given.
};

// An error of the start of the daemon that is reported as it is, as the
// original prints it before it exits.
class StartupError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

/**
 * @brief The default port of -R: 4739.
 *
 * @original IPFIX_PORT of ipfix.h, the default port of -R.
 */
constexpr int kDefaultIpfixPort = 4739;

[[noreturn]] void
die_usage (const char *fmt, ...)
  __attribute__ ((format (printf, 1, 2)));

long
convtime (const char *s);

void
set_timeout (DaemonConfig &config, const char *to_spec);

std::optional<softflowd_cpp::TrackLevel>
parse_track_level (const char *s);

std::optional<ExportFormat>
parse_netflow_version (const char *s);

std::optional<TransportProtocol>
parse_transport_protocol (const char *s);

std::optional<TimeFormat>
parse_time_format (const char *s);

std::vector<std::pair<std::string, std::string>>
parse_destinations (const std::string &spec);

bool
should_track_ipv6 (const DaemonConfig &config);

bool
parse_mac_address (const char *str, std::array<std::uint8_t, 6> &mac);

void
print_usage ();

}  // namespace softflowd_cpp

#endif  // SOFTFLOWD_CPP_OPTIONS_HPP
