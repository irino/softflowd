#![allow(dead_code)]

use clap::Parser;

use crate::common::FlowTracker;

/// The value of `-B`: a decimal number of bytes, and not more than C can hold in an int (C reads
/// it with `parse_int_arg()` between 0 and INT_MAX).
fn parse_pcap_buffer_size(value: &str) -> Result<usize, String> {
    let size: usize = value.parse().map_err(|e| format!("{e}"))?;
    if size > i32::MAX as usize {
        return Err(format!("{size} is more than {}", i32::MAX));
    }
    Ok(size)
}

/// Traffic flow monitoring daemon rewritten in Rust.
///
/// softflowd is a flow-based network traffic monitor. It listens on a network
/// interface or reads packet captures, tracks active network flows semi-statefully,
/// and exports them using NetFlow/IPFIX protocols.
#[derive(Parser, Debug)]
#[command(
    name = "rsoftflowd",
    infer_long_args = true,
    version = "0.1.0",
    about = "Traffic flow monitoring daemon rewritten in Rust",
    long_about = "rsoftflowd is a software implementation of a flow-based network traffic monitor.\n\
                  It reads network traffic and gathers information about active traffic flows. \n\
                  A 'traffic flow' is communication between two IP addresses or (if the \n\
                  overlying protocol is TCP or UDP) address/port tuples."
)]
pub struct RsoftflowdArgs {
    /// Specify interface to listen on (\[idx:\]interface)
    #[arg(
        short = 'i',
        long = "interface",
        value_name = "[idx:]interface",
        conflicts_with = "pcap_file",
        help = "Specify interface to listen on ([idx:]interface)"
    )]
    pub interface: Option<String>,

    /// Specify packet capture file to read
    #[arg(
        short = 'r',
        long = "read",
        value_name = "pcap_file",
        conflicts_with = "interface",
        help = "Specify packet capture file to read"
    )]
    pub pcap_file: Option<String>,

    /// Record pid in specified file (default: /var/run/softflowd.pid)
    #[arg(
        short = 'p',
        long = "pidfile",
        value_name = "pidfile",
        help = "Record pid in specified file (default: /var/run/softflowd.pid)"
    )]
    pub pidfile: Option<String>,

    /// Location of control socket (default: /var/run/softflowd.ctl)
    #[arg(
        short = 'c',
        long = "control-socket",
        value_name = "socketfile",
        help = "Location of control socket (default: /var/run/softflowd.ctl)"
    )]
    pub ctlsock: Option<String>,

    /// Specify maximum number of flows to track (1 or more, default 8192)
    #[arg(
        short = 'm',
        long = "max-flows",
        value_name = "max_flows",
        default_value_t = 8192,
        help = "Specify maximum number of flows to track (1 or more, default 8192)"
    )]
    pub max_flows: u32,

    /// Specify named timeout (timeout=time) e.g., tcp=3600
    #[arg(
        short = 't',
        long = "timeout",
        value_name = "timeout=time",
        action = clap::ArgAction::Append,
        help = "Specify named timeout (timeout=time)"
    )]
    pub timeouts: Vec<String>,

    /// Don't daemonise (run in foreground)
    #[arg(
        short = 'd',
        long = "foreground",
        help = "Don't daemonise (run in foreground)"
    )]
    pub dont_fork: bool,

    /// Debug mode: foreground + verbosity + track v6 flows
    #[arg(
        short = 'D',
        long = "debug",
        help = "Debug mode: foreground + verbosity + track v6 flows"
    )]
    pub debug: bool,

    /// NetFlow export packet version (1|5|9|10|psamp)
    #[arg(
        short = 'v',
        long = "netflow-version",
        value_name = "version",
        default_value = "5",
        value_parser = clap::builder::PossibleValuesParser::new([
            "1", "5", "9", "10", "psamp",
            #[cfg(feature = "ntopng")]
            "ntopng",
        ]),
        help = if cfg!(feature = "ntopng") {
            "NetFlow export packet version (1|5|9|10|psamp|ntopng)"
        } else {
            "NetFlow export packet version (1|5|9|10|psamp)"
        }
    )]
    pub netflow_version: String,

    /// Send Cisco NetFlow(tm)-compatible packets to host:port
    #[arg(
        short = 'n',
        long = "netflow-dest",
        value_name = "host:port",
        overrides_with = "collector",
        help = "Send Cisco NetFlow(tm)-compatible packets to host:port"
    )]
    pub collector: Option<String>,

    /// Set TTL/hoplimit for export datagrams
    #[arg(
        short = 'L',
        long = "hoplimit",
        value_name = "hoplimit",
        help = "Set TTL/hoplimit for export datagrams"
    )]
    pub hoplimit: Option<i32>,

    /// Set flow tracking level (default: full)
    #[arg(
        short = 'T',
        long = "track",
        value_name = "level",
        default_value = "full",
        value_parser = ["full", "port", "proto", "ip", "vlan", "ether"],
        help = "Set flow tracking level (default: full)"
    )]
    pub track_level: String,

    /// Specify transport layer protocol for exporting packets (udp|tcp|sctp)
    #[arg(
        short = 'P',
        long = "export-protocol",
        value_name = "protocol",
        default_value = "udp",
        value_parser = ["udp", "tcp", "sctp"],
        help = "Specify transport layer protocol for exporting packets"
    )]
    pub transport_protocol: String,

    /// Specify periodical sampling rate (denominator)
    #[arg(
        short = 's',
        long = "sampling-rate",
        value_name = "rate",
        default_value_t = 0,
        help = "Specify periodical sampling rate (denominator)"
    )]
    pub sampling_rate: u32,

    /// Specify length for packet capture (snaplen)
    #[arg(
        short = 'C',
        long = "snaplen",
        value_name = "capture_length",
        // C keeps it in an int.
        value_parser = clap::value_parser!(u32).range(..=i32::MAX as i64),
        help = "Specify length for packet capture (snaplen)"
    )]
    pub capture_length: Option<u32>,

    /// Specify send interface name (Linux only)
    #[arg(
        short = 'S',
        long = "send-interface",
        value_name = "send_interface_name",
        help = "Specify send interface name (Linux only)"
    )]
    pub send_interface: Option<String>,

    /// Specify Exporter IP (IPv4 or IPv6) address
    #[arg(
        short = 'e',
        long = "exporter-ip",
        value_name = "address",
        help = "Specify Exporter IP (IPv4 or IPv6) address"
    )]
    pub exporter_ip: Option<String>,

    /// Require the whole TCP/UDP/ICMP header instead of only the fields used
    #[arg(
        short = 'f',
        long = "full-transport-header-check",
        help = "Require the whole TCP/UDP/ICMP header instead of only the fields used (ports, TCP flags, ICMP type/code)"
    )]
    pub full_transport_header_check: bool,

    /// Flow table lookup: tree, hash-tree (default) or hash
    #[arg(
        short = 'F',
        long = "flow-lookup",
        value_name = "mode",
        default_value = "hash-tree",
        value_parser = ["tree", "hash-tree", "hash"],
        help = "Flow table lookup: tree, hash-tree (default) or hash"
    )]
    pub flow_lookup: String,

    /// Load balancing mode for multiple destinations
    #[arg(
        short = 'l',
        long = "load-balance",
        help = "Load balancing mode for multiple destinations"
    )]
    pub load_balance: bool,

    /// Track IPv6 flows, regardless of whether selected NetFlow export protocol supports it
    #[arg(
        short = '6',
        long = "track-ipv6",
        help = "Track IPv6 flows, regardless of whether selected NetFlow export protocol supports it"
    )]
    pub always_v6: bool,

    /// Specify MAC Address to determine direction (requires -T ether)
    #[arg(
        short = 'H',
        long = "direction-mac",
        value_name = "MAC",
        help = "Specify MAC Address to determine direction (requires -T ether)"
    )]
    pub direction_mac: Option<String>,

    /// Specify absolute time format for exporting records (sec|milli|micro|nano)
    #[arg(
        short = 'A',
        long = "absolute-time",
        value_name = "format",
        value_parser = ["sec", "milli", "micro", "nano"],
        help = "Specify absolute time format for exporting records"
    )]
    pub time_format: Option<String>,

    /// Libpcap buffer size in bytes
    #[arg(
        short = 'B',
        long = "pcap-buffer-size",
        value_name = "bytes",
        value_parser = parse_pcap_buffer_size,
        help = "Libpcap buffer size in bytes"
    )]
    pub buffer_size: Option<usize>,

    /// Bidirectional mode in IPFIX (-b work with -v 10)
    #[arg(
        short = 'b',
        long = "bidirectional",
        help = "Bidirectional mode in IPFIX (-b work with -v 10)"
    )]
    pub bidirection: bool,

    /// Specify port number for PSAMP receive mode
    #[arg(
        short = 'R',
        long = "psamp-port",
        value_name = "receive_port",
        help = "Specify port number for PSAMP receive mode"
    )]
    pub recv_port: Option<u16>,

    /// Enable multithread
    #[arg(short = 'M', long = "multithread", help = "Enable multithread")]
    pub use_thread: bool,

    /// Disable promiscuous mode
    #[arg(short = 'N', long = "no-promisc", help = "Disable promiscuous mode")]
    pub no_promisc: bool,

    /// Specify number of MPLS labels (1 to 10)
    #[arg(
        short = 'x',
        long = "mpls-labels",
        value_name = "labels",
        help = "Specify number of MPLS labels (1 to 10)"
    )]
    pub max_num_label: Option<u32>,

    /// Specify seconds for reinitialize boot time
    #[arg(
        short = 'I',
        long = "reinit-interval",
        value_name = "seconds",
        help = "Specify seconds for reinitialize boot time"
    )]
    pub boot_time_reinit: Option<String>,

    /// Gauge cpu clock for benchmark
    #[arg(
        short = 'g',
        long = "gauge-cpu-clock",
        help = "Gauge cpu clock (total and export) for benchmark"
    )]
    pub gauge_clock: bool,

    /// BPF filter expression
    #[arg(value_name = "bpf_program", help = "BPF filter expression")]
    pub bpf_expression: Vec<String>,

    /// Adjusting time for reading pcap file (-a work with -r)
    #[arg(
        short = 'a',
        long = "adjust-time",
        help = "Adjusting time for reading pcap file (-a work with -r)"
    )]
    pub adjust_time: bool,
}

/// Control softflowd daemon.
///
/// softflowctl is a remote control program used to control a running
/// softflowd daemon via a Unix domain socket.
#[derive(Parser, Debug)]
#[command(
    name = "rsoftflowctl",
    version = "0.1.0",
    about = "Control rsoftflowd daemon",
    long_about = "rsoftflowctl is a remote control program used to control a running rsoftflowd daemon via a Unix domain socket."
)]
pub struct RsoftflowctlArgs {
    /// Specify control socket path (default: /var/run/softflowd.ctl)
    #[arg(
        short = 'c',
        long = "control-socket",
        value_name = "ctlsock",
        default_value = "/var/run/softflowd.ctl",
        help = "Specify control socket path (default: /var/run/softflowd.ctl)"
    )]
    pub ctlsock: String,

    /// The command to send to softflowd (e.g. statistics, dump-flows, shutdown, expire-all)
    #[arg(
        value_name = "command",
        help = "The command to send to softflowd (e.g. statistics, dump-flows, shutdown, expire-all)"
    )]
    pub command: String,
}

/// Parse the command line like `Parser::parse()`, but exit with status 1 for a
/// command line that is wrong, as the C version does (clap exits with 2).  Help
/// and version are written to standard output and end with status 0.
///
/// Original: softflowd.c / softflowctl.c, usage() and exit (1)
pub fn parse_args_or_exit<T: Parser>() -> T {
    match T::try_parse() {
        Ok(args) => args,
        Err(e) => {
            let status = if e.use_stderr() { 1 } else { 0 };
            let _ = e.print();
            std::process::exit(status);
        }
    }
}

pub fn parse_interface_spec(s: &str) -> (u16, String) {
    if let Some((idx_str, name)) = s.split_once(':') {
        if !idx_str.is_empty()
            && let Ok(idx) = idx_str.parse::<u16>()
        {
            return (idx, name.to_string());
        }
        return (0, name.to_string());
    }
    (0, s.to_string())
}

/// Parse a time such as `90`, `5m` or `1h30m` into seconds.
///
/// Original: `convtime()` in `convtime.c`.  A time that does not fit in an
/// `i32` is an error, as in `set_timeout()` of the C version.  A sign and
/// white space, which `strtol()` accepts there, are not accepted here.
pub fn parse_duration(s: &str) -> Option<i32> {
    if s.is_empty() {
        return None;
    }
    let mut total: i64 = 0;
    let mut rest = s;
    while !rest.is_empty() {
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        let secs: i64 = rest[..digits].parse().ok()?;
        rest = &rest[digits..];
        let mult: i64 = match rest.bytes().next() {
            None => 1,
            Some(b's' | b'S') => 1,
            Some(b'm' | b'M') => 60,
            Some(b'h' | b'H') => 3600,
            Some(b'd' | b'D') => 3600 * 24,
            Some(b'w' | b'W') => 3600 * 24 * 7,
            Some(_) => return None,
        };
        rest = rest.get(1..).unwrap_or("");
        total = total.checked_add(secs.checked_mul(mult)?)?;
        if total > i64::from(i32::MAX) {
            return None;
        }
    }
    i32::try_from(total).ok()
}

/// Parse a MAC address: exactly `aa:bb:cc:dd:ee:ff`, six groups of one or two
/// hexadecimal digits separated by colons.
///
/// Original: `parse_mac_address()` in `options.c`.  Nothing else is accepted: no
/// other separator, no sign, no white space, no group of three digits and no
/// seventh group.
pub fn parse_mac_address(mac_str: &str) -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut parts = mac_str.split(':');
    for byte in mac.iter_mut() {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        *byte = u8::from_str_radix(part, 16).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(mac)
}

const BOOTTIME_MAX_DAY: u64 = 49;
const BOOTTIME_MAX_HOUR: u64 = 1193;
const BOOTTIME_MAX_MIN: u64 = 71582;
const BOOTTIME_MAX_SEC: u64 = 4294944;

pub fn parse_boot_time_reinit(s: &str) -> Result<u64, &'static str> {
    const NO_DIGITS: &str = "No digits were found in boot_time_reinit";
    const OUT_OF_RANGE: &str = "strtol: Numerical result out of range";
    // C reads the number and does not look at what follows it; this version does.
    const BAD_UNIT: &str = "Invalid unit in boot_time_reinit (d, h, m or s)";
    if s.is_empty() {
        return Err(NO_DIGITS);
    }
    let digits_len = s.bytes().take_while(u8::is_ascii_digit).count();
    if digits_len == 0 {
        return Err(NO_DIGITS);
    }
    let num_str = &s[..digits_len];
    // C: strtol(), a number that does not fit a long is out of range.
    let mut val = num_str.parse::<i64>().map_err(|_| OUT_OF_RANGE)? as u64;
    let rest = &s[digits_len..];
    let unit = if rest.is_empty() {
        's'
    } else if rest.len() == 1 {
        let c = rest.chars().next().unwrap_or(' ').to_ascii_lowercase();
        match c {
            'd' | 'h' | 'm' | 's' => c,
            _ => return Err(BAD_UNIT),
        }
    } else {
        return Err(BAD_UNIT);
    };

    match unit {
        'd' => {
            if val > BOOTTIME_MAX_DAY {
                val = BOOTTIME_MAX_DAY;
            }
            val = val.checked_mul(24 * 60 * 60).ok_or(OUT_OF_RANGE)?;
        }
        'h' => {
            if val > BOOTTIME_MAX_HOUR {
                val = BOOTTIME_MAX_HOUR;
            }
            val = val.checked_mul(60 * 60).ok_or(OUT_OF_RANGE)?;
        }
        'm' => {
            if val > BOOTTIME_MAX_MIN {
                val = BOOTTIME_MAX_MIN;
            }
            val = val.checked_mul(60).ok_or(OUT_OF_RANGE)?;
        }
        _ => {
            if val > BOOTTIME_MAX_SEC {
                val = BOOTTIME_MAX_SEC;
            }
        }
    }
    Ok(val)
}

/// Apply the `-t name=time` options.
///
/// Original: `set_timeout()` in `softflowd.c`.  On a wrong option it returns
/// the message, and the caller prints it and exits with 1.
pub fn apply_timeouts(tracker: &mut FlowTracker, timeout_specs: &[String]) -> Result<(), String> {
    for spec in timeout_specs {
        let (name, value) = match spec.split_once('=') {
            Some((name, value)) if !value.is_empty() => (name, value),
            _ => return Err(format!("Invalid -t option \"{}\".", spec)),
        };
        let val = parse_duration(value).ok_or_else(|| "Invalid -t timeout.".to_string())?;
        match name {
            "tcp" => tracker.param.tcp_timeout = val,
            "tcp.rst" => tracker.param.tcp_rst_timeout = val,
            "tcp.fin" => tracker.param.tcp_fin_timeout = val,
            "udp" => tracker.param.udp_timeout = val,
            "icmp" => tracker.param.icmp_timeout = val,
            "general" => tracker.param.general_timeout = val,
            "maxlife" => tracker.param.maximum_lifetime = val,
            "expint" => tracker.param.expiry_interval = val,
            _ => return Err("Invalid -t name.".to_string()),
        }
        if tracker.param.general_timeout == 0 {
            return Err("\"general\" flow timeout must be greater than zero".to_string());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opts_parsing_defaults() {
        let args = RsoftflowdArgs::try_parse_from(["rsoftflowd", "-i", "eth0"]).unwrap();
        assert_eq!(args.interface, Some("eth0".to_string()));
        assert_eq!(args.max_flows, 8192);
        assert_eq!(args.flow_lookup, "hash-tree");
        assert_eq!(args.netflow_version, "5");
        assert_eq!(args.track_level, "full");
        assert!(!args.full_transport_header_check);
    }

    #[test]
    fn test_opts_parsing_custom_flags() {
        let args = RsoftflowdArgs::try_parse_from([
            "rsoftflowd",
            "-i",
            "3:eth0",
            "-f",
            "-F",
            "hash",
            "-v",
            "psamp",
            "-m",
            "1000",
            "-d",
            "-6",
        ])
        .unwrap();
        assert_eq!(args.interface, Some("3:eth0".to_string()));
        assert!(args.full_transport_header_check);
        assert_eq!(args.flow_lookup, "hash");
        assert_eq!(args.netflow_version, "psamp");
        assert_eq!(args.max_flows, 1000);
        assert!(args.dont_fork);
        assert!(args.always_v6);
    }

    #[test]
    fn test_opts_invalid_flow_lookup() {
        let res = RsoftflowdArgs::try_parse_from(["softflowd", "-i", "eth0", "-F", "invalid"]);
        assert!(res.is_err());
    }

    #[test]
    fn test_opts_invalid_netflow_version() {
        let res = RsoftflowdArgs::try_parse_from(["rsoftflowd", "-i", "eth0", "-v", "99"]);
        assert!(res.is_err());
    }

    #[test]
    fn test_softflowctl_args() {
        let args = RsoftflowctlArgs::try_parse_from([
            "rsoftflowctl",
            "-c",
            "/tmp/test.sock",
            "statistics",
        ])
        .unwrap();
        assert_eq!(args.ctlsock, "/tmp/test.sock");
        assert_eq!(args.command, "statistics");
    }

    #[test]
    fn test_parse_boot_time_reinit() {
        assert_eq!(parse_boot_time_reinit("10"), Ok(10));
        assert_eq!(parse_boot_time_reinit("2h"), Ok(7200));
        assert_eq!(parse_boot_time_reinit("50d"), Ok(4233600));
        // The messages are those of C (D26): no digits, a number that does not fit a long.
        assert_eq!(
            parse_boot_time_reinit("abc"),
            Err("No digits were found in boot_time_reinit")
        );
        assert!(parse_boot_time_reinit("1x2").is_err());
        assert_eq!(
            parse_boot_time_reinit("99999999999999999999"),
            Err("strtol: Numerical result out of range")
        );
    }

    #[test]
    fn parse_duration_follows_convtime() {
        assert_eq!(parse_duration("90"), Some(90));
        assert_eq!(parse_duration("5m"), Some(300));
        assert_eq!(parse_duration("1h30m"), Some(5400));
        assert_eq!(parse_duration("1W"), Some(604800));
        assert_eq!(parse_duration("5s5"), Some(10));
        // The largest time that fits in an i32 (24855 days is 2147472000 s).
        assert_eq!(parse_duration("2147483647"), Some(i32::MAX));
        assert_eq!(parse_duration("24855d"), Some(2147472000));
        assert_eq!(parse_duration(""), None);
        assert_eq!(parse_duration("abc"), None);
        assert_eq!(parse_duration("-1"), None);
        assert_eq!(parse_duration("5x"), None);
        assert_eq!(parse_duration("m"), None);
        assert_eq!(parse_duration("2147483648"), None);
        assert_eq!(parse_duration("24856d"), None);
        assert_eq!(parse_duration("99999999999"), None);
        assert_eq!(parse_duration("99999999999999999999999"), None);
    }

    fn timeouts(specs: &[&str]) -> Result<(), String> {
        let mut tracker = FlowTracker::new(8192);
        let specs: Vec<String> = specs.iter().map(|s| s.to_string()).collect();
        apply_timeouts(&mut tracker, &specs)
    }

    #[test]
    fn apply_timeouts_rejects_what_the_c_version_rejects() {
        assert_eq!(timeouts(&["tcp=1h", "udp=30", "maxlife=2d"]), Ok(()));
        for bad in [
            "tcp",
            "tcp=",
            "tcp=xyz",
            "udp=abc",
            "udp=",
            "udp=-1",
            "bogus=1",
            "expint=abc",
            "maxlife=99999999999",
            "general=0",
        ] {
            assert!(timeouts(&[bad]).is_err(), "{bad} was accepted");
        }
        // The names are case sensitive, as in the C version.
        assert!(timeouts(&["TCP=5"]).is_err());
    }

    // The tests below were written from what ./softflowd (C) does with the same input.
    // The cases where the Rust version differs from C are not here; they are reported.

    #[test]
    fn parse_interface_spec_is_strict_like_c() {
        // C: `./softflowd -D -i SPEC -n 127.0.0.1:9` prints "Using NAME (idx: N)".
        for (spec, idx, name) in [
            ("3:lo", 3, "lo"),         // Using lo (idx: 3)
            ("lo", 0, "lo"),           // Using lo (idx: 0)
            (":lo", 0, "lo"),          // Using lo (idx: 0)
            ("abc:lo", 0, "lo"),       // Using lo (idx: 0), atoi("abc") is 0
            ("65535:lo", 65535, "lo"), // Using lo (idx: 65535)
            ("65536:lo", 0, "lo"),     // Using lo (idx: 0), 65536 does not fit 16 bits
            ("+3:lo", 3, "lo"),        // Using lo (idx: 3)
            ("0:lo", 0, "lo"),         // Using lo (idx: 0)
            ("007:lo", 7, "lo"),       // Using lo (idx: 7)
            ("1:2:lo", 1, "2:lo"),     // Using 2:lo (idx: 1), only the first colon splits
            // Not a decimal number of 0 to 65535 (an optional '+' is the only sign): no index.
            ("70000:lo", 0, "lo"),                   // Using lo (idx: 0)
            ("99999999999:lo", 0, "lo"),             // Using lo (idx: 0)
            ("-1:lo", 0, "lo"),                      // Using lo (idx: 0)
            ("3x:lo", 0, "lo"),                      // Using lo (idx: 0)
            (" 3:lo", 0, "lo"),                      // Using lo (idx: 0)
            ("+:lo", 0, "lo"),                       // Using lo (idx: 0)
            ("00000000000000000000007:lo", 7, "lo"), // Using lo (idx: 7)
        ] {
            assert_eq!(
                parse_interface_spec(spec),
                (idx, name.to_string()),
                "{spec:?}"
            );
        }
        // C: "Wrong interface is specified." for "3:" and for ""; here the name is empty and
        // the caller in rsoftflowd.rs makes that error.
        assert_eq!(parse_interface_spec("3:").1, "");
        assert_eq!(parse_interface_spec("").1, "");
    }

    #[test]
    fn parse_mac_address_is_strict_like_c() {
        // C: `./softflowd -r FILE -H MAC` runs, or prints "Invalid MAC address MAC" and exits
        // with status 1; both versions accept only six groups of one or two hex digits with ":".
        let mac = |s: &str| parse_mac_address(s);
        assert_eq!(mac("02:00:00:00:00:01"), Some([0x02, 0, 0, 0, 0, 0x01]));
        assert_eq!(
            mac("AA:BB:CC:DD:EE:FF"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(
            mac("aa:Bb:cC:dD:eE:Ff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(mac("00:00:00:00:00:00"), Some([0; 6]));
        assert_eq!(mac("ff:ff:ff:ff:ff:ff"), Some([0xff; 6]));
        // One digit is enough.
        assert_eq!(mac("1:2:3:4:5:6"), Some([1, 2, 3, 4, 5, 6]));
        assert_eq!(mac("02:00:00:00:00:0"), Some([2, 0, 0, 0, 0, 0]));
        for bad in [
            "02-00-00-00-00-01", // only ":" separates
            "1-2-3-4-5-6",
            "aa:bb-cc:dd-ee:ff",
            "aa:bb:cc:dd:ee",       // five groups
            "aa:bb:cc:dd:ee:ff:00", // a seventh group
            "aa:bb:cc:dd:ee:ff:gg",
            "aa:bb:cc:dd:ee:ff-",
            "aa:bb:cc:dd:ee:ff:",
            "aa:bb:cc:dd:ee:ff ", // white space
            " 2:00:00:00:00:01",
            "002:00:00:00:00:01", // three digits
            "0x2:00:00:00:00:01",
            "+2:00:00:00:00:01", // a sign
            "-2:00:00:00:00:01",
            "02:00:00:00:00:",
            ":00:00:00:00:01",
            "::::::",
            "g2:00:00:00:00:01",
            "02.00.00.00.00.01",
            "020000000001",
            "",
        ] {
            assert_eq!(mac(bad), None, "{bad:?} was accepted");
        }
    }

    #[test]
    fn parse_duration_follows_convtime_more() {
        // C: convtime() of convtime.c, with the range of set_timeout() (0 to INT_MAX);
        // `./softflowd -r FILE -t udp=VALUE` accepts and rejects the same values.
        for (s, secs) in [
            ("0", 0),
            ("00", 0),
            ("007", 7),
            ("5M", 300),
            ("5S", 5),
            ("5H", 18000),
            ("5D", 432000),
            ("5w", 3024000),
            ("1h30", 3630), // a number without a unit at the end is seconds
            ("1h1h", 7200), // a unit can repeat
            ("1m2", 62),
            ("5m5s5", 310),
        ] {
            assert_eq!(parse_duration(s), Some(secs), "{s:?}");
        }
        for bad in [
            "5 ", "5m ", "1.5h", "1,5", "0x10", "1d-1", "1e3", "5mm", "5ms", "s",
        ] {
            assert_eq!(parse_duration(bad), None, "{bad:?} was accepted");
        }
    }

    #[test]
    fn apply_timeouts_messages_and_values_follow_c() {
        // C: set_timeout() of options.c; the message is the first line that
        // `./softflowd -r FILE -t SPEC` prints before it exits with status 1.
        let err = |specs: &[&str]| timeouts(specs).unwrap_err();
        assert_eq!(err(&["tcp"]), "Invalid -t option \"tcp\".");
        assert_eq!(err(&["tcp="]), "Invalid -t option \"tcp=\".");
        assert_eq!(err(&["=5"]), "Invalid -t name.");
        assert_eq!(err(&["tcp.rst2=1"]), "Invalid -t name.");
        assert_eq!(err(&["bogus=1"]), "Invalid -t name.");
        assert_eq!(err(&["TCP=5"]), "Invalid -t name.");
        // The value is checked before the name.
        assert_eq!(err(&["bogus=abc"]), "Invalid -t timeout.");
        assert_eq!(err(&["tcp=5=6"]), "Invalid -t timeout.");
        assert_eq!(err(&["udp=-1"]), "Invalid -t timeout.");
        assert_eq!(err(&["udp=abc"]), "Invalid -t timeout.");
        let general = "\"general\" flow timeout must be greater than zero";
        assert_eq!(err(&["general=0"]), general);
        // It is checked after every option, so a later one cannot repair it.
        assert_eq!(err(&["general=0", "general=5"]), general);
        assert_eq!(err(&["udp=5", "general=0"]), general);
        // Zero is fine for the others, and every name has its own field.
        assert_eq!(timeouts(&["udp=0", "general=1d"]), Ok(()));

        // C: `softflowctl timeouts` of `softflowd -d -i lo -t tcp=11 -t tcp.rst=12 ...`
        // prints 11s, 12s, 13s, 14s, 15s, 60s (general=1m), 7200s (maxlife=2h), 18s.
        let mut tracker = FlowTracker::new(8192);
        let specs: Vec<String> = [
            "tcp=11",
            "tcp.rst=12",
            "tcp.fin=13",
            "udp=14",
            "icmp=15",
            "general=1m",
            "maxlife=2h",
            "expint=18",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        apply_timeouts(&mut tracker, &specs).unwrap();
        let p = &tracker.param;
        assert_eq!(
            [
                p.tcp_timeout,
                p.tcp_rst_timeout,
                p.tcp_fin_timeout,
                p.udp_timeout,
                p.icmp_timeout,
                p.general_timeout,
                p.maximum_lifetime,
                p.expiry_interval
            ],
            [11, 12, 13, 14, 15, 60, 7200, 18]
        );
    }
}
