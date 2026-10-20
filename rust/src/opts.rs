use clap::Parser;

/// Traffic flow monitoring daemon rewritten in Rust.
///
/// softflowd is a flow-based network traffic monitor. It listens on a network
/// interface or reads packet captures, tracks active network flows semi-statefully,
/// and exports them using NetFlow/IPFIX protocols.
#[derive(Parser, Debug)]
#[command(
    name = "rsoftflowd",
    version = "0.1.0",
    about = "Traffic flow monitoring daemon rewritten in Rust",
    long_about = "rsoftflowd is a software implementation of a flow-based network traffic monitor.\n\
                  It reads network traffic and gathers information about active traffic flows. \n\
                  A 'traffic flow' is communication between two IP addresses or (if the \n\
                  overlying protocol is TCP or UDP) address/port tuples."
)]
pub struct RsoftflowdArgs {
    /// Specify interface to listen on ([idx:]interface)
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
    #[arg(short = 'd', long = "foreground", help = "Don't daemonise (run in foreground)")]
    pub dont_fork: bool,

    /// Debug mode: foreground + verbosity + track v6 flows
    #[arg(short = 'D', long = "debug", help = "Debug mode: foreground + verbosity + track v6 flows")]
    pub debug: bool,

    /// NetFlow export packet version (1|5|9|10|psamp)
    #[arg(
        short = 'v',
        long = "netflow-version",
        value_name = "version",
        default_value = "5",
        value_parser = ["1", "5", "9", "10", "psamp"],
        help = "NetFlow export packet version (1|5|9|10|psamp)"
    )]
    pub netflow_version: String,

    /// Send Cisco NetFlow(tm)-compatible packets to host:port
    #[arg(
        short = 'n',
        long = "netflow-dest",
        value_name = "host:port",
        help = "Send Cisco NetFlow(tm)-compatible packets to host:port"
    )]
    pub collector: Option<String>,

    /// Set TTL/hoplimit for export datagrams
    #[arg(short = 'L', long = "hoplimit", value_name = "hoplimit", help = "Set TTL/hoplimit for export datagrams")]
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
    #[arg(short = 'C', long = "snaplen", value_name = "capture_length", help = "Specify length for packet capture (snaplen)")]
    pub capture_length: Option<u32>,

    /// Specify send interface name (Linux only)
    #[arg(short = 'S', long = "send-interface", value_name = "send_interface_name", help = "Specify send interface name (Linux only)")]
    pub send_interface: Option<String>,

    /// Specify Exporter IP (IPv4 or IPv6) address
    #[arg(short = 'e', long = "exporter-ip", value_name = "address", help = "Specify Exporter IP (IPv4 or IPv6) address")]
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
    #[arg(short = 'l', long = "load-balance", help = "Load balancing mode for multiple destinations")]
    pub load_balance: bool,

    /// Track IPv6 flows, regardless of whether selected NetFlow export protocol supports it
    #[arg(short = '6', long = "track-ipv6", help = "Track IPv6 flows, regardless of whether selected NetFlow export protocol supports it")]
    pub always_v6: bool,

    /// Specify MAC Address to determine direction (requires -T ether)
    #[arg(short = 'H', long = "direction-mac", value_name = "MAC", help = "Specify MAC Address to determine direction (requires -T ether)")]
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
    #[arg(short = 'B', long = "pcap-buffer-size", value_name = "bytes", help = "Libpcap buffer size in bytes")]
    pub buffer_size: Option<usize>,

    /// Bidirectional mode in IPFIX (-b work with -v 10)
    #[arg(short = 'b', long = "bidirectional", help = "Bidirectional mode in IPFIX (-b work with -v 10)")]
    pub bidirection: bool,

    /// Specify port number for PSAMP receive mode
    #[arg(short = 'R', long = "psamp-port", value_name = "receive_port", help = "Specify port number for PSAMP receive mode")]
    pub recv_port: Option<u16>,

    /// Enable multithread
    #[arg(short = 'M', long = "multithread", help = "Enable multithread")]
    pub use_thread: bool,

    /// Disable promiscuous mode
    #[arg(short = 'N', long = "no-promisc", help = "Disable promiscuous mode")]
    pub no_promisc: bool,

    /// Specify number of MPLS labels (1 to 10)
    #[arg(short = 'x', long = "mpls-labels", value_name = "labels", help = "Specify number of MPLS labels (1 to 10)")]
    pub max_num_label: Option<u32>,

    /// Specify seconds for reinitialize boot time
    #[arg(short = 'I', long = "reinit-interval", value_name = "seconds", help = "Specify seconds for reinitialize boot time")]
    pub boot_time_reinit: Option<String>,

    /// Gauge cpu clock for benchmark
    #[arg(short = 'g', long = "gauge-cpu-clock", help = "Gauge cpu clock (total and export) for benchmark")]
    pub gauge_clock: bool,

    /// BPF filter expression
    #[arg(value_name = "bpf_program", trailing_var_arg = true, help = "BPF filter expression")]
    pub bpf_expression: Vec<String>,

    /// Adjusting time for reading pcap file (-a work with -r)
    #[arg(short = 'a', long = "adjust-time", help = "Adjusting time for reading pcap file (-a work with -r)")]
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
        let args = RsoftflowctlArgs::try_parse_from(["rsoftflowctl", "-c", "/tmp/test.sock", "statistics"]).unwrap();
        assert_eq!(args.ctlsock, "/tmp/test.sock");
        assert_eq!(args.command, "statistics");
    }
}
