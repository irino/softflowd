use clap::Parser;

/// Traffic flow monitoring daemon rewritten in Rust.
///
/// rsoftflowd is a flow-based network traffic monitor. It listens on a network
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
                  overlying protocol is TCP or UDP) address/port tuples.\n\n\
                  It is a Rust rewrite/port of softflowd."
)]
pub struct RsoftflowdArgs {
    /// Specify a network interface on which to listen
    #[arg(short = 'i', long = "interface", help = "Specify a network interface on which to listen ([idx:]interface)")]
    pub interface: Option<String>,

    /// Specify a pcap packet capture file to read from
    #[arg(short = 'r', long = "read", help = "Specify a pcap packet capture file to read from")]
    pub pcap_file: Option<String>,

    /// Specify PID file location (default: /var/run/softflowd.pid)
    #[arg(short = 'p', long = "pidfile", help = "Specify PID file location (default: /var/run/softflowd.pid)")]
    pub pidfile: Option<String>,

    /// Specify control socket path (default: /var/run/softflowd.ctl)
    #[arg(short = 'c', long = "control-socket", help = "Specify control socket path (default: /var/run/softflowd.ctl)")]
    pub ctlsock: Option<String>,

    /// Specify max flows to track concurrently
    #[arg(short = 'm', long = "max-flows", default_value_t = 8192, help = "Specify max flows to track concurrently")]
    pub max_flows: u32,

    /// Set timeout (timeout_name=time) e.g., tcp=3600
    #[arg(short = 't', long = "timeout", action = clap::ArgAction::Append, help = "Set timeout (timeout_name=time) e.g., tcp=3600")]
    pub timeouts: Vec<String>,

    /// Do not fork and daemonise
    #[arg(short = 'd', long = "foreground", help = "Do not fork and daemonise")]
    pub dont_fork: bool,

    /// Debug mode (implies -d and verbose logging)
    #[arg(short = 'D', long = "debug", help = "Debug mode (implies -d and verbose logging)")]
    pub debug: bool,

    /// Netflow export version (1, 5, 9, 10, psamp)
    #[arg(short = 'v', long = "netflow-version", default_value = "5", help = "Netflow export version (1, 5, 9, 10, psamp)")]
    pub netflow_version: String,

    /// Specify collector address (host:port) or comma-separated list
    #[arg(short = 'n', long = "netflow-dest", help = "Specify collector address (host:port) or comma-separated list")]
    pub collector: Option<String>,

    /// Set the IPv4 TTL or IPv6 Hop Limit
    #[arg(short = 'L', long = "hoplimit", help = "Set the IPv4 TTL or IPv6 Hop Limit")]
    pub hoplimit: Option<i32>,

    /// Specify flow track level (ip, proto, full, vlan, ether)
    #[arg(short = 'T', long = "track", default_value = "full", help = "Specify flow track level (ip, proto, full, vlan, ether)")]
    pub track_level: String,

    /// Transport protocol for exporting (udp, tcp)
    #[arg(short = 'P', long = "export-protocol", default_value = "udp", help = "Transport protocol for exporting (udp, tcp)")]
    pub transport_protocol: String,

    /// Specify periodical sampling rate
    #[arg(short = 's', long = "sampling-rate", default_value_t = 0, help = "Specify periodical sampling rate")]
    pub sampling_rate: u32,

    /// Specify length for packet capture (snaplen)
    #[arg(short = 'C', long = "snaplen", help = "Specify length for packet capture (snaplen)")]
    pub capture_length: Option<u32>,

    /// Specify send interface name (Linux only)
    #[arg(short = 'S', long = "send-interface", help = "Specify send interface name (Linux only)")]
    pub send_interface: Option<String>,

    /// Specify exporter IP address
    #[arg(short = 'e', long = "exporter-ip", help = "Specify exporter IP address")]
    pub exporter_ip: Option<String>,

    /// Require the whole TCP/UDP/ICMP header instead of only the fields used
    #[arg(short = 'f', long = "full-transport-header-check", help = "Require the whole TCP/UDP/ICMP header instead of only the fields used")]
    pub full_transport_header_check: bool,

    /// Flow table lookup: tree, hash-tree (default) or hash
    #[arg(short = 'F', long = "flow-lookup", default_value = "hash-tree", help = "Flow table lookup: tree, hash-tree (default) or hash")]
    pub flow_lookup: String,

    /// Load balancing mode for multiple destinations
    #[arg(short = 'l', long = "load-balance", help = "Load balancing mode for multiple destinations")]
    pub load_balance: bool,

    /// Track IPv6 flows, regardless of NetFlow export protocol support
    #[arg(short = '6', long = "track-ipv6", help = "Track IPv6 flows, regardless of NetFlow export protocol support")]
    pub always_v6: bool,

    /// Specify MAC Address to determine direction (requires -T ether)
    #[arg(short = 'H', long = "direction-mac", help = "Specify MAC Address to determine direction (requires -T ether)")]
    pub direction_mac: Option<String>,

    /// Specify absolute time format for exporting records (sec|milli|micro|nano)
    #[arg(short = 'A', long = "absolute-time", help = "Specify absolute time format for exporting records (sec|milli|micro|nano)")]
    pub time_format: Option<String>,

    /// Libpcap buffer size in bytes
    #[arg(short = 'B', long = "pcap-buffer-size", help = "Libpcap buffer size in bytes")]
    pub buffer_size: Option<usize>,

    /// Bidirectional mode in IPFIX (-b work with -v 10)
    #[arg(short = 'b', long = "bidirectional", help = "Bidirectional mode in IPFIX (-b work with -v 10)")]
    pub bidirection: bool,

    /// Specify port number for PSAMP receive mode
    #[arg(short = 'R', long = "psamp-port", help = "Specify port number for PSAMP receive mode")]
    pub recv_port: Option<u16>,

    /// Enable multithread
    #[arg(short = 'M', long = "multithread", help = "Enable multithread")]
    pub use_thread: bool,

    /// Disable promiscuous mode
    #[arg(short = 'N', long = "no-promisc", help = "Disable promiscuous mode")]
    pub no_promisc: bool,

    /// Specify number of MPLS labels
    #[arg(short = 'x', long = "mpls-labels", help = "Specify number of MPLS labels")]
    pub max_num_label: Option<u32>,

    /// Specify seconds for reinitialize boot time
    #[arg(short = 'I', long = "reinit-interval", help = "Specify seconds for reinitialize boot time")]
    pub boot_time_reinit: Option<String>,

    /// Gauge cpu clock for benchmark
    #[arg(short = 'g', long = "gauge-cpu-clock", help = "Gauge cpu clock for benchmark")]
    pub gauge_clock: bool,

    /// BPF filter expression
    #[arg(trailing_var_arg = true, help = "BPF filter expression")]
    pub bpf_expression: Vec<String>,

    /// Adjust time to packet time
    #[arg(short = 'a', long = "adjust-time", help = "Adjust time to packet time")]
    pub adjust_time: bool,
}

/// Control rsoftflowd daemon rewritten in Rust.
///
/// rsoftflowctl is a remote control program used to control a running
/// rsoftflowd daemon via a Unix domain socket.
#[derive(Parser, Debug)]
#[command(
    name = "rsoftflowctl",
    version = "0.1.0",
    about = "Control rsoftflowd daemon rewritten in Rust",
    long_about = "rsoftflowctl is a remote control program used to control a running rsoftflowd daemon."
)]
pub struct RsoftflowctlArgs {
    /// Specify control socket path
    #[arg(short = 'c', long = "control-socket", default_value = "/var/run/softflowd.ctl", help = "Specify control socket path")]
    pub ctlsock: String,

    /// The command to send to softflowd (e.g. statistics, dump-flows, shutdown, expire-all)
    #[arg(help = "The command to send to softflowd (e.g. statistics, dump-flows, shutdown, expire-all)")]
    pub command: String,
}
