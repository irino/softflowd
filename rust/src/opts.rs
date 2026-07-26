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
    #[arg(short = 'i', help = "Specify a network interface on which to listen")]
    pub interface: Option<String>,

    /// Specify a pcap packet capture file to read from
    #[arg(short = 'r', help = "Specify a pcap packet capture file to read from")]
    pub pcap_file: Option<String>,

    /// Specify PID file location (default: /var/run/softflowd.pid)
    #[arg(short = 'p', help = "Specify PID file location (default: /var/run/softflowd.pid)")]
    pub pidfile: Option<String>,

    /// Specify control socket path (default: /var/run/softflowd.ctl)
    #[arg(short = 'c', help = "Specify control socket path (default: /var/run/softflowd.ctl)")]
    pub ctlsock: Option<String>,

    /// Specify max flows to track concurrently
    #[arg(short = 'm', default_value_t = 8192, help = "Specify max flows to track concurrently")]
    pub max_flows: u32,

    /// Set timeout (timeout_name=time) e.g., tcp=3600
    #[arg(short = 't', action = clap::ArgAction::Append, help = "Set timeout (timeout_name=time) e.g., tcp=3600")]
    pub timeouts: Vec<String>,

    /// Do not fork and daemonise
    #[arg(short = 'd', help = "Do not fork and daemonise")]
    pub dont_fork: bool,

    /// Debug mode (implies -d and verbose logging)
    #[arg(short = 'D', help = "Debug mode (implies -d and verbose logging)")]
    pub debug: bool,

    /// Netflow export version (1, 5, 9, 10)
    #[arg(short = 'v', default_value = "5", help = "Netflow export version (1, 5, 9, 10)")]
    pub netflow_version: String,

    /// Specify collector address (host:port) or comma-separated list
    #[arg(short = 'n', help = "Specify collector address (host:port) or comma-separated list")]
    pub collector: Option<String>,

    /// Set the IPv4 TTL or IPv6 Hop Limit
    #[arg(short = 'L', help = "Set the IPv4 TTL or IPv6 Hop Limit")]
    pub hoplimit: Option<i32>,

    /// Specify flow track level (ip, proto, full, vlan, ether)
    #[arg(short = 'T', default_value = "full", help = "Specify flow track level (ip, proto, full, vlan, ether)")]
    pub track_level: String,

    /// Transport protocol for exporting (udp, tcp)
    #[arg(short = 'P', default_value = "udp", help = "Transport protocol for exporting (udp, tcp)")]
    pub transport_protocol: String,

    /// Specify periodical sampling rate
    #[arg(short = 's', default_value_t = 0, help = "Specify periodical sampling rate")]
    pub sampling_rate: u32,

    /// Specify length for packet capture (snaplen)
    #[arg(short = 'C', help = "Specify length for packet capture (snaplen)")]
    pub capture_length: Option<u32>,

    /// Specify send interface name (Linux only)
    #[arg(short = 'S', help = "Specify send interface name (Linux only)")]
    pub send_interface: Option<String>,

    /// Specify exporter IP address
    #[arg(short = 'e', help = "Specify exporter IP address")]
    pub exporter_ip: Option<String>,

    /// Load balancing mode for multiple destinations
    #[arg(short = 'l', help = "Load balancing mode for multiple destinations")]
    pub load_balance: bool,

    /// BPF filter expression
    #[arg(trailing_var_arg = true, help = "BPF filter expression")]
    pub bpf_expression: Vec<String>,

    /// Adjust time to packet time
    #[arg(short = 'a', help = "Adjust time to packet time")]
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
    #[arg(short = 'c', default_value = "/var/run/softflowd.ctl", help = "Specify control socket path")]
    pub ctlsock: String,

    /// The command to send to softflowd (e.g. statistics, dump-flows, shutdown, expire-all)
    #[arg(help = "The command to send to softflowd (e.g. statistics, dump-flows, shutdown, expire-all)")]
    pub command: String,
}
