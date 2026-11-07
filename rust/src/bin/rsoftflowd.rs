use clap::Parser;
use nix::sys::signal::{self, SigAction, SigHandler, Signal};
use std::net::{IpAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::mpsc::channel;
use std::thread;
use std::time::{Duration, Instant};

use rsoftflowd::common::{
    ExpiryKey, ExpiryReason, FLOW_END_REASON_ACTIVE_TIMEOUT, FLOW_END_REASON_END_OF_FLOW,
    FLOW_END_REASON_IDLE_TIMEOUT, FLOW_END_REASON_LACK_OF_RESOURCE, Flow, FlowKey, FlowLookupMode,
    FlowTracker, TimeVal, TrackLevel,
};
use rsoftflowd::control::{
    ControlCommand, render_dump_flows, render_help, render_statistics, render_timeouts,
    start_control_server,
};
use rsoftflowd::exporter::{Destination, ExportSocket, NetflowTarget, SendParameter, send_flows};
use rsoftflowd::opts::RsoftflowdArgs;
use rsoftflowd::packet_parser::{ParsedPacket, parse_packet};

fn parse_interface_spec(s: &str) -> (u16, String) {
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
fn parse_duration(s: &str) -> Option<i32> {
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

fn parse_mac_address(mac_str: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = mac_str.split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for i in 0..6 {
        match u8::from_str_radix(parts[i], 16) {
            Ok(val) => mac[i] = val,
            Err(_) => return None,
        }
    }
    Some(mac)
}

const BOOTTIME_MAX_DAY: u64 = 49;
const BOOTTIME_MAX_HOUR: u64 = 1193;
const BOOTTIME_MAX_MIN: u64 = 71582;
const BOOTTIME_MAX_SEC: u64 = 4294944;

fn parse_boot_time_reinit(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let digits_len = s.bytes().take_while(u8::is_ascii_digit).count();
    if digits_len == 0 {
        return None;
    }
    let num_str = &s[..digits_len];
    let mut val: u64 = num_str.parse().ok()?;
    let rest = &s[digits_len..];
    let unit = if rest.is_empty() {
        's'
    } else if rest.len() == 1 {
        let c = rest.chars().next()?.to_ascii_lowercase();
        match c {
            'd' | 'h' | 'm' | 's' => c,
            _ => return None,
        }
    } else {
        return None;
    };

    match unit {
        'd' => {
            if val > BOOTTIME_MAX_DAY {
                val = BOOTTIME_MAX_DAY;
            }
            val = val.checked_mul(24 * 60 * 60)?;
        }
        'h' => {
            if val > BOOTTIME_MAX_HOUR {
                val = BOOTTIME_MAX_HOUR;
            }
            val = val.checked_mul(60 * 60)?;
        }
        'm' => {
            if val > BOOTTIME_MAX_MIN {
                val = BOOTTIME_MAX_MIN;
            }
            val = val.checked_mul(60)?;
        }
        _ => {
            if val > BOOTTIME_MAX_SEC {
                val = BOOTTIME_MAX_SEC;
            }
        }
    }
    Some(val)
}

fn validate_hostport(s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err("Invalid -n argument.".to_string());
    }
    let (host, port) = match s.rfind(':') {
        Some(idx) => (&s[..idx], &s[idx + 1..]),
        None => return Err("Invalid -n argument.".to_string()),
    };
    if host.is_empty() || port.is_empty() {
        return Err("Invalid -n argument.".to_string());
    }
    if let Ok(portnum) = port.parse::<u64>()
        && portnum > 65535
    {
        return Err("Invalid -n argument.".to_string());
    }
    match s.to_socket_addrs() {
        Ok(mut addrs) => {
            if addrs.next().is_none() {
                return Err(format!("No addresses found for {}", s));
            }
        }
        Err(e) => {
            return Err(format!("No addresses found for {}: {}", s, e));
        }
    }
    Ok(())
}

/// Apply the `-t name=time` options.
///
/// Original: `set_timeout()` in `softflowd.c`.  On a wrong option it returns
/// the message, and the caller prints it and exits with 1.
fn apply_timeouts(tracker: &mut FlowTracker, timeout_specs: &[String]) -> Result<(), String> {
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

static GRACEFUL_SHUTDOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn sig_handler(sig: libc::c_int) {
    if sig == libc::SIGHUP {
        log::info!("SIGHUP received");
    } else {
        GRACEFUL_SHUTDOWN.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

fn register_signals() {
    let sa = SigAction::new(
        SigHandler::Handler(sig_handler),
        signal::SaFlags::empty(),
        signal::SigSet::empty(),
    );
    unsafe {
        let _ = signal::sigaction(Signal::SIGINT, &sa);
        let _ = signal::sigaction(Signal::SIGTERM, &sa);
        let _ = signal::sigaction(Signal::SIGHUP, &sa);
    }
}

fn drop_privileges() {
    #[cfg(unix)]
    {
        if unsafe { libc::geteuid() } == 0 {
            if let Some(pw) = nix::unistd::User::from_name("nobody").ok().flatten() {
                let _ = nix::unistd::setgid(pw.gid);
                let _ = nix::unistd::setuid(pw.uid);
                log::info!(
                    "Dropped privileges to nobody (uid: {}, gid: {})",
                    pw.uid,
                    pw.gid
                );
            } else {
                log::warn!("Could not find 'nobody' user to drop privileges");
            }
        }
    }
}

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = RsoftflowdArgs::parse();

    // Option validations
    if args.interface.is_none() && args.pcap_file.is_none() {
        eprintln!("Must specify a packet source (-i or -r).\n");
        std::process::exit(1);
    }
    if args.max_flows < 1 {
        eprintln!("Invalid maximum flows\n");
        std::process::exit(1);
    }
    if let Some(hl) = args.hoplimit
        && !(0..=255).contains(&hl)
    {
        eprintln!("Invalid hop limit\n");
        std::process::exit(1);
    }
    if let Some(labels) = args.max_num_label
        && !(1..=10).contains(&labels)
    {
        eprintln!("Invalid number of MPLS label (1 to 10)\n");
        std::process::exit(1);
    }

    if let Some(ref col_str) = args.collector {
        if col_str.is_empty() {
            eprintln!("Invalid -n argument.\n");
            std::process::exit(1);
        }
        for addr_str in col_str.split(',') {
            let addr_str = addr_str.trim();
            if addr_str.is_empty() {
                eprintln!("Invalid -n argument.\n");
                std::process::exit(1);
            }
            if let Err(msg) = validate_hostport(addr_str) {
                eprintln!("{}\n", msg);
                std::process::exit(1);
            }
        }
    }

    let track_level = TrackLevel::from_name(&args.track_level)
        .expect("Invalid track level specified. Choose ip, proto, full, vlan, or ether");

    unsafe extern "C" {
        fn clock() -> libc::clock_t;
    }
    let boottime = unsafe { clock() };

    let (user_ifidx, capture_dev) = if let Some(ref if_spec) = args.interface {
        let (idx, name) = parse_interface_spec(if_spec);
        if name.is_empty() {
            eprintln!("Wrong interface is specified.\n");
            std::process::exit(1);
        }
        (idx, Some(name))
    } else {
        (0, None)
    };

    let if_index = if user_ifidx != 0 {
        user_ifidx
    } else if let Some(ref dev) = capture_dev {
        nix::net::if_::if_nametoindex(dev.as_str()).unwrap_or(1) as u16
    } else {
        0
    };

    if args.debug
        && let Some(ref dev) = capture_dev
    {
        eprintln!("Using {} (idx: {})", dev, if_index);
    }

    let mut tracker = FlowTracker::new(args.max_flows);
    tracker.param.track_level = track_level;
    tracker.param.sample_rate = if args.sampling_rate < 2 {
        0
    } else {
        args.sampling_rate
    };
    if let Some(ref ifname) = capture_dev {
        tracker.param.interface_name = ifname.clone();
    }
    if let Some(ref exp_ip_str) = args.exporter_ip
        && let Ok(ip) = exp_ip_str.parse::<IpAddr>()
    {
        tracker.param.exporter_ip = Some(ip);
    }
    if let Err(msg) = apply_timeouts(&mut tracker, &args.timeouts) {
        eprintln!("{}\n", msg);
        std::process::exit(1);
    }

    if let Some(mode) = FlowLookupMode::from_name(&args.flow_lookup) {
        tracker.set_flow_lookup(mode);
    } else {
        log::error!("Invalid flow lookup mode: {}", args.flow_lookup);
        std::process::exit(1);
    }

    if let Some(ref mac_str) = args.direction_mac {
        if let Some(mac) = parse_mac_address(mac_str) {
            tracker.param.direction_mac = Some(mac);
            tracker.param.direction_mac_set = true;
        } else {
            log::error!("Invalid MAC address format: {}", mac_str);
            std::process::exit(1);
        }
    }

    tracker.param.bidirection = args.bidirection;
    tracker.param.gauge_clock = args.gauge_clock;
    tracker.param.max_num_label = args.max_num_label.unwrap_or(0) as u8;
    if let Some(ref format) = args.time_format {
        tracker.param.time_format = match format.as_str() {
            "sec" => b's',
            "milli" => b'm',
            "micro" => b'M',
            "nano" => b'n',
            _ => b's',
        };
    }
    if let Some(ref boot_reinit) = args.boot_time_reinit {
        match parse_boot_time_reinit(boot_reinit) {
            Some(v) => tracker.param.boot_time_reinit = v,
            None => {
                eprintln!("No digits were found in boot_time_reinit\n");
                std::process::exit(1);
            }
        }
    }

    // 4. Resolve and setup Netflow Exporter Targets
    let is_ntopng = args.netflow_version.to_lowercase() == "ntopng";
    let is_psamp = args.netflow_version.to_lowercase() == "psamp";
    let version = if is_ntopng {
        0x7fff0001
    } else if is_psamp {
        10
    } else {
        args.netflow_version.parse::<u32>().unwrap_or(5)
    };
    tracker.param.is_psamp = is_psamp;
    let want_v6 = args.always_v6 || version == 9 || version == 10;

    let mut targets = NetflowTarget {
        destinations: Vec::new(),
        version,
        is_loadbalance: args.load_balance,
    };

    // 5. Start UNIX domain socket control server (before daemonizing, as in C)
    let (cmd_tx, cmd_rx) = channel::<ControlCommand>();
    let ctl_path = args
        .ctlsock
        .as_deref()
        .map(|p| {
            if p == "none" {
                "".to_string()
            } else {
                p.to_string()
            }
        })
        .or_else(|| {
            if args.pcap_file.is_some() {
                None
            } else {
                Some("/var/run/softflowd.ctl".to_string())
            }
        });
    let ctl_path = if ctl_path.as_deref() == Some("") {
        None
    } else {
        ctl_path
    };

    let mut control_listener = None;
    if let Some(ref path) = ctl_path {
        match start_control_server(path.clone(), cmd_tx.clone()) {
            Ok(listener) => control_listener = Some(listener),
            Err(e) => {
                eprintln!("Failed to start control server: {}\n", e);
                std::process::exit(1);
            }
        }
    }

    // 7. Packet Capture Setup (libpcap) - before daemonizing, as in C
    let pcap_file_mode = args.pcap_file.is_some();
    tracker.param.adjust_time = args.adjust_time;

    let pcap_stats: std::sync::Arc<std::sync::Mutex<Option<(u64, u64, u64)>>> =
        std::sync::Arc::new(std::sync::Mutex::new(None));

    let (packet_tx, packet_rx) = channel::<ParsedPacket>();
    let bpf_expression = if !args.bpf_expression.is_empty() {
        Some(args.bpf_expression.join(" "))
    } else {
        None
    };

    let mut pcap_file_capture = None;
    let mut pcap_device_capture = None;

    if let Some(ref file_path) = args.pcap_file {
        match pcap::Capture::from_file(file_path) {
            Ok(mut capture) => {
                if let Some(ref filter) = bpf_expression {
                    log::info!("Applying BPF filter: \"{}\"", filter);
                    if let Err(e) = capture.filter(filter, true) {
                        eprintln!("PCAP capture error: {}\n", e);
                        std::process::exit(1);
                    }
                }
                pcap_file_capture = Some(capture);
            }
            Err(e) => {
                eprintln!("PCAP capture error: {}\n", e);
                std::process::exit(1);
            }
        }
    } else if let Some(ref dev_name) = capture_dev {
        if dev_name.is_empty() {
            eprintln!("Wrong interface is specified.\n");
            std::process::exit(1);
        }
        let snaplen = args.capture_length.unwrap_or(256) as i32;
        let mut builder = match pcap::Capture::from_device(dev_name.as_str()) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("PCAP capture error: {}\n", e);
                std::process::exit(1);
            }
        }
        .snaplen(snaplen)
        .promisc(!args.no_promisc);

        if let Some(buf_size) = args.buffer_size {
            builder = builder.buffer_size(buf_size as i32);
        } else {
            builder = builder.buffer_size(1024 * 1024);
        }
        builder = builder.immediate_mode(true);
        let mut capture = match builder.open() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("PCAP capture error: {}\n", e);
                std::process::exit(1);
            }
        };

        if let Some(ref filter) = bpf_expression {
            log::info!("Applying BPF filter: \"{}\"", filter);
            if let Err(e) = capture.filter(filter, true) {
                eprintln!("PCAP capture error: {}\n", e);
                std::process::exit(1);
            }
        }
        pcap_device_capture = Some(capture);
    } else {
        eprintln!("Must specify either a live interface (-i) or offline pcap file (-r)\n");
        std::process::exit(1);
    }

    // 2. Daemonize if requested (before logging init as C does)
    if !args.dont_fork && !args.debug && args.pcap_file.is_none() {
        let res = nix::unistd::daemon(true, false);
        if let Err(e) = res {
            eprintln!("Failed to daemonise: {}", e);
            std::process::exit(1);
        }
    }

    // 1. Logging setup
    let log_level = if args.debug {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    if args.dont_fork || args.debug {
        struct StderrLogger;
        impl log::Log for StderrLogger {
            fn enabled(&self, metadata: &log::Metadata) -> bool {
                metadata.level() <= log::max_level()
            }
            fn log(&self, record: &log::Record) {
                if self.enabled(record.metadata()) {
                    eprintln!("{}", record.args());
                }
            }
            fn flush(&self) {
                let _ = std::io::stderr().flush();
            }
        }
        static STDERR_LOGGER: StderrLogger = StderrLogger;
        let _ = log::set_logger(&STDERR_LOGGER);
        log::set_max_level(log_level);
    } else {
        match syslog::init(syslog::Facility::LOG_DAEMON, log_level, Some("rsoftflowd")) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("Failed to initialize syslog: {}", e);
            }
        }
    }

    // Resolve PID file path
    let pidfile_path = match args.pidfile.as_deref() {
        Some("none") => None,
        Some(path) => Some(path.to_string()),
        None => {
            if args.dont_fork || args.debug || args.pcap_file.is_some() {
                None
            } else {
                Some("/var/run/softflowd.pid".to_string())
            }
        }
    };

    // Write PID file
    if let Some(ref path) = pidfile_path {
        if let Ok(content) = std::fs::read_to_string(path)
            && let Ok(pid) = content.trim().parse::<i32>()
            && pid > 0
        {
            let res = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None);
            if res.is_ok() || res.err() == Some(nix::errno::Errno::EPERM) {
                eprintln!("Already running under pid {}", pid);
                std::process::exit(1);
            }
        }
        if let Err(e) = std::fs::write(path, format!("{}\n", std::process::id())) {
            if !args.dont_fork && !args.debug && args.pcap_file.is_some() {
                eprintln!("Couldn't open pidfile {}: {}", path, e);
                std::process::exit(1);
            } else {
                log::warn!("Could not write PID file {}: {}", path, e);
            }
        }
    }

    // Drop privileges if running as root
    drop_privileges();

    if let Some(ref col_str) = args.collector {
        for addr_str in col_str.split(',') {
            let addr_str = addr_str.trim();
            if addr_str.is_empty() {
                continue;
            }
            if is_ntopng {
                #[cfg(feature = "ntopng")]
                {
                    match zmq::Context::new() {
                        context => match context.socket(zmq::PUB) {
                            Ok(socket) => {
                                let connect_str = format!("tcp://{}", addr_str);
                                log::info!("Connecting ZMQ socket '{}'", connect_str);
                                if let Err(e) = socket.connect(&connect_str) {
                                    log::error!(
                                        "Failed to connect ZMQ socket {}: {}",
                                        connect_str,
                                        e
                                    );
                                    std::process::exit(1);
                                }
                                targets.destinations.push(Destination {
                                    socket: ExportSocket::Zmq { context, socket },
                                    arg: addr_str.to_string(),
                                });
                            }
                            Err(e) => {
                                log::error!("Failed to create ZMQ socket: {}", e);
                                std::process::exit(1);
                            }
                        },
                    }
                }
                #[cfg(not(feature = "ntopng"))]
                {
                    eprintln!("ntopng export not enabled\n");
                    std::process::exit(1);
                }
            } else {
                match addr_str.to_socket_addrs() {
                    Ok(mut addrs) => {
                        if let Some(socket_addr) = addrs.next() {
                            let proto = args.transport_protocol.to_lowercase();
                            let socket = match proto.as_str() {
                                "tcp" => match TcpStream::connect(socket_addr) {
                                    Ok(s) => ExportSocket::Tcp(s),
                                    Err(e) => {
                                        log::error!(
                                            "Failed to connect to TCP collector {}: {}",
                                            socket_addr,
                                            e
                                        );
                                        std::process::exit(1);
                                    }
                                },
                                _ => {
                                    // Default UDP
                                    let s = UdpSocket::bind("0.0.0.0:0")
                                        .expect("Failed to bind UDP socket");
                                    if let Some(hl) = args.hoplimit {
                                        let _ = s.set_ttl(hl as u32);
                                    }
                                    if let Err(e) = s.connect(socket_addr) {
                                        log::error!(
                                            "Failed to connect UDP collector {}: {}",
                                            socket_addr,
                                            e
                                        );
                                        std::process::exit(1);
                                    }

                                    // Bind to specific device if requested (Linux only)
                                    #[cfg(target_os = "linux")]
                                    if let Some(ref send_if) = args.send_interface
                                        && let Err(e) =
                                            rsoftflowd::net_util_unsafe::bind_socket_to_device(
                                                &s, send_if,
                                            )
                                    {
                                        log::error!(
                                            "Failed to bind to interface {}: {}",
                                            send_if,
                                            e
                                        );
                                        std::process::exit(1);
                                    }

                                    ExportSocket::Udp(s)
                                }
                            };
                            targets.destinations.push(Destination {
                                socket,
                                arg: addr_str.to_string(),
                            });
                        }
                    }
                    Err(e) => {
                        log::error!("Failed to resolve collector address {}: {}", addr_str, e);
                        std::process::exit(1);
                    }
                }
            }
        }
    }

    // 6. Signal integration
    register_signals();

    let max_num_label = tracker.param.max_num_label;
    let full_l4hdr = args.full_transport_header_check;

    if let Some(mut capture) = pcap_file_capture {
        let linktype = capture.get_datalink().0;
        let packet_tx_clone = packet_tx.clone();
        let pcap_stats_clone = pcap_stats.clone();

        thread::spawn(move || {
            log::debug!("Packet capture thread started.");
            loop {
                if GRACEFUL_SHUTDOWN.load(std::sync::atomic::Ordering::SeqCst) {
                    log::debug!("Packet capture thread shutting down.");
                    break;
                }
                match capture.next_packet() {
                    Ok(raw_packet) => {
                        let caplen = raw_packet.header.caplen;
                        let len = raw_packet.header.len;
                        #[allow(clippy::unnecessary_cast)]
                        let timestamp = TimeVal {
                            tv_sec: raw_packet.header.ts.tv_sec as i64,
                            tv_usec: raw_packet.header.ts.tv_usec as i32,
                        };
                        let data = raw_packet.data.to_vec();

                        if let Ok(st) = capture.stats() {
                            let mut s = pcap_stats_clone.lock().unwrap();
                            *s =
                                Some((st.received as u64, st.dropped as u64, st.if_dropped as u64));
                        }

                        if let Some(parsed) = parse_packet(
                            linktype,
                            &data,
                            caplen,
                            len,
                            track_level,
                            max_num_label,
                            full_l4hdr,
                            timestamp,
                        ) {
                            let _ = packet_tx_clone.send(parsed);
                        }
                    }
                    Err(pcap::Error::NoMorePackets) => {
                        log::info!("Shutting down after pcap EOF");
                        if let Ok(st) = capture.stats() {
                            let mut s = pcap_stats_clone.lock().unwrap();
                            *s =
                                Some((st.received as u64, st.dropped as u64, st.if_dropped as u64));
                        }
                        GRACEFUL_SHUTDOWN.store(true, std::sync::atomic::Ordering::SeqCst);
                        break;
                    }
                    Err(e) => {
                        log::error!("PCAP capture error: {}", e);
                        break;
                    }
                }
            }
            log::debug!("Packet capture thread exited.");
        });
    } else if let Some(mut capture) = pcap_device_capture {
        let linktype = capture.get_datalink().0;
        let packet_tx_clone = packet_tx.clone();
        let pcap_stats_clone = pcap_stats.clone();

        thread::spawn(move || {
            loop {
                if GRACEFUL_SHUTDOWN.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
                match capture.next_packet() {
                    Ok(raw_packet) => {
                        let caplen = raw_packet.header.caplen;
                        let len = raw_packet.header.len;
                        #[allow(clippy::unnecessary_cast)]
                        let timestamp = TimeVal {
                            tv_sec: raw_packet.header.ts.tv_sec as i64,
                            tv_usec: raw_packet.header.ts.tv_usec as i32,
                        };
                        let data = raw_packet.data.to_vec();

                        if let Ok(st) = capture.stats() {
                            let mut s = pcap_stats_clone.lock().unwrap();
                            *s =
                                Some((st.received as u64, st.dropped as u64, st.if_dropped as u64));
                        }

                        if let Some(parsed) = parse_packet(
                            linktype,
                            &data,
                            caplen,
                            len,
                            track_level,
                            max_num_label,
                            full_l4hdr,
                            timestamp,
                        ) {
                            let _ = packet_tx_clone.send(parsed);
                        }
                    }
                    Err(_) => {
                        continue;
                    }
                }
            }
        });
    } else {
        log::error!("Must specify either a live interface (-i) or offline pcap file (-r)");
        std::process::exit(1);
    }

    drop(packet_tx);

    // Drop privileges if running as root
    drop_privileges();

    // 8. Main Event Loop
    log::info!(
        "rsoftflowd v{} starting data collection",
        env!("CARGO_PKG_VERSION")
    );
    let cap_src = args
        .pcap_file
        .as_deref()
        .unwrap_or_else(|| args.interface.as_deref().unwrap_or(""));
    for dest in &targets.destinations {
        let (host, serv) = if let Some(idx) = dest.arg.rfind(':') {
            (&dest.arg[..idx], &dest.arg[idx + 1..])
        } else {
            (&dest.arg[..], "")
        };
        log::info!("Exporting flows from {} to [{}]:{}", cap_src, host, serv);
    }
    let mut last_expiry_scan = Instant::now();
    let mut stop_gather = false;
    let pid = std::process::id();
    let prefix = format!("softflowd[{}]: ", pid);

    loop {
        // Handle signals
        if GRACEFUL_SHUTDOWN.load(std::sync::atomic::Ordering::SeqCst) {
            log::info!("Shutting down gracefully...");
            flush_all_flows(&mut tracker, &targets, if_index);
            break;
        }

        // Handle control commands
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                ControlCommand::Statistics { resp } => {
                    let st = *pcap_stats.lock().unwrap();
                    let stats_str = render_statistics(&tracker, st);
                    let _ = resp.send(format!("{}{}", prefix, stats_str));
                }
                ControlCommand::DumpFlows { resp } => {
                    let dump_str = render_dump_flows(&tracker);
                    let _ = resp.send(format!("{}Dumping flow data:\n{}", prefix, dump_str));
                }
                ControlCommand::Shutdown { resp } => {
                    log::info!("Shutdown command received.");
                    GRACEFUL_SHUTDOWN.store(true, std::sync::atomic::Ordering::SeqCst);
                    let _ = resp.send(format!("{}Shutting down gracefully...\n", prefix));
                }
                ControlCommand::ExpireAll { resp } => {
                    let count = expire_all_flows(&mut tracker, &targets, if_index);
                    let _ = resp.send(format!("{}Expired {} flows.\n", prefix, count));
                }
                ControlCommand::DeleteAll { resp } => {
                    let count = tracker.flows.len();
                    tracker.flows.clear();
                    tracker.expiries.clear();
                    tracker.flow_slots.clear();
                    let _ = resp.send(format!("{}Deleted {} flows.\n", prefix, count));
                }
                ControlCommand::Exit { resp } => {
                    log::info!("Exit command received.");
                    let _ = resp.send(format!("{}Exiting now...\n", prefix));
                    if let Some(ref path) = ctl_path {
                        let _ = std::fs::remove_file(path);
                    }
                    if let Some(ref path) = pidfile_path {
                        let _ = std::fs::remove_file(path);
                    }
                    std::process::exit(0);
                }
                ControlCommand::DebugPlus { resp } => {
                    let _ = resp.send(format!("{}Debug level increased.\n", prefix));
                }
                ControlCommand::DebugMinus { resp } => {
                    let _ = resp.send(format!("{}Debug level decreased.\n", prefix));
                }
                ControlCommand::StartGather { resp } => {
                    stop_gather = false;
                    let _ = resp.send(format!("{}Data collection resumed.\n", prefix));
                }
                ControlCommand::StopGather { resp } => {
                    stop_gather = true;
                    let _ = resp.send(format!("{}Data collection stopped.\n", prefix));
                }
                ControlCommand::SendTemplate { resp } => {
                    rsoftflowd::exporter::export_common::ipfix_resend_template();
                    let _ = resp.send(format!(
                        "{}Template will be sent at next flow export\n",
                        prefix
                    ));
                }
                ControlCommand::Timeouts { resp } => {
                    let timeouts_str = render_timeouts(&tracker);
                    let _ = resp.send(format!("{}Printing timeouts:\n{}", prefix, timeouts_str));
                }
                ControlCommand::Help { resp } => {
                    let _ = resp.send(render_help().to_string());
                }
            }
        }

        // Process incoming packet events
        let mut packets_processed_this_loop = 0;
        let mut channel_disconnected = false;
        loop {
            match packet_rx.try_recv() {
                Ok(parsed) => {
                    if !stop_gather {
                        process_parsed_packet(&mut tracker, parsed, want_v6, &targets, if_index);
                    }
                    packets_processed_this_loop += 1;
                    if packets_processed_this_loop > 1000 {
                        break;
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    break;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    channel_disconnected = true;
                    break;
                }
            }
        }

        // Periodic flow expiry checks
        let scan_interval = Duration::from_secs(tracker.param.expiry_interval.max(1) as u64);
        if last_expiry_scan.elapsed() >= scan_interval {
            scan_expiries(&mut tracker, &targets, false, if_index);
            last_expiry_scan = Instant::now();
        }

        // Small sleep to yield CPU in live mode, unless we processed packets
        if packets_processed_this_loop == 0 {
            thread::sleep(Duration::from_millis(50));
        }

        // In offline PCAP file mode, if the packet channel is empty and thread has finished, we exit!
        if (pcap_file_mode && channel_disconnected)
            || GRACEFUL_SHUTDOWN.load(std::sync::atomic::Ordering::SeqCst)
        {
            log::warn!("Shutting down on user request");
            flush_all_flows(&mut tracker, &targets, if_index);
            // Print stats to stdout before exit as C softflowd does
            let st = *pcap_stats.lock().unwrap();
            let final_stats = render_statistics(&tracker, st);
            print!("{}", final_stats);
            break;
        }
    }

    log::info!("Shutting down complete, exiting.");
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();

    // Close control socket listener first, then remove file
    drop(control_listener);

    // Cleanup UNIX socket file and PID file
    if let Some(ref path) = ctl_path {
        let _ = std::fs::remove_file(path);
    }
    if let Some(ref path) = pidfile_path {
        let _ = std::fs::remove_file(path);
    }

    if tracker.param.gauge_clock {
        unsafe extern "C" {
            fn clock() -> libc::clock_t;
        }
        let total_clocks = unsafe { clock() } - boottime;
        eprintln!("cpu clocks: {}", total_clocks);
        eprintln!(
            "cpu clocks (export): {} ({} calls)",
            tracker.param.export_clocks, tracker.param.export_calls
        );
    }

    std::process::exit(0);
}

fn process_parsed_packet(
    tracker: &mut FlowTracker,
    parsed: ParsedPacket,
    want_v6: bool,
    targets: &NetflowTarget,
    ifidx: u16,
) {
    if !want_v6 && parsed.af == 10 {
        tracker.param.non_ip_packets += 1;
        return;
    }

    if tracker.param.total_packets == 0 {
        tracker.param.system_boot_time = parsed.timestamp;
    }

    // -I オプション対応: ブートタイムの再初期化
    if tracker.param.boot_time_reinit > 0 {
        let diff = parsed.timestamp.tv_sec - tracker.param.system_boot_time.tv_sec;
        if diff >= tracker.param.boot_time_reinit as i64 {
            log::info!("Reinitializing system boot time due to -I option.");
            tracker.param.system_boot_time = parsed.timestamp;
        }
    }

    // Sampling
    if tracker.param.sample_rate > 0
        && !(tracker.param.total_packets + tracker.param.non_sampled_packets)
            .is_multiple_of(tracker.param.sample_rate as u64)
    {
        tracker.param.non_sampled_packets += 1;
        return;
    }

    tracker.param.total_packets += 1;

    let timeval_packet = parsed.timestamp;
    tracker.param.last_packet_time = timeval_packet;

    // PSAMP mode: export immediately
    if tracker.param.is_psamp {
        rsoftflowd::exporter::psamp::send_psamp(
            &parsed.raw_packet,
            parsed.length.min(128),
            parsed.timestamp,
            targets,
            tracker.param.total_packets,
            &mut tracker.param,
        );
        return;
    }

    // Fragment packets count
    if parsed.is_frag {
        tracker.param.frag_packets += 1;
    }

    let (key, ndx) = FlowKey::canonical(
        parsed.af,
        parsed.protocol,
        parsed.src_ip,
        parsed.dst_ip,
        parsed.src_port,
        parsed.dst_port,
        parsed.vlan_id,
        0, // outbound vlan
        parsed.src_mac,
        parsed.dst_mac,
        &parsed.mpls_labels,
        tracker.param.track_level,
    );

    // Hash lookup mode: expire resident flow on collision
    if tracker.flow_lookup == FlowLookupMode::Hash {
        let slot = key.hash_index(tracker.nbuckets);
        if let Some(resident_key) = tracker.flow_slots.get(&slot).cloned()
            && resident_key != key
            && let Some(mut resident_flow) = tracker.flows.remove(&resident_key)
        {
            if let Some(exp_key) = resident_flow.expiry_key {
                tracker.expiries.remove(&exp_key);
            }
            resident_flow.expiry_reason = ExpiryReason::Collision;
            resident_flow.flow_end_reason = FLOW_END_REASON_LACK_OF_RESOURCE;
            tracker.param.flows_force_expired += 1;
            accumulate_stats(tracker, &resident_flow);
            let flow_refs = vec![&resident_flow];
            let sp = SendParameter {
                flows: &flow_refs,
                target: targets,
                ifidx,
                param: &mut tracker.param,
                verbose: false,
            };
            let _ = send_flows(sp);
        }
        tracker.flow_slots.insert(slot, key.clone());
    }

    // Get or create flow
    if !tracker.flows.contains_key(&key) {
        // Enforce max flows limit (evict oldest first)
        if tracker.flows.len() >= tracker.param.max_flows as usize {
            evict_oldest_flow(tracker, targets, ifidx);
        }

        let mut flow = Flow {
            flow_seq: tracker.param.next_flow_seq,
            flow_start: timeval_packet,
            flow_last: timeval_packet,
            octets: [0, 0],
            packets: [0, 0],
            tcp_flags: [0, 0],
            tos: [0, 0],
            ip6_flowlabel: [0, 0],
            src_mac: parsed.src_mac,
            dst_mac: parsed.dst_mac,
            flow_end_reason: FLOW_END_REASON_IDLE_TIMEOUT,
            key: key.clone(),
            expiry_key: None,
            expiry_reason: ExpiryReason::General,
        };

        tracker.param.next_flow_seq += 1;

        flow.octets[ndx] = parsed.length;
        flow.packets[ndx] = 1;
        flow.tcp_flags[ndx] = parsed.tcp_flags;
        flow.tos[ndx] = parsed.tos;
        flow.ip6_flowlabel[ndx] = parsed.ip6_flowlabel;

        // Set expiry
        update_flow_expiry(&mut tracker.expiries, &tracker.param, &mut flow);
        tracker.flows.insert(key, flow);
    } else {
        let flow = tracker.flows.get_mut(&key).unwrap();
        flow.octets[ndx] = flow.octets[ndx].saturating_add(parsed.length);
        flow.packets[ndx] = flow.packets[ndx].saturating_add(1);
        flow.tcp_flags[ndx] |= parsed.tcp_flags;
        flow.tos[ndx] = parsed.tos;
        flow.flow_last = timeval_packet;

        // Update expiry
        update_flow_expiry(&mut tracker.expiries, &tracker.param, flow);
    }
}

fn update_flow_expiry(
    expiries: &mut std::collections::BTreeMap<ExpiryKey, FlowKey>,
    param: &rsoftflowd::common::FlowTrackParameters,
    flow: &mut Flow,
) {
    if let Some(old_expiry) = flow.expiry_key {
        expiries.remove(&old_expiry);
    }

    let mut expires_at = flow.flow_last.tv_sec as u32 + param.general_timeout as u32;
    let mut reason = ExpiryReason::General;
    // A flow that matches no branch below ends by the general timeout.
    flow.flow_end_reason = FLOW_END_REASON_IDLE_TIMEOUT;

    // Standard flow expiry logic
    if flow.octets[0] > (1 << 31) || flow.octets[1] > (1 << 31) {
        expires_at = 0; // immediate
        reason = ExpiryReason::OverBytes;
        flow.flow_end_reason = FLOW_END_REASON_LACK_OF_RESOURCE;
    } else if param.maximum_lifetime != 0
        && (flow.flow_last.tv_sec - flow.flow_start.tv_sec) as i32 > param.maximum_lifetime
    {
        expires_at = 0;
        reason = ExpiryReason::MaxLife;
        flow.flow_end_reason = FLOW_END_REASON_ACTIVE_TIMEOUT;
    } else if flow.key.protocol == 6 {
        // TCP
        let rst = (flow.tcp_flags[0] & 0x04) != 0 || (flow.tcp_flags[1] & 0x04) != 0;
        let fin = ((flow.tcp_flags[0] & 0x01) != 0) && ((flow.tcp_flags[1] & 0x01) != 0);

        if rst && param.tcp_rst_timeout > 0 {
            expires_at = flow.flow_last.tv_sec as u32 + param.tcp_rst_timeout as u32;
            reason = ExpiryReason::TcpRst;
            flow.flow_end_reason = FLOW_END_REASON_END_OF_FLOW;
        } else if fin && param.tcp_fin_timeout > 0 {
            expires_at = flow.flow_last.tv_sec as u32 + param.tcp_fin_timeout as u32;
            reason = ExpiryReason::TcpFin;
            flow.flow_end_reason = FLOW_END_REASON_END_OF_FLOW;
        } else if param.tcp_timeout > 0 {
            expires_at = flow.flow_last.tv_sec as u32 + param.tcp_timeout as u32;
            reason = ExpiryReason::Tcp;
            flow.flow_end_reason = FLOW_END_REASON_IDLE_TIMEOUT;
        }
    } else if flow.key.protocol == 17 && param.udp_timeout > 0 {
        expires_at = flow.flow_last.tv_sec as u32 + param.udp_timeout as u32;
        reason = ExpiryReason::Udp;
        flow.flow_end_reason = FLOW_END_REASON_IDLE_TIMEOUT;
    } else if (flow.key.protocol == 1 || flow.key.protocol == 58) && param.icmp_timeout > 0 {
        expires_at = flow.flow_last.tv_sec as u32 + param.icmp_timeout as u32;
        reason = ExpiryReason::Icmp;
        flow.flow_end_reason = FLOW_END_REASON_IDLE_TIMEOUT;
    }

    if param.maximum_lifetime != 0 && expires_at != 0 {
        let max_expiry = flow.flow_start.tv_sec as u32 + param.maximum_lifetime as u32;
        expires_at = expires_at.min(max_expiry);
    }

    let new_expiry = ExpiryKey {
        expires_at,
        flow_seq: flow.flow_seq,
    };
    flow.expiry_key = Some(new_expiry);
    flow.expiry_reason = reason;

    expiries.insert(new_expiry, flow.key.clone());
}

fn evict_oldest_flow(tracker: &mut FlowTracker, targets: &NetflowTarget, ifidx: u16) {
    if let Some((&expiry_key, flow_key)) = tracker.expiries.iter().next() {
        let flow_key = flow_key.clone();
        if let Some(mut flow) = tracker.flows.remove(&flow_key) {
            tracker.expiries.remove(&expiry_key);
            if tracker.flow_lookup == FlowLookupMode::Hash {
                let slot = flow.key.hash_index(tracker.nbuckets);
                if tracker.flow_slots.get(&slot) == Some(&flow_key) {
                    tracker.flow_slots.remove(&slot);
                }
            }
            tracker.param.flows_force_expired += 1;
            flow.expiry_reason = ExpiryReason::Overflows;
            flow.flow_end_reason = FLOW_END_REASON_LACK_OF_RESOURCE;
            // Accumulate statistics
            accumulate_stats(tracker, &flow);
            log::debug!(
                "EXPIRED: {} ({:p})",
                rsoftflowd::control::format_flow(&flow),
                &flow
            );
            let flow_refs = vec![&flow];
            let sp = SendParameter {
                flows: &flow_refs,
                target: targets,
                ifidx,
                param: &mut tracker.param,
                verbose: true,
            };
            let _ = send_flows(sp);
        }
    }
}

fn accumulate_stats(tracker: &mut FlowTracker, flow: &Flow) {
    tracker.param.flows_expired += 1;
    tracker.param.flows_pp[flow.key.protocol as usize % 256] += 1;

    let duration_sec = (flow.flow_last.tv_sec - flow.flow_start.tv_sec) as f64
        + ((flow.flow_last.tv_usec - flow.flow_start.tv_usec) as f64 / 1_000_000.0);
    let duration_sec = duration_sec.max(0.0);

    let n = tracker.param.flows_expired as f64;
    tracker.param.duration.update(duration_sec, n);

    let proto_n = tracker.param.flows_pp[flow.key.protocol as usize % 256] as f64;
    tracker.param.duration_pp[flow.key.protocol as usize % 256].update(duration_sec, proto_n);

    let octets = (flow.octets[0] + flow.octets[1]) as f64;
    tracker.param.octets.update(octets, n);
    tracker.param.octets_pp[flow.key.protocol as usize % 256] += octets as u64;

    let packets = (flow.packets[0] + flow.packets[1]) as f64;
    tracker.param.packets.update(packets, n);
    tracker.param.packets_pp[flow.key.protocol as usize % 256] += packets as u64;

    // Expiry reasons
    match flow.expiry_reason {
        ExpiryReason::General => tracker.param.expired_general += 1,
        ExpiryReason::Tcp => tracker.param.expired_tcp += 1,
        ExpiryReason::TcpRst => tracker.param.expired_tcp_rst += 1,
        ExpiryReason::TcpFin => tracker.param.expired_tcp_fin += 1,
        ExpiryReason::Udp => tracker.param.expired_udp += 1,
        ExpiryReason::Icmp => tracker.param.expired_icmp += 1,
        ExpiryReason::MaxLife => tracker.param.expired_maxlife += 1,
        ExpiryReason::OverBytes => tracker.param.expired_overbytes += 1,
        ExpiryReason::Overflows => tracker.param.expired_maxflows += 1,
        ExpiryReason::Flush => tracker.param.expired_flush += 1,
        ExpiryReason::Collision => tracker.param.expired_collision += 1,
    }
}

fn scan_expiries(
    tracker: &mut FlowTracker,
    targets: &NetflowTarget,
    force_all: bool,
    ifidx: u16,
) -> usize {
    log::debug!(
        "Starting expiry scan: mode {}",
        if force_all { 1 } else { 0 }
    );

    let now_sec = if tracker.param.adjust_time && tracker.param.last_packet_time.tv_sec > 0 {
        tracker.param.last_packet_time.tv_sec as u32
    } else {
        match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs() as u32,
            Err(_) => 0,
        }
    };

    let mut expired_keys = Vec::new();
    for (&exp_key, flow_key) in &tracker.expiries {
        if force_all || exp_key.expires_at == 0 || exp_key.expires_at <= now_sec {
            expired_keys.push((exp_key, flow_key.clone()));
        } else {
            // Since BTreeMap is sorted, we can stop at first non-expired flow!
            if !force_all {
                break;
            }
        }
    }

    let mut expired_flows = Vec::new();
    for (exp_key, flow_key) in &expired_keys {
        if let Some(mut flow) = tracker.flows.remove(flow_key) {
            tracker.expiries.remove(exp_key);
            if tracker.flow_lookup == FlowLookupMode::Hash {
                let slot = flow.key.hash_index(tracker.nbuckets);
                if tracker.flow_slots.get(&slot) == Some(flow_key) {
                    tracker.flow_slots.remove(&slot);
                }
            }
            if force_all {
                flow.expiry_reason = ExpiryReason::Flush;
            }
            log::debug!(
                "Queuing flow seq:{} ({:p}) for expiry reason {:?}",
                flow.flow_seq,
                &flow,
                flow.expiry_reason
            );
            accumulate_stats(tracker, &flow);
            expired_flows.push(flow);
        }
    }

    let count = expired_flows.len();
    log::debug!("Finished scan {} flow(s) to be evicted", count);

    if count > 0 {
        for flow in &expired_flows {
            log::debug!(
                "EXPIRED: {} ({:p})",
                rsoftflowd::control::format_flow(flow),
                flow
            );
        }

        // Convert to array of refs
        let flow_refs: Vec<&Flow> = expired_flows.iter().collect();
        let sp = SendParameter {
            flows: &flow_refs,
            target: targets,
            ifidx,
            param: &mut tracker.param,
            verbose: true,
        };
        let _ = send_flows(sp);
    }

    count
}

fn expire_all_flows(tracker: &mut FlowTracker, targets: &NetflowTarget, ifidx: u16) -> usize {
    scan_expiries(tracker, targets, true, ifidx)
}

fn flush_all_flows(tracker: &mut FlowTracker, targets: &NetflowTarget, ifidx: u16) {
    expire_all_flows(tracker, targets, ifidx);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_boot_time_reinit() {
        assert_eq!(parse_boot_time_reinit("10"), Some(10));
        assert_eq!(parse_boot_time_reinit("2h"), Some(7200));
        assert_eq!(parse_boot_time_reinit("50d"), Some(4233600));
        assert_eq!(parse_boot_time_reinit("abc"), None);
        assert_eq!(parse_boot_time_reinit("1x2"), None);
        assert_eq!(parse_boot_time_reinit("99999999999999999999"), None);
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

    #[test]
    fn maximum_lifetime_expiry_boundary() {
        let mut expiries = std::collections::BTreeMap::new();
        let param = rsoftflowd::common::FlowTrackParameters {
            maximum_lifetime: 60,
            udp_timeout: 300,
            ..Default::default()
        };

        let key = FlowKey::canonical(
            2,  // AF_INET
            17, // UDP
            "192.168.0.1".parse().unwrap(),
            "192.168.0.2".parse().unwrap(),
            1234,
            5678,
            0,
            0,
            [0; 6],
            [0; 6],
            &[],
            TrackLevel::Full,
        )
        .0;

        // Flow age equals maximum_lifetime (60 seconds)
        let mut flow_equal = Flow {
            flow_seq: 1,
            flow_start: TimeVal {
                tv_sec: 1000,
                tv_usec: 0,
            },
            flow_last: TimeVal {
                tv_sec: 1060,
                tv_usec: 0,
            },
            octets: [100, 0],
            packets: [1, 0],
            tcp_flags: [0, 0],
            tos: [0, 0],
            ip6_flowlabel: [0, 0],
            src_mac: [0; 6],
            dst_mac: [0; 6],
            flow_end_reason: FLOW_END_REASON_IDLE_TIMEOUT,
            key: key.clone(),
            expiry_key: None,
            expiry_reason: ExpiryReason::General,
        };

        update_flow_expiry(&mut expiries, &param, &mut flow_equal);
        assert_ne!(flow_equal.expiry_reason, ExpiryReason::MaxLife);
        assert_ne!(flow_equal.flow_end_reason, FLOW_END_REASON_ACTIVE_TIMEOUT);

        // Flow age is 1 second older than maximum_lifetime (61 seconds)
        let mut flow_older = Flow {
            flow_seq: 2,
            flow_start: TimeVal {
                tv_sec: 1000,
                tv_usec: 0,
            },
            flow_last: TimeVal {
                tv_sec: 1061,
                tv_usec: 0,
            },
            octets: [100, 0],
            packets: [1, 0],
            tcp_flags: [0, 0],
            tos: [0, 0],
            ip6_flowlabel: [0, 0],
            src_mac: [0; 6],
            dst_mac: [0; 6],
            flow_end_reason: FLOW_END_REASON_IDLE_TIMEOUT,
            key,
            expiry_key: None,
            expiry_reason: ExpiryReason::General,
        };

        update_flow_expiry(&mut expiries, &param, &mut flow_older);
        assert_eq!(flow_older.expiry_reason, ExpiryReason::MaxLife);
        assert_eq!(flow_older.flow_end_reason, FLOW_END_REASON_ACTIVE_TIMEOUT);
        assert_eq!(flow_older.expiry_key.unwrap().expires_at, 0);
    }

    #[test]
    fn test_flow_eviction_exports() {
        use byteorder::{BigEndian, ByteOrder};
        use std::net::Ipv4Addr;

        for lookup_mode in [
            FlowLookupMode::Tree,
            FlowLookupMode::Hash,
            FlowLookupMode::HashTree,
        ] {
            let mut tracker = FlowTracker::new(5);
            tracker.set_flow_lookup(lookup_mode);

            let recv_socket =
                UdpSocket::bind("127.0.0.1:0").expect("Failed to bind UDP receiver socket");
            let recv_addr = recv_socket
                .local_addr()
                .expect("Failed to get local address");
            let send_socket =
                UdpSocket::bind("127.0.0.1:0").expect("Failed to bind UDP sender socket");
            send_socket
                .connect(recv_addr)
                .expect("Failed to connect to receiver socket");

            let targets = NetflowTarget {
                destinations: vec![Destination {
                    socket: ExportSocket::Udp(send_socket),
                    arg: recv_addr.to_string(),
                }],
                version: 5,
                is_loadbalance: false,
            };

            // Feed 6 different flows (ports 1001 to 1006)
            for port in 1001..=1006 {
                let parsed = ParsedPacket {
                    af: 2,       // AF_INET
                    protocol: 6, // TCP
                    src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                    dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
                    src_port: port,
                    dst_port: 80,
                    vlan_id: 0,
                    src_mac: [0; 6],
                    dst_mac: [0; 6],
                    mpls_labels: vec![],
                    tcp_flags: 0x02,
                    tos: 0,
                    is_frag: false,
                    is_first: true,
                    ip6_flowlabel: 0,
                    length: 40,
                    timestamp: TimeVal {
                        tv_sec: 1600000000,
                        tv_usec: 0,
                    },
                    raw_packet: vec![0; 40],
                };
                process_parsed_packet(&mut tracker, parsed, true, &targets, 1);
            }

            expire_all_flows(&mut tracker, &targets, 1);

            recv_socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut total_records = 0;
            let mut buf = [0u8; 2048];

            while let Ok((len, _)) = recv_socket.recv_from(&mut buf) {
                if len >= 24 {
                    let count = BigEndian::read_u16(&buf[2..4]) as usize;
                    total_records += count;
                }
            }

            assert_eq!(
                total_records, 6,
                "Expected 6 flow records exported for mode {:?}, got {}",
                lookup_mode, total_records
            );
            assert_eq!(tracker.param.flows_expired, 6);
        }
    }
}
