use clap::Parser;
use nix::sys::signal::{self, SigAction, SigHandler, Signal};
use std::io::Write;
use std::net::{IpAddr, ToSocketAddrs};
use std::os::unix::net::UnixListener;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rsoftflowd::capture::{PacketEvent, process_parsed_packet, setup_packet_capture};
use rsoftflowd::common::{FlowLookupMode, FlowTracker, TrackLevel, cpu_clock};
use rsoftflowd::control::{
    ControlCommand, render_dump_flows, render_help, render_statistics, render_timeouts,
    start_control_server,
};
use rsoftflowd::expire::*;
use rsoftflowd::exporter::NetflowTarget;
use rsoftflowd::netsock::setup_export_targets;
use rsoftflowd::opts::{
    RsoftflowdArgs, apply_timeouts, parse_boot_time_reinit, parse_interface_spec, parse_mac_address,
};

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

static GRACEFUL_SHUTDOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn sig_handler(sig: libc::c_int) {
    if sig == libc::SIGHUP {
        log::info!("SIGHUP received");
    } else {
        GRACEFUL_SHUTDOWN.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Register signal handlers for SIGINT, SIGTERM, SIGHUP.
///
/// Original: daemon.c (`register_signals()`)
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

/// Drop privileges from root to 'nobody'.
///
/// Original: daemon.c (`drop_privileges()`)
fn drop_privileges() {
    #[cfg(unix)]
    {
        if unsafe { libc::geteuid() } == 0 {
            if let Some(pw) = nix::unistd::User::from_name("nobody").ok().flatten() {
                let _ = nix::unistd::setgid(pw.gid);
                let _ = nix::unistd::setuid(pw.uid);
                log::info!("Dropped privileges to nobody");
            } else {
                log::warn!("Could not find 'nobody' user to drop privileges");
            }
        }
    }
}

fn validate_options(args: &RsoftflowdArgs) {
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
}

fn init_tracker(args: &RsoftflowdArgs) -> (TrackLevel, libc::clock_t, u16, FlowTracker) {
    let track_level = TrackLevel::from_name(&args.track_level)
        .expect("Invalid track level specified. Choose ip, proto, full, vlan, or ether");

    let boottime = cpu_clock();

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

    tracker.param.adjust_time = args.adjust_time;

    (track_level, boottime, if_index, tracker)
}

fn resolve_ctl_path(args: &RsoftflowdArgs) -> Option<String> {
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
    if ctl_path.as_deref() == Some("") {
        None
    } else {
        ctl_path
    }
}

fn daemonize_and_init_log(args: &RsoftflowdArgs) {
    if !args.dont_fork && !args.debug && args.pcap_file.is_none() {
        let res = nix::unistd::daemon(true, false);
        if let Err(e) = res {
            eprintln!("Failed to daemonise: {}", e);
            std::process::exit(1);
        }
    }

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
}

fn resolve_and_write_pidfile(args: &RsoftflowdArgs) -> Option<String> {
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

    pidfile_path
}

#[allow(clippy::too_many_arguments)]
fn run_main_loop(
    args: RsoftflowdArgs,
    mut tracker: FlowTracker,
    targets: NetflowTarget,
    want_v6: bool,
    ctl_path: Option<String>,
    control_listener: Option<UnixListener>,
    pcap_file_mode: bool,
    pcap_stats: Arc<Mutex<Option<(u64, u64, u64)>>>,
    packet_rx: std::sync::mpsc::Receiver<PacketEvent>,
    pidfile_path: Option<String>,
    boottime: libc::clock_t,
    if_index: u16,
    cmd_rx: std::sync::mpsc::Receiver<ControlCommand>,
) -> Result<(), Box<dyn std::error::Error>> {
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
                Ok(event) => {
                    if !stop_gather {
                        match event {
                            PacketEvent::Parsed(parsed) => {
                                process_parsed_packet(
                                    &mut tracker,
                                    parsed,
                                    want_v6,
                                    &targets,
                                    if_index,
                                );
                            }
                            PacketEvent::NonIp => {
                                tracker.param.non_ip_packets += 1;
                            }
                            PacketEvent::TooShort => {
                                tracker.param.bad_packets += 1;
                                tracker.param.total_packets += 1;
                            }
                        }
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
            thread::sleep(Duration::from_millis(1));
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
        let total_clocks = cpu_clock() - boottime;
        eprintln!("cpu clocks: {}", total_clocks);
        eprintln!(
            "cpu clocks (export): {} ({} calls)",
            tracker.param.export_clocks, tracker.param.export_calls
        );
    }

    Ok(())
}

/// Main entry point of rsoftflowd.
///
/// Original: softflowd.c (`main()`)
pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = RsoftflowdArgs::parse();

    validate_options(&args);
    let (track_level, boottime, if_index, mut tracker) = init_tracker(&args);

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

    let (cmd_tx, cmd_rx) = channel::<ControlCommand>();
    let ctl_path = resolve_ctl_path(&args);
    let mut control_listener = None;
    if let Some(ref path) = ctl_path {
        match start_control_server(path.clone(), cmd_tx) {
            Ok(listener) => control_listener = Some(listener),
            Err(e) => {
                eprintln!("Failed to start control server: {}\n", e);
                std::process::exit(1);
            }
        }
    }

    let pcap_stats = Arc::new(Mutex::new(None));
    let (packet_tx, packet_rx) = channel::<PacketEvent>();

    let capture_dev = if let Some(ref if_spec) = args.interface {
        let (_, name) = parse_interface_spec(if_spec);
        if name.is_empty() {
            eprintln!("Wrong interface is specified.\n");
            std::process::exit(1);
        }
        Some(name)
    } else {
        None
    };

    let pcap_file_mode = setup_packet_capture(
        &args,
        capture_dev.as_deref(),
        track_level,
        tracker.param.max_num_label,
        args.full_transport_header_check,
        packet_tx,
        pcap_stats.clone(),
        &GRACEFUL_SHUTDOWN,
    );

    daemonize_and_init_log(&args);
    let pidfile_path = resolve_and_write_pidfile(&args);
    drop_privileges();
    setup_export_targets(&args, &mut targets, is_ntopng);
    register_signals();
    drop_privileges();

    run_main_loop(
        args,
        tracker,
        targets,
        want_v6,
        ctl_path,
        control_listener,
        pcap_file_mode,
        pcap_stats,
        packet_rx,
        pidfile_path,
        boottime,
        if_index,
        cmd_rx,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsoftflowd::common::{
        ExpiryReason, FLOW_END_REASON_ACTIVE_TIMEOUT, FLOW_END_REASON_IDLE_TIMEOUT, Flow, FlowKey,
        TimeVal,
    };
    use rsoftflowd::exporter::{Destination, ExportSocket};
    use rsoftflowd::packet_parser::ParsedPacket;

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
        use std::net::{Ipv4Addr, UdpSocket};

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
