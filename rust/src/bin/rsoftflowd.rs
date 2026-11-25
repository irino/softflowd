#![forbid(unsafe_code)]
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM, SIGUSR1};
use std::io::Write;
use std::net::{IpAddr, ToSocketAddrs, UdpSocket};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rsoftflowd::capture::{
    FileSource, PacketEvent, RawPacket, process_packet, process_raw_packet, setup_packet_capture,
    spawn_psamp_receiver,
};
use rsoftflowd::cli_errors::parse_daemon_args_or_exit;
use rsoftflowd::common::{FlowLookupMode, FlowTracker, TimeVal, TrackLevel, cpu_clock};
use rsoftflowd::control::{
    ControlCommand, render_dump_flows, render_help, render_statistics, render_statistics_body,
    render_timeouts, start_control_server,
};
use rsoftflowd::expire::*;
use rsoftflowd::exporter::NetflowTarget;
use rsoftflowd::netsock::{recvsock, setup_export_targets};
use rsoftflowd::opts::{
    RsoftflowdArgs, apply_timeouts, parse_boot_time_reinit, parse_interface_spec, parse_mac_address,
};
use rsoftflowd::packet_parser::ParsedPacket;
use rsoftflowd::usage::die_usage;

/// Why an argument of -n is refused.  Original: options.c, `parse_hostport()`.
enum HostPortError {
    /// "Invalid -n argument." with the usage.
    Invalid,
    /// The name or the port does not resolve: the message only, without the usage.
    NoAddresses(String),
}

fn validate_hostport(s: &str) -> Result<(), HostPortError> {
    // C: there must be a ':', something after it, and something in the argument before it.
    let (host, port) = match s.rfind(':') {
        Some(idx) if idx + 1 < s.len() && !s.is_empty() => (&s[..idx], &s[idx + 1..]),
        _ => return Err(HostPortError::Invalid),
    };
    // C: a numeric port that is too big for 16 bits (or for the number) is refused.
    if port.starts_with(|c: char| c.is_ascii_digit())
        && port.bytes().all(|b| b.is_ascii_digit())
        && !matches!(port.parse::<u64>(), Ok(n) if n <= 65535)
    {
        return Err(HostPortError::Invalid);
    }
    let resolved = s
        .to_socket_addrs()
        .is_ok_and(|mut addrs| addrs.next().is_some());
    if resolved {
        Ok(())
    } else {
        Err(HostPortError::NoAddresses(format!(
            "No addresses found for [{host}]:{port}"
        )))
    }
}

static GRACEFUL_SHUTDOWN: std::sync::LazyLock<Arc<AtomicBool>> =
    std::sync::LazyLock::new(|| Arc::new(AtomicBool::new(false)));
static HUP_RECEIVED: std::sync::LazyLock<Arc<AtomicBool>> =
    std::sync::LazyLock::new(|| Arc::new(AtomicBool::new(false)));
static USR1_RECEIVED: std::sync::LazyLock<Arc<AtomicBool>> =
    std::sync::LazyLock::new(|| Arc::new(AtomicBool::new(false)));

/// Register signal handlers for SIGINT, SIGTERM, SIGHUP.
///
/// Original: daemon.c (`register_signals()`)
fn register_signals() {
    let _ = signal_hook::flag::register(SIGINT, Arc::clone(&GRACEFUL_SHUTDOWN));
    let _ = signal_hook::flag::register(SIGTERM, Arc::clone(&GRACEFUL_SHUTDOWN));
    let _ = signal_hook::flag::register(SIGHUP, Arc::clone(&HUP_RECEIVED));
    let _ = signal_hook::flag::register(SIGUSR1, Arc::clone(&USR1_RECEIVED));
}

/// Drop privileges from root to 'nobody'.
///
/// Original: daemon.c (`drop_privileges()`)
fn drop_privileges() {
    #[cfg(unix)]
    {
        if nix::unistd::geteuid().is_root() {
            if let Some(pw) = nix::unistd::User::from_name("nobody").ok().flatten() {
                let _ = nix::unistd::setgid(pw.gid);
                let _ = nix::unistd::setuid(pw.uid);
            } else {
                log::warn!("Could not find 'nobody' user to drop privileges");
            }
        }
    }
}

/// Checks the options.  Returns the socket of `-R`, which C makes while it reads the options.
fn validate_options(args: &RsoftflowdArgs) -> Option<UdpSocket> {
    if args.max_flows < 1 {
        die_usage("Invalid maximum flows\n\n");
    }
    if let Some(hl) = args.hoplimit
        && !(0..=255).contains(&hl)
    {
        die_usage("Invalid hop limit\n\n");
    }
    if let Some(labels) = args.max_num_label
        && !(1..=10).contains(&labels)
    {
        die_usage("Invalid number of MPLS label (1 to 10)\n\n");
    }

    if let Some(ref col_str) = args.collector {
        if col_str.is_empty() {
            die_usage("Invalid -n argument.\n");
        }
        for addr_str in col_str.split(',') {
            let addr_str = addr_str.trim();
            if addr_str.is_empty() {
                die_usage("Invalid -n argument.\n");
            }
            match validate_hostport(addr_str) {
                Ok(()) => {}
                Err(HostPortError::Invalid) => die_usage("Invalid -n argument.\n"),
                Err(HostPortError::NoAddresses(msg)) => {
                    eprintln!("{msg}");
                    std::process::exit(1);
                }
            }
        }
    }
    let rsock = args.recv_port.map(recvsock);
    // C looks for the source after the options, so the errors of the options come first.
    if args.interface.is_none() && args.pcap_file.is_none() && rsock.is_none() {
        die_usage("-i, -r or -R option not specified.\n");
    }
    rsock
}

fn init_tracker(args: &RsoftflowdArgs) -> (TrackLevel, libc::clock_t, u16, FlowTracker) {
    let track_level = TrackLevel::from_name(&args.track_level)
        .expect("Invalid track level specified. Choose ip, proto, full, vlan, or ether");

    let boottime = cpu_clock();

    let (user_ifidx, capture_dev) = if let Some(ref if_spec) = args.interface {
        let (idx, name) = parse_interface_spec(if_spec);
        if name.is_empty() {
            die_usage("Wrong interface is specified.\n\n");
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
    // The interface, or the file name with -r (as the C version does).
    if let Some(ref ifname) = capture_dev {
        tracker.param.interface_name = ifname.clone();
    } else if let Some(ref file) = args.pcap_file {
        tracker.param.interface_name = file.clone();
    }
    if let Some(ref exp_ip_str) = args.exporter_ip {
        // C: getaddrinfo(); a name is resolved, and an error is written and the program goes on.
        let resolved = exp_ip_str.parse::<IpAddr>().ok().or_else(|| {
            (exp_ip_str.as_str(), 0u16)
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
                .map(|addr| addr.ip())
        });
        match resolved {
            Some(ip) => tracker.param.exporter_ip = Some(ip),
            None => eprintln!("getaddrinfo: Name or service not known"),
        }
    }
    if let Err(msg) = apply_timeouts(&mut tracker, &args.timeouts) {
        // C: the message of the "general" timeout is written without the usage.
        if msg.contains("must be greater than zero") {
            eprintln!("{msg}");
            std::process::exit(1);
        }
        die_usage(&format!("{msg}\n"));
    }

    if let Some(mode) = FlowLookupMode::from_name(&args.flow_lookup) {
        tracker.set_flow_lookup(mode);
    } else {
        die_usage("Invalid flow lookup mode\n\n");
    }

    if let Some(ref mac_str) = args.direction_mac {
        if let Some(mac) = parse_mac_address(mac_str) {
            tracker.param.direction_mac = Some(mac);
            tracker.param.direction_mac_set = true;
        } else {
            eprintln!("Invalid MAC address {mac_str}");
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
            Ok(v) => tracker.param.boot_time_reinit = v,
            Err(msg) => die_usage(&format!("{msg}\n")),
        }
    }

    tracker.param.adjust_time = args.adjust_time;
    tracker.param.use_thread = args.use_thread;

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
    // As C: -d, -D and -r (a file) run in the foreground and log to standard error.
    if args.dont_fork || args.debug || args.pcap_file.is_some() {
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
    mut file_source: Option<FileSource>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut stop_gather = false;
    // The parsed packet that every packet is written into, as C passes one flow structure.
    let mut scratch = ParsedPacket::default();
    // As C: 1 after an error that ended the run, otherwise 0.
    let mut exit_status = 0;
    let mut expiry_wakeup: Option<Instant> = None;
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
                    // As C: the loop is left with the return value of the control socket,
                    // so the status is 1 (a signal gives 0).
                    exit_status = 1;
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
                    log::warn!("Exiting immediately on user request");
                    let _ = resp.send(format!("{}Exiting now...\n", prefix));
                    if let Some(ref path) = ctl_path {
                        let _ = std::fs::remove_file(path);
                    }
                    if let Some(ref path) = pidfile_path {
                        let _ = std::fs::remove_file(path);
                    }
                    std::process::exit(1); // as C, see Shutdown
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

        // A shutdown request is handled at the end of the loop, where the flows
        // are exported before the program exits.
        if HUP_RECEIVED.swap(false, Ordering::SeqCst) {
            log::info!("SIGHUP received (config reload not implemented)");
        }
        if USR1_RECEIVED.swap(false, Ordering::SeqCst) {
            log::info!(
                "stats: tracked={} total_packets={}",
                tracker.flows.len(),
                tracker.param.total_packets
            );
        }

        // Process incoming packet events
        let mut packets_processed_this_loop = 0;
        let mut channel_disconnected = false;
        let mut read_error: Option<String> = None;
        // As pcap_dispatch(max_flows) of C: a batch is at most `-m` packets.  With
        // -r the batch is complete unless the file ends, so that it does not
        // depend on the speed of the capture thread.
        let batch_limit = tracker.param.max_flows as usize;
        loop {
            // A regular pcap file is read here, packet by packet, without the capture thread.
            if let Some(source) = file_source.as_mut() {
                match source.capture.next_packet() {
                    Ok(packet) => {
                        if !stop_gather {
                            #[allow(clippy::unnecessary_cast)]
                            let timestamp = TimeVal {
                                tv_sec: packet.header.ts.tv_sec as i64,
                                tv_usec: packet.header.ts.tv_usec as i32,
                            };
                            let raw = RawPacket {
                                linktype: source.linktype,
                                data: packet.data,
                                caplen: packet.header.caplen,
                                orig_len: packet.header.len,
                                timestamp,
                            };
                            process_packet(
                                &mut tracker,
                                &mut scratch,
                                &raw,
                                want_v6,
                                &targets,
                                if_index,
                            );
                        }
                        packets_processed_this_loop += 1;
                        if packets_processed_this_loop >= batch_limit {
                            break;
                        }
                    }
                    Err(pcap::Error::NoMorePackets) => {
                        // The statistics of a file are read once, at its end.
                        if let Ok(st) = source.capture.stats() {
                            *pcap_stats.lock().unwrap() =
                                Some((st.received as u64, st.dropped as u64, st.if_dropped as u64));
                        }
                        log::info!("Shutting down after pcap EOF");
                        channel_disconnected = true;
                        break;
                    }
                    Err(e) => {
                        read_error = Some(e.to_string());
                        break;
                    }
                }
                continue;
            }
            let next = if pcap_file_mode {
                packet_rx
                    .recv_timeout(Duration::from_millis(50))
                    .map_err(|e| match e {
                        std::sync::mpsc::RecvTimeoutError::Timeout => {
                            std::sync::mpsc::TryRecvError::Empty
                        }
                        std::sync::mpsc::RecvTimeoutError::Disconnected => {
                            std::sync::mpsc::TryRecvError::Disconnected
                        }
                    })
            } else {
                packet_rx.try_recv()
            };
            match next {
                Ok(PacketEvent::ReadError(message)) => {
                    read_error = Some(message);
                    break;
                }
                Ok(PacketEvent::Raw(raw_event)) => {
                    if !stop_gather {
                        process_raw_packet(
                            &mut tracker,
                            &mut scratch,
                            raw_event,
                            want_v6,
                            &targets,
                            if_index,
                        );
                    }
                    packets_processed_this_loop += 1;
                    if packets_processed_this_loop >= batch_limit {
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

        // Over -m after the batch, or a flow is due: scan, and force-expire the
        // oldest flows over -m, exporting them together, as C does.
        // As C: the expiry is looked at when poll() returns, that is, when a packet
        // came or the timeout that next_expire() gave has passed.
        let timed_out = expiry_wakeup.is_some_and(|w| Instant::now() >= w);
        // After a read error C leaves the loop at once: no expiry follows.
        if read_error.is_none()
            && (tracker.flows.len() > tracker.param.max_flows as usize
                || ((packets_processed_this_loop > 0 || timed_out) && next_expire_is_now(&tracker)))
        {
            let mode = if pcap_file_mode {
                ExpireMode::Forced
            } else {
                ExpireMode::Normal
            };
            expire_over_limit(&mut tracker, &targets, mode, if_index);
        }

        // The next timeout of poll(), computed again after every round (C).
        if packets_processed_this_loop > 0 || timed_out || expiry_wakeup.is_none() {
            expiry_wakeup =
                next_expire(&tracker).map(|ms| Instant::now() + Duration::from_millis(ms));
        }

        // Small sleep to yield CPU in live mode, unless we processed packets
        if packets_processed_this_loop == 0 {
            thread::sleep(Duration::from_millis(1));
        }

        // In offline PCAP file mode, if the packet channel is empty and thread has finished, we exit!
        if read_error.is_some()
            || (pcap_file_mode && channel_disconnected)
            || GRACEFUL_SHUTDOWN.load(std::sync::atomic::Ordering::SeqCst)
        {
            if let Some(ref message) = read_error {
                // As C: the flows that are still in the table are not exported.
                log::error!("Exiting on pcap_dispatch: {}", message);
                log::error!("Exiting immediately on internal error");
                exit_status = 1;
            } else {
                log::warn!("Shutting down on user request");
                flush_all_flows(&mut tracker, &targets, if_index);
            }
            // As C: the statistics go to stdout only when a file is read (-r),
            // not at the end of a live capture.
            if pcap_file_mode {
                let st = *pcap_stats.lock().unwrap();
                let final_stats = render_statistics_body(&tracker, st);
                print!("{}", final_stats);
            }
            break;
        }
    }

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
        if tracker.param.use_thread {
            eprintln!("cpu clocks (export): n/a with threaded export");
        } else {
            eprintln!(
                "cpu clocks (export): {} ({} calls)",
                tracker.param.export_clocks, tracker.param.export_calls
            );
        }
    }

    if exit_status != 0 {
        use std::io::Write;
        let _ = std::io::stdout().flush();
        std::process::exit(exit_status);
    }

    Ok(())
}

/// Main entry point of rsoftflowd.
///
/// Original: softflowd.c (`main()`)
pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: RsoftflowdArgs = parse_daemon_args_or_exit();

    let rsock = validate_options(&args);
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
                // C: unix_listener(): the text of errno, without "(os error N)".
                let text = e.to_string();
                let text = text.split(" (os error").next().unwrap_or(&text);
                if text.contains("shorter than SUN_LEN") {
                    eprintln!("control socket path too long");
                } else {
                    eprintln!("unix domain bind(\"{path}\") error: {text}");
                }
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

    // The source is opened before the daemonization and before the privileges
    // are dropped, as the C version does.  The capture thread starts reading
    // after the start-up log lines below.
    let (capture_start_tx, capture_start_rx) = channel::<()>();
    // As C: -R is the source only when neither -i nor -r is given.  Otherwise its socket
    // stays bound (in `rsock`) and is not read.
    let mut psamp_input = None;
    let (pcap_file_mode, file_source) = if let Some(socket) = rsock
        .as_ref()
        .filter(|_| args.interface.is_none() && args.pcap_file.is_none())
    {
        let socket = socket
            .try_clone()
            .expect("Failed to duplicate the PSAMP receive socket");
        psamp_input = Some((socket, packet_tx));
        (false, None)
    } else {
        setup_packet_capture(
            &args,
            capture_dev.as_deref(),
            track_level,
            tracker.param.max_num_label,
            args.full_transport_header_check,
            packet_tx,
            pcap_stats.clone(),
            &GRACEFUL_SHUTDOWN,
            capture_start_rx,
        )
    };

    daemonize_and_init_log(&args);
    let pidfile_path = resolve_and_write_pidfile(&args);
    // As C: only a daemon drops its privileges (-d, -D and -r stay in the foreground).
    if !(args.dont_fork || args.debug || args.pcap_file.is_some()) {
        drop_privileges();
    }
    setup_export_targets(&args, &mut targets, is_ntopng);
    register_signals();

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
    let _ = capture_start_tx.send(());
    // As C: the boot time (SysUptime) is the time of the start of the main loop.
    tracker.param.system_boot_time = TimeVal::now();
    // The thread is started here, after the fork of the daemonization.
    if let Some((socket, packet_tx)) = psamp_input {
        spawn_psamp_receiver(socket, packet_tx, &GRACEFUL_SHUTDOWN);
    }

    run_main_loop(
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
        file_source,
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
            key: std::sync::Arc::new(key.clone()),
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
            key: std::sync::Arc::new(key),
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
        use rsoftflowd::capture::process_parsed_packet;
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
                };
                process_parsed_packet(&mut tracker, parsed, true, &targets, 1);
            }

            // The batch is over: the table is brought back to -m, and the flows
            // that leave are exported (here and with expire_all_flows(), all 6).
            expire_over_limit(&mut tracker, &targets, ExpireMode::Forced, 1);
            assert!(tracker.flows.len() <= 5);
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
