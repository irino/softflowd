use std::net::{IpAddr, UdpSocket, TcpStream, ToSocketAddrs};
use std::sync::mpsc::channel;
use std::thread;
use std::time::{Duration, Instant};
use clap::Parser;
use nix::sys::signal::{self, SigAction, SigHandler, Signal};

use rsoftflowd::common::{
    FlowTracker, Flow, FlowKey, TimeVal, ExpiryReason, ExpiryKey, TrackLevel
};
use rsoftflowd::opts::RsoftflowdArgs;
use rsoftflowd::packet_parser::{parse_packet, ParsedPacket};
use rsoftflowd::exporter::{Destination, ExportSocket, NetflowTarget, SendParameter, send_flows};
use rsoftflowd::control::{ControlCommand, start_control_server, render_statistics, render_dump_flows};

fn parse_duration(s: &str) -> Option<i32> {
    let mut val = 0;
    let mut current_num = 0;
    for c in s.chars() {
        if c.is_ascii_digit() {
            current_num = current_num * 10 + c.to_digit(10).unwrap() as i32;
        } else {
            let mult = match c.to_ascii_lowercase() {
                's' => 1,
                'm' => 60,
                'h' => 3600,
                'd' => 3600 * 24,
                'w' => 3600 * 24 * 7,
                _ => return None,
            };
            val += current_num * mult;
            current_num = 0;
        }
    }
    val += current_num; // default seconds if no suffix
    Some(val)
}

fn apply_timeouts(tracker: &mut FlowTracker, timeout_specs: &[String]) {
    for spec in timeout_specs {
        let parts: Vec<&str> = spec.split('=').collect();
        if parts.len() != 2 {
            log::warn!("Invalid timeout specification: {}", spec);
            continue;
        }
        let name = parts[0].trim().to_ascii_lowercase();
        let val_str = parts[1].trim();
        let val = match parse_duration(val_str) {
            Some(v) => v,
            None => {
                log::warn!("Invalid timeout duration: {}", val_str);
                continue;
            }
        };

        match name.as_str() {
            "tcp" => tracker.param.tcp_timeout = val,
            "tcp.rst" => tracker.param.tcp_rst_timeout = val,
            "tcp.fin" => tracker.param.tcp_fin_timeout = val,
            "udp" => tracker.param.udp_timeout = val,
            "icmp" => tracker.param.icmp_timeout = val,
            "general" => tracker.param.general_timeout = val,
            "maxlife" => tracker.param.maximum_lifetime = val,
            "expint" => tracker.param.expiry_interval = val,
            _ => log::warn!("Unknown timeout name: {}", name),
        }
    }
}

static GRACEFUL_SHUTDOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn sig_handler(_sig: libc::c_int) {
    GRACEFUL_SHUTDOWN.store(true, std::sync::atomic::Ordering::SeqCst);
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
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = RsoftflowdArgs::parse();

    // 1. Logging setup
    let log_level = if args.debug {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    env_logger::Builder::new()
        .filter(None, log_level)
        .init();

    // 2. Daemonize if requested
    if !args.dont_fork && !args.debug {
        log::info!("Daemonising rsoftflowd...");
        if let Err(e) = nix::unistd::daemon(true, false) {
            log::error!("Failed to daemonise: {}", e);
            std::process::exit(1);
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
        if let Err(e) = std::fs::write(path, format!("{}\n", std::process::id())) {
            log::warn!("Could not write PID file {}: {}", path, e);
        }
    }

    // 3. Setup Flow Tracker
    let track_level = TrackLevel::from_str(&args.track_level)
        .expect("Invalid track level specified. Choose ip, proto, full, vlan, or ether");

    let mut tracker = FlowTracker::new(args.max_flows);
    tracker.param.track_level = track_level;
    tracker.param.sample_rate = args.sampling_rate;
    if let Some(ref ifname) = args.interface {
        tracker.param.interface_name = ifname.clone();
    }
    if let Some(ref exp_ip_str) = args.exporter_ip {
        if let Ok(ip) = exp_ip_str.parse::<IpAddr>() {
            tracker.param.exporter_ip = Some(ip);
        }
    }
    apply_timeouts(&mut tracker, &args.timeouts);

    // 4. Resolve and setup Netflow Exporter Targets
    let version = args.netflow_version.parse::<u16>().unwrap_or(5);
    let mut targets = NetflowTarget {
        destinations: Vec::new(),
        version,
        is_loadbalance: args.load_balance,
    };

    if let Some(ref col_str) = args.collector {
        for addr_str in col_str.split(',') {
            let addr_str = addr_str.trim();
            if addr_str.is_empty() {
                continue;
            }
            match addr_str.to_socket_addrs() {
                Ok(mut addrs) => {
                    if let Some(socket_addr) = addrs.next() {
                        let proto = args.transport_protocol.to_lowercase();
                        let socket = match proto.as_str() {
                            "tcp" => {
                                match TcpStream::connect(socket_addr) {
                                    Ok(s) => ExportSocket::Tcp(s),
                                    Err(e) => {
                                        log::error!("Failed to connect to TCP collector {}: {}", socket_addr, e);
                                        std::process::exit(1);
                                    }
                                }
                            }
                            _ => {
                                // Default UDP
                                let s = UdpSocket::bind("0.0.0.0:0")?;
                                s.connect(socket_addr)?;

                                // Bind to specific device if requested (Linux only)
                                #[cfg(target_os = "linux")]
                                if let Some(ref send_if) = args.send_interface {
                                    if let Err(e) = rsoftflowd::net_util_unsafe::bind_socket_to_device(&s, send_if) {
                                        log::error!("Failed to bind to interface {}: {}", send_if, e);
                                        std::process::exit(1);
                                    }
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

    // 5. Start UNIX domain socket control server
    let (cmd_tx, cmd_rx) = channel::<ControlCommand>();
    let ctl_path = match args.ctlsock.as_deref() {
        Some("none") => None,
        Some(path) => Some(path.to_string()),
        None => {
            if args.pcap_file.is_some() {
                None
            } else {
                Some("/var/run/softflowd.ctl".to_string())
            }
        }
    };
    let mut control_listener = None;
    if let Some(ref path) = ctl_path {
        match start_control_server(path.clone(), cmd_tx) {
            Ok(listener) => control_listener = Some(listener),
            Err(e) => {
                log::error!("Failed to start control server: {}", e);
                std::process::exit(1);
            }
        }
    }

    // 6. Signal integration
    register_signals();

    // 7. Packet Capture Setup (libpcap)
    let pcap_file_mode = args.pcap_file.is_some();
    tracker.param.adjust_time = args.adjust_time;

    // Start background packet receiver thread to read from PCAP
    let (packet_tx, packet_rx) = channel::<ParsedPacket>();
    let bpf_filter = if !args.bpf_expression.is_empty() {
        Some(args.bpf_expression.join(" "))
    } else {
        None
    };

    if let Some(ref file_path) = args.pcap_file {
        let mut capture = pcap::Capture::from_file(file_path)?;
        if let Some(ref filter) = bpf_filter {
            log::info!("Applying BPF filter: \"{}\"", filter);
            capture.filter(filter, true)?;
        }
        let linktype = capture.get_datalink().0;
        let packet_tx_clone = packet_tx.clone();

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
                        let timestamp = TimeVal {
                            tv_sec: raw_packet.header.ts.tv_sec as i64,
                            tv_usec: raw_packet.header.ts.tv_usec as i32,
                        };

                        if let Some(parsed) = parse_packet(linktype, &raw_packet.data, caplen, len, track_level, timestamp) {
                            let _ = packet_tx_clone.send(parsed);
                        }
                    }
                    Err(pcap::Error::NoMorePackets) => {
                        log::info!("End of PCAP file reached.");
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
    } else if let Some(ref dev_name) = args.interface {
        let snaplen = args.capture_length.unwrap_or(256) as i32;
        let mut builder = pcap::Capture::from_device(dev_name.as_str())?
            .snaplen(snaplen)
            .promisc(true)
            .buffer_size(1024 * 1024);
        builder = builder.immediate_mode(true);
        let mut capture = builder.open()?;

        if let Some(ref filter) = bpf_filter {
            log::info!("Applying BPF filter: \"{}\"", filter);
            capture.filter(filter, true)?;
        }
        let linktype = capture.get_datalink().0;
        let packet_tx_clone = packet_tx.clone();

        thread::spawn(move || {
            loop {
                if GRACEFUL_SHUTDOWN.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
                match capture.next_packet() {
                    Ok(raw_packet) => {
                        let caplen = raw_packet.header.caplen;
                        let len = raw_packet.header.len;
                        let timestamp = TimeVal {
                            tv_sec: raw_packet.header.ts.tv_sec as i64,
                            tv_usec: raw_packet.header.ts.tv_usec as i32,
                        };

                        if let Some(parsed) = parse_packet(linktype, &raw_packet.data, caplen, len, track_level, timestamp) {
                            let _ = packet_tx_clone.send(parsed);
                        }
                    }
                    Err(_) => {
                        // In live capture, timeout is normal, loop again
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

    // 8. Main Event Loop
    log::info!("rsoftflowd started. Version: {}", version);
    let mut last_expiry_scan = Instant::now();

    loop {
        // Handle signals
        if GRACEFUL_SHUTDOWN.load(std::sync::atomic::Ordering::SeqCst) {
            log::info!("Shutting down gracefully...");
            // Expire and flush all active flows
            flush_all_flows(&mut tracker, &targets);
            break;
        }

        // Handle control commands
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                ControlCommand::Statistics { resp } => {
                    let stats_str = render_statistics(&tracker);
                    let _ = resp.send(stats_str);
                }
                ControlCommand::DumpFlows { resp } => {
                    let dump_str = render_dump_flows(&tracker);
                    let _ = resp.send(dump_str);
                }
                ControlCommand::Shutdown { resp } => {
                    log::info!("Shutdown command received.");
                    GRACEFUL_SHUTDOWN.store(true, std::sync::atomic::Ordering::SeqCst);
                    let _ = resp.send("softflowd: Shutting down gracefully...\n".to_string());
                }
                ControlCommand::ExpireAll { resp } => {
                    let count = expire_all_flows(&mut tracker, &targets);
                    let _ = resp.send(format!("softflowd: Expired {} flows.\n", count));
                }
                ControlCommand::DeleteAll { resp } => {
                    let count = tracker.flows.len();
                    tracker.flows.clear();
                    tracker.expiries.clear();
                    let _ = resp.send(format!("softflowd: Deleted {} flows.\n", count));
                }
                ControlCommand::Exit { resp } => {
                    log::info!("Exit command received.");
                    let _ = resp.send("softflowd: Exiting now...\n".to_string());
                    std::process::exit(0);
                }
                ControlCommand::DebugPlus { resp } => {
                    let _ = resp.send("softflowd: Debug level increased (not implemented).\n".to_string());
                }
                ControlCommand::DebugMinus { resp } => {
                    let _ = resp.send("softflowd: Debug level decreased (not implemented).\n".to_string());
                }
                ControlCommand::StartGather { resp } => {
                    let _ = resp.send("softflowd: Data collection resumed.\n".to_string());
                }
                ControlCommand::StopGather { resp } => {
                    let _ = resp.send("softflowd: Data collection stopped.\n".to_string());
                }
                ControlCommand::SendTemplate { resp } => {
                    let _ = resp.send("softflowd: Template will be sent at next export.\n".to_string());
                }
            }
        }

        // Process incoming packet events
        let mut packets_processed_this_loop = 0;
        let mut channel_disconnected = false;
        loop {
            match packet_rx.try_recv() {
                Ok(parsed) => {
                    process_parsed_packet(&mut tracker, parsed);
                    packets_processed_this_loop += 1;
                    if packets_processed_this_loop > 1000 {
                        // Return to check commands/timers
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
            scan_expiries(&mut tracker, &targets, false);
            last_expiry_scan = Instant::now();
        }

        // Small sleep to yield CPU in live mode, unless we processed packets
        if packets_processed_this_loop == 0 {
            thread::sleep(Duration::from_millis(50));
        }

        // In offline PCAP file mode, if the packet channel is empty and thread has finished, we exit!
        if (pcap_file_mode && channel_disconnected) || GRACEFUL_SHUTDOWN.load(std::sync::atomic::Ordering::SeqCst) {
            log::info!("Shutting down. Processing remaining flows.");
            flush_all_flows(&mut tracker, &targets);
            // Print stats to stdout before exit as C softflowd does
            let final_stats = render_statistics(&tracker);
            println!("{}", final_stats);
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

    std::process::exit(0);
}

fn process_parsed_packet(tracker: &mut FlowTracker, parsed: ParsedPacket) {
    if tracker.param.total_packets == 0 {
        tracker.param.system_boot_time = parsed.timestamp;
    }

    // Sampling
    if tracker.param.sample_rate > 0 {
        if (tracker.param.total_packets + tracker.param.non_sampled_packets) % tracker.param.sample_rate as u64 > 0 {
            tracker.param.non_sampled_packets += 1;
            return;
        }
    }

    tracker.param.total_packets += 1;

    let timeval_packet = parsed.timestamp;
    tracker.param.last_packet_time = timeval_packet;

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

    // Get or create flow
    if !tracker.flows.contains_key(&key) {
        // Enforce max flows limit (evict oldest first)
        if tracker.flows.len() >= tracker.param.max_flows as usize {
            evict_oldest_flow(tracker);
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
            flow_end_reason: 0,
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

    // Standard flow expiry logic
    if flow.octets[0] > (1 << 31) || flow.octets[1] > (1 << 31) {
        expires_at = 0; // immediate
        reason = ExpiryReason::OverBytes;
        flow.flow_end_reason = 2; // Lack of resources / overbytes
    } else if param.maximum_lifetime != 0 && (flow.flow_last.tv_sec - flow.flow_start.tv_sec) as i32 >= param.maximum_lifetime {
        expires_at = 0;
        reason = ExpiryReason::MaxLife;
        flow.flow_end_reason = 1; // Active timeout
    } else if flow.key.protocol == 6 {
        // TCP
        let rst = (flow.tcp_flags[0] & 0x04) != 0 || (flow.tcp_flags[1] & 0x04) != 0;
        let fin = ((flow.tcp_flags[0] & 0x01) != 0) && ((flow.tcp_flags[1] & 0x01) != 0);

        if rst && param.tcp_rst_timeout > 0 {
            expires_at = flow.flow_last.tv_sec as u32 + param.tcp_rst_timeout as u32;
            reason = ExpiryReason::TcpRst;
            flow.flow_end_reason = 3; // End of flow
        } else if fin && param.tcp_fin_timeout > 0 {
            expires_at = flow.flow_last.tv_sec as u32 + param.tcp_fin_timeout as u32;
            reason = ExpiryReason::TcpFin;
            flow.flow_end_reason = 3;
        } else if param.tcp_timeout > 0 {
            expires_at = flow.flow_last.tv_sec as u32 + param.tcp_timeout as u32;
            reason = ExpiryReason::Tcp;
            flow.flow_end_reason = 4; // Idle timeout
        }
    } else if flow.key.protocol == 17 && param.udp_timeout > 0 {
        expires_at = flow.flow_last.tv_sec as u32 + param.udp_timeout as u32;
        reason = ExpiryReason::Udp;
        flow.flow_end_reason = 4;
    } else if (flow.key.protocol == 1 || flow.key.protocol == 58) && param.icmp_timeout > 0 {
        expires_at = flow.flow_last.tv_sec as u32 + param.icmp_timeout as u32;
        reason = ExpiryReason::Icmp;
        flow.flow_end_reason = 4;
    }

    if param.maximum_lifetime != 0 && expires_at != 0 {
        let max_expiry = flow.flow_start.tv_sec as u32 + param.maximum_lifetime as u32;
        expires_at = expires_at.min(max_expiry);
    }

    let new_expiry = ExpiryKey { expires_at, flow_seq: flow.flow_seq };
    flow.expiry_key = Some(new_expiry);
    flow.expiry_reason = reason;

    expiries.insert(new_expiry, flow.key.clone());
}

fn evict_oldest_flow(tracker: &mut FlowTracker) {
    if let Some((&expiry_key, flow_key)) = tracker.expiries.iter().next() {
        if let Some(mut flow) = tracker.flows.remove(flow_key) {
            tracker.expiries.remove(&expiry_key);
            tracker.param.flows_force_expired += 1;
            flow.expiry_reason = ExpiryReason::Overflows;
            flow.flow_end_reason = 2; // Lack of resources
            // Accumulate statistics
            accumulate_stats(tracker, &flow);
            log::debug!(
                "EXPIRED: {} ({:p})",
                rsoftflowd::control::format_flow(&flow),
                &flow
            );
        }
    }
}

fn accumulate_stats(tracker: &mut FlowTracker, flow: &Flow) {
    tracker.param.flows_expired += 1;
    tracker.param.flows_pp[flow.key.protocol as usize % 256] += 1;

    let duration_sec = (flow.flow_last.tv_sec - flow.flow_start.tv_sec) as f64 +
        ((flow.flow_last.tv_usec - flow.flow_start.tv_usec) as f64 / 1_000_000.0);
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
    }
}

fn scan_expiries(tracker: &mut FlowTracker, targets: &NetflowTarget, force_all: bool) -> usize {
    log::debug!("Starting expiry scan: mode {}", if force_all { 1 } else { 0 });

    let now_sec = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as u32,
        Err(_) => 0,
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
            if force_all {
                flow.expiry_reason = ExpiryReason::Flush;
                flow.flow_end_reason = 3; // End of flow
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
            ifidx: 1, // Default index
            param: &mut tracker.param,
            verbose: true,
        };
        let _ = send_flows(sp);
    }

    count
}

fn expire_all_flows(tracker: &mut FlowTracker, targets: &NetflowTarget) -> usize {
    scan_expiries(tracker, targets, true)
}

fn flush_all_flows(tracker: &mut FlowTracker, targets: &NetflowTarget) {
    expire_all_flows(tracker, targets);
}
