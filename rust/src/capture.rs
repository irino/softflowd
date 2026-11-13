use crate::common::{
    ExpiryReason, FLOW_END_REASON_IDLE_TIMEOUT, FLOW_END_REASON_LACK_OF_RESOURCE, Flow, FlowKey,
    FlowLookupMode, FlowTracker, TimeVal, TrackLevel,
};
use crate::expire::{evict_oldest_flow, update_flow_expiry};
use crate::exporter::psamp::send_psamp;
use crate::exporter::{NetflowTarget, SendParameter, send_flows};
use crate::opts::RsoftflowdArgs;
use crate::packet_parser::{ParseError, ParsedPacket, parse_packet};
use crate::stats::accumulate_stats;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Debug)]
pub enum PacketEvent {
    Parsed(ParsedPacket),
    NonIp,
    TooShort,
}

/// Opens the packet capture source (live interface or PCAP file), applies BPF filters,
/// and starts the capture thread.
///
/// Original: capture.c (`setup_packet_capture()`)
#[allow(clippy::too_many_arguments)]
pub fn setup_packet_capture(
    args: &RsoftflowdArgs,
    capture_dev: Option<&str>,
    track_level: TrackLevel,
    max_num_label: u8,
    full_l4hdr: bool,
    packet_tx: Sender<PacketEvent>,
    pcap_stats: Arc<Mutex<Option<(u64, u64, u64)>>>,
    graceful_shutdown: &'static AtomicBool,
) -> bool {
    let pcap_file_mode = args.pcap_file.is_some();
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
    } else if let Some(dev_name) = capture_dev {
        if dev_name.is_empty() {
            eprintln!("Wrong interface is specified.\n");
            std::process::exit(1);
        }
        let snaplen = args.capture_length.unwrap_or(256) as i32;
        let mut builder = match pcap::Capture::from_device(dev_name) {
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

    if let Some(mut capture) = pcap_file_capture {
        let linktype = capture.get_datalink().0;
        let packet_tx_clone = packet_tx.clone();
        let pcap_stats_clone = pcap_stats.clone();

        thread::spawn(move || {
            log::debug!("Packet capture thread started.");
            loop {
                if graceful_shutdown.load(std::sync::atomic::Ordering::SeqCst) {
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

                        match parse_packet(
                            linktype,
                            &data,
                            caplen,
                            len,
                            track_level,
                            max_num_label,
                            full_l4hdr,
                            timestamp,
                        ) {
                            Ok(parsed) => {
                                let _ = packet_tx_clone.send(PacketEvent::Parsed(parsed));
                            }
                            Err(ParseError::NonIp) => {
                                let _ = packet_tx_clone.send(PacketEvent::NonIp);
                            }
                            Err(ParseError::TooShort) => {
                                let _ = packet_tx_clone.send(PacketEvent::TooShort);
                            }
                        }
                    }
                    Err(pcap::Error::NoMorePackets) => {
                        log::info!("Shutting down after pcap EOF");
                        if let Ok(st) = capture.stats() {
                            let mut s = pcap_stats_clone.lock().unwrap();
                            *s =
                                Some((st.received as u64, st.dropped as u64, st.if_dropped as u64));
                        }
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
                if graceful_shutdown.load(std::sync::atomic::Ordering::SeqCst) {
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

                        match parse_packet(
                            linktype,
                            &data,
                            caplen,
                            len,
                            track_level,
                            max_num_label,
                            full_l4hdr,
                            timestamp,
                        ) {
                            Ok(parsed) => {
                                let _ = packet_tx_clone.send(PacketEvent::Parsed(parsed));
                            }
                            Err(ParseError::NonIp) => {
                                let _ = packet_tx_clone.send(PacketEvent::NonIp);
                            }
                            Err(ParseError::TooShort) => {
                                let _ = packet_tx_clone.send(PacketEvent::TooShort);
                            }
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

    pcap_file_mode
}

/// Processes a parsed packet, updating flow tracking state and exporting flows or PSAMP records as needed.
///
/// Original: capture.c, packet.c (`process_packet()`)
pub fn process_parsed_packet(
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
        send_psamp(
            &parsed.raw_packet,
            parsed.raw_packet.len() as u32,
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
