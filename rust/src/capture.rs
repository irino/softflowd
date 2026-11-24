use crate::common::{
    ExpiryReason, FLOW_END_REASON_IDLE_TIMEOUT, FLOW_END_REASON_LACK_OF_RESOURCE, Flow, FlowKey,
    FlowLookupMode, FlowTracker, TimeVal, TrackLevel,
};
use crate::expire::update_flow_expiry;
use crate::exporter::psamp::send_psamp;
use crate::exporter::{NetflowTarget, SendParameter, send_flows};
use crate::opts::RsoftflowdArgs;
use crate::packet_parser::{ParseError, ParsedPacket, datalink_supported, parse_packet_into};
use crate::stats::accumulate_stats;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Debug)]
pub struct RawPacketEvent {
    pub linktype: i32,
    pub data: Vec<u8>,
    pub caplen: u32,
    pub orig_len: u32,
    pub timestamp: TimeVal,
}

#[derive(Debug)]
pub enum PacketEvent {
    Raw(RawPacketEvent),
    /// Reading the file failed, for example because of a damaged record header.
    /// C: pcap_dispatch() returns -1.
    ReadError(String),
}

/// A pcap file that the main thread reads itself, packet by packet, without a
/// capture thread, a channel and a copy of each packet.
///
/// Only a regular file is read this way: reading a FIFO or a terminal blocks, and the
/// main thread must go on with the timers and the control socket (C waits with poll()).
pub struct FileSource {
    pub capture: pcap::Capture<pcap::Offline>,
    pub linktype: i32,
}

/// The text of an error of libpcap, as `pcap_geterr()` gives it: the crate writes "libpcap error:" before it.
fn pcap_message(e: &pcap::Error) -> String {
    match e {
        pcap::Error::PcapError(text) => text.clone(),
        other => other.to_string(),
    }
}

/// As C (capture.c, setup_packet_capture()): a data link type that is not read is
/// reported before the filter is applied, and the program exits with 1.
fn check_datalink(linktype: i32) {
    if !datalink_supported(linktype) {
        eprintln!("Unsupported datalink type {}", linktype);
        std::process::exit(1);
    }
}

/// Opens the packet capture source (live interface or PCAP file), applies BPF filters,
/// and starts the capture thread.  The thread waits for a message on
/// `start_rx` before it reads the first packet, so that the caller can open the
/// source with the privileges it has, then daemonize, drop the privileges and
/// write its start-up log lines before any packet, or the end of a file, is
/// seen.
///
/// Original: capture.c (`setup_packet_capture()`)
#[allow(clippy::too_many_arguments)]
pub fn setup_packet_capture(
    args: &RsoftflowdArgs,
    capture_dev: Option<&str>,
    _track_level: TrackLevel,
    _max_num_label: u8,
    _full_l4hdr: bool,
    packet_tx: Sender<PacketEvent>,
    pcap_stats: Arc<Mutex<Option<(u64, u64, u64)>>>,
    graceful_shutdown: &'static AtomicBool,
    start_rx: Receiver<()>,
) -> (bool, Option<FileSource>) {
    let pcap_file_mode = args.pcap_file.is_some();
    let regular_file = args
        .pcap_file
        .as_deref()
        .is_some_and(|path| std::fs::metadata(path).is_ok_and(|m| m.is_file()));
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
                check_datalink(capture.get_datalink().0);
                if let Some(ref filter) = bpf_expression {
                    log::info!("Applying BPF filter: \"{}\"", filter);
                    if let Err(e) = capture.filter(filter, true) {
                        eprintln!("pcap_compile(\"{}\"): {}", filter, pcap_message(&e));
                        std::process::exit(1);
                    }
                }
                pcap_file_capture = Some(capture);
            }
            Err(e) => {
                eprintln!("pcap_open_offline({}): {}", file_path, pcap_message(&e));
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
                eprintln!("pcap_create: {}", pcap_message(&e));
                std::process::exit(1);
            }
        }
        .snaplen(snaplen)
        // The read times out every second, so that the libpcap counters are
        // refreshed when no packet comes (immediate mode: no delay for packets).
        .timeout(1000)
        .promisc(!args.no_promisc);

        // As C: the buffer size of libpcap (2 MiB) unless -B is given.
        if let Some(buf_size) = args.buffer_size {
            builder = builder.buffer_size(buf_size as i32);
        }
        builder = builder.immediate_mode(true);
        let mut capture = match builder.open() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("pcap_activate: {}", pcap_message(&e));
                std::process::exit(1);
            }
        };
        check_datalink(capture.get_datalink().0);

        if let Some(ref filter) = bpf_expression {
            log::info!("Applying BPF filter: \"{}\"", filter);
            if let Err(e) = capture.filter(filter, true) {
                eprintln!("pcap_compile(\"{}\"): {}", filter, pcap_message(&e));
                std::process::exit(1);
            }
        }
        pcap_device_capture = Some(capture);
    } else {
        eprintln!("Must specify either a live interface (-i) or offline pcap file (-r)\n");
        std::process::exit(1);
    }

    // A regular file is read by the main thread, see FileSource.
    let file_source = if regular_file {
        pcap_file_capture.take().map(|capture| FileSource {
            linktype: capture.get_datalink().0,
            capture,
        })
    } else {
        None
    };

    if let Some(mut capture) = pcap_file_capture {
        let linktype = capture.get_datalink().0;
        let packet_tx_clone = packet_tx.clone();
        let pcap_stats_clone = pcap_stats.clone();
        let graceful_shutdown_clone = graceful_shutdown;

        thread::spawn(move || {
            if start_rx.recv().is_err() {
                return;
            }
            log::debug!("Packet capture thread started.");
            loop {
                if graceful_shutdown_clone.load(std::sync::atomic::Ordering::SeqCst) {
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

                        // The statistics of a file are read once, at its end: libpcap has
                        // none for a file, so a call for each packet only builds an error.
                        let raw_event = RawPacketEvent {
                            linktype,
                            data,
                            caplen,
                            orig_len: len,
                            timestamp,
                        };
                        let _ = packet_tx_clone.send(PacketEvent::Raw(raw_event));
                    }
                    Err(pcap::Error::NoMorePackets) => {
                        if let Ok(st) = capture.stats() {
                            let mut s = pcap_stats_clone.lock().unwrap();
                            *s =
                                Some((st.received as u64, st.dropped as u64, st.if_dropped as u64));
                        }
                        log::info!("Shutting down after pcap EOF");
                        break;
                    }
                    Err(e) => {
                        let _ = packet_tx_clone.send(PacketEvent::ReadError(e.to_string()));
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
            if start_rx.recv().is_err() {
                return;
            }
            let mut last_stats = std::time::Instant::now() - std::time::Duration::from_secs(2);
            refresh_pcap_stats(&mut capture, &pcap_stats_clone, &mut last_stats);
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

                        refresh_pcap_stats(&mut capture, &pcap_stats_clone, &mut last_stats);

                        let raw_event = RawPacketEvent {
                            linktype,
                            data,
                            caplen,
                            orig_len: len,
                            timestamp,
                        };
                        let _ = packet_tx_clone.send(PacketEvent::Raw(raw_event));
                    }
                    Err(_) => {
                        // A timeout: keep the counters of the control socket current.
                        refresh_pcap_stats(&mut capture, &pcap_stats_clone, &mut last_stats);
                        continue;
                    }
                }
            }
        });
    } else if file_source.is_none() {
        log::error!("Must specify either a live interface (-i) or offline pcap file (-r)");
        std::process::exit(1);
    }

    (pcap_file_mode, file_source)
}

pub fn process_raw_packet(
    tracker: &mut FlowTracker,
    scratch: &mut ParsedPacket,
    raw: RawPacketEvent,
    want_v6: bool,
    targets: &NetflowTarget,
    ifidx: u16,
) {
    let packet = RawPacket {
        linktype: raw.linktype,
        data: &raw.data,
        caplen: raw.caplen,
        orig_len: raw.orig_len,
        timestamp: raw.timestamp,
    };
    process_packet(tracker, scratch, &packet, want_v6, targets, ifidx);
}

/// A packet that the caller owns, read from the capture without a copy.
pub struct RawPacket<'a> {
    pub linktype: i32,
    pub data: &'a [u8],
    pub caplen: u32,
    pub orig_len: u32,
    pub timestamp: TimeVal,
}

/// Counts and tracks one packet: the work of C's `process_packet()` callback.
pub fn process_packet(
    tracker: &mut FlowTracker,
    scratch: &mut ParsedPacket,
    raw: &RawPacket<'_>,
    want_v6: bool,
    targets: &NetflowTarget,
    ifidx: u16,
) {
    if tracker.param.total_packets == 0 && tracker.param.non_sampled_packets == 0 {
        tracker.param.system_boot_time = raw.timestamp;
    }

    if tracker.param.boot_time_reinit > 0 {
        let diff = raw.timestamp.tv_sec - tracker.param.system_boot_time.tv_sec;
        if diff >= tracker.param.boot_time_reinit as i64 {
            log::info!("Reinitializing system boot time due to -I option.");
            tracker.param.system_boot_time = raw.timestamp;
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
    tracker.param.last_packet_time = raw.timestamp;

    if tracker.param.is_psamp {
        send_psamp(
            raw.data,
            raw.caplen,
            raw.timestamp,
            targets,
            tracker.param.total_packets,
            &tracker.param,
        );
        return;
    }

    match parse_packet_into(
        raw.linktype,
        raw.data,
        raw.caplen,
        raw.orig_len,
        tracker.param.track_level,
        tracker.param.max_num_label,
        tracker.param.full_l4hdr_check,
        raw.timestamp,
        scratch,
    ) {
        Ok(()) => {
            if !want_v6 && scratch.af == 10 {
                tracker.param.non_ip_packets += 1;
                tracker.param.total_packets -= 1;
                return;
            }
            process_valid_parsed_packet(tracker, scratch, targets, ifidx);
        }
        Err(ParseError::NonIp) => {
            tracker.param.non_ip_packets += 1;
            tracker.param.total_packets -= 1;
        }
        Err(ParseError::TooShort) => {
            tracker.param.bad_packets += 1;
        }
        Err(ParseError::TooShortV6) => {
            // C decides by the family of the datalink header: without -6 an IPv6
            // packet is not IP, however short it is.
            if want_v6 {
                tracker.param.bad_packets += 1;
            } else {
                tracker.param.non_ip_packets += 1;
                tracker.param.total_packets -= 1;
            }
        }
    }
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

    // PSAMP mode is handled by process_packet(), before the packet is parsed: the
    // parsed packet does not hold the raw packet, which is not copied for each packet.
    process_valid_parsed_packet(tracker, &parsed, targets, ifidx);
}

fn process_valid_parsed_packet(
    tracker: &mut FlowTracker,
    parsed: &ParsedPacket,
    targets: &NetflowTarget,
    ifidx: u16,
) {
    let timeval_packet = parsed.timestamp;

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

    // Get or create the flow.  One lookup serves a packet of a known flow: the key is
    // hashed and compared once, not by contains_key() and again by get_mut().
    match tracker.flows.get_mut(&key) {
        Some(flow) => {
            flow.octets[ndx] = flow.octets[ndx].saturating_add(parsed.length);
            flow.packets[ndx] = flow.packets[ndx].saturating_add(1);
            flow.tcp_flags[ndx] |= parsed.tcp_flags;
            // As C (process_packet): the ToS is that of the packet that made the flow; it
            // is not changed by the next packets.
            flow.flow_last = timeval_packet;

            // Update expiry, unless the flow is to be expired at once (expires_at 0)
            if flow.expiry_key.is_none_or(|k| k.expires_at != 0) {
                update_flow_expiry(&mut tracker.expiries, &tracker.param, flow);
            }
        }
        None => {
            // As in C, the table may go over -m for the length of a batch of
            // packets; expire_over_limit() brings it back after the batch.
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
                key: std::sync::Arc::new(key.clone()),
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
        }
    }
}

/// received, dropped, dropped by the interface
type SharedPcapStats = Arc<Mutex<Option<(u64, u64, u64)>>>;

/// Copy the libpcap counters for the control socket and the final statistics, at
/// most once a second (the call is a system call).
fn refresh_pcap_stats(
    capture: &mut pcap::Capture<pcap::Active>,
    shared: &SharedPcapStats,
    last: &mut std::time::Instant,
) {
    if last.elapsed() < std::time::Duration::from_secs(1) {
        return;
    }
    *last = std::time::Instant::now();
    if let Ok(st) = capture.stats() {
        *shared.lock().unwrap() =
            Some((st.received as u64, st.dropped as u64, st.if_dropped as u64));
    }
}
