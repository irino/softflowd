use crate::common::{Flow, FlowTracker};
use std::os::unix::net::UnixListener;
use std::sync::mpsc::Sender;
use std::thread;

pub enum ControlCommand {
    Statistics { resp: Sender<String> },
    DumpFlows { resp: Sender<String> },
    Shutdown { resp: Sender<String> },
    ExpireAll { resp: Sender<String> },
    DeleteAll { resp: Sender<String> },
    Exit { resp: Sender<String> },
    DebugPlus { resp: Sender<String> },
    DebugMinus { resp: Sender<String> },
    StartGather { resp: Sender<String> },
    StopGather { resp: Sender<String> },
    SendTemplate { resp: Sender<String> },
    Timeouts { resp: Sender<String> },
    Help { resp: Sender<String> },
}

/// Makes the control socket.  A daemon does this before its fork, so that a failure is
/// written to the standard error, as C does.
///
/// Original: netsock.c (`unix_listener()`)
pub fn bind_control_socket(path: &str) -> std::io::Result<UnixListener> {
    let _ = std::fs::remove_file(path);
    UnixListener::bind(path)
}

/// Binds the control socket and starts the thread that serves it.
pub fn start_control_server(
    path: String,
    cmd_tx: Sender<ControlCommand>,
) -> std::io::Result<UnixListener> {
    let listener = bind_control_socket(&path)?;
    spawn_control_server(&listener, cmd_tx)?;
    Ok(listener)
}

/// Starts the thread that serves the control socket.  A daemon does this after its fork,
/// because a thread does not survive a fork.
pub fn spawn_control_server(
    listener: &UnixListener,
    cmd_tx: Sender<ControlCommand>,
) -> std::io::Result<()> {
    let listener_for_thread = listener.try_clone()?;
    thread::spawn(move || {
        for stream in listener_for_thread.incoming() {
            match stream {
                Ok(stream) => {
                    let cmd_tx = cmd_tx.clone();
                    thread::spawn(move || {
                        use std::io::{BufRead, BufReader, Write};
                        let mut reader = BufReader::new(&stream);
                        let mut line = String::new();
                        if reader.read_line(&mut line).is_ok() {
                            let cmd_str = line.trim();
                            let (tx, rx) = std::sync::mpsc::channel();
                            let cmd = match cmd_str {
                                "statistics" => ControlCommand::Statistics { resp: tx },
                                "dump-flows" => ControlCommand::DumpFlows { resp: tx },
                                "shutdown" => ControlCommand::Shutdown { resp: tx },
                                "expire-all" => ControlCommand::ExpireAll { resp: tx },
                                "delete-all" => ControlCommand::DeleteAll { resp: tx },
                                "exit" => ControlCommand::Exit { resp: tx },
                                "debug+" => ControlCommand::DebugPlus { resp: tx },
                                "debug-" => ControlCommand::DebugMinus { resp: tx },
                                "start-gather" => ControlCommand::StartGather { resp: tx },
                                "stop-gather" => ControlCommand::StopGather { resp: tx },
                                "send-template" => ControlCommand::SendTemplate { resp: tx },
                                "timeouts" => ControlCommand::Timeouts { resp: tx },
                                "help" => ControlCommand::Help { resp: tx },
                                _ => {
                                    let _ = (&stream).write_all(
                                        format!("Unknown control command \"{}\"\n", cmd_str)
                                            .as_bytes(),
                                    );
                                    return;
                                }
                            };
                            if cmd_tx.send(cmd).is_ok()
                                && let Ok(resp_str) = rx.recv()
                            {
                                let _ = (&stream).write_all(resp_str.as_bytes());
                            }
                        }
                    });
                }
                Err(e) => {
                    log::error!("Control server accept error: {}", e);
                    break;
                }
            }
        }
    });

    Ok(())
}

fn format_time(t: i64) -> String {
    let datetime = chrono::DateTime::from_timestamp(t, 0).unwrap_or_default();
    datetime.format("%Y-%m-%dT%H:%M:%S").to_string()
}

fn format_ethermac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

pub fn format_flow(flow: &Flow) -> String {
    let addr1 = flow.key.addr[0].to_string();
    let addr2 = flow.key.addr[1].to_string();
    let start_time = format_time(flow.flow_start.tv_sec);
    let fin_time = format_time(flow.flow_last.tv_sec);

    format!(
        "seq:{} [{}]:{} <> [{}]:{} proto:{} \
         octets>:{} packets>:{} octets<:{} packets<:{} \
         start:{}.{:03} finish:{}.{:03} tcp>:{:02x} tcp<:{:02x} \
         flowlabel>:{:08x} flowlabel<:{:08x} \
         vlan>:{} vlan<:{} ether:{} <> {}",
        flow.flow_seq,
        addr1,
        flow.key.port[0],
        addr2,
        flow.key.port[1],
        flow.key.protocol,
        flow.octets[0],
        flow.packets[0],
        flow.octets[1],
        flow.packets[1],
        start_time,
        (flow.flow_start.tv_usec + 500) / 1000,
        fin_time,
        (flow.flow_last.tv_usec + 500) / 1000,
        flow.tcp_flags[0],
        flow.tcp_flags[1],
        flow.ip6_flowlabel[0],
        flow.ip6_flowlabel[1],
        flow.key.vlanid[0],
        flow.key.vlanid[1],
        format_ethermac(&flow.key.ethermac[0]),
        format_ethermac(&flow.key.ethermac[1])
    )
}

/// Reads the protocols database: the name of the first entry of each number.
///
/// The format of a line is "name number [alias ...]", and "#" starts a
/// comment, as in `/etc/protocols`.
fn parse_protocols(text: &str) -> std::collections::HashMap<u8, String> {
    let mut names = std::collections::HashMap::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        let mut fields = line.split_whitespace();
        if let (Some(name), Some(number)) = (fields.next(), fields.next())
            && let Ok(number) = number.parse::<u8>()
        {
            // getprotobynumber() returns the first entry of a number.
            names.entry(number).or_insert_with(|| name.to_string());
        }
    }
    names
}

/// The name of an IP protocol for the per-protocol statistics.
///
/// Like C (`getprotobynumber()`), the name comes from `/etc/protocols`.
/// Where the file has no entry, for example in a container without it, the
/// names of the common protocols are used, and otherwise "Unknown".
fn protocol_name(protocol: u8) -> String {
    static DATABASE: std::sync::OnceLock<std::collections::HashMap<u8, String>> =
        std::sync::OnceLock::new();
    let database = DATABASE.get_or_init(|| {
        std::fs::read_to_string("/etc/protocols")
            .map(|text| parse_protocols(&text))
            .unwrap_or_default()
    });
    if let Some(name) = database.get(&protocol) {
        return name.clone();
    }
    match protocol {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        58 => "ipv6-icmp",
        _ => "Unknown",
    }
    .to_string()
}

/// Reads `/etc/protocols` now.  A daemon calls this before it changes its root directory, as C
/// calls `setprotoent(1)` before `drop_privs()`: after the `chroot` the file is not there, and
/// the names would be those of the common protocols only.
pub fn load_protocol_names() {
    let _ = protocol_name(0);
}

/// The reply of the control socket: the header of control.c, then the statistics.
pub fn render_statistics(tracker: &FlowTracker, pcap_stats: Option<(u64, u64, u64)>) -> String {
    let start_time_str = format_time(tracker.param.system_boot_time.tv_sec);
    format!(
        "Accumulated statistics since {} UTC:\n{}",
        start_time_str,
        render_statistics_body(tracker, pcap_stats)
    )
}

/// The statistics without the header: what C writes at the end of a file (stats.c,
/// statistics()).
pub fn render_statistics_body(
    tracker: &FlowTracker,
    pcap_stats: Option<(u64, u64, u64)>,
) -> String {
    let mut out = String::new();
    let p = &tracker.param;

    out.push_str(&format!(
        "Number of active flows: {}\n",
        tracker.flows.len()
    ));
    out.push_str(&format!("Packets processed: {}\n", p.total_packets));
    if p.non_sampled_packets > 0 {
        out.push_str(&format!("Packets non-sampled: {}\n", p.non_sampled_packets));
    }
    out.push_str(&format!("Fragments: {}\n", p.frag_packets));
    out.push_str(&format!(
        "Ignored packets: {} ({} non-IP, {} too short)\n",
        p.non_ip_packets + p.bad_packets,
        p.non_ip_packets,
        p.bad_packets
    ));
    out.push_str(&format!(
        "Flows expired: {} ({} forced)\n",
        p.flows_expired, p.flows_force_expired
    ));
    out.push_str(&format!(
        "Flows exported: {} ({} records) in {} packets ({} failures)\n",
        p.flows_exported, p.records_sent, p.packets_sent, p.flows_dropped
    ));

    if tracker.flow_lookup != crate::common::FlowLookupMode::Tree {
        // C: flow_table_bytes = buckets * sizeof (pointer)
        let size_bytes = tracker.nbuckets as usize * 8;
        let size_kb = size_bytes / 1024;
        let size_str = if size_kb > 0 {
            format!("{} KiB", size_kb)
        } else {
            format!("{} B", size_bytes)
        };
        let (used, maxdepth) = tracker.table_usage();
        out.push_str(&format!(
            "Flow table: {}, {} buckets ({}), {} in use, max depth {}, {} collisions\n",
            tracker.flow_lookup.name(),
            tracker.nbuckets,
            size_str,
            used,
            maxdepth,
            p.expired_collision
        ));
    }

    if let Some((recv, drop, ifdrop)) = pcap_stats {
        out.push_str(&format!("Packets received by libpcap: {}\n", recv));
        out.push_str(&format!("Packets dropped by libpcap: {}\n", drop));
        out.push_str(&format!("Packets dropped by interface: {}\n", ifdrop));
    }

    out.push('\n');

    if p.flows_expired > 0 {
        out.push_str("Expired flow statistics:  minimum       average       maximum\n");
        out.push_str(&format!(
            "  Flow bytes:        {:12.0}  {:12.0}  {:12.0}\n",
            p.octets.min, p.octets.mean, p.octets.max
        ));
        out.push_str(&format!(
            "  Flow packets:      {:12.0}  {:12.0}  {:12.0}\n",
            p.packets.min, p.packets.mean, p.packets.max
        ));
        out.push_str(&format!(
            "  Duration:          {:12.2}s {:12.2}s {:12.2}s\n",
            p.duration.min, p.duration.mean, p.duration.max
        ));
        out.push('\n');

        out.push_str("Expired flow reasons:\n");
        out.push_str(&format!(
            "       tcp = {:9}   tcp.rst = {:9}   tcp.fin = {:9}\n",
            p.expired_tcp, p.expired_tcp_rst, p.expired_tcp_fin
        ));
        out.push_str(&format!(
            "       udp = {:9}      icmp = {:9}   general = {:9}\n",
            p.expired_udp, p.expired_icmp, p.expired_general
        ));
        out.push_str(&format!("   maxlife = {:9}\n", p.expired_maxlife));
        out.push_str(&format!("over 2 GiB = {:9}\n", p.expired_overbytes));
        out.push_str(&format!("  maxflows = {:9}\n", p.expired_maxflows));
        out.push_str(&format!("   flushed = {:9}\n", p.expired_flush));
        if tracker.flow_lookup == crate::common::FlowLookupMode::Hash {
            out.push_str(&format!(" collision = {:9}\n", p.expired_collision));
        }
        out.push('\n');

        out.push_str("Per-protocol statistics:     Octets      Packets   Avg Life    Max Life\n");
        for i in 0..256 {
            if p.packets_pp[i] > 0 {
                let proto_str = format!("{} ({})", protocol_name(i as u8), i);
                out.push_str(&format!(
                    "  {:>17}: {:14} {:12}   {:>8.2}s {:>10.2}s\n",
                    proto_str,
                    p.octets_pp[i],
                    p.packets_pp[i],
                    p.duration_pp[i].mean,
                    p.duration_pp[i].max
                ));
            }
        }
    }

    out
}

pub fn render_timeouts(tracker: &FlowTracker) -> String {
    let p = &tracker.param;
    // C (stats.c): the labels are right-aligned to 22 columns.
    let rows = [
        ("TCP timeout", p.tcp_timeout),
        ("TCP post-RST timeout", p.tcp_rst_timeout),
        ("TCP post-FIN timeout", p.tcp_fin_timeout),
        ("UDP timeout", p.udp_timeout),
        ("ICMP timeout", p.icmp_timeout),
        ("General timeout", p.general_timeout),
        ("Maximum lifetime", p.maximum_lifetime),
        ("Expiry interval", p.expiry_interval),
    ];
    rows.iter()
        .map(|(label, secs)| format!("{label:>22}: {secs}s\n"))
        .collect()
}

pub fn render_help() -> &'static str {
    "Valid control words are:\n\
\tdebug+ debug- delete-all dump-flows exit expire-all\n\
\tshutdown start-gather statistics stop-gather timeouts\n\
\tsend-template\n"
}

pub fn render_dump_flows(tracker: &FlowTracker) -> String {
    let mut out = String::new();
    let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(_) => 0,
    };

    // As C (stats.c, dump_flows()): in the order of the expiry events, not in the
    // (random) order of a hash table.
    for (exp, flow_key) in tracker.expiries.iter() {
        let Some(flow) = tracker.flows.get(flow_key) else {
            continue;
        };
        out.push_str(&format!("ACTIVE {}\n", format_flow(flow)));
        let expires_in = exp.expires_at as i64 - now;
        if expires_in < 0 {
            out.push_str(&format!(
                "EXPIRY EVENT for flow {} now{}\n",
                flow.flow_seq,
                if exp.expires_at == 0 { " (FORCED)" } else { "" }
            ));
        } else {
            out.push_str(&format!(
                "EXPIRY EVENT for flow {} in {} seconds\n",
                flow.flow_seq, expires_in
            ));
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocols_database_first_entry_wins_and_comments_are_ignored() {
        let text = "# a comment\nip\t0\tIP\t# internet protocol\nicmp 1 ICMP\n\
                    xns-idp 22 XNS-IDP\nxns-idp-again 22\nbad line\nbig 300 BIG\n";
        let names = parse_protocols(text);
        assert_eq!(names.get(&0).map(String::as_str), Some("ip"));
        assert_eq!(names.get(&1).map(String::as_str), Some("icmp"));
        assert_eq!(names.get(&22).map(String::as_str), Some("xns-idp"));
        assert_eq!(names.len(), 3, "{names:?}");
    }

    #[test]
    fn common_protocols_have_a_name_without_the_database() {
        // Holds with and without /etc/protocols.
        assert_eq!(protocol_name(6), "tcp");
        assert_eq!(protocol_name(17), "udp");
        assert_eq!(protocol_name(1), "icmp");
    }
}
