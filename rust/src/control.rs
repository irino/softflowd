use std::os::unix::net::UnixListener;
use std::sync::mpsc::Sender;
use std::thread;
use crate::common::{FlowTracker, Flow};

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
}

pub fn start_control_server(
    path: String,
    cmd_tx: Sender<ControlCommand>,
) -> std::io::Result<UnixListener> {
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;

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
                                _ => {
                                    let _ = (&stream).write_all(format!("Unknown control command \"{}\"\n", cmd_str).as_bytes());
                                    return;
                                }
                            };
                            if cmd_tx.send(cmd).is_ok() {
                                if let Ok(resp_str) = rx.recv() {
                                    let _ = (&stream).write_all(resp_str.as_bytes());
                                }
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

    Ok(listener)
}

fn format_time(t: i64) -> String {
    let datetime = chrono::DateTime::from_timestamp(t, 0).unwrap_or_default();
    datetime.format("%Y-%m-%dT%H:%M:%S").to_string()
}

fn format_ethermac(mac: &[u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
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

pub fn render_statistics(tracker: &FlowTracker) -> String {
    let mut out = String::new();
    let p = &tracker.param;

    out.push_str(&format!("Number of active flows: {}\n", tracker.flows.len()));
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
    out.push_str(&format!("Flows expired: {} ({} forced)\n", p.flows_expired, p.flows_force_expired));
    out.push_str(&format!(
        "Flows exported: {} ({} records) in {} packets ({} failures)\n",
        p.flows_exported, p.records_sent, p.packets_sent, p.flows_dropped
    ));
    out.push_str("\n");

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
        out.push_str("\n");

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
        out.push_str("\n");

        out.push_str("Per-protocol statistics:     Octets      Packets   Avg Life    Max Life\n");
        for i in 0..256 {
            if p.packets_pp[i] > 0 {
                let proto_name = match i {
                    1 => "icmp",
                    6 => "tcp",
                    17 => "udp",
                    58 => "ipv6-icmp",
                    _ => "unknown",
                };
                let proto_str = format!("{} ({})", proto_name, i);
                out.push_str(&format!(
                    "  {:17}: {:14} {:12}   {:8.2}s {:10.2}s\n",
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

pub fn render_dump_flows(tracker: &FlowTracker) -> String {
    let mut out = String::new();
    let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(_) => 0,
    };

    for flow in tracker.flows.values() {
        out.push_str(&format!("ACTIVE {}\n", format_flow(flow)));
        if let Some(exp) = flow.expiry_key {
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
        }
        out.push_str("\n");
    }
    out
}
