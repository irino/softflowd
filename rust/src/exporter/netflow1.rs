use crate::exporter::{SendParameter, get_active_now};
// use std::io::Write;

pub fn send_netflow_v1(sp: SendParameter) -> i32 {
    let now = get_active_now(sp.param);
    let uptime_ms = now.sub_ms(&sp.param.system_boot_time);

    let mut packet = Vec::with_capacity(1500);
    let mut flows_in_packet = 0;
    let mut num_packets = 0;
    let mut offset_to_flow_count = 0;

    let target_flows = sp.flows;
    let ifidx = sp.ifidx;

    for flow in target_flows {
        if flow.key.af != 2 {
            continue;
        }

        for dir in 0..2 {
            if flow.octets[dir] == 0 {
                continue;
            }

            if flows_in_packet >= 24 {
                // Send current packet
                if let Err(e) = send_packet(&mut packet, &sp, offset_to_flow_count, flows_in_packet) {
                    log::error!("Failed to send netflow v1 packet: {}", e);
                    sp.param.flows_dropped += flows_in_packet as u64;
                    return -1;
                }
                sp.param.records_sent += flows_in_packet as u64;
                sp.param.flows_exported += flows_in_packet as u64;
                flows_in_packet = 0;
                num_packets += 1;
            }

            if flows_in_packet == 0 {
                packet.clear();
                // 1. Write Header (16 bytes)
                packet.extend_from_slice(&1u16.to_be_bytes()); // Version
                offset_to_flow_count = packet.len();
                packet.extend_from_slice(&0u16.to_be_bytes()); // Flows count
                packet.extend_from_slice(&uptime_ms.to_be_bytes());
                packet.extend_from_slice(&(now.tv_sec as u32).to_be_bytes());
                packet.extend_from_slice(&((now.tv_usec * 1000) as u32).to_be_bytes());
            }

            // 2. Write Flow Record (40 bytes)
            let src_ip = match flow.key.addr[dir] {
                std::net::IpAddr::V4(ip) => u32::from(ip),
                _ => 0,
            };
            let dst_ip = match flow.key.addr[dir ^ 1] {
                std::net::IpAddr::V4(ip) => u32::from(ip),
                _ => 0,
            };

            packet.extend_from_slice(&src_ip.to_be_bytes());
            packet.extend_from_slice(&dst_ip.to_be_bytes());
            packet.extend_from_slice(&0u32.to_be_bytes()); // Nexthop IP
            packet.extend_from_slice(&ifidx.to_be_bytes());
            packet.extend_from_slice(&ifidx.to_be_bytes());
            packet.extend_from_slice(&flow.packets[dir].to_be_bytes());
            packet.extend_from_slice(&flow.octets[dir].to_be_bytes());

            let flow_start_ms = flow.flow_start.sub_ms(&sp.param.system_boot_time);
            let flow_last_ms = flow.flow_last.sub_ms(&sp.param.system_boot_time);
            packet.extend_from_slice(&flow_start_ms.to_be_bytes());
            packet.extend_from_slice(&flow_last_ms.to_be_bytes());

            packet.extend_from_slice(&flow.key.port[dir].to_be_bytes());
            packet.extend_from_slice(&flow.key.port[dir ^ 1].to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes()); // Pad
            packet.push(flow.key.protocol);
            packet.push(flow.tos[dir]);
            packet.push(flow.tcp_flags[dir]);
            packet.push(0); // Pad2
            packet.push(0); // Pad3
            packet.push(0); // Pad4
            packet.extend_from_slice(&0u32.to_be_bytes()); // Reserved

            flows_in_packet += 1;
        }
    }

    // Send leftovers
    if flows_in_packet > 0 {
        if let Err(e) = send_packet(&mut packet, &sp, offset_to_flow_count, flows_in_packet) {
            log::error!("Failed to send netflow v1 packet leftovers: {}", e);
            sp.param.flows_dropped += flows_in_packet as u64;
            return -1;
        }
        sp.param.records_sent += flows_in_packet as u64;
        sp.param.flows_exported += flows_in_packet as u64;
        num_packets += 1;
    }

    sp.param.packets_sent += num_packets;
    num_packets as i32
}

fn send_packet(
    packet: &mut [u8],
    sp: &SendParameter,
    offset_to_flow_count: usize,
    flows_count: u16,
) -> std::io::Result<()> {
    let count_bytes = flows_count.to_be_bytes();
    packet[offset_to_flow_count] = count_bytes[0];
    packet[offset_to_flow_count + 1] = count_bytes[1];

    let mut sent = 0;
    sp.target.send_multi_destinations(packet, &mut sent)
}
