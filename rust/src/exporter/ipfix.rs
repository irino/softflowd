use crate::exporter::{SendParameter, get_active_now};
// use std::io::Write;

// IPFIX Constants
const IPFIX_TEMPLATE_SET_ID: u16 = 2;
const IPFIX_OPTION_TEMPLATE_SET_ID: u16 = 3;

const IPFIX_SOFTFLOWD_V4_TEMPLATE_ID: u16 = 1024;
const IPFIX_SOFTFLOWD_V6_TEMPLATE_ID: u16 = 2048;
const IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID: u16 = 256;

const IPFIX_SOURCE_IPV4_ADDRESS: u16 = 8;
const IPFIX_DESTINATION_IPV4_ADDRESS: u16 = 12;
const IPFIX_SOURCE_IPV6_ADDRESS: u16 = 27;
const IPFIX_DESTINATION_IPV6_ADDRESS: u16 = 28;
const IPFIX_OCTET_DELTA_COUNT: u16 = 1;
const IPFIX_PACKET_DELTA_COUNT: u16 = 2;
const IPFIX_INGRESS_INTERFACE: u16 = 10;
const IPFIX_EGRESS_INTERFACE: u16 = 14;
const IPFIX_FLOW_START_SYSUPTIME: u16 = 166;
const IPFIX_FLOW_END_SYSUPTIME: u16 = 167;
const IPFIX_SOURCE_TRANSPORT_PORT: u16 = 7;
const IPFIX_DESTINATION_TRANSPORT_PORT: u16 = 11;
const IPFIX_PROTOCOL_IDENTIFIER: u16 = 4;
const IPFIX_TCP_CONTROL_BITS: u16 = 6;
const IPFIX_IP_VERSION: u16 = 60;
const IPFIX_IP_CLASS_OF_SERVICE: u16 = 5;
const IPFIX_SYSTEM_INIT_TIME_MILLISECONDS: u16 = 160;

static mut PKTS_UNTIL_TEMPLATE: i32 = -1;

fn write_templates(packet: &mut Vec<u8>) {
    // 1. IPv4 Template Flowset
    packet.extend_from_slice(&IPFIX_TEMPLATE_SET_ID.to_be_bytes());
    packet.extend_from_slice(&64u16.to_be_bytes());
    packet.extend_from_slice(&IPFIX_SOFTFLOWD_V4_TEMPLATE_ID.to_be_bytes());
    packet.extend_from_slice(&14u16.to_be_bytes());

    let v4_fields = [
        (IPFIX_SOURCE_IPV4_ADDRESS, 4),
        (IPFIX_DESTINATION_IPV4_ADDRESS, 4),
        (IPFIX_OCTET_DELTA_COUNT, 4),
        (IPFIX_PACKET_DELTA_COUNT, 4),
        (IPFIX_INGRESS_INTERFACE, 4),
        (IPFIX_EGRESS_INTERFACE, 4),
        (IPFIX_SOURCE_TRANSPORT_PORT, 2),
        (IPFIX_DESTINATION_TRANSPORT_PORT, 2),
        (IPFIX_PROTOCOL_IDENTIFIER, 1),
        (IPFIX_TCP_CONTROL_BITS, 1),
        (IPFIX_IP_VERSION, 1),
        (IPFIX_IP_CLASS_OF_SERVICE, 1),
        (IPFIX_FLOW_START_SYSUPTIME, 4),
        (IPFIX_FLOW_END_SYSUPTIME, 4),
    ];
    for &(id, len) in &v4_fields {
        packet.extend_from_slice(&(id as u16).to_be_bytes());
        packet.extend_from_slice(&(len as u16).to_be_bytes());
    }

    // 2. IPv6 Template Flowset
    packet.extend_from_slice(&IPFIX_TEMPLATE_SET_ID.to_be_bytes());
    packet.extend_from_slice(&64u16.to_be_bytes());
    packet.extend_from_slice(&IPFIX_SOFTFLOWD_V6_TEMPLATE_ID.to_be_bytes());
    packet.extend_from_slice(&14u16.to_be_bytes());

    let v6_fields = [
        (IPFIX_SOURCE_IPV6_ADDRESS, 16),
        (IPFIX_DESTINATION_IPV6_ADDRESS, 16),
        (IPFIX_OCTET_DELTA_COUNT, 4),
        (IPFIX_PACKET_DELTA_COUNT, 4),
        (IPFIX_INGRESS_INTERFACE, 4),
        (IPFIX_EGRESS_INTERFACE, 4),
        (IPFIX_SOURCE_TRANSPORT_PORT, 2),
        (IPFIX_DESTINATION_TRANSPORT_PORT, 2),
        (IPFIX_PROTOCOL_IDENTIFIER, 1),
        (IPFIX_TCP_CONTROL_BITS, 1),
        (IPFIX_IP_VERSION, 1),
        (IPFIX_IP_CLASS_OF_SERVICE, 1),
        (IPFIX_FLOW_START_SYSUPTIME, 4),
        (IPFIX_FLOW_END_SYSUPTIME, 4),
    ];
    for &(id, len) in &v6_fields {
        packet.extend_from_slice(&(id as u16).to_be_bytes());
        packet.extend_from_slice(&(len as u16).to_be_bytes());
    }
}

fn write_option_template(packet: &mut Vec<u8>) {
    packet.extend_from_slice(&IPFIX_OPTION_TEMPLATE_SET_ID.to_be_bytes());
    packet.extend_from_slice(&24u16.to_be_bytes());
    packet.extend_from_slice(&IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID.to_be_bytes());
    packet.extend_from_slice(&4u16.to_be_bytes()); // Scope length
    packet.extend_from_slice(&8u16.to_be_bytes()); // Options length

    // Scope: System (ID 144)
    packet.extend_from_slice(&144u16.to_be_bytes());
    packet.extend_from_slice(&4u16.to_be_bytes());

    // Option: SystemInitTimeMilliseconds (ID 160)
    packet.extend_from_slice(&IPFIX_SYSTEM_INIT_TIME_MILLISECONDS.to_be_bytes());
    packet.extend_from_slice(&8u16.to_be_bytes());
}

fn write_option_data(packet: &mut Vec<u8>, boot_time: &crate::common::TimeVal) {
    packet.extend_from_slice(&IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID.to_be_bytes());
    packet.extend_from_slice(&12u16.to_be_bytes());

    // Scope (System ID = 1)
    packet.extend_from_slice(&1u32.to_be_bytes());

    // Init Time
    let ms = (boot_time.tv_sec as u64 * 1000) + (boot_time.tv_usec as u64 / 1000);
    packet.extend_from_slice(&ms.to_be_bytes());
}

pub fn send_ipfix(sp: SendParameter) -> i32 {
    let now = get_active_now(sp.param);
    let mut packet = Vec::with_capacity(1500);
    let mut flows_in_packet = 0;
    let mut num_packets = 0;
    let mut current_template_id = 0;
    let mut offset_to_flowset_len = 0;
    let mut flowset_start_offset = 0;

    let target_flows = sp.flows;
    let ifidx = sp.ifidx;

    let mut send_templates_now = false;
    unsafe {
        if PKTS_UNTIL_TEMPLATE <= 0 {
            send_templates_now = true;
            PKTS_UNTIL_TEMPLATE = 16;
        }
        PKTS_UNTIL_TEMPLATE -= 1;
    }

    if send_templates_now {
        packet.clear();
        packet.extend_from_slice(&10u16.to_be_bytes()); // Version (IPFIX)
        packet.extend_from_slice(&0u16.to_be_bytes()); // Length (fill later)
        packet.extend_from_slice(&(now.tv_sec as u32).to_be_bytes());
        packet.extend_from_slice(&(sp.param.records_sent as u32).to_be_bytes()); // Sequence
        packet.extend_from_slice(&0u32.to_be_bytes()); // Observation Domain ID

        write_templates(&mut packet);
        write_option_template(&mut packet);
        write_option_data(&mut packet, &sp.param.system_boot_time);

        let packet_len = packet.len() as u16;
        let len_bytes = packet_len.to_be_bytes();
        packet[2] = len_bytes[0];
        packet[3] = len_bytes[1];

        let mut sent = 0;
        let _ = sp.target.send_multi_destinations(&packet, &mut sent);
        sp.param.packets_sent += 1;
        packet.clear();
    }

    for flow in target_flows {
        let is_v6 = flow.key.af == 10;
        let flow_template_id = if is_v6 { IPFIX_SOFTFLOWD_V6_TEMPLATE_ID } else { IPFIX_SOFTFLOWD_V4_TEMPLATE_ID };

        for dir in 0..2 {
            if flow.octets[dir] == 0 {
                continue;
            }

            if packet.len() >= 1400 || (flows_in_packet > 0 && current_template_id != flow_template_id) {
                // Close current flowset
                let flowset_len = (packet.len() - flowset_start_offset) as u16;
                packet[offset_to_flowset_len] = (flowset_len >> 8) as u8;
                packet[offset_to_flowset_len + 1] = (flowset_len & 0xFF) as u8;

                // Send packet
                if let Err(e) = send_packet(&mut packet, &sp) {
                    log::error!("Failed to send IPFIX packet: {}", e);
                    sp.param.flows_dropped += flows_in_packet as u64;
                    return -1;
                }
                sp.param.records_sent += flows_in_packet as u64;
                sp.param.flows_exported += flows_in_packet as u64;
                flows_in_packet = 0;
                num_packets += 1;
                current_template_id = 0;
            }

            if packet.is_empty() {
                packet.extend_from_slice(&10u16.to_be_bytes()); // Version
                packet.extend_from_slice(&0u16.to_be_bytes()); // Length (fill at end)
                packet.extend_from_slice(&(now.tv_sec as u32).to_be_bytes());
                packet.extend_from_slice(&((sp.param.records_sent + sp.param.flows_exported) as u32).to_be_bytes());
                packet.extend_from_slice(&0u32.to_be_bytes());
            }

            if current_template_id != flow_template_id {
                if current_template_id != 0 {
                    // Close previous flowset
                    let flowset_len = (packet.len() - flowset_start_offset) as u16;
                    let len_bytes = flowset_len.to_be_bytes();
                    packet[offset_to_flowset_len] = len_bytes[0];
                    packet[offset_to_flowset_len + 1] = len_bytes[1];
                }

                // Start new flowset
                flowset_start_offset = packet.len();
                packet.extend_from_slice(&flow_template_id.to_be_bytes());
                offset_to_flowset_len = packet.len();
                packet.extend_from_slice(&0u16.to_be_bytes()); // Flowset length placeholder

                current_template_id = flow_template_id;
            }

            // Write Flow Record data
            if is_v6 {
                let src_bytes = match flow.key.addr[dir] {
                    std::net::IpAddr::V6(ip) => ip.octets(),
                    _ => [0; 16],
                };
                let dst_bytes = match flow.key.addr[dir ^ 1] {
                    std::net::IpAddr::V6(ip) => ip.octets(),
                    _ => [0; 16],
                };
                packet.extend_from_slice(&src_bytes);
                packet.extend_from_slice(&dst_bytes);
            } else {
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
            }

            packet.extend_from_slice(&flow.octets[dir].to_be_bytes());
            packet.extend_from_slice(&flow.packets[dir].to_be_bytes());
            packet.extend_from_slice(&(ifidx as u32).to_be_bytes());
            packet.extend_from_slice(&(ifidx as u32).to_be_bytes());
            packet.extend_from_slice(&flow.key.port[dir].to_be_bytes());
            packet.extend_from_slice(&flow.key.port[dir ^ 1].to_be_bytes());
            packet.push(flow.key.protocol);
            packet.push(flow.tcp_flags[dir]);
            packet.push(if is_v6 { 6 } else { 4 });
            packet.push(flow.tos[dir]);

            // Flow start and end in SysUpTime (milliseconds)
            let start_ms = flow.flow_start.sub_ms(&sp.param.system_boot_time);
            let end_ms = flow.flow_last.sub_ms(&sp.param.system_boot_time);
            packet.extend_from_slice(&(start_ms as u32).to_be_bytes());
            packet.extend_from_slice(&(end_ms as u32).to_be_bytes());

            flows_in_packet += 1;
        }
    }

    if flows_in_packet > 0 {
        // Close last flowset
        let flowset_len = (packet.len() - flowset_start_offset) as u16;
        packet[offset_to_flowset_len] = (flowset_len >> 8) as u8;
        packet[offset_to_flowset_len + 1] = (flowset_len & 0xFF) as u8;

        if let Err(e) = send_packet(&mut packet, &sp) {
            log::error!("Failed to send IPFIX leftovers: {}", e);
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

fn send_packet(packet: &mut [u8], sp: &SendParameter) -> std::io::Result<()> {
    // Fill IPFIX total length in header
    let len = packet.len() as u16;
    packet[2] = (len >> 8) as u8;
    packet[3] = (len & 0xFF) as u8;

    let mut sent = 0;
    sp.target.send_multi_destinations(packet, &mut sent)
}
