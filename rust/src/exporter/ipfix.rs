use crate::exporter::{SendParameter, get_active_now};
// use std::io::Write;

// IPFIX Constants
const IPFIX_TEMPLATE_SET_ID: u16 = 2;
const IPFIX_OPTION_TEMPLATE_SET_ID: u16 = 3;

const IPFIX_SET_HEADER_LEN: u16 = 4;
const IPFIX_TEMPLATE_HEADER_LEN: u16 = 4;
const IPFIX_FIELD_SPEC_LEN: u16 = 4;

const IPFIX_SOFTFLOWD_V4_TEMPLATE_ID: u16 = 1024;
const IPFIX_SOFTFLOWD_ICMPV4_TEMPLATE_ID: u16 = 1025;
const IPFIX_SOFTFLOWD_V6_TEMPLATE_ID: u16 = 2048;
const IPFIX_SOFTFLOWD_ICMPV6_TEMPLATE_ID: u16 = 2049;
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
const IPFIX_FLOW_START_MILLISECONDS: u16 = 152;
const IPFIX_FLOW_END_MILLISECONDS: u16 = 153;
const IPFIX_FLOW_START_MICROSECONDS: u16 = 154;
const IPFIX_FLOW_END_MICROSECONDS: u16 = 155;
const IPFIX_FLOW_START_NANOSECONDS: u16 = 156;
const IPFIX_FLOW_END_NANOSECONDS: u16 = 157;
const IPFIX_FLOW_DIRECTION: u16 = 61;
const IPFIX_FLOW_END_REASON: u16 = 136;
const IPFIX_MPLS_LABEL_STACK_SECTION: u16 = 70;
const IPFIX_SOURCE_TRANSPORT_PORT: u16 = 7;
const IPFIX_DESTINATION_TRANSPORT_PORT: u16 = 11;
const IPFIX_PROTOCOL_IDENTIFIER: u16 = 4;
const IPFIX_TCP_CONTROL_BITS: u16 = 6;
const IPFIX_IP_VERSION: u16 = 60;
const IPFIX_IP_CLASS_OF_SERVICE: u16 = 5;
const IPFIX_SYSTEM_INIT_TIME_MILLISECONDS: u16 = 160;

static mut PKTS_UNTIL_TEMPLATE: i32 = -1;

fn write_templates(packet: &mut Vec<u8>, time_format: u8) {
    let (start_ie, end_ie, time_len) = match time_format {
        b'm' => (IPFIX_FLOW_START_MILLISECONDS, IPFIX_FLOW_END_MILLISECONDS, 8u16),
        b'M' => (IPFIX_FLOW_START_MICROSECONDS, IPFIX_FLOW_END_MICROSECONDS, 8u16),
        b'n' => (IPFIX_FLOW_START_NANOSECONDS, IPFIX_FLOW_END_NANOSECONDS, 8u16),
        _ => (IPFIX_FLOW_START_SYSUPTIME, IPFIX_FLOW_END_SYSUPTIME, 4u16),
    };

    let v4_fields: [(u16, u16); 16] = [
        (IPFIX_SOURCE_IPV4_ADDRESS, 4),
        (IPFIX_DESTINATION_IPV4_ADDRESS, 4),
        (start_ie, time_len),
        (end_ie, time_len),
        (IPFIX_OCTET_DELTA_COUNT, 4),
        (IPFIX_PACKET_DELTA_COUNT, 4),
        (IPFIX_INGRESS_INTERFACE, 4),
        (IPFIX_EGRESS_INTERFACE, 4),
        (IPFIX_FLOW_DIRECTION, 1),
        (IPFIX_FLOW_END_REASON, 1),
        (IPFIX_SOURCE_TRANSPORT_PORT, 2),
        (IPFIX_DESTINATION_TRANSPORT_PORT, 2),
        (IPFIX_PROTOCOL_IDENTIFIER, 1),
        (IPFIX_TCP_CONTROL_BITS, 1),
        (IPFIX_IP_CLASS_OF_SERVICE, 1),
        (IPFIX_IP_VERSION, 1),
    ];

    let v6_fields: [(u16, u16); 16] = [
        (IPFIX_SOURCE_IPV6_ADDRESS, 16),
        (IPFIX_DESTINATION_IPV6_ADDRESS, 16),
        (start_ie, time_len),
        (end_ie, time_len),
        (IPFIX_OCTET_DELTA_COUNT, 4),
        (IPFIX_PACKET_DELTA_COUNT, 4),
        (IPFIX_INGRESS_INTERFACE, 4),
        (IPFIX_EGRESS_INTERFACE, 4),
        (IPFIX_FLOW_DIRECTION, 1),
        (IPFIX_FLOW_END_REASON, 1),
        (IPFIX_SOURCE_TRANSPORT_PORT, 2),
        (IPFIX_DESTINATION_TRANSPORT_PORT, 2),
        (IPFIX_PROTOCOL_IDENTIFIER, 1),
        (IPFIX_TCP_CONTROL_BITS, 1),
        (IPFIX_IP_CLASS_OF_SERVICE, 1),
        (IPFIX_IP_VERSION, 1),
    ];

    let v4_len = IPFIX_TEMPLATE_HEADER_LEN + (v4_fields.len() as u16 * IPFIX_FIELD_SPEC_LEN);
    let v6_len = IPFIX_TEMPLATE_HEADER_LEN + (v6_fields.len() as u16 * IPFIX_FIELD_SPEC_LEN);
    let total_set_len = IPFIX_SET_HEADER_LEN + v4_len + v6_len;

    // Template Set Header
    packet.extend_from_slice(&IPFIX_TEMPLATE_SET_ID.to_be_bytes());
    packet.extend_from_slice(&total_set_len.to_be_bytes());

    // 1. IPv4 Template
    packet.extend_from_slice(&IPFIX_SOFTFLOWD_V4_TEMPLATE_ID.to_be_bytes());
    packet.extend_from_slice(&(v4_fields.len() as u16).to_be_bytes());
    for &(id, len) in &v4_fields {
        packet.extend_from_slice(&id.to_be_bytes());
        packet.extend_from_slice(&len.to_be_bytes());
    }

    // 2. IPv6 Template
    packet.extend_from_slice(&IPFIX_SOFTFLOWD_V6_TEMPLATE_ID.to_be_bytes());
    packet.extend_from_slice(&(v6_fields.len() as u16).to_be_bytes());
    for &(id, len) in &v6_fields {
        packet.extend_from_slice(&id.to_be_bytes());
        packet.extend_from_slice(&len.to_be_bytes());
    }
}

pub fn get_flow_direction(flow: &crate::common::Flow, param: &crate::common::FlowTrackParameters) -> u8 {
    if param.direction_mac_set && param.track_level >= crate::common::TrackLevel::FullVlanEther {
        if let Some(mac) = param.direction_mac {
            if flow.src_mac == mac { return 2; } // Egress
            if flow.dst_mac == mac { return 1; } // Ingress
        }
    }
    0
}

fn write_option_template(packet: &mut Vec<u8>) {
    let scope_fields = [
        (144u16, 4u16), // meteringProcessId
    ];
    let option_fields = [
        (IPFIX_SYSTEM_INIT_TIME_MILLISECONDS, 8u16),
        (305u16, 4u16), // samplingPacketInterval
        (306u16, 4u16), // samplingPacketSpace
        (304u16, 2u16), // selectorAlgorithm
        (82u16, 16u16), // interfaceName
        (400u16, 4u16), // exporterIPv4Address
        (401u16, 16u16), // exporterIPv6Address
        (403u16, 4u16), // originalExporterIPv4Address
        (404u16, 16u16), // originalExporterIPv6Address
    ];

    let field_count = (scope_fields.len() + option_fields.len()) as u16;
    let scope_field_count = scope_fields.len() as u16;

    let set_len = IPFIX_SET_HEADER_LEN
        + 2 // Template ID
        + 2 // Field Count
        + 2 // Scope Field Count
        + (field_count * IPFIX_FIELD_SPEC_LEN);

    packet.extend_from_slice(&IPFIX_OPTION_TEMPLATE_SET_ID.to_be_bytes());
    packet.extend_from_slice(&set_len.to_be_bytes());
    packet.extend_from_slice(&IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID.to_be_bytes());
    packet.extend_from_slice(&field_count.to_be_bytes());
    packet.extend_from_slice(&scope_field_count.to_be_bytes());

    for &(id, len) in &scope_fields {
        packet.extend_from_slice(&id.to_be_bytes());
        packet.extend_from_slice(&len.to_be_bytes());
    }
    for &(id, len) in &option_fields {
        packet.extend_from_slice(&id.to_be_bytes());
        packet.extend_from_slice(&len.to_be_bytes());
    }
}

fn write_option_data(packet: &mut Vec<u8>, boot_time: &crate::common::TimeVal, param: &crate::common::FlowTrackParameters) {
    let option_data_len = 82u16; // Set Header (4) + Scope (4) + Options (74) = 82 bytes

    packet.extend_from_slice(&IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID.to_be_bytes());
    packet.extend_from_slice(&option_data_len.to_be_bytes());

    // meteringProcessId (4 bytes)
    packet.extend_from_slice(&param.metering_process_id.to_be_bytes());

    // systemInitTimeMilliseconds (8 bytes)
    let ms = (boot_time.tv_sec as u64 * 1000) + (boot_time.tv_usec as u64 / 1000);
    packet.extend_from_slice(&ms.to_be_bytes());

    // samplingPacketInterval (4 bytes)
    packet.extend_from_slice(&1u32.to_be_bytes());

    // samplingPacketSpace (4 bytes)
    let space = if param.sample_rate > 0 { param.sample_rate - 1 } else { 0 };
    packet.extend_from_slice(&space.to_be_bytes());

    // selectorAlgorithm (2 bytes)
    packet.extend_from_slice(&1u16.to_be_bytes());

    // interfaceName (16 bytes)
    let mut ifname_bytes = [0u8; 16];
    let name_bytes = param.interface_name.as_bytes();
    let copy_len = name_bytes.len().min(15);
    ifname_bytes[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
    packet.extend_from_slice(&ifname_bytes);

    // exporterIPv4Address (4 bytes)
    let exp_v4 = match param.exporter_ip {
        Some(std::net::IpAddr::V4(ip)) => u32::from(ip),
        _ => 0,
    };
    packet.extend_from_slice(&exp_v4.to_be_bytes());

    // exporterIPv6Address (16 bytes)
    let exp_v6 = match param.exporter_ip {
        Some(std::net::IpAddr::V6(ip)) => ip.octets(),
        _ => [0u8; 16],
    };
    packet.extend_from_slice(&exp_v6);

    // originalExporterIPv4Address (4 bytes)
    packet.extend_from_slice(&0u32.to_be_bytes());

    // originalExporterIPv6Address (16 bytes)
    packet.extend_from_slice(&[0u8; 16]);
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

        write_templates(&mut packet, sp.param.time_format);
        write_option_template(&mut packet);
        write_option_data(&mut packet, &sp.param.system_boot_time, sp.param);

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
                // Close current flowset with 4-byte padding
                let mut flowset_len = (packet.len() - flowset_start_offset) as u16;
                let pad = (4 - (packet.len() % 4)) % 4;
                for _ in 0..pad {
                    packet.push(0);
                    flowset_len += 1;
                }
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
                    // Close previous flowset with 4-byte padding
                    let mut flowset_len = (packet.len() - flowset_start_offset) as u16;
                    let pad = (4 - (packet.len() % 4)) % 4;
                    for _ in 0..pad {
                        packet.push(0);
                        flowset_len += 1;
                    }
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

            // 1. IP Addresses
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

            // 2. Time fields
            if sp.param.time_format == b's' {
                packet.extend_from_slice(&(flow.flow_start.tv_sec as u32).to_be_bytes());
                packet.extend_from_slice(&(flow.flow_last.tv_sec as u32).to_be_bytes());
            } else if sp.param.time_format == b'm' {
                let start_ms = (flow.flow_start.tv_sec as u64 * 1000) + (flow.flow_start.tv_usec as u64 / 1000);
                let end_ms = (flow.flow_last.tv_sec as u64 * 1000) + (flow.flow_last.tv_usec as u64 / 1000);
                packet.extend_from_slice(&start_ms.to_be_bytes());
                packet.extend_from_slice(&end_ms.to_be_bytes());
            } else if sp.param.time_format == b'M' {
                let start_us = (flow.flow_start.tv_sec as u64 * 1_000_000) + flow.flow_start.tv_usec as u64;
                let end_us = (flow.flow_last.tv_sec as u64 * 1_000_000) + flow.flow_last.tv_usec as u64;
                packet.extend_from_slice(&start_us.to_be_bytes());
                packet.extend_from_slice(&end_us.to_be_bytes());
            } else if sp.param.time_format == b'n' {
                let start_ns = (flow.flow_start.tv_sec as u64 * 1_000_000_000) + (flow.flow_start.tv_usec as u64 * 1000);
                let end_ns = (flow.flow_last.tv_sec as u64 * 1_000_000_000) + (flow.flow_last.tv_usec as u64 * 1000);
                packet.extend_from_slice(&start_ns.to_be_bytes());
                packet.extend_from_slice(&end_ns.to_be_bytes());
            } else {
                let start_ms = flow.flow_start.sub_ms(&sp.param.system_boot_time);
                let end_ms = flow.flow_last.sub_ms(&sp.param.system_boot_time);
                packet.extend_from_slice(&(start_ms as u32).to_be_bytes());
                packet.extend_from_slice(&(end_ms as u32).to_be_bytes());
            }

            // 3. Common fields
            packet.extend_from_slice(&flow.octets[dir].to_be_bytes());
            packet.extend_from_slice(&flow.packets[dir].to_be_bytes());
            packet.extend_from_slice(&(ifidx as u32).to_be_bytes());
            packet.extend_from_slice(&(ifidx as u32).to_be_bytes());
            let dir_val = get_flow_direction(flow, &sp.param);
            packet.push(dir_val);
            packet.push(flow.flow_end_reason);

            // 4. Transport fields
            packet.extend_from_slice(&flow.key.port[dir].to_be_bytes());
            packet.extend_from_slice(&flow.key.port[dir ^ 1].to_be_bytes());
            packet.push(flow.key.protocol);
            packet.push(flow.tcp_flags[dir]);
            packet.push(flow.tos[dir]);
            packet.push(if is_v6 { 6 } else { 4 });

            flows_in_packet += 1;
        }
    }
            // Write flow direction
            let dir_val = get_flow_direction(flow, &sp.param);
            packet.push(dir_val);

            // Write MPLS labels
            if flow.key.mpls_label_depth > 0 {
                let depth = flow.key.mpls_label_depth as usize;
                // IPFIX mplsLabelStackSection format: 1 octet for number of labels + labels
                packet.push(depth as u8);
                for i in 0..depth {
                    let label = flow.key.mpls_labels[i];
                    packet.extend_from_slice(&label.to_be_bytes());
                }
            } else {
                packet.push(0); // 0 labels
            }

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
