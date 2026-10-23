#![allow(non_snake_case)]
#![allow(dead_code)]

use std::net::IpAddr;
use crate::common::{Flow, FlowTrackParameters, TrackLevel};
use crate::exporter::{
    SendParameter,
    export_common::{
        conv_unix_to_ntp, export_build_flow_header, get_pkts_until_template,
        ipfix_flow_direction, ipfix_flow_to_template_index, set_pkts_until_template,
        decrement_pkts_until_template, IPFIX_DEFAULT_TEMPLATE_INTERVAL,
        IPFIX_SOFTFLOWD_ICMPV4_TEMPLATE_ID, IPFIX_SOFTFLOWD_ICMPV6_TEMPLATE_ID,
        IPFIX_SOFTFLOWD_MAX_PACKET_SIZE, IPFIX_SOFTFLOWD_V4_TEMPLATE_ID,
        IPFIX_SOFTFLOWD_V6_TEMPLATE_ID, IPFIX_TEMPLATE_SET_ID,
        NETFLOW9_TEMPLATE_SET_ID, REVERSE_PEN,
        TMPLICMPV4, TMPLICMPV6, TMPLMAX, TMPLV4, TMPLV6,
    },
};

pub struct ExportCtx<'a> {
    pub sp: &'a SendParameter<'a>,
    pub flow: &'a Flow,
    pub i: usize,
}

pub type EncoderFn = fn(dst: &mut [u8], length: usize, ctx: &ExportCtx);

#[derive(Clone, Copy)]
pub struct FieldSpecEncoder {
    pub ie: u16,
    pub length: usize,
    pub encoder: EncoderFn,
}

// -------------------------------------------------------------------
// Encoders matching C export.c
// -------------------------------------------------------------------

fn enc_zero(dst: &mut [u8], _length: usize, _ctx: &ExportCtx) {
    dst.fill(0);
}

fn enc_octetDeltaCount(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    let bytes = ctx.flow.octets[ctx.i].to_be_bytes();
    dst[..4].copy_from_slice(&bytes);
}

fn enc_packetDeltaCount(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    let bytes = ctx.flow.packets[ctx.i].to_be_bytes();
    dst[..4].copy_from_slice(&bytes);
}

fn enc_protocolIdentifier(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    dst[0] = ctx.flow.key.protocol;
}

fn enc_ipClassOfService(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    dst[0] = ctx.flow.tos[ctx.i];
}

fn enc_tcpControlBits(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    dst[0] = ctx.flow.tcp_flags[ctx.i];
}

fn enc_sourceTransportPort(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    let bytes = ctx.flow.key.port[ctx.i].to_be_bytes();
    dst[..2].copy_from_slice(&bytes);
}

fn enc_destinationTransportPort(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    let bytes = ctx.flow.key.port[ctx.i ^ 1].to_be_bytes();
    dst[..2].copy_from_slice(&bytes);
}

fn enc_icmpTypeCode(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    let bytes = ctx.flow.key.port[ctx.i ^ 1].to_be_bytes();
    dst[..2].copy_from_slice(&bytes);
}

fn enc_sourceIPv4Address(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    if let IpAddr::V4(ipv4) = ctx.flow.key.addr[ctx.i] {
        dst[..4].copy_from_slice(&ipv4.octets());
    } else {
        dst[..4].fill(0);
    }
}

fn enc_destinationIPv4Address(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    if let IpAddr::V4(ipv4) = ctx.flow.key.addr[ctx.i ^ 1] {
        dst[..4].copy_from_slice(&ipv4.octets());
    } else {
        dst[..4].fill(0);
    }
}

fn enc_sourceIPv6Address(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    if let IpAddr::V6(ipv6) = ctx.flow.key.addr[ctx.i] {
        dst[..16].copy_from_slice(&ipv6.octets());
    } else {
        dst[..16].fill(0);
    }
}

fn enc_destinationIPv6Address(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    if let IpAddr::V6(ipv6) = ctx.flow.key.addr[ctx.i ^ 1] {
        dst[..16].copy_from_slice(&ipv6.octets());
    } else {
        dst[..16].fill(0);
    }
}

fn enc_sourceMacAddress(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    dst[..6].copy_from_slice(&ctx.flow.key.ethermac[ctx.i]);
}

fn enc_postDestinationMacAddress(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    dst[..6].copy_from_slice(&ctx.flow.key.ethermac[ctx.i ^ 1]);
}

fn enc_ifidx16(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    let bytes = ctx.sp.ifidx.to_be_bytes();
    dst[..2].copy_from_slice(&bytes);
}

fn enc_ifidx32(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    let bytes = (ctx.sp.ifidx as u32).to_be_bytes();
    dst[..4].copy_from_slice(&bytes);
}

fn enc_flowStartSysUpTime(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    let sub = ctx.flow.flow_start.sub_ms(&ctx.sp.param.system_boot_time);
    dst[..4].copy_from_slice(&sub.to_be_bytes());
}

fn enc_flowEndSysUpTime(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    let sub = ctx.flow.flow_last.sub_ms(&ctx.sp.param.system_boot_time);
    dst[..4].copy_from_slice(&sub.to_be_bytes());
}

fn enc_flowStartSeconds(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    let s = ctx.flow.flow_start.tv_sec as u32;
    dst[..4].copy_from_slice(&s.to_be_bytes());
}

fn enc_flowEndSeconds(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    let s = ctx.flow.flow_last.tv_sec as u32;
    dst[..4].copy_from_slice(&s.to_be_bytes());
}

fn enc_flowStartMilliSeconds(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    let ms = (ctx.flow.flow_start.tv_sec as u64) * 1000 + (ctx.flow.flow_start.tv_usec as u64) / 1000;
    dst[..8].copy_from_slice(&ms.to_be_bytes());
}

fn enc_flowEndMilliSeconds(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    let ms = (ctx.flow.flow_last.tv_sec as u64) * 1000 + (ctx.flow.flow_last.tv_usec as u64) / 1000;
    dst[..8].copy_from_slice(&ms.to_be_bytes());
}

fn enc_flowStartMicroSeconds(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    let ntp = conv_unix_to_ntp(ctx.flow.flow_start);
    let val = ((ntp.second as u64) << 32) | (ntp.fraction as u64);
    dst[..8].copy_from_slice(&val.to_be_bytes());
}

fn enc_flowEndMicroSeconds(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    let ntp = conv_unix_to_ntp(ctx.flow.flow_last);
    let val = ((ntp.second as u64) << 32) | (ntp.fraction as u64);
    dst[..8].copy_from_slice(&val.to_be_bytes());
}

fn enc_flowEndReason(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    dst[0] = ctx.flow.flow_end_reason;
}

fn enc_vlanId(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    let bytes = ctx.flow.key.vlanid[ctx.i].to_be_bytes();
    dst[..2].copy_from_slice(&bytes);
}

fn enc_postVlanId(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    let bytes = ctx.flow.key.vlanid[ctx.i ^ 1].to_be_bytes();
    dst[..2].copy_from_slice(&bytes);
}

fn enc_interfaceName(dst: &mut [u8], length: usize, ctx: &ExportCtx) {
    let name_bytes = ctx.sp.param.interface_name.as_bytes();
    let n = length.min(name_bytes.len()).min(dst.len());
    dst[..n].copy_from_slice(&name_bytes[..n]);
}

fn enc_nf9OptionScopeInterface(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    let bytes = (ctx.sp.ifidx as u32).to_be_bytes();
    dst[..4].copy_from_slice(&bytes);
}

fn enc_samplingInterval(dst: &mut [u8], length: usize, ctx: &ExportCtx) {
    let rate = if ctx.sp.param.sample_rate > 1 { ctx.sp.param.sample_rate } else { 1 };
    let bytes = rate.to_be_bytes();
    let n = length.min(4);
    dst[..n].copy_from_slice(&bytes[4 - n..]);
}

fn enc_systemInitTimeMilliseconds(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    let ms = (ctx.sp.param.system_boot_time.tv_sec as u64) * 1000 + (ctx.sp.param.system_boot_time.tv_usec as u64) / 1000;
    dst[..8].copy_from_slice(&ms.to_be_bytes());
}

fn enc_meteringProcessId(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    let bytes = ctx.sp.param.metering_process_id.to_be_bytes();
    dst[..4].copy_from_slice(&bytes);
}

fn enc_samplingPacketInterval(dst: &mut [u8], length: usize, ctx: &ExportCtx) {
    let rate = if ctx.sp.param.sample_rate > 1 { ctx.sp.param.sample_rate } else { 1 };
    let bytes = rate.to_be_bytes();
    let n = length.min(4);
    dst[..n].copy_from_slice(&bytes[4 - n..]);
}

fn enc_samplingPacketSpace(dst: &mut [u8], length: usize, ctx: &ExportCtx) {
    let space = if ctx.sp.param.sample_rate > 0 { ctx.sp.param.sample_rate - 1 } else { 0 };
    let bytes = space.to_be_bytes();
    let n = length.min(4);
    dst[..n].copy_from_slice(&bytes[4 - n..]);
}

fn enc_selectorAlgorithm(dst: &mut [u8], length: usize, _ctx: &ExportCtx) {
    let bytes = 1u16.to_be_bytes(); // systematic count-based
    let n = length.min(2);
    dst[..n].copy_from_slice(&bytes[2 - n..]);
}

fn enc_samplingAlgorithm(dst: &mut [u8], _length: usize, _ctx: &ExportCtx) {
    dst[0] = 1; // deterministic
}

fn enc_exporterAddress(dst: &mut [u8], length: usize, ctx: &ExportCtx) {
    if let Some(ip) = ctx.sp.param.exporter_ip {
        match ip {
            IpAddr::V4(v4) if length == 4 => dst[..4].copy_from_slice(&v4.octets()),
            IpAddr::V6(v6) if length == 16 => dst[..16].copy_from_slice(&v6.octets()),
            _ => dst[..length].fill(0),
        }
    } else {
        dst[..length].fill(0);
    }
}

fn enc_ipVersion(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    dst[0] = if ctx.flow.key.af == libc::AF_INET as u16 { 4 } else { 6 };
}

fn enc_flowDirection(dst: &mut [u8], _length: usize, ctx: &ExportCtx) {
    dst[0] = ipfix_flow_direction(ctx.flow, ctx.i, ctx.sp.param);
}

// -------------------------------------------------------------------
// Field Tables
// -------------------------------------------------------------------

const FIELD_NETFLOW_V1V5_COMMON: [FieldSpecEncoder; 11] = [
    FieldSpecEncoder { ie: 8, length: 4, encoder: enc_sourceIPv4Address },
    FieldSpecEncoder { ie: 12, length: 4, encoder: enc_destinationIPv4Address },
    FieldSpecEncoder { ie: 15, length: 4, encoder: enc_zero }, // NextHop
    FieldSpecEncoder { ie: 10, length: 2, encoder: enc_ifidx16 },
    FieldSpecEncoder { ie: 14, length: 2, encoder: enc_ifidx16 },
    FieldSpecEncoder { ie: 2, length: 4, encoder: enc_packetDeltaCount },
    FieldSpecEncoder { ie: 1, length: 4, encoder: enc_octetDeltaCount },
    FieldSpecEncoder { ie: 22, length: 4, encoder: enc_flowStartSysUpTime },
    FieldSpecEncoder { ie: 21, length: 4, encoder: enc_flowEndSysUpTime },
    FieldSpecEncoder { ie: 7, length: 2, encoder: enc_sourceTransportPort },
    FieldSpecEncoder { ie: 11, length: 2, encoder: enc_destinationTransportPort },
];

const FIELD_NETFLOWV1_TAIL: [FieldSpecEncoder; 5] = [
    FieldSpecEncoder { ie: 210, length: 2, encoder: enc_zero },
    FieldSpecEncoder { ie: 4, length: 1, encoder: enc_protocolIdentifier },
    FieldSpecEncoder { ie: 5, length: 1, encoder: enc_ipClassOfService },
    FieldSpecEncoder { ie: 6, length: 1, encoder: enc_tcpControlBits },
    FieldSpecEncoder { ie: 210, length: 7, encoder: enc_zero },
];

const FIELD_NETFLOWV5_TAIL: [FieldSpecEncoder; 9] = [
    FieldSpecEncoder { ie: 210, length: 1, encoder: enc_zero },
    FieldSpecEncoder { ie: 6, length: 1, encoder: enc_tcpControlBits },
    FieldSpecEncoder { ie: 4, length: 1, encoder: enc_protocolIdentifier },
    FieldSpecEncoder { ie: 5, length: 1, encoder: enc_ipClassOfService },
    FieldSpecEncoder { ie: 16, length: 2, encoder: enc_zero }, // bgpSourceAs
    FieldSpecEncoder { ie: 17, length: 2, encoder: enc_zero }, // bgpDestAs
    FieldSpecEncoder { ie: 9, length: 1, encoder: enc_zero },  // srcMask
    FieldSpecEncoder { ie: 13, length: 1, encoder: enc_zero }, // dstMask
    FieldSpecEncoder { ie: 210, length: 2, encoder: enc_zero },
];

fn emit_group(fields: &[FieldSpecEncoder], packet: &mut [u8], mut offset: usize, ctx: &ExportCtx) -> usize {
    for f in fields {
        (f.encoder)(&mut packet[offset..offset + f.length], f.length, ctx);
        offset += f.length;
    }
    offset
}

// -------------------------------------------------------------------
// NetFlow v1 / v5: Fixed Export
// -------------------------------------------------------------------

fn send_fixed_flow(mut sp: SendParameter, version: u16) -> i32 {
    let tail_fields = if version == 1 { &FIELD_NETFLOWV1_TAIL[..] } else { &FIELD_NETFLOWV5_TAIL[..] };
    let maxflows = if version == 1 { 24 } else { 30 };

    let mut packet = vec![0u8; 1500];
    let mut num_packets = 0;
    let mut offset = 0;
    let mut j = 0;

    for flow in sp.flows {
        if flow.key.af != libc::AF_INET as u16 {
            continue;
        }

        let need = (flow.octets[0] > 0) as usize + (flow.octets[1] > 0) as usize;
        if need == 0 {
            continue;
        }

        if j + need > maxflows {
            if send_fixed_packet(&mut sp, &mut packet, offset, j as u16) < 0 {
                return -1;
            }
            j = 0;
            num_packets += 1;
        }

        if j == 0 {
            packet.clear();
            offset = export_build_flow_header(&mut packet, version, sp.param);
            packet.resize(1500, 0);
        }

        for k in 0..2 {
            if flow.octets[k] == 0 {
                continue;
            }
            let ctx = ExportCtx { sp: &sp, flow, i: k };
            offset = emit_group(&FIELD_NETFLOW_V1V5_COMMON, &mut packet, offset, &ctx);
            offset = emit_group(tail_fields, &mut packet, offset, &ctx);
            j += 1;
        }
    }

    if j != 0 {
        if send_fixed_packet(&mut sp, &mut packet, offset, j as u16) < 0 {
            return -1;
        }
        num_packets += 1;
    }

    sp.param.packets_sent += num_packets as u64;
    num_packets
}

fn send_fixed_packet(sp: &mut SendParameter, packet: &mut [u8], offset: usize, count: u16) -> i32 {
    sp.param.records_sent += count as u64;
    let count_bytes = count.to_be_bytes();
    packet[2..4].copy_from_slice(&count_bytes);

    let mut sent = 0;
    if sp.target.send_multi_destinations(&packet[..offset], &mut sent).is_err() {
        return -1;
    }
    sp.param.flows_exported += count as u64;
    0
}

pub fn send_netflow_v1(sp: SendParameter) -> i32 {
    send_fixed_flow(sp, 1)
}

pub fn send_netflow_v5(sp: SendParameter) -> i32 {
    send_fixed_flow(sp, 5)
}

// -------------------------------------------------------------------
// NetFlow v9 / IPFIX: Templated Export
// -------------------------------------------------------------------

#[derive(Clone)]
struct ExportTemplate {
    template_id: u16,
    fields: Vec<FieldSpecEncoder>,
    bi_fields: Vec<FieldSpecEncoder>,
    data_len: usize,
}

fn build_templates(param: &FlowTrackParameters, bi_flag: bool, version: u16) -> [ExportTemplate; TMPLMAX] {
    let mut tmpls = Vec::with_capacity(TMPLMAX);

    for idx in 0..TMPLMAX {
        let (v6, icmp, tmpl_id) = match idx {
            TMPLV4 => (false, false, IPFIX_SOFTFLOWD_V4_TEMPLATE_ID),
            TMPLICMPV4 => (false, true, IPFIX_SOFTFLOWD_ICMPV4_TEMPLATE_ID),
            TMPLV6 => (true, false, IPFIX_SOFTFLOWD_V6_TEMPLATE_ID),
            TMPLICMPV6 => (true, true, IPFIX_SOFTFLOWD_ICMPV6_TEMPLATE_ID),
            _ => (false, false, IPFIX_SOFTFLOWD_V4_TEMPLATE_ID),
        };

        let mut fields = Vec::new();
        // IP Addrs
        if v6 {
            fields.push(FieldSpecEncoder { ie: 27, length: 16, encoder: enc_sourceIPv6Address });
            fields.push(FieldSpecEncoder { ie: 28, length: 16, encoder: enc_destinationIPv6Address });
        } else {
            fields.push(FieldSpecEncoder { ie: 8, length: 4, encoder: enc_sourceIPv4Address });
            fields.push(FieldSpecEncoder { ie: 12, length: 4, encoder: enc_destinationIPv4Address });
        }

        // Time fields
        if version == 10 && param.time_format == b's' {
            fields.push(FieldSpecEncoder { ie: 150, length: 4, encoder: enc_flowStartSeconds });
            fields.push(FieldSpecEncoder { ie: 151, length: 4, encoder: enc_flowEndSeconds });
        } else if version == 10 && param.time_format == b'm' {
            fields.push(FieldSpecEncoder { ie: 152, length: 8, encoder: enc_flowStartMilliSeconds });
            fields.push(FieldSpecEncoder { ie: 153, length: 8, encoder: enc_flowEndMilliSeconds });
        } else if version == 10 && (param.time_format == b'M' || param.time_format == b'n') {
            fields.push(FieldSpecEncoder { ie: 154, length: 8, encoder: enc_flowStartMicroSeconds });
            fields.push(FieldSpecEncoder { ie: 155, length: 8, encoder: enc_flowEndMicroSeconds });
        } else {
            fields.push(FieldSpecEncoder { ie: 22, length: 4, encoder: enc_flowStartSysUpTime });
            fields.push(FieldSpecEncoder { ie: 21, length: 4, encoder: enc_flowEndSysUpTime });
        }

        // Common fields
        fields.push(FieldSpecEncoder { ie: 1, length: 4, encoder: enc_octetDeltaCount });
        fields.push(FieldSpecEncoder { ie: 2, length: 4, encoder: enc_packetDeltaCount });
        fields.push(FieldSpecEncoder { ie: 10, length: 4, encoder: enc_ifidx32 });
        fields.push(FieldSpecEncoder { ie: 14, length: 4, encoder: enc_ifidx32 });
        fields.push(FieldSpecEncoder { ie: 61, length: 1, encoder: enc_flowDirection });
        fields.push(FieldSpecEncoder { ie: 136, length: 1, encoder: enc_flowEndReason });

        // Transport / ICMP
        if icmp {
            let ie = if v6 { 179 } else { 176 };
            fields.push(FieldSpecEncoder { ie, length: 2, encoder: enc_icmpTypeCode });
            fields.push(FieldSpecEncoder { ie: 4, length: 1, encoder: enc_protocolIdentifier });
            fields.push(FieldSpecEncoder { ie: 60, length: 1, encoder: enc_ipVersion });
            fields.push(FieldSpecEncoder { ie: 5, length: 1, encoder: enc_ipClassOfService });
        } else {
            fields.push(FieldSpecEncoder { ie: 7, length: 2, encoder: enc_sourceTransportPort });
            fields.push(FieldSpecEncoder { ie: 11, length: 2, encoder: enc_destinationTransportPort });
            fields.push(FieldSpecEncoder { ie: 4, length: 1, encoder: enc_protocolIdentifier });
            fields.push(FieldSpecEncoder { ie: 6, length: 1, encoder: enc_tcpControlBits });
            fields.push(FieldSpecEncoder { ie: 60, length: 1, encoder: enc_ipVersion });
            fields.push(FieldSpecEncoder { ie: 5, length: 1, encoder: enc_ipClassOfService });
        }

        if param.track_level >= TrackLevel::FullVlan {
            fields.push(FieldSpecEncoder { ie: 58, length: 2, encoder: enc_vlanId });
            fields.push(FieldSpecEncoder { ie: 59, length: 2, encoder: enc_postVlanId });
        }
        if param.track_level >= TrackLevel::FullVlanEther {
            fields.push(FieldSpecEncoder { ie: 56, length: 6, encoder: enc_sourceMacAddress });
            fields.push(FieldSpecEncoder { ie: 57, length: 6, encoder: enc_postDestinationMacAddress });
        }

        let mut bi_fields = Vec::new();
        if bi_flag && version == 10 {
            bi_fields.push(FieldSpecEncoder { ie: 1 | 0x8000, length: 4, encoder: enc_octetDeltaCount });
            bi_fields.push(FieldSpecEncoder { ie: 2 | 0x8000, length: 4, encoder: enc_packetDeltaCount });
            bi_fields.push(FieldSpecEncoder { ie: 5 | 0x8000, length: 1, encoder: enc_ipClassOfService });
            if !icmp {
                bi_fields.push(FieldSpecEncoder { ie: 6 | 0x8000, length: 1, encoder: enc_tcpControlBits });
            }
        }

        let mut data_len = fields.iter().map(|f| f.length).sum::<usize>()
            + bi_fields.iter().map(|f| f.length).sum::<usize>();
        data_len += param.max_num_label as usize * 3;

        tmpls.push(ExportTemplate {
            template_id: tmpl_id,
            fields,
            bi_fields,
            data_len,
        });
    }

    [tmpls[0].clone(), tmpls[1].clone(), tmpls[2].clone(), tmpls[3].clone()]
}

fn put_templates(packet: &mut Vec<u8>, tmpls: &[ExportTemplate; TMPLMAX], bi_flag: bool, version: u16) {
    let set_id = if version == 10 { IPFIX_TEMPLATE_SET_ID } else { NETFLOW9_TEMPLATE_SET_ID };

    for tmpl in tmpls {
        let set_start = packet.len();
        packet.extend_from_slice(&set_id.to_be_bytes());
        let len_offset = packet.len();
        packet.extend_from_slice(&0u16.to_be_bytes()); // placeholder for set length

        packet.extend_from_slice(&tmpl.template_id.to_be_bytes());
        let count = (tmpl.fields.len() + tmpl.bi_fields.len()) as u16;
        packet.extend_from_slice(&count.to_be_bytes());

        for f in &tmpl.fields {
            packet.extend_from_slice(&f.ie.to_be_bytes());
            packet.extend_from_slice(&(f.length as u16).to_be_bytes());
        }
        if bi_flag && version == 10 {
            for f in &tmpl.bi_fields {
                packet.extend_from_slice(&f.ie.to_be_bytes());
                packet.extend_from_slice(&(f.length as u16).to_be_bytes());
                packet.extend_from_slice(&REVERSE_PEN.to_be_bytes());
            }
        }

        let set_len = (packet.len() - set_start) as u16;
        packet[len_offset..len_offset + 2].copy_from_slice(&set_len.to_be_bytes());
    }
}

pub fn send_ipfix_flows(sp: SendParameter, bi_flag: bool, version: u16) -> i32 {
    let tmpls = build_templates(sp.param, bi_flag, version);
    let mut num_packets = 0;
    let mut j = 0;
    let num_flows = sp.flows.len();

    if get_pkts_until_template() <= 0 {
        set_pkts_until_template(0);
    }

    let mut packet = Vec::with_capacity(IPFIX_SOFTFLOWD_MAX_PACKET_SIZE);

    while j < num_flows {
        packet.clear();
        let _ = export_build_flow_header(&mut packet, version, sp.param);

        if get_pkts_until_template() <= 0 {
            put_templates(&mut packet, &tmpls, bi_flag, version);
            set_pkts_until_template(IPFIX_DEFAULT_TEMPLATE_INTERVAL);

            if sp.target.is_loadbalance && sp.target.destinations.len() > 1 {
                // Send template-only packet to all destinations
                let tmpl_len = packet.len() as u16;
                if version == 10 {
                    packet[2..4].copy_from_slice(&tmpl_len.to_be_bytes());
                } else {
                    packet[2..4].copy_from_slice(&1u16.to_be_bytes());
                }
                let mut sent = 0;
                let _ = sp.target.send_multi_destinations(&packet, &mut sent);
                packet.clear();
                let _ = export_build_flow_header(&mut packet, version, sp.param);
            }
        }

        let mut current_set_start = 0;
        let mut last_tmplindex: Option<usize> = None;
        let mut records_in_packet = 0;
        let mut i = 0;

        while i + j < num_flows {
            let flow = sp.flows[i + j];
            let tmplindex = ipfix_flow_to_template_index(flow);
            let tmpl = &tmpls[tmplindex];

            let rec_needed = if bi_flag { 1 } else { (flow.octets[0] > 0) as usize + (flow.octets[1] > 0) as usize };
            if rec_needed == 0 {
                i += 1;
                continue;
            }

            let needed_space = 4 + rec_needed * tmpl.data_len;
            if packet.len() + needed_space > IPFIX_SOFTFLOWD_MAX_PACKET_SIZE {
                break;
            }

            if last_tmplindex != Some(tmplindex) {
                // Close previous set if any
                if let Some(_) = last_tmplindex {
                    let set_len = (packet.len() - current_set_start) as u16;
                    packet[current_set_start + 2..current_set_start + 4].copy_from_slice(&set_len.to_be_bytes());
                }

                current_set_start = packet.len();
                packet.extend_from_slice(&tmpl.template_id.to_be_bytes());
                packet.extend_from_slice(&0u16.to_be_bytes()); // placeholder for set length
                last_tmplindex = Some(tmplindex);
            }

            let frecnum = if bi_flag { 1 } else { 2 };
            for dir in 0..frecnum {
                if !bi_flag && flow.octets[dir] == 0 {
                    continue;
                }

                let ctx = ExportCtx { sp: &sp, flow, i: dir };
                let old_len = packet.len();
                packet.resize(old_len + tmpl.data_len, 0);

                let mut off = emit_group(&tmpl.fields, &mut packet, old_len, &ctx);
                if bi_flag && dir == 0 {
                    let bictx = ExportCtx { sp: &sp, flow, i: 1 };
                    off = emit_group(&tmpl.bi_fields, &mut packet, off, &bictx);
                }
                for k in 0..sp.param.max_num_label as usize {
                    let lbl_bytes = flow.key.mpls_labels[k].to_be_bytes();
                    packet[off..off + 3].copy_from_slice(&lbl_bytes[1..4]);
                    off += 3;
                }
                records_in_packet += 1;
            }

            i += 1;
        }

        if let Some(_) = last_tmplindex {
            let set_len = (packet.len() - current_set_start) as u16;
            packet[current_set_start + 2..current_set_start + 4].copy_from_slice(&set_len.to_be_bytes());
        }

        // Align packet to 4 bytes
        let pad = (4 - (packet.len() % 4)) % 4;
        if pad > 0 {
            packet.resize(packet.len() + pad, 0);
        }

        sp.param.records_sent += records_in_packet;

        if version == 10 {
            let total_len = packet.len() as u16;
            packet[2..4].copy_from_slice(&total_len.to_be_bytes());
            let seq = (sp.param.records_sent & 0xffffffff) as u32;
            packet[8..12].copy_from_slice(&seq.to_be_bytes());
        } else {
            let count = records_in_packet as u16;
            packet[2..4].copy_from_slice(&count.to_be_bytes());
            let seq = (sp.param.records_sent & 0xffffffff) as u32;
            packet[12..16].copy_from_slice(&seq.to_be_bytes());
        }

        let mut sent = 0;
        if sp.target.send_multi_destinations(&packet, &mut sent).is_err() {
            return -1;
        }

        num_packets += 1;
        decrement_pkts_until_template();
        j += i;
    }

    sp.param.flows_exported += j as u64;
    sp.param.packets_sent += num_packets as u64;
    num_packets
}

pub fn send_netflow_v9(sp: SendParameter) -> i32 {
    send_ipfix_flows(sp, false, 9)
}

pub fn send_ipfix(sp: SendParameter) -> i32 {
    send_ipfix_flows(sp, false, 10)
}

pub fn send_ipfix_bi(sp: SendParameter) -> i32 {
    send_ipfix_flows(sp, true, 10)
}

pub fn send_flows(sp: SendParameter) -> i32 {
    match sp.target.version {
        1 => send_netflow_v1(sp),
        5 => send_netflow_v5(sp),
        9 => send_netflow_v9(sp),
        10 => {
            if sp.param.bidirection {
                send_ipfix_bi(sp)
            } else {
                send_ipfix(sp)
            }
        }
        _ => -1,
    }
}
