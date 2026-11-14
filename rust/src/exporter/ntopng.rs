#![cfg(feature = "ntopng")]

use crate::common::{Flow, TrackLevel};
use crate::exporter::{ExportSocket, SendParameter};
use std::net::IpAddr;

const NTOPNG_MSG_VERSION: u8 = 4;
const NTOPNG_FLAG_IS_TLV: u8 = 1 << 1;
const NTOPNG_MAX_TLV_SIZE: usize = 16384;

const TLV_VERSION: u8 = 1;
const TLV_FORMAT_TLV: u8 = 1;
const TLV_END_OF_RECORD: u8 = 1;
const TLV_UINT8: u8 = 2;
const TLV_UINT16: u8 = 3;
const TLV_UINT32: u8 = 4;
const TLV_UINT64: u8 = 5;
const TLV_STRING: u8 = 11;

fn tlv_put_be(buf: &mut Vec<u8>, v: u64, bytes: usize) {
    for i in (0..bytes).rev() {
        buf.push(((v >> (8 * i)) & 0xff) as u8);
    }
}

fn tlv_uint_bytes(v: u64) -> usize {
    if v <= 0xff {
        1
    } else if v <= 0xffff {
        2
    } else if v <= 0xffffffff {
        4
    } else {
        8
    }
}

fn tlv_uint_type(bytes: usize) -> u8 {
    match bytes {
        1 => TLV_UINT8,
        2 => TLV_UINT16,
        4 => TLV_UINT32,
        _ => TLV_UINT64,
    }
}

fn tlv_put_uint(buf: &mut Vec<u8>, max_size: usize, key: u32, value: u64) -> Result<(), ()> {
    let kb = tlv_uint_bytes(key as u64);
    let vb = tlv_uint_bytes(value);
    if buf.len() + 1 + kb + vb > max_size {
        return Err(());
    }
    buf.push((tlv_uint_type(kb) << 4) | tlv_uint_type(vb));
    tlv_put_be(buf, key as u64, kb);
    tlv_put_be(buf, value, vb);
    Ok(())
}

fn tlv_put_string(buf: &mut Vec<u8>, max_size: usize, key: u32, value: &str) -> Result<(), ()> {
    let slen = value.len();
    let kb = tlv_uint_bytes(key as u64);
    if slen > 0xffff || buf.len() + 1 + kb + 2 + slen > max_size {
        return Err(());
    }
    buf.push((tlv_uint_type(kb) << 4) | TLV_STRING);
    tlv_put_be(buf, key as u64, kb);
    tlv_put_be(buf, slen as u64, 2);
    buf.extend_from_slice(value.as_bytes());
    Ok(())
}

fn tlv_end_record(buf: &mut Vec<u8>, max_size: usize) -> Result<(), ()> {
    if buf.len() + 1 > max_size {
        return Err(());
    }
    buf.push(TLV_END_OF_RECORD);
    Ok(())
}

fn add_tlv_flow(
    sp: &SendParameter,
    flow: &Flow,
    buf: &mut Vec<u8>,
    max_size: usize,
) -> Result<(), ()> {
    tlv_put_uint(buf, max_size, 7, flow.key.port[0] as u64)?; // NTOPNG_L4_SRC_PORT
    tlv_put_uint(buf, max_size, 11, flow.key.port[1] as u64)?; // NTOPNG_L4_DST_PORT
    tlv_put_uint(buf, max_size, 1, flow.octets[0] as u64)?; // NTOPNG_IN_BYTES
    tlv_put_uint(buf, max_size, 2, flow.packets[0] as u64)?; // NTOPNG_IN_PKTS
    tlv_put_uint(buf, max_size, 23, flow.octets[1] as u64)?; // NTOPNG_OUT_BYTES
    tlv_put_uint(buf, max_size, 24, flow.packets[1] as u64)?; // NTOPNG_OUT_PKTS
    tlv_put_uint(buf, max_size, 22, flow.flow_start.tv_sec as u64)?; // NTOPNG_FIRST_SWITCHED
    tlv_put_uint(buf, max_size, 21, flow.flow_last.tv_sec as u64)?; // NTOPNG_LAST_SWITCHED
    tlv_put_uint(buf, max_size, 6, flow.tcp_flags[0] as u64)?; // NTOPNG_TCP_FLAGS
    tlv_put_uint(buf, max_size, 4, flow.key.protocol as u64)?; // NTOPNG_PROTOCOL

    match flow.key.addr[0] {
        IpAddr::V4(v4) => {
            tlv_put_string(buf, max_size, 8, &v4.to_string())?; // NTOPNG_IPV4_SRC_ADDR
            match flow.key.addr[1] {
                IpAddr::V4(v4_dst) => {
                    tlv_put_string(buf, max_size, 12, &v4_dst.to_string())?; // NTOPNG_IPV4_DST_ADDR
                }
                _ => return Err(()),
            }
        }
        IpAddr::V6(v6) => {
            tlv_put_string(buf, max_size, 27, &v6.to_string())?; // NTOPNG_IPV6_SRC_ADDR
            match flow.key.addr[1] {
                IpAddr::V6(v6_dst) => {
                    tlv_put_string(buf, max_size, 28, &v6_dst.to_string())?; // NTOPNG_IPV6_DST_ADDR
                }
                _ => return Err(()),
            }
        }
    }

    if sp.param.track_level >= TrackLevel::FullVlan {
        tlv_put_uint(buf, max_size, 58, flow.key.vlanid[0] as u64)?; // NTOPNG_SRC_VLAN
        tlv_put_uint(buf, max_size, 59, flow.key.vlanid[1] as u64)?; // NTOPNG_DST_VLAN
    }

    if sp.param.track_level >= TrackLevel::FullVlanEther {
        let mac0 = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            flow.key.ethermac[0][0],
            flow.key.ethermac[0][1],
            flow.key.ethermac[0][2],
            flow.key.ethermac[0][3],
            flow.key.ethermac[0][4],
            flow.key.ethermac[0][5]
        );
        let mac1 = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            flow.key.ethermac[1][0],
            flow.key.ethermac[1][1],
            flow.key.ethermac[1][2],
            flow.key.ethermac[1][3],
            flow.key.ethermac[1][4],
            flow.key.ethermac[1][5]
        );
        tlv_put_string(buf, max_size, 56, &mac0)?; // NTOPNG_IN_SRC_MAC
        tlv_put_string(buf, max_size, 57, &mac1)?; // NTOPNG_OUT_DST_MAC
    }

    tlv_end_record(buf, max_size)
}

fn send_ntopng_message(sp: &SendParameter, start_at_flow: usize) -> usize {
    static MSG_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let mut payload = Vec::with_capacity(NTOPNG_MAX_TLV_SIZE);
    payload.push(TLV_VERSION);
    payload.push(TLV_FORMAT_TLV);

    let mut flow = start_at_flow;
    let mut added = 0;

    while flow < sp.flows.len() {
        let mark = payload.len();
        let f = sp.flows[flow];
        if add_tlv_flow(sp, f, &mut payload, NTOPNG_MAX_TLV_SIZE).is_err() {
            payload.truncate(mark);
            if added > 0 {
                break;
            }
            log::warn!("ntopng: flow too large for a TLV message");
        } else {
            added += 1;
        }
        flow += 1;
    }

    if added == 0 {
        return flow;
    }

    let msg_id = MSG_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut header = [0u8; 36];
    header[0..4].copy_from_slice(b"flow");
    header[16] = NTOPNG_MSG_VERSION;
    header[17] = NTOPNG_FLAG_IS_TLV;
    let uncompressed_size = payload.len() as u32;
    header[20..24].copy_from_slice(&uncompressed_size.to_be_bytes());
    header[24..28].copy_from_slice(&uncompressed_size.to_be_bytes());
    header[28..32].copy_from_slice(&msg_id.to_be_bytes());
    header[32..36].copy_from_slice(&0u32.to_ne_bytes());

    for dest in &sp.target.destinations {
        if let ExportSocket::Zmq { ref socket, .. } = dest.socket {
            if let Err(e) = socket.send(&header[..], zmq::SNDMORE) {
                log::warn!("ntopng: zmq_send failed: {}", e);
            }
            if let Err(e) = socket.send(&payload, 0) {
                log::warn!("ntopng: zmq_send failed: {}", e);
            }
        }
    }

    flow
}

pub fn send_ntopng(sp: &mut SendParameter) -> i32 {
    let mut flow_idx = 0;
    let mut packets = 0;

    while flow_idx < sp.flows.len() {
        flow_idx = send_ntopng_message(sp, flow_idx);
        packets += 1;
    }

    sp.param.records_sent += flow_idx as u64;
    sp.param.packets_sent += packets as u64;

    packets
}
