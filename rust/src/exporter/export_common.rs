use crate::common::{Flow, FlowTrackParameters, TimeVal};
use std::sync::atomic::{AtomicI32, Ordering};

pub const IPFIX_SOFTFLOWD_V4_TEMPLATE_ID: u16 = 1024;
pub const IPFIX_SOFTFLOWD_ICMPV4_TEMPLATE_ID: u16 = 1025;
pub const IPFIX_SOFTFLOWD_V6_TEMPLATE_ID: u16 = 2048;
pub const IPFIX_SOFTFLOWD_ICMPV6_TEMPLATE_ID: u16 = 2049;
pub const IPFIX_SOFTFLOWD_OPTION_TEMPLATE_ID: u16 = 256;
pub const IPFIX_DEFAULT_TEMPLATE_INTERVAL: i32 = 16;
pub const IPFIX_SOFTFLOWD_MAX_PACKET_SIZE: usize = 1428;

pub const IPFIX_TEMPLATE_SET_ID: u16 = 2;
pub const IPFIX_OPTION_TEMPLATE_SET_ID: u16 = 3;
pub const NETFLOW9_TEMPLATE_SET_ID: u16 = 0;
pub const NETFLOW9_OPTION_TEMPLATE_SET_ID: u16 = 1;

pub const REVERSE_PEN: u32 = 29305;

pub const TMPLV4: usize = 0;
pub const TMPLICMPV4: usize = 1;
pub const TMPLV6: usize = 2;
pub const TMPLICMPV6: usize = 3;
pub const TMPLMAX: usize = 4;

static IPFIX_PKTS_UNTIL_TEMPLATE: AtomicI32 = AtomicI32::new(-1);

pub fn ipfix_resend_template() {
    let current = IPFIX_PKTS_UNTIL_TEMPLATE.load(Ordering::Relaxed);
    if current > 0 {
        IPFIX_PKTS_UNTIL_TEMPLATE.store(0, Ordering::Relaxed);
    }
}

pub fn get_pkts_until_template() -> i32 {
    IPFIX_PKTS_UNTIL_TEMPLATE.load(Ordering::Relaxed)
}

pub fn set_pkts_until_template(val: i32) {
    IPFIX_PKTS_UNTIL_TEMPLATE.store(val, Ordering::Relaxed);
}

pub fn decrement_pkts_until_template() {
    IPFIX_PKTS_UNTIL_TEMPLATE.fetch_sub(1, Ordering::Relaxed);
}

pub struct NtpTime {
    pub second: u32,
    pub fraction: u32,
}

pub fn conv_unix_to_ntp(tv: TimeVal) -> NtpTime {
    let second = (tv.tv_sec as u64 + 0x83AA7E80) as u32;
    let fraction = ((tv.tv_usec as f64 + 1.0) * (1u64 << 32) as f64 * 1.0e-6) as u32;
    NtpTime { second, fraction }
}

pub fn ipfix_flow_direction(flow: &Flow, i: usize, param: &FlowTrackParameters) -> u8 {
    if param.direction_mac_set
        && param.track_level >= crate::common::TrackLevel::FullVlanEther
        && let Some(dir_mac) = param.direction_mac
    {
        if flow.key.ethermac[i] == dir_mac {
            return 1; // EGRESS
        }
        if flow.key.ethermac[i ^ 1] == dir_mac {
            return 2; // INGRESS
        }
    }
    i as u8
}

pub fn ipfix_flow_to_template_index(flow: &Flow) -> usize {
    if flow.key.af == libc::AF_INET as u16 {
        if flow.key.protocol == libc::IPPROTO_ICMP as u8 {
            TMPLICMPV4
        } else {
            TMPLV4
        }
    } else if flow.key.af == libc::AF_INET6 as u16 {
        if flow.key.protocol == libc::IPPROTO_ICMPV6 as u8 {
            TMPLICMPV6
        } else {
            TMPLV6
        }
    } else {
        TMPLV4
    }
}

pub fn valuate_icmp(flow: &Flow) -> bool {
    (flow.key.af == libc::AF_INET as u16 && flow.key.protocol == libc::IPPROTO_ICMP as u8)
        || (flow.key.af == libc::AF_INET6 as u16 && flow.key.protocol == libc::IPPROTO_ICMPV6 as u8)
}

pub fn export_build_flow_header(
    packet: &mut Vec<u8>,
    version: u16,
    param: &FlowTrackParameters,
) -> usize {
    let now = crate::exporter::get_active_now(param);
    let sys_uptime = now.sub_ms(&param.system_boot_time);

    match version {
        1 | 5 => {
            packet.extend_from_slice(&version.to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes()); // placeholder for flows count
            packet.extend_from_slice(&sys_uptime.to_be_bytes());
            packet.extend_from_slice(&(now.tv_sec as u32).to_be_bytes());
            packet.extend_from_slice(&((now.tv_usec * 1000) as u32).to_be_bytes());
            if version == 5 {
                packet.extend_from_slice(&(param.flows_exported as u32).to_be_bytes());
                packet.push(0); // engine_type
                packet.push(0); // engine_id
                let sampling = if param.sample_rate > 0 {
                    0x4000 | (param.sample_rate & 0x3FFF) as u16
                } else {
                    0
                };
                packet.extend_from_slice(&sampling.to_be_bytes());
            }
            packet.len()
        }
        9 => {
            packet.extend_from_slice(&9u16.to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes()); // placeholder for flows count
            packet.extend_from_slice(&sys_uptime.to_be_bytes());
            packet.extend_from_slice(&(now.tv_sec as u32).to_be_bytes());
            packet.extend_from_slice(
                &((param.flows_exported + param.records_sent) as u32).to_be_bytes(),
            );
            packet.extend_from_slice(&0u32.to_be_bytes()); // observation domain id
            packet.len()
        }
        _ => {
            // IPFIX (10)
            packet.extend_from_slice(&10u16.to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes()); // placeholder for length
            packet.extend_from_slice(&(now.tv_sec as u32).to_be_bytes());
            packet.extend_from_slice(
                &((param.flows_exported + param.records_sent) as u32).to_be_bytes(),
            );
            packet.extend_from_slice(&0u32.to_be_bytes()); // observation domain id
            packet.len()
        }
    }
}

/// Length of the interfaceName field (IE 82) of the option records.
pub const INTERFACE_NAME_FIELD_LEN: usize = 16;

/// Encode the interface name of the option records: the capture interface,
/// or the file name with `-r`, cut at 15 bytes and padded with zeros.  Like
/// the C version (it keeps the name in a buffer of 16 bytes with strlcpy), the
/// field always ends with a NUL.
///
/// Original: export.c (`enc_interfaceName()`)
pub fn interface_name_field(name: &str) -> [u8; INTERFACE_NAME_FIELD_LEN] {
    let mut field = [0u8; INTERFACE_NAME_FIELD_LEN];
    let bytes = name.as_bytes();
    let n = bytes.len().min(INTERFACE_NAME_FIELD_LEN - 1);
    field[..n].copy_from_slice(&bytes[..n]);
    field
}

#[cfg(test)]
mod interface_name_tests {
    use super::*;

    #[test]
    fn short_name_is_zero_padded() {
        let f = interface_name_field("eth0");
        assert_eq!(&f[..4], b"eth0");
        assert!(f[4..].iter().all(|&b| b == 0));
    }

    #[test]
    fn long_name_is_cut_at_15_bytes_and_ends_with_nul() {
        let f = interface_name_field("/tmp/a-long-file-name.pcap");
        assert_eq!(&f, b"/tmp/a-long-fil\0");
    }

    #[test]
    fn name_of_exactly_15_bytes_is_kept() {
        assert_eq!(
            &interface_name_field("0123456789abcde"),
            b"0123456789abcde\0"
        );
    }
}
