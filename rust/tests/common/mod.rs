//! Helpers shared by the integration tests.

use std::net::{IpAddr, Ipv4Addr};

use rsoftflowd::common::{ExpiryReason, FLOW_END_REASON_END_OF_FLOW, Flow, FlowKey, TimeVal};

/// A TCP flow from 192.168.1.100:12345 to 192.168.1.200:80.
pub fn make_dummy_flow() -> Flow {
    let key = FlowKey {
        af: 2,
        protocol: 6, // TCP
        addr: [
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
        ],
        port: [12345, 80],
        vlanid: [0, 0],
        ethermac: [[0; 6]; 2],
        mpls_label_depth: 0,
        mpls_labels: [0; 10],
    };

    Flow {
        flow_seq: 1,
        flow_start: TimeVal {
            tv_sec: 1600000000,
            tv_usec: 0,
        },
        flow_last: TimeVal {
            tv_sec: 1600000010,
            tv_usec: 0,
        },
        octets: [1000, 500],
        packets: [10, 5],
        tcp_flags: [0x02, 0x10], // SYN, ACK
        tos: [0x10, 0x00],
        ip6_flowlabel: [0, 0],
        src_mac: [0; 6],
        dst_mac: [0; 6],
        flow_end_reason: FLOW_END_REASON_END_OF_FLOW,
        key,
        expiry_key: None,
        expiry_reason: ExpiryReason::General,
    }
}
