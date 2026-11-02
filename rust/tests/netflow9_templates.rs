//! The templates of NetFlow v9.
//!
//! This is a test binary of its own on purpose: the exporter sends the
//! templates only when a process-wide counter (`pkts_until_template`) has run
//! out, so a test that needs them in the first packet cannot share a process
//! with other tests that send flows.

mod common;

use std::net::UdpSocket;
use std::time::Duration;

use byteorder::{BigEndian, ByteOrder};

use rsoftflowd::common::{FlowTrackParameters, TimeVal};
use rsoftflowd::exporter::export_common::set_pkts_until_template;
use rsoftflowd::exporter::{Destination, ExportSocket, NetflowTarget, SendParameter, send_flows};

// Reads the template flowset (set id 0) of a NetFlow v9 packet and returns
// the templates as (template id, field types).
fn nf9_templates(packet: &[u8]) -> Vec<(u16, Vec<u16>)> {
    let mut templates = Vec::new();
    let mut off = 20; // the header of NetFlow v9
    while off + 4 <= packet.len() {
        let set_id = BigEndian::read_u16(&packet[off..]);
        let set_len = BigEndian::read_u16(&packet[off + 2..]) as usize;
        assert!(set_len >= 4 && off + set_len <= packet.len());
        if set_id == 0 {
            let end = off + set_len;
            let mut p = off + 4;
            while p + 4 <= end {
                let id = BigEndian::read_u16(&packet[p..]);
                if id < 256 {
                    break; // padding
                }
                let count = BigEndian::read_u16(&packet[p + 2..]) as usize;
                p += 4;
                let mut fields = Vec::new();
                for _ in 0..count {
                    fields.push(BigEndian::read_u16(&packet[p..]));
                    p += 4;
                }
                templates.push((id, fields));
            }
        }
        off += set_len;
    }
    templates
}

// NetFlow v9 uses the same templates as IPFIX, as the C version does: IPv4,
// ICMPv4, IPv6 and ICMPv6, all with flowDirection (61) and flowEndReason
// (136), and the ICMP type and code (32 or 139) only in the ICMP templates.
#[test]
fn test_netflow_v9_templates_follow_the_c_version() {
    let packet = export_netflow_v9();
    let templates = nf9_templates(&packet);
    let ids: Vec<u16> = templates.iter().map(|t| t.0).collect();
    assert_eq!(ids, vec![1024, 1025, 2048, 2049]);
    for (id, fields) in &templates {
        assert!(fields.contains(&136), "template {id}: no flowEndReason");
        assert!(fields.contains(&61), "template {id}: no flowDirection");
        let is_icmp = *id == 1025 || *id == 2049;
        assert_eq!(
            fields.contains(&32) || fields.contains(&139),
            is_icmp,
            "template {id}: the ICMP type and code"
        );
    }
}

// Sends one flow as NetFlow v9 to a local socket and returns the packet.
fn export_netflow_v9() -> Vec<u8> {
    let recv_socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind the receiver");
    let recv_addr = recv_socket.local_addr().unwrap();
    let send_socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind the sender");
    send_socket.connect(recv_addr).unwrap();

    let targets = NetflowTarget {
        destinations: vec![Destination {
            socket: ExportSocket::Udp(send_socket),
            arg: recv_addr.to_string(),
        }],
        version: 9,
        is_loadbalance: false,
    };
    let flow = common::make_dummy_flow();
    let flow_refs = vec![&flow];
    let mut param = FlowTrackParameters {
        system_boot_time: TimeVal {
            tv_sec: 1599999900,
            tv_usec: 0,
        },
        adjust_time: true,
        last_packet_time: TimeVal {
            tv_sec: 1600000010,
            tv_usec: 0,
        },
        ..Default::default()
    };
    let sp = SendParameter {
        flows: &flow_refs,
        target: &targets,
        ifidx: 1,
        param: &mut param,
        verbose: false,
    };

    // Send the templates with the first packet.
    set_pkts_until_template(0);
    assert!(send_flows(sp) > 0, "send_flows returned an error");

    let mut buf = [0u8; 2048];
    recv_socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (len, _) = recv_socket
        .recv_from(&mut buf)
        .expect("Failed to receive the NetFlow v9 packet");
    buf[..len].to_vec()
}
