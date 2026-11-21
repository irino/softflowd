//! ICMP is not a biflow with `-b`: the type and code of a reply (echo reply)
//! differ from those of the request (echo), so the ICMP templates have no
//! reverse fields and an ICMP flow is exported as one record for each
//! direction.
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

const TEMPLATE_ICMPV4: u16 = 1025;
const REVERSE_BIT: u16 = 0x8000;

// The fields of a template of IPFIX as (ie, length, is reverse).
fn ipfix_template(packet: &[u8], wanted: u16) -> Vec<(u16, u16, bool)> {
    let mut off = 16; // the header of IPFIX
    while off + 4 <= packet.len() {
        let set_id = BigEndian::read_u16(&packet[off..]);
        let set_len = BigEndian::read_u16(&packet[off + 2..]) as usize;
        assert!(set_len >= 4 && off + set_len <= packet.len());
        if set_id == 2 {
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
                    let ie = BigEndian::read_u16(&packet[p..]);
                    let len = BigEndian::read_u16(&packet[p + 2..]);
                    p += 4;
                    let reverse = ie & REVERSE_BIT != 0;
                    if reverse {
                        p += 4; // the private enterprise number
                    }
                    fields.push((ie & !REVERSE_BIT, len, reverse));
                }
                if id == wanted {
                    return fields;
                }
            }
        }
        off += set_len;
    }
    panic!("template {wanted} not found");
}

// The length of the data set of a template.
fn data_set_length(packet: &[u8], wanted: u16) -> usize {
    let mut off = 16;
    while off + 4 <= packet.len() {
        let set_id = BigEndian::read_u16(&packet[off..]);
        let set_len = BigEndian::read_u16(&packet[off + 2..]) as usize;
        if set_id == wanted {
            return set_len;
        }
        off += set_len;
    }
    panic!("data set {wanted} not found");
}

// Sends one ICMP flow that has octets in both directions, with -b.
fn export_icmp_biflow() -> Vec<u8> {
    let recv_socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind the receiver");
    let recv_addr = recv_socket.local_addr().unwrap();
    let send_socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind the sender");
    send_socket.connect(recv_addr).unwrap();

    let targets = NetflowTarget {
        destinations: vec![Destination {
            socket: ExportSocket::Udp(send_socket),
            arg: recv_addr.to_string(),
        }],
        version: 10,
        is_loadbalance: false,
    };
    let mut flow = common::make_dummy_flow();
    let key = std::sync::Arc::make_mut(&mut flow.key);
    key.protocol = 1; // ICMP
    key.port = [0, 0x0800];
    flow.octets = [84, 84];
    flow.packets = [1, 1];
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
        bidirection: true,
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
        .expect("Failed to receive the IPFIX packet");
    buf[..len].to_vec()
}

#[test]
fn test_icmp_has_no_biflow_template_and_one_record_for_each_direction() {
    let packet = export_icmp_biflow();

    let fields = ipfix_template(&packet, TEMPLATE_ICMPV4);
    assert!(
        fields.iter().all(|f| !f.2),
        "the ICMP template has reverse fields: {fields:?}"
    );

    // The size of a record is the sum of the field lengths; the data set has
    // the header of 4 octets, the two records and up to 3 octets of padding.
    let record_len: usize = fields.iter().map(|f| f.1 as usize).sum();
    let set_len = data_set_length(&packet, TEMPLATE_ICMPV4);
    assert_eq!((set_len - 4) / record_len, 2, "records of the ICMP flow");
}
