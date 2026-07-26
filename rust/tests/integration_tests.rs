use std::net::{UdpSocket, IpAddr, Ipv4Addr};
use std::os::unix::net::UnixStream;
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;
use std::fs::File;
use std::io::{Write, BufReader, BufRead};
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};

use rsoftflowd::common::{
    Flow, FlowKey, TimeVal, ExpiryReason, TrackLevel, FlowTrackParameters
};
use rsoftflowd::packet_parser::parse_packet;
use rsoftflowd::exporter::{
    Destination, ExportSocket, NetflowTarget, SendParameter, send_flows
};
use rsoftflowd::control::{start_control_server, ControlCommand};

// -------------------------------------------------------------
// Test 1: rsoftflowd and rsoftflowctl connection
// -------------------------------------------------------------
#[test]
fn test_control_server_connection() {
    let socket_path = "/tmp/test_rsoftflowd_ctl.sock";
    let _ = std::fs::remove_file(socket_path);

    let (cmd_tx, cmd_rx) = channel();

    // Start server in background
    start_control_server(socket_path.to_string(), cmd_tx).expect("Failed to start control server");

    // Spawn a dummy daemon event loop thread that handles the commands received from control server
    let daemon_handle = thread::spawn(move || {
        if let Ok(cmd) = cmd_rx.recv() {
            match cmd {
                ControlCommand::Statistics { resp } => {
                    resp.send("Number of active flows: 42\n".to_string()).unwrap();
                }
                _ => panic!("Unexpected command"),
            }
        }
    });

    // Connect from client side
    let mut stream = UnixStream::connect(socket_path).expect("Failed to connect to control socket");
    stream.write_all(b"statistics\n").expect("Failed to send command");

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader.read_line(&mut response).expect("Failed to read response");

    assert_eq!(response, "Number of active flows: 42\n");

    daemon_handle.join().unwrap();
    let _ = std::fs::remove_file(socket_path);
}

// -------------------------------------------------------------
// Test 2: rsoftflowd pcap file reading & parsing
// -------------------------------------------------------------
fn create_temp_pcap(path: &str) -> std::io::Result<()> {
    let mut file = File::create(path)?;

    // Global Header (24 bytes)
    file.write_u32::<BigEndian>(0xa1b2c3d4)?; // magic
    file.write_u16::<BigEndian>(2)?; // version_major
    file.write_u16::<BigEndian>(4)?; // version_minor
    file.write_i32::<BigEndian>(0)?; // thiszone
    file.write_u32::<BigEndian>(0)?; // sigfigs
    file.write_u32::<BigEndian>(65535)?; // snaplen
    file.write_u32::<BigEndian>(1)?; // network (DLT_EN10MB = 1)

    // Packet Data: Ethernet + IPv4 + TCP (SYN)
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Dst MAC
    pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // Src MAC
    pkt.write_u16::<BigEndian>(0x0800)?; // Type: IPv4

    pkt.write_u8(0x45)?; // Version: 4, IHL: 5
    pkt.write_u8(0x00)?; // ToS
    pkt.write_u16::<BigEndian>(40)?; // Total Length (IP + TCP = 40 bytes)
    pkt.write_u16::<BigEndian>(0x1234)?; // ID
    pkt.write_u16::<BigEndian>(0x4000)?; // Flags/Fragment Offset (Don't Fragment)
    pkt.write_u8(64)?; // TTL
    pkt.write_u8(6)?; // Protocol: TCP
    pkt.write_u16::<BigEndian>(0)?; // Checksum
    pkt.extend_from_slice(&[192, 168, 1, 100]); // Src IP
    pkt.extend_from_slice(&[192, 168, 1, 200]); // Dst IP

    pkt.write_u16::<BigEndian>(12345)?; // Src Port
    pkt.write_u16::<BigEndian>(80)?; // Dst Port
    pkt.write_u32::<BigEndian>(100)?; // Seq
    pkt.write_u32::<BigEndian>(0)?; // Ack
    pkt.write_u16::<BigEndian>(0x5002)?; // Offset: 5, Flags: SYN (0x02)
    pkt.write_u16::<BigEndian>(65535)?; // Window
    pkt.write_u16::<BigEndian>(0)?; // Checksum
    pkt.write_u16::<BigEndian>(0)?; // Urgent Pointer

    // Packet Header (16 bytes)
    file.write_u32::<BigEndian>(1600000000)?; // ts_sec
    file.write_u32::<BigEndian>(12345)?; // ts_usec
    file.write_u32::<BigEndian>(pkt.len() as u32)?; // caplen
    file.write_u32::<BigEndian>(pkt.len() as u32)?; // len

    file.write_all(&pkt)?;
    Ok(())
}

#[test]
fn test_pcap_file_reading() {
    let pcap_path = "/tmp/test_rsoftflowd_read.pcap";
    create_temp_pcap(pcap_path).expect("Failed to create temporary PCAP file");

    let mut capture = pcap::Capture::from_file(pcap_path).expect("Failed to open PCAP file");
    let linktype = capture.get_datalink().0;

    assert_eq!(linktype, 1); // DLT_EN10MB

    let raw_packet = capture.next_packet().expect("Failed to read packet");
    let caplen = raw_packet.header.caplen;
    let len = raw_packet.header.len;
    let timestamp = TimeVal {
        tv_sec: raw_packet.header.ts.tv_sec as i64,
        tv_usec: raw_packet.header.ts.tv_usec as i32,
    };

    assert_eq!(timestamp.tv_sec, 1600000000);
    assert_eq!(timestamp.tv_usec, 12345);

    let parsed = parse_packet(
        linktype,
        &raw_packet.data,
        caplen,
        len,
        TrackLevel::Full,
        timestamp,
    ).expect("Failed to parse packet");

    assert_eq!(parsed.af, 2); // AF_INET
    assert_eq!(parsed.protocol, 6); // TCP
    assert_eq!(parsed.src_port, 12345);
    assert_eq!(parsed.dst_port, 80);
    assert_eq!(parsed.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
    assert_eq!(parsed.dst_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)));
    assert_eq!(parsed.tcp_flags, 0x02); // SYN
    assert_eq!(parsed.length, 40); // IP(20) + TCP(20)

    let _ = std::fs::remove_file(pcap_path);
}

// -------------------------------------------------------------
// Test 3: Exporter versions packet frame generation
// -------------------------------------------------------------
fn make_dummy_flow() -> Flow {
    let key = FlowKey {
        af: 2,
        protocol: 6, // TCP
        addr: [IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200))],
        port: [12345, 80],
        vlanid: [0, 0],
        ethermac: [[0; 6]; 2],
        mpls_label_depth: 0,
        mpls_labels: [0; 10],
    };

    Flow {
        flow_seq: 1,
        flow_start: TimeVal { tv_sec: 1600000000, tv_usec: 0 },
        flow_last: TimeVal { tv_sec: 1600000010, tv_usec: 0 },
        octets: [1000, 500],
        packets: [10, 5],
        tcp_flags: [0x02, 0x10], // SYN, ACK
        tos: [0x10, 0x00],
        ip6_flowlabel: [0, 0],
        flow_end_reason: 3, // End of flow
        key,
        expiry_key: None,
        expiry_reason: ExpiryReason::General,
    }
}

fn test_exporter_version(version: u16) -> Vec<u8> {
    // Bind receiver UDP socket
    let recv_socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind UDP receiver socket");
    let recv_addr = recv_socket.local_addr().expect("Failed to get local address");

    // Bind sender UDP socket
    let send_socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind UDP sender socket");
    send_socket.connect(recv_addr).expect("Failed to connect to receiver socket");

    let targets = NetflowTarget {
        destinations: vec![Destination {
            socket: ExportSocket::Udp(send_socket),
            arg: recv_addr.to_string(),
        }],
        version,
        is_loadbalance: false,
    };

    let flow = make_dummy_flow();
    let flow_refs = vec![&flow];
    let mut param = FlowTrackParameters::default();
    param.system_boot_time = TimeVal { tv_sec: 1599999900, tv_usec: 0 };
    param.adjust_time = true;
    param.last_packet_time = TimeVal { tv_sec: 1600000010, tv_usec: 0 };

    let sp = SendParameter {
        flows: &flow_refs,
        target: &targets,
        ifidx: 1,
        param: &mut param,
        verbose: false,
    };

    let count = send_flows(sp);
    assert!(count > 0, "send_flows returned error or 0 packets");

    let mut buf = [0u8; 2048];
    recv_socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let (received_len, _) = recv_socket.recv_from(&mut buf).expect("Failed to receive exported Netflow/IPFIX packet");

    buf[..received_len].to_vec()
}

#[test]
fn test_exporter_netflow_v1() {
    let packet = test_exporter_version(1);
    assert!(packet.len() >= 16);
    let version = BigEndian::read_u16(&packet[0..2]);
    let count = BigEndian::read_u16(&packet[2..4]);
    assert_eq!(version, 1);
    assert!(count > 0);
}

#[test]
fn test_exporter_netflow_v5() {
    let packet = test_exporter_version(5);
    assert!(packet.len() >= 24);
    let version = BigEndian::read_u16(&packet[0..2]);
    let count = BigEndian::read_u16(&packet[2..4]);
    assert_eq!(version, 5);
    assert!(count > 0);
}

#[test]
fn test_exporter_netflow_v9() {
    let packet = test_exporter_version(9);
    assert!(packet.len() >= 20);
    let version = BigEndian::read_u16(&packet[0..2]);
    assert_eq!(version, 9);
}

#[test]
fn test_exporter_ipfix() {
    let packet = test_exporter_version(10);
    assert!(packet.len() >= 16);
    let version = BigEndian::read_u16(&packet[0..2]);
    assert_eq!(version, 10);
}
