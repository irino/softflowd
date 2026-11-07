use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

mod common;
use common::make_dummy_flow;

use rsoftflowd::common::{
    FLOW_END_REASON_ACTIVE_TIMEOUT, FLOW_END_REASON_END_OF_FLOW, FLOW_END_REASON_FORCE_END,
    FLOW_END_REASON_IDLE_TIMEOUT, FLOW_END_REASON_LACK_OF_RESOURCE, Flow, FlowTrackParameters,
    TimeVal, TrackLevel,
};
use rsoftflowd::control::{ControlCommand, start_control_server};
use rsoftflowd::exporter::{Destination, ExportSocket, NetflowTarget, SendParameter, send_flows};
use rsoftflowd::packet_parser::parse_packet;

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
                    resp.send("Number of active flows: 42\n".to_string())
                        .unwrap();
                }
                _ => panic!("Unexpected command"),
            }
        }
    });

    // Connect from client side
    let mut stream = UnixStream::connect(socket_path).expect("Failed to connect to control socket");
    stream
        .write_all(b"statistics\n")
        .expect("Failed to send command");

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .expect("Failed to read response");

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
    // tv_sec is not an i64 on every target, so the cast is needed there.
    #[allow(clippy::unnecessary_cast)]
    let timestamp = TimeVal {
        tv_sec: raw_packet.header.ts.tv_sec as i64,
        tv_usec: raw_packet.header.ts.tv_usec as i32,
    };

    assert_eq!(timestamp.tv_sec, 1600000000);
    assert_eq!(timestamp.tv_usec, 12345);

    let parsed = parse_packet(
        linktype,
        raw_packet.data,
        caplen,
        len,
        TrackLevel::Full,
        0,
        false,
        timestamp,
    )
    .expect("Failed to parse packet");

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
fn test_exporter_version(version: u16) -> Vec<u8> {
    // Bind receiver UDP socket
    let recv_socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind UDP receiver socket");
    let recv_addr = recv_socket
        .local_addr()
        .expect("Failed to get local address");

    // Bind sender UDP socket
    let send_socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind UDP sender socket");
    send_socket
        .connect(recv_addr)
        .expect("Failed to connect to receiver socket");

    let targets = NetflowTarget {
        destinations: vec![Destination {
            socket: ExportSocket::Udp(send_socket),
            arg: recv_addr.to_string(),
        }],
        version: version as u32,
        is_loadbalance: false,
    };

    let flow = make_dummy_flow();
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

    let count = send_flows(sp);
    assert!(count > 0, "send_flows returned error or 0 packets");

    let mut buf = [0u8; 2048];
    recv_socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (received_len, _) = recv_socket
        .recv_from(&mut buf)
        .expect("Failed to receive exported Netflow/IPFIX packet");

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

#[test]
fn test_exporter_ipfix_biflow() {
    let recv_socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind UDP receiver socket");
    let recv_addr = recv_socket
        .local_addr()
        .expect("Failed to get local address");

    let send_socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind UDP sender socket");
    send_socket
        .connect(recv_addr)
        .expect("Failed to connect to receiver socket");

    let targets = NetflowTarget {
        destinations: vec![Destination {
            socket: ExportSocket::Udp(send_socket),
            arg: recv_addr.to_string(),
        }],
        version: 10,
        is_loadbalance: false,
    };

    let flow = make_dummy_flow();
    let flow_refs = vec![&flow];
    let mut param = FlowTrackParameters {
        system_boot_time: TimeVal {
            tv_sec: 1599999900,
            tv_usec: 0,
        },
        bidirection: true,
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

    let count = send_flows(sp);
    assert!(count > 0, "send_flows returned error or 0 packets");

    let mut buf = [0u8; 2048];
    recv_socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (received_len, _) = recv_socket
        .recv_from(&mut buf)
        .expect("Failed to receive IPFIX biflow packet");
    assert!(received_len >= 16);
    let version = BigEndian::read_u16(&buf[0..2]);
    assert_eq!(version, 10);
}

#[test]
fn test_packet_parser_dlt_ppp() {
    // DLT_PPP packet with IPv4
    // 5 bytes PPP header: e.g. [0xff, 0x03, 0x00, 0x00, 0x21] + IPv4 header (20 bytes) + UDP (8 bytes)
    let mut ppp_packet = vec![0xff, 0x03, 0x00, 0x00, 0x21]; // proto 0x0021 = IPv4
    // IPv4 header
    let ip_header: [u8; 20] = [
        0x45, 0x00, 0x00, 0x28, // v4, ihl=5, total_len=40
        0x12, 0x34, 0x00, 0x00, // id, flags
        0x40, 0x11, 0x00, 0x00, // ttl=64, proto=UDP(17), chksum
        192, 168, 1, 10, 192, 168, 1, 20,
    ];
    ppp_packet.extend_from_slice(&ip_header);
    // UDP header (8 bytes)
    let udp_header: [u8; 8] = [
        0x10, 0x00, // sport 4096
        0x20, 0x00, // dport 8192
        0x00, 0x14, // len 20
        0x00, 0x00,
    ];
    ppp_packet.extend_from_slice(&udp_header);

    let timestamp = TimeVal {
        tv_sec: 1600000000,
        tv_usec: 0,
    };
    let parsed = parse_packet(
        rsoftflowd::packet_parser::DLT_PPP,
        &ppp_packet,
        ppp_packet.len() as u32,
        ppp_packet.len() as u32,
        TrackLevel::Full,
        0,
        false,
        timestamp,
    )
    .expect("Failed to parse DLT_PPP packet");

    assert_eq!(parsed.af, 2);
    assert_eq!(parsed.protocol, 17);
    assert_eq!(parsed.src_port, 4096);
    assert_eq!(parsed.dst_port, 8192);
}

#[test]
fn test_packet_parser_dlt_pflog() {
    // DLT_PFLOG packet: 48 bytes pflog header + IPv4 header (20 bytes) + UDP (8 bytes)
    let mut pflog_packet = vec![0; 48];
    pflog_packet[1] = 2; // AF_INET = 2

    let ip_header: [u8; 20] = [
        0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 10, 0, 0, 1, 10, 0,
        0, 2,
    ];
    pflog_packet.extend_from_slice(&ip_header);

    let udp_header: [u8; 8] = [
        0x04, 0x00, // sport 1024
        0x08, 0x00, // dport 2048
        0x00, 0x14, 0x00, 0x00,
    ];
    pflog_packet.extend_from_slice(&udp_header);

    let timestamp = TimeVal {
        tv_sec: 1600000000,
        tv_usec: 0,
    };
    let parsed = parse_packet(
        rsoftflowd::packet_parser::DLT_PFLOG,
        &pflog_packet,
        pflog_packet.len() as u32,
        pflog_packet.len() as u32,
        TrackLevel::Full,
        0,
        false,
        timestamp,
    )
    .expect("Failed to parse DLT_PFLOG packet");

    assert_eq!(parsed.af, 2);
    assert_eq!(parsed.protocol, 17);
    assert_eq!(parsed.src_port, 1024);
    assert_eq!(parsed.dst_port, 2048);
}

#[test]
fn test_psamp_exporter() {
    let recv_socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind UDP receiver socket");
    let recv_addr = recv_socket
        .local_addr()
        .expect("Failed to get local address");

    let send_socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind UDP sender socket");
    send_socket
        .connect(recv_addr)
        .expect("Failed to connect to receiver socket");

    let targets = NetflowTarget {
        destinations: vec![Destination {
            socket: ExportSocket::Udp(send_socket),
            arg: recv_addr.to_string(),
        }],
        version: 10,
        is_loadbalance: false,
    };

    let dummy_packet = [0x45; 64];
    let timestamp = TimeVal {
        tv_sec: 1600000000,
        tv_usec: 500,
    };
    let mut param = FlowTrackParameters::default();
    let sent = rsoftflowd::exporter::psamp::send_psamp(
        &dummy_packet,
        64,
        timestamp,
        &targets,
        1,
        &mut param,
    );
    assert!(sent >= 0);

    let mut buf = [0u8; 2048];
    recv_socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (received_len, _) = recv_socket
        .recv_from(&mut buf)
        .expect("Failed to receive PSAMP packet");
    assert!(received_len >= 16);
    let version = BigEndian::read_u16(&buf[0..2]);
    assert_eq!(version, 10);
}

#[test]
fn test_psamp_sequence_numbers_first_20() {
    let pcap_path = "/tmp/test_psamp_120.pcap";
    let _ = std::fs::remove_file(pcap_path);

    {
        let mut file = File::create(pcap_path).unwrap();
        // Global Header (24 bytes)
        file.write_u32::<BigEndian>(0xa1b2c3d4).unwrap(); // magic
        file.write_u16::<BigEndian>(2).unwrap(); // version_major
        file.write_u16::<BigEndian>(4).unwrap(); // version_minor
        file.write_i32::<BigEndian>(0).unwrap(); // thiszone
        file.write_u32::<BigEndian>(0).unwrap(); // sigfigs
        file.write_u32::<BigEndian>(65535).unwrap(); // snaplen
        file.write_u32::<BigEndian>(1).unwrap(); // network (DLT_EN10MB = 1)

        for i in 0..120 {
            let mut pkt = Vec::new();
            pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Dst MAC
            pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // Src MAC
            pkt.write_u16::<BigEndian>(0x0800).unwrap(); // Type: IPv4

            pkt.write_u8(0x45).unwrap(); // Version: 4, IHL: 5
            pkt.write_u8(0x00).unwrap(); // ToS
            pkt.write_u16::<BigEndian>(40).unwrap(); // Total Length
            pkt.write_u16::<BigEndian>((0x1234 + i) as u16).unwrap(); // ID
            pkt.write_u16::<BigEndian>(0x4000).unwrap(); // Flags
            pkt.write_u8(64).unwrap(); // TTL
            pkt.write_u8(6).unwrap(); // Protocol: TCP
            pkt.write_u16::<BigEndian>(0).unwrap(); // Checksum
            pkt.extend_from_slice(&[192, 168, 1, 100]); // Src IP
            pkt.extend_from_slice(&[192, 168, 1, 200]); // Dst IP

            pkt.write_u16::<BigEndian>(12345).unwrap(); // Src Port
            pkt.write_u16::<BigEndian>(80).unwrap(); // Dst Port
            pkt.write_u32::<BigEndian>(100).unwrap(); // Seq
            pkt.write_u32::<BigEndian>(0).unwrap(); // Ack
            pkt.write_u16::<BigEndian>(0x5002).unwrap(); // Flags: SYN
            pkt.write_u16::<BigEndian>(65535).unwrap(); // Window
            pkt.write_u16::<BigEndian>(0).unwrap(); // Checksum
            pkt.write_u16::<BigEndian>(0).unwrap(); // Urgent

            file.write_u32::<BigEndian>(1600000000 + i).unwrap(); // ts_sec
            file.write_u32::<BigEndian>(0).unwrap(); // ts_usec
            file.write_u32::<BigEndian>(pkt.len() as u32).unwrap();
            file.write_u32::<BigEndian>(pkt.len() as u32).unwrap();
            file.write_all(&pkt).unwrap();
        }
    }

    let recv_socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind UDP receiver socket");
    let rcvbuf: libc::c_int = 8 * 1024 * 1024;
    unsafe {
        libc::setsockopt(
            recv_socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &rcvbuf as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
    let recv_addr = recv_socket
        .local_addr()
        .expect("Failed to get local address");

    let send_socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind UDP sender socket");
    send_socket
        .connect(recv_addr)
        .expect("Failed to connect to receiver socket");

    let targets = NetflowTarget {
        destinations: vec![Destination {
            socket: ExportSocket::Udp(send_socket),
            arg: recv_addr.to_string(),
        }],
        version: 10,
        is_loadbalance: false,
    };

    let mut capture = pcap::Capture::from_file(pcap_path).expect("Failed to open PCAP file");
    let mut param = FlowTrackParameters {
        is_psamp: true,
        ..Default::default()
    };

    let mut total_packets = 0u64;
    while let Ok(raw_packet) = capture.next_packet() {
        total_packets += 1;
        param.total_packets = total_packets;
        param.last_packet_time = TimeVal {
            tv_sec: raw_packet.header.ts.tv_sec,
            tv_usec: raw_packet.header.ts.tv_usec as i32,
        };
        let timestamp = param.last_packet_time;
        rsoftflowd::exporter::psamp::send_psamp(
            raw_packet.data,
            raw_packet.header.caplen,
            timestamp,
            &targets,
            total_packets,
            &mut param,
        );
    }

    recv_socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let mut seq_numbers = Vec::new();
    let mut buf = [0u8; 2048];

    for _ in 0..25 {
        match recv_socket.recv_from(&mut buf) {
            Ok((len, _)) => {
                if len >= 12 {
                    let version = BigEndian::read_u16(&buf[0..2]);
                    if version == 10 {
                        let seq = BigEndian::read_u32(&buf[8..12]);
                        seq_numbers.push(seq);
                    }
                }
            }
            Err(_) => break,
        }
    }

    let _ = std::fs::remove_file(pcap_path);

    assert!(
        seq_numbers.len() >= 20,
        "Expected at least 20 messages, got {}",
        seq_numbers.len()
    );

    let expected = vec![
        0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 16, 17,
    ];
    assert_eq!(&seq_numbers[0..20], &expected[..]);
}

#[test]
fn test_control_rendering() {
    let tracker = rsoftflowd::common::FlowTracker::new(1024);
    let stats = rsoftflowd::control::render_statistics(&tracker, Some((100, 5, 2)));
    assert!(stats.contains("Number of active flows:"));
    assert!(stats.contains("Packets received by libpcap: 100"));
    assert!(stats.contains("Packets dropped by libpcap: 5"));
    assert!(stats.contains("Packets dropped by interface: 2"));

    let timeouts = rsoftflowd::control::render_timeouts(&tracker);
    assert!(timeouts.contains("tcp ="));

    let help = rsoftflowd::control::render_help();
    assert!(help.contains("Valid control words are:"));

    let dump = rsoftflowd::control::render_dump_flows(&tracker);
    assert_eq!(dump, "");
}

#[test]
fn test_flow_lookup_modes() {
    let mut tracker = rsoftflowd::common::FlowTracker::new(1024);
    tracker.set_flow_lookup(rsoftflowd::common::FlowLookupMode::Tree);
    assert_eq!(tracker.nbuckets, 1);
    let (used, depth) = tracker.table_usage();
    assert_eq!(used, 0);
    assert_eq!(depth, 0);

    tracker.set_flow_lookup(rsoftflowd::common::FlowLookupMode::HashTree);
    assert!(tracker.nbuckets >= 1024);

    tracker.set_flow_lookup(rsoftflowd::common::FlowLookupMode::Hash);
    assert!(tracker.nbuckets >= 2048);

    let stats = rsoftflowd::control::render_statistics(&tracker, Some((10, 0, 0)));
    assert!(stats.contains("Flow table: hash"));
}

fn run_rsoftflowd_with_timeout(args: &[&str], timeout: Duration) -> std::process::ExitStatus {
    let bin = env!("CARGO_BIN_EXE_rsoftflowd");
    let mut child = std::process::Command::new(bin)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to spawn rsoftflowd");

    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status,
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    panic!("Process timed out for args: {:?}", args);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                let _ = child.kill();
                panic!("Error waiting for process for args {:?}: {}", args, e);
            }
        }
    }
}

#[test]
fn test_cli_error_exits_1() {
    let cases = vec![
        vec!["-i", "nonexistent0", "-n", "127.0.0.1:9"],
        vec!["-n", ""],
        vec!["-I", "abc"],
    ];
    for args in cases {
        let status = run_rsoftflowd_with_timeout(&args, Duration::from_secs(5));
        assert!(!status.success(), "Expected failure for args: {:?}", args);
        assert_eq!(
            status.code(),
            Some(1),
            "Expected exit status 1 for args: {:?}",
            args
        );
    }
}

// -------------------------------------------------------------
// Test: NetFlow v5 flow sequence numbers
// -------------------------------------------------------------
#[test]
fn test_exporter_netflow_v5_sequence_numbers() {
    let recv_socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind UDP receiver socket");
    let recv_addr = recv_socket
        .local_addr()
        .expect("Failed to get local address");

    let send_socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind UDP sender socket");
    send_socket
        .connect(recv_addr)
        .expect("Failed to connect to receiver socket");

    let targets = NetflowTarget {
        destinations: vec![Destination {
            socket: ExportSocket::Udp(send_socket),
            arg: recv_addr.to_string(),
        }],
        version: 5,
        is_loadbalance: false,
    };

    let mut flows = Vec::new();
    for i in 0..86 {
        let mut flow = make_dummy_flow();
        flow.key.port[0] = 10000 + i as u16;
        flow.octets = [1000, 0]; // 1 record per flow
        flows.push(flow);
    }
    let flow_refs: Vec<&Flow> = flows.iter().collect();

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

    let packets_sent = send_flows(sp);
    assert_eq!(packets_sent, 3);

    recv_socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let expected_seqs = vec![0u32, 30u32, 60u32];
    for expected_seq in expected_seqs {
        let mut buf = [0u8; 2048];
        let (received_len, _) = recv_socket
            .recv_from(&mut buf)
            .expect("Failed to receive Netflow v5 packet");
        assert!(received_len >= 24);
        let version = BigEndian::read_u16(&buf[0..2]);
        let count = BigEndian::read_u16(&buf[2..4]);
        let seq = BigEndian::read_u32(&buf[16..20]);
        assert_eq!(version, 5);
        assert_eq!(seq, expected_seq);
        assert!(count > 0);
    }
}

// -------------------------------------------------------------
// Test: flowEndReason values follow the IANA IPFIX registry
// -------------------------------------------------------------
#[test]
fn test_flow_end_reason_values() {
    assert_eq!(FLOW_END_REASON_IDLE_TIMEOUT, 1);
    assert_eq!(FLOW_END_REASON_ACTIVE_TIMEOUT, 2);
    assert_eq!(FLOW_END_REASON_END_OF_FLOW, 3);
    assert_eq!(FLOW_END_REASON_FORCE_END, 4);
    assert_eq!(FLOW_END_REASON_LACK_OF_RESOURCE, 5);
}

// -------------------------------------------------------------
// Test D6: Logging stderr with -d -r FILE compares first four lines with C wording
// -------------------------------------------------------------
#[test]
fn test_d6_logging_stderr_first_four_lines() {
    let pcap_path = "/tmp/test_d6.pcap";
    let _ = std::fs::remove_file(pcap_path);
    create_temp_pcap(pcap_path).unwrap();

    let bin = env!("CARGO_BIN_EXE_rsoftflowd");
    let output = std::process::Command::new(bin)
        .args(["-d", "-r", pcap_path, "-n", "127.0.0.1:9"])
        .output()
        .expect("Failed to execute rsoftflowd");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let lines: Vec<&str> = stderr.lines().collect();

    assert!(
        lines.len() >= 4,
        "Expected at least 4 lines of stderr, got {}: {:?}",
        lines.len(),
        lines
    );
    assert_eq!(
        lines[0],
        format!(
            "rsoftflowd v{} starting data collection",
            env!("CARGO_PKG_VERSION")
        )
    );
    assert_eq!(
        lines[1],
        format!("Exporting flows from {} to [127.0.0.1]:9", pcap_path)
    );
    assert_eq!(lines[2], "Shutting down after pcap EOF");
    assert_eq!(lines[3], "Shutting down on user request");

    let _ = std::fs::remove_file(pcap_path);
}

// -------------------------------------------------------------
// Test: the names of the flow tracking levels (-T) of the C version
// -------------------------------------------------------------
#[test]
fn test_track_level_names() {
    for name in ["ip", "proto", "port", "full", "vlan", "ether"] {
        let level = TrackLevel::from_name(name).unwrap_or_else(|| panic!("{name} is not a level"));
        assert_eq!(level.to_str(), name);
    }
    // The names are not case sensitive, as in the C version.
    assert_eq!(TrackLevel::from_name("PORT"), Some(TrackLevel::IpProtoPort));
    assert_eq!(TrackLevel::from_name("bogus"), None);
}

#[cfg(feature = "ntopng")]
#[test]
fn test_ntopng_exporter() {
    let sub_socket = zmq::Context::new().socket(zmq::SUB).unwrap();
    sub_socket.bind("tcp://127.0.0.1:0").unwrap();
    let endpoint = sub_socket.get_last_endpoint().unwrap().unwrap();
    let host_port = endpoint.strip_prefix("tcp://").unwrap();
    sub_socket.set_subscribe(b"flow").unwrap();

    let send_context = zmq::Context::new();
    let send_socket = send_context.socket(zmq::PUB).unwrap();
    send_socket.connect(&endpoint).unwrap();

    let target = NetflowTarget {
        destinations: vec![Destination {
            socket: ExportSocket::Zmq {
                context: send_context,
                socket: send_socket,
            },
            arg: host_port.to_string(),
        }],
        version: 0x7fff0001,
        is_loadbalance: false,
    };

    let flow = make_dummy_flow();
    let flow_refs = vec![&flow];
    let mut param = FlowTrackParameters::default();
    let sp = SendParameter {
        flows: &flow_refs,
        target: &target,
        ifidx: 1,
        param: &mut param,
        verbose: false,
    };

    let count = rsoftflowd::exporter::export::send_flows(sp);
    assert!(count > 0);

    let mut msg_header = zmq::Message::new();
    sub_socket.recv(&mut msg_header, 0).unwrap();
    assert_eq!(msg_header.len(), 36);
    assert_eq!(&msg_header[0..4], b"flow");
    assert_eq!(msg_header[16], 4);
    assert_eq!(msg_header[17], 2);

    let mut msg_payload = zmq::Message::new();
    sub_socket.recv(&mut msg_payload, 0).unwrap();
    assert!(msg_payload.len() > 2);
    assert_eq!(msg_payload[0], 1);
    assert_eq!(msg_payload[1], 1);
}
