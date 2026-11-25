//! The PSAMP receive mode, `-R port` (D44): `rsoftflowd` reads the PSAMP data records that
//! softflowd exports (`-v psamp`) from a UDP port, as C does, and handles each packet as if it
//! had been captured.

use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// IPFIX_SOFTFLOWD_MAX_PACKET_SIZE: the size of a PSAMP message of softflowd.
const MESSAGE_SIZE: usize = 1428;

fn free_udp_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap().port()
}

/// An Ethernet frame of an IPv4/TCP packet (SYN, 20 octets of IP header, 20 of TCP header).
fn tcp_frame(src_port: u16) -> Vec<u8> {
    let mut frame = vec![0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01, 0x08, 0x00];
    frame.extend_from_slice(&[0x45, 0, 0, 40, 0, 1, 0, 0, 64, 6, 0, 0]);
    frame.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&80u16.to_be_bytes());
    frame.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0x20, 0, 0, 0, 0, 0]);
    frame
}

/// A PSAMP message as `send_psamp()` of C writes it: `octets` is the sectionExportedOctets.
fn psamp_message(frame: &[u8], seconds: u32, octets: u16, set_id: u16, version: u16) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&version.to_be_bytes());
    message.extend_from_slice(&(MESSAGE_SIZE as u16).to_be_bytes());
    message.extend_from_slice(&seconds.to_be_bytes());
    message.extend_from_slice(&[0; 8]); // sequence number, observation domain
    message.extend_from_slice(&set_id.to_be_bytes());
    message.extend_from_slice(&((MESSAGE_SIZE - 16) as u16).to_be_bytes());
    message.extend_from_slice(&1u64.to_be_bytes()); // selectionSequenceId
    message.extend_from_slice(&(seconds + 0x83AA_7E80).to_be_bytes()); // NTP seconds
    message.extend_from_slice(&0u32.to_be_bytes()); // NTP fraction
    message.extend_from_slice(&octets.to_be_bytes());
    message.extend_from_slice(frame);
    message.resize(MESSAGE_SIZE, 0);
    message
}

struct Receiver {
    child: Child,
    port: u16,
    ctl: std::path::PathBuf,
    dir: std::path::PathBuf,
}

impl Receiver {
    fn start(collector: u16, tag: &str) -> Receiver {
        let dir = std::env::temp_dir().join(format!("rsoftflowd_d44_{tag}_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let port = free_udp_port();
        let ctl = dir.join("ctl");
        let child = Command::new(env!("CARGO_BIN_EXE_rsoftflowd"))
            .args(["-d", "-a", "-R", &port.to_string()])
            .args(["-n", &format!("127.0.0.1:{collector}")])
            .arg("-p")
            .arg(dir.join("pid"))
            .arg("-c")
            .arg(&ctl)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to execute rsoftflowd");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ctl.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(ctl.exists(), "the control socket did not appear");
        Receiver {
            child,
            port,
            ctl,
            dir,
        }
    }

    /// Asks for the shutdown (the flows are exported), and returns the exit status.
    fn shutdown(mut self) -> Option<i32> {
        let _ = Command::new(env!("CARGO_BIN_EXE_rsoftflowctl"))
            .arg("-c")
            .arg(&self.ctl)
            .arg("shutdown")
            .output();
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status.code();
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                panic!("rsoftflowd did not exit after the shutdown");
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let _ = std::fs::remove_dir_all(&self.dir);
        status
    }
}

/// The 48-octet records of the NetFlow v5 datagrams that the collector got:
/// (source port, packets, octets).
fn v5_records(collector: &UdpSocket) -> Vec<(u16, u32, u32)> {
    let mut records = Vec::new();
    let mut buf = [0u8; 2048];
    while let Ok(n) = collector.recv(&mut buf) {
        assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 5);
        let count = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        assert_eq!(n, 24 + 48 * count);
        for i in 0..count {
            let r = &buf[24 + 48 * i..24 + 48 * (i + 1)];
            records.push((
                u16::from_be_bytes([r[32], r[33]]),
                u32::from_be_bytes([r[16], r[17], r[18], r[19]]),
                u32::from_be_bytes([r[20], r[21], r[22], r[23]]),
            ));
        }
    }
    records.sort();
    records
}

#[test]
fn test_d44_psamp_datagrams_are_read_with_r() {
    let collector = UdpSocket::bind("127.0.0.1:0").unwrap();
    collector
        .set_read_timeout(Some(Duration::from_millis(1500)))
        .unwrap();
    let receiver = Receiver::start(collector.local_addr().unwrap().port(), "read");
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let to = ("127.0.0.1", receiver.port);
    let secs = 1_700_000_000;
    let frame = tcp_frame(1000);
    // Two packets of one flow, and a packet of another one.
    sender
        .send_to(
            &psamp_message(&frame, secs, frame.len() as u16, 3072, 10),
            to,
        )
        .unwrap();
    sender
        .send_to(
            &psamp_message(&frame, secs + 1, frame.len() as u16, 3072, 10),
            to,
        )
        .unwrap();
    sender
        .send_to(&psamp_message(&tcp_frame(1001), secs + 2, 54, 3072, 10), to)
        .unwrap();
    // Not used, and no reason to stop: a short datagram, a message of another version, and
    // a set that is not the PSAMP data set (the template, for example).
    sender.send_to(&[0, 10, 0, 0, 0], to).unwrap();
    sender
        .send_to(&psamp_message(&frame, secs, 54, 3072, 9), to)
        .unwrap();
    sender
        .send_to(&psamp_message(&frame, secs, 54, 2, 10), to)
        .unwrap();
    std::thread::sleep(Duration::from_millis(500));

    assert_eq!(receiver.shutdown(), Some(1)); // as C, see D45
    assert_eq!(v5_records(&collector), vec![(1000, 2, 80), (1001, 1, 40)]);
}

#[test]
fn test_d44_frame_section_longer_than_the_datagram_is_cut() {
    let collector = UdpSocket::bind("127.0.0.1:0").unwrap();
    collector
        .set_read_timeout(Some(Duration::from_millis(1500)))
        .unwrap();
    let receiver = Receiver::start(collector.local_addr().unwrap().port(), "cut");
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let to = ("127.0.0.1", receiver.port);
    let frame = tcp_frame(1000);
    // The record says 3000 octets, the datagram has less: the packet is what was received,
    // and its length is 3000 as it is in a pcap record (the flow counts 3000 - 14 octets).
    sender
        .send_to(&psamp_message(&frame, 1_700_000_000, 3000, 3072, 10), to)
        .unwrap();
    // A datagram that ends inside the frame section: the packet is too short for TCP.
    let mut short = psamp_message(&frame, 1_700_000_001, 54, 3072, 10);
    short.truncate(38 + 20);
    sender.send_to(&short, to).unwrap();
    std::thread::sleep(Duration::from_millis(500));

    assert_eq!(receiver.shutdown(), Some(1)); // as C, see D45
    assert_eq!(v5_records(&collector), vec![(1000, 1, 2986)]);
}

#[test]
fn test_d44_port_in_use_is_written_like_c_and_exits_with_1() {
    let busy = UdpSocket::bind("0.0.0.0:0").unwrap();
    let port = busy.local_addr().unwrap().port();
    let out = Command::new(env!("CARGO_BIN_EXE_rsoftflowd"))
        .args(["-R", &port.to_string(), "-n", "127.0.0.1:9"])
        .output()
        .expect("Failed to execute rsoftflowd");
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        format!("bind to UDP port {port} failed: Address already in use\n")
    );
}

#[test]
fn test_d44_r_is_a_packet_source() {
    // Before D44, -R was ignored, and this command line asked for -i or -r.
    let out = Command::new(env!("CARGO_BIN_EXE_rsoftflowd"))
        .args(["-R", "0", "-c", "/nonexistent/dir/ctl"])
        .output()
        .expect("Failed to execute rsoftflowd");
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "unix domain bind(\"/nonexistent/dir/ctl\") error: No such file or directory\n"
    );
}
