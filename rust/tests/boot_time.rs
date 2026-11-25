//! The boot time (SysUptime) of the exported flows (D46).  As C does: it is the time of the
//! start, and only `-a` takes the time of the first packet instead; `-I` sets it again when
//! the flows are expired (the scan of the expiry), not for each packet.  The time of a flow
//! that is before the boot time is a 32 bit number that wraps, as `timeval_sub_ms()` of C.

use rsoftflowd::common::TimeVal;
use std::net::UdpSocket;
use std::process::Command;
use std::time::Duration;

/// A pcap file of 8 UDP packets from 10.0.0.1 to 10.0.0.2, each with its own source port
/// 2000..2007, at the times 1000, 1002, ... (a time of 1970).
fn pcap_file(tag: &str) -> std::path::PathBuf {
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0i32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&1u32.to_le_bytes()); // Ethernet
    for i in 0..8u32 {
        let mut frame = vec![0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01, 0x08, 0x00];
        frame.extend_from_slice(&[0x45, 0, 0, 32, 0, 1, 0, 0, 64, 17, 0, 0]);
        frame.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        frame.extend_from_slice(&(2000 + i as u16).to_be_bytes());
        frame.extend_from_slice(&53u16.to_be_bytes());
        frame.extend_from_slice(&[0, 12, 0, 0, b'a', b'b', b'c', b'd']);
        for field in [
            1000 + 2 * i,
            500_000,
            frame.len() as u32,
            frame.len() as u32,
        ] {
            pcap.extend_from_slice(&field.to_le_bytes());
        }
        pcap.extend_from_slice(&frame);
    }
    let dir = std::env::temp_dir().join(format!("rsoftflowd_d46_{tag}_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("old.pcap");
    std::fs::write(&path, pcap).unwrap();
    path
}

/// Runs `rsoftflowd -r` with NetFlow v5 and returns the uptime of the header of each datagram and
/// (source port, first, last) of each record, sorted by the port.
fn run(tag: &str, extra: &[&str]) -> (Vec<u32>, Vec<(u16, u32, u32)>) {
    let pcap = pcap_file(tag);
    let collector = UdpSocket::bind("127.0.0.1:0").unwrap();
    collector
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_rsoftflowd"))
        .arg("-r")
        .arg(&pcap)
        .args(["-v", "5", "-n"])
        .arg(format!(
            "127.0.0.1:{}",
            collector.local_addr().unwrap().port()
        ))
        .args(extra)
        .output()
        .expect("Failed to execute rsoftflowd");
    let _ = std::fs::remove_dir_all(pcap.parent().unwrap());
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let mut uptimes = Vec::new();
    let mut records = Vec::new();
    let mut buf = [0u8; 2048];
    while let Ok(n) = collector.recv(&mut buf) {
        let count = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        assert_eq!(n, 24 + 48 * count);
        uptimes.push(u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]));
        for i in 0..count {
            let r = &buf[24 + 48 * i..24 + 48 * (i + 1)];
            records.push((
                u16::from_be_bytes([r[32], r[33]]),
                u32::from_be_bytes([r[24], r[25], r[26], r[27]]),
                u32::from_be_bytes([r[28], r[29], r[30], r[31]]),
            ));
        }
    }
    records.sort();
    (uptimes, records)
}

#[test]
fn test_d46_with_a_the_boot_time_is_the_time_of_the_first_packet() {
    let (uptimes, records) = run("a", &["-a"]);
    let firsts: Vec<u32> = records.iter().map(|r| r.1).collect();
    assert_eq!(firsts, [0, 2000, 4000, 6000, 8000, 10000, 12000, 14000]);
    assert_eq!(uptimes, [14000]);
}

#[test]
fn test_d46_without_a_the_boot_time_is_the_time_of_the_start() {
    let (uptimes, records) = run("no_a", &[]);
    // The packets are from 1970, before the start: the times of the flows wrap, and are not
    // 0 for the first flow (the old code took the time of the first packet).
    assert_eq!(records.len(), 8);
    assert!(
        records.iter().all(|r| r.1 != 0 && r.1 == r.2),
        "{records:?}"
    );
    // The step between the packets is 2 s, whatever the start time is.
    for pair in records.windows(2) {
        assert_eq!(pair[1].1.wrapping_sub(pair[0].1), 2000);
    }
    // The header: the uptime is the time since the start (a few ms, not the 14 s of the file).
    assert!(uptimes.iter().all(|u| *u < 60_000), "{uptimes:?}");
}

#[test]
fn test_d46_i_sets_the_boot_time_when_the_flows_are_expired() {
    // Expected from the C version: with -m 2 the flows are expired in batches, and after a
    // batch that is more than 3 s after the boot time, the boot time is the time of the
    // batch; the times before it are negative, and wrap.
    let (uptimes, records) = run("i", &["-a", "-I", "3", "-m", "2", "-t", "udp=100"]);
    let firsts: Vec<u32> = records.iter().map(|r| r.1).collect();
    assert_eq!(
        firsts,
        [
            4294961296, 4294963296, 4294961296, 4294963296, 4294961296, 4294963296, 4294965296, 0
        ]
    );
    assert_eq!(uptimes, [0, 0, 0, 0]);
}

#[test]
fn test_d46_a_time_before_the_boot_time_wraps_like_c() {
    let at = TimeVal {
        tv_sec: 1,
        tv_usec: 0,
    };
    let boot = TimeVal {
        tv_sec: 2,
        tv_usec: 500_000,
    };
    // (-1.5 s) as C computes it: (u32)(-2) * 1000 + 500
    assert_eq!(at.sub_ms(&boot), 4294965796);
    assert_eq!(boot.sub_ms(&at), 1500);
}
