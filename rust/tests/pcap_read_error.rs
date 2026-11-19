//! Errors of the pcap file.
//!
//! A read error (D40): C leaves the main loop at once, writes
//! "Exiting immediately on internal error", does not export the flows that are
//! still in the table, and exits with the status 1.

use std::io::Write;

// A pcap file of one whole packet (not IP) and a record header whose caplen is
// bigger than the snaplen, which libpcap refuses.
fn damaged_pcap() -> Vec<u8> {
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0i32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&1u32.to_le_bytes()); // Ethernet
    for caplen in [60u32, 0x7fff_ffff] {
        pcap.extend_from_slice(&1u32.to_le_bytes());
        pcap.extend_from_slice(&0u32.to_le_bytes());
        pcap.extend_from_slice(&caplen.to_le_bytes());
        pcap.extend_from_slice(&caplen.to_le_bytes());
        if caplen == 60 {
            pcap.extend_from_slice(&[0u8; 60]);
        }
    }
    pcap
}

#[test]
fn test_d40_read_error_exits_with_status_1() {
    let dir = std::env::temp_dir().join(format!("rsoftflowd_d40_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("damaged.pcap");
    std::fs::File::create(&path)
        .unwrap()
        .write_all(&damaged_pcap())
        .unwrap();

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_rsoftflowd"))
        .args(["-r"])
        .arg(&path)
        .args(["-n", "127.0.0.1:9"])
        .output()
        .expect("Failed to execute rsoftflowd");
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(out.status.code(), Some(1), "{out:?}");
    // The statistics are written, as C does after the loop.
    assert!(String::from_utf8_lossy(&out.stdout).contains("Ignored packets: 1 (1 non-IP"));
}

// D42: a data link type that is not read (here 3, AX.25) is refused at the start, as
// C does ("Unsupported datalink type 3", status 1), not read as a file of non-IP packets.
#[test]
fn test_d42_unsupported_datalink_exits_with_status_1() {
    let mut pcap = damaged_pcap();
    pcap[20..24].copy_from_slice(&3u32.to_le_bytes());

    let dir = std::env::temp_dir().join(format!("rsoftflowd_d42_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("linktype3.pcap");
    std::fs::File::create(&path)
        .unwrap()
        .write_all(&pcap)
        .unwrap();

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_rsoftflowd"))
        .args(["-r"])
        .arg(&path)
        .args(["-n", "127.0.0.1:9"])
        .output()
        .expect("Failed to execute rsoftflowd");
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stderr).trim(),
        "Unsupported datalink type 3"
    );
    assert!(out.stdout.is_empty(), "{out:?}");
}
