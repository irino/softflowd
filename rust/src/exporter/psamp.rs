use std::io::Write;
use byteorder::{BigEndian, WriteBytesExt};
use crate::common::TimeVal;
use crate::exporter::NetflowTarget;

const PSAMP_SOFTFLOWD_TEMPLATE_ID: u16 = 3072;
const PSAMP_SELECTION_SEQUENCE_ID: u16 = 301;
const PSAMP_OBSERVATION_TIME_MICROSECONDS: u16 = 324;
const PSAMP_SECTION_EXPORTED_OCTETS: u16 = 410;
const PSAMP_DATA_LINK_FRAME_SECTION: u16 = 315;

static mut PKTS_UNTIL_TEMPLATE: i32 = -1;

fn write_psamp_template(packet: &mut Vec<u8>) {
    // Set ID = 2 (IPFIX Template Set)
    packet.write_u16::<BigEndian>(2).unwrap();
    // Length: 4 (set header) + 4 (template record header) + 4 * 4 (fields) = 24
    packet.write_u16::<BigEndian>(24).unwrap();
    packet.write_u16::<BigEndian>(PSAMP_SOFTFLOWD_TEMPLATE_ID).unwrap();
    packet.write_u16::<BigEndian>(4).unwrap(); // 4 fields

    // 1. selectionSequenceId (8 bytes)
    packet.write_u16::<BigEndian>(PSAMP_SELECTION_SEQUENCE_ID).unwrap();
    packet.write_u16::<BigEndian>(8).unwrap();

    // 2. observationTimeMicroseconds (8 bytes)
    packet.write_u16::<BigEndian>(PSAMP_OBSERVATION_TIME_MICROSECONDS).unwrap();
    packet.write_u16::<BigEndian>(8).unwrap();

    // 3. sectionExportedOctets (2 bytes)
    packet.write_u16::<BigEndian>(PSAMP_SECTION_EXPORTED_OCTETS).unwrap();
    packet.write_u16::<BigEndian>(2).unwrap();

    // 4. dataLinkFrameSection (variable size in template: e.g. 120 bytes max or similar. In C, it is 1400 - headers = 1374 bytes)
    packet.write_u16::<BigEndian>(PSAMP_DATA_LINK_FRAME_SECTION).unwrap();
    packet.write_u16::<BigEndian>(128).unwrap(); // Fixed frame capture length in template
}

pub fn send_psamp(
    pkt: &[u8],
    caplen: u32,
    tv: TimeVal,
    target: &NetflowTarget,
    total_packets: u64,
) -> i32 {
    let mut packet = Vec::with_capacity(1500);

    let mut send_template = false;
    unsafe {
        if PKTS_UNTIL_TEMPLATE <= 0 {
            send_template = true;
            PKTS_UNTIL_TEMPLATE = 16;
        }
        PKTS_UNTIL_TEMPLATE -= 1;
    }

    if send_template {
        // Send a template packet first
        packet.clear();
        packet.write_u16::<BigEndian>(10).unwrap(); // Version (IPFIX)
        packet.write_u16::<BigEndian>(0).unwrap(); // Length (fill at end)
        packet.write_u32::<BigEndian>(tv.tv_sec as u32).unwrap();
        packet.write_u32::<BigEndian>((total_packets & 0xFFFFFFFF) as u32).unwrap();
        packet.write_u32::<BigEndian>(0).unwrap(); // Observation Domain ID

        write_psamp_template(&mut packet);

        let len = packet.len() as u16;
        packet[2] = (len >> 8) as u8;
        packet[3] = (len & 0xFF) as u8;

        let mut sent = 0;
        let _ = target.send_multi_destinations(&packet, &mut sent);
        packet.clear();
    }

    // Prepare PSAMP data packet
    packet.clear();
    packet.write_u16::<BigEndian>(10).unwrap(); // Version
    packet.write_u16::<BigEndian>(0).unwrap(); // Length
    packet.write_u32::<BigEndian>(tv.tv_sec as u32).unwrap();
    packet.write_u32::<BigEndian>((total_packets & 0xFFFFFFFF) as u32).unwrap();
    packet.write_u32::<BigEndian>(0).unwrap();

    // Data Set Header
    packet.write_u16::<BigEndian>(PSAMP_SOFTFLOWD_TEMPLATE_ID).unwrap();
    packet.write_u16::<BigEndian>(0).unwrap(); // Set length (fill later)
    let set_start = packet.len() - 4;

    // Field 1: selectionSequenceId (8 bytes)
    packet.write_u64::<BigEndian>(total_packets).unwrap();

    // Field 2: observationTimeMicroseconds (8 bytes of NTP timestamp)
    // NTP seconds = tv_sec + 2208988800. Micros scaled to 2^32
    let ntp_sec = (tv.tv_sec + 2208988800) as u32;
    let ntp_frac = ((tv.tv_usec as u64 * (1u64 << 32)) / 1_000_000) as u32;
    packet.write_u32::<BigEndian>(ntp_sec).unwrap();
    packet.write_u32::<BigEndian>(ntp_frac).unwrap();

    // Field 3: sectionExportedOctets (2 bytes)
    let copysize = caplen.min(128) as u16;
    packet.write_u16::<BigEndian>(copysize).unwrap();

    // Field 4: dataLinkFrameSection (128 bytes)
    let payload_len = copysize as usize;
    packet.write_all(&pkt[..payload_len]).unwrap();
    if payload_len < 128 {
        packet.write_all(&vec![0; 128 - payload_len]).unwrap(); // Padding to match template
    }

    // Set lengths
    let total_len = packet.len() as u16;
    packet[2] = (total_len >> 8) as u8;
    packet[3] = (total_len & 0xFF) as u8;

    let set_len = (packet.len() - set_start) as u16;
    packet[set_start + 2] = (set_len >> 8) as u8;
    packet[set_start + 3] = (set_len & 0xFF) as u8;

    let mut sent = 0;
    let _ = target.send_multi_destinations(&packet, &mut sent);

    1
}
