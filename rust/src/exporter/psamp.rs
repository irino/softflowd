use crate::common::{FlowTrackParameters, TimeVal};
use crate::exporter::NetflowTarget;
use crate::exporter::export_common::IPFIX_SOFTFLOWD_MAX_PACKET_SIZE;
use byteorder::{BigEndian, WriteBytesExt};
use std::io::Write;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

const PSAMP_SOFTFLOWD_TEMPLATE_ID: u16 = 3072;
const PSAMP_SELECTION_SEQUENCE_ID: u16 = 301;
const PSAMP_OBSERVATION_TIME_MICROSECONDS: u16 = 324;
const PSAMP_SECTION_EXPORTED_OCTETS: u16 = 410;
const PSAMP_DATA_LINK_FRAME_SECTION: u16 = 315;

const PSAMP_FIXED_FIELDS_SIZE: usize = 8 + 8 + 2;
pub const PSAMP_DATALINKFRAME_SIZE: usize =
    IPFIX_SOFTFLOWD_MAX_PACKET_SIZE - 16 - 4 - PSAMP_FIXED_FIELDS_SIZE;

static PSAMP_SEQUENCE_NUMBER: AtomicU32 = AtomicU32::new(0);
static PSAMP_PKTS_UNTIL_TEMPLATE: AtomicI32 = AtomicI32::new(-1);

/// Puts the sequence number and the template counter back to the values of a new process.
/// The tests use it, so that they do not depend on what the other tests exported before.
#[doc(hidden)]
pub fn reset_psamp_state() {
    PSAMP_SEQUENCE_NUMBER.store(0, Ordering::Relaxed);
    PSAMP_PKTS_UNTIL_TEMPLATE.store(-1, Ordering::Relaxed);
}

pub fn psamp_resend_template() {
    let current = PSAMP_PKTS_UNTIL_TEMPLATE.load(Ordering::Relaxed);
    if current > 0 {
        PSAMP_PKTS_UNTIL_TEMPLATE.store(0, Ordering::Relaxed);
    }
}

fn write_psamp_template(packet: &mut Vec<u8>) {
    // Set ID = 2 (IPFIX Template Set)
    packet.write_u16::<BigEndian>(2).unwrap();
    // Length: 4 (set header) + 4 (template record header) + 4 * 4 (fields) = 24
    packet.write_u16::<BigEndian>(24).unwrap();
    packet
        .write_u16::<BigEndian>(PSAMP_SOFTFLOWD_TEMPLATE_ID)
        .unwrap();
    packet.write_u16::<BigEndian>(4).unwrap(); // 4 fields

    // 1. selectionSequenceId (8 bytes)
    packet
        .write_u16::<BigEndian>(PSAMP_SELECTION_SEQUENCE_ID)
        .unwrap();
    packet.write_u16::<BigEndian>(8).unwrap();

    // 2. observationTimeMicroseconds (8 bytes)
    packet
        .write_u16::<BigEndian>(PSAMP_OBSERVATION_TIME_MICROSECONDS)
        .unwrap();
    packet.write_u16::<BigEndian>(8).unwrap();

    // 3. sectionExportedOctets (2 bytes)
    packet
        .write_u16::<BigEndian>(PSAMP_SECTION_EXPORTED_OCTETS)
        .unwrap();
    packet.write_u16::<BigEndian>(2).unwrap();

    // 4. dataLinkFrameSection (1390 bytes, matching C PSAMP_DATALINKFRAME_SIZE)
    packet
        .write_u16::<BigEndian>(PSAMP_DATA_LINK_FRAME_SECTION)
        .unwrap();
    packet
        .write_u16::<BigEndian>(PSAMP_DATALINKFRAME_SIZE as u16)
        .unwrap();
}

pub fn send_psamp(
    pkt: &[u8],
    caplen: u32,
    tv: TimeVal,
    target: &NetflowTarget,
    total_packets: u64,
    param: &FlowTrackParameters,
) -> i32 {
    let mut packet = Vec::with_capacity(1500);

    let mut send_template = false;
    let current_pkts = PSAMP_PKTS_UNTIL_TEMPLATE.load(Ordering::Relaxed);
    if current_pkts <= 0 {
        send_template = true;
        PSAMP_PKTS_UNTIL_TEMPLATE.store(16, Ordering::Relaxed);
    }
    PSAMP_PKTS_UNTIL_TEMPLATE.fetch_sub(1, Ordering::Relaxed);

    let now = crate::exporter::get_active_now(param);
    let seq = PSAMP_SEQUENCE_NUMBER.load(Ordering::Relaxed);

    if send_template {
        // Send a template packet first
        packet.clear();
        packet.write_u16::<BigEndian>(10).unwrap(); // Version (IPFIX)
        packet.write_u16::<BigEndian>(0).unwrap(); // Length (fill at end)
        packet.write_u32::<BigEndian>(now.tv_sec as u32).unwrap();
        packet.write_u32::<BigEndian>(seq).unwrap();
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
    packet.write_u32::<BigEndian>(now.tv_sec as u32).unwrap();
    packet.write_u32::<BigEndian>(seq).unwrap();
    packet.write_u32::<BigEndian>(0).unwrap();

    // Data Set Header
    packet
        .write_u16::<BigEndian>(PSAMP_SOFTFLOWD_TEMPLATE_ID)
        .unwrap();
    packet.write_u16::<BigEndian>(0).unwrap(); // Set length (fill later)
    let set_start = packet.len() - 4;

    // Field 1: selectionSequenceId (8 bytes)
    packet.write_u64::<BigEndian>(total_packets).unwrap();

    // Field 2: observationTimeMicroseconds (8 bytes of NTP timestamp)
    // NTP seconds = tv_sec + 2208988800. Micros scaled to 2^32
    // Note: Retain RFC-compliant NTP fraction calculation ((tv_usec * 2^32) / 1,000,000).
    // The C implementation includes a non-compliant +1µs offset quirk ((tv_usec + 1) * 2^32 / 1,000,000).
    let ntp_sec = (tv.tv_sec + 2208988800) as u32;
    let ntp_frac = ((tv.tv_usec as u64 * (1u64 << 32)) / 1_000_000) as u32;
    packet.write_u32::<BigEndian>(ntp_sec).unwrap();
    packet.write_u32::<BigEndian>(ntp_frac).unwrap();

    // Field 3: sectionExportedOctets (2 bytes)
    // Match C by exporting the actual captured frame length (caplen), capped at 1390 bytes (PSAMP_DATALINKFRAME_SIZE).
    let copysize = caplen.min(PSAMP_DATALINKFRAME_SIZE as u32) as u16;
    packet.write_u16::<BigEndian>(copysize).unwrap();

    // Field 4: dataLinkFrameSection (1390 bytes fixed template field)
    // Match C by zero-padding shorter frames up to 1390 bytes.
    let payload_len = (copysize as usize).min(pkt.len());
    packet.write_all(&pkt[..payload_len]).unwrap();
    if payload_len < PSAMP_DATALINKFRAME_SIZE {
        packet
            .write_all(&vec![0; PSAMP_DATALINKFRAME_SIZE - payload_len])
            .unwrap();
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

    PSAMP_SEQUENCE_NUMBER.fetch_add(1, Ordering::Relaxed);

    1
}

/// What `parse_psamp_datagram()` made of a datagram (C: the return value of `recv_psamp()`).
#[derive(Debug, PartialEq)]
pub enum PsampDatagram {
    /// A PSAMP data record of softflowd: the packet is `datagram[offset..offset + caplen]`.
    Packet {
        timestamp: TimeVal,
        caplen: u32,
        orig_len: u32,
        offset: usize,
    },
    /// An IPFIX message that is not a PSAMP data record of softflowd, for example its
    /// template.  C: 0.
    Other,
    /// Too short, or not IPFIX.  C: -1.
    Invalid,
}

/// IPFIX message header, set header, selectionSequenceId, observationTimeMicroseconds and
/// sectionExportedOctets: what comes before the frame section.
const PSAMP_RECORD_HEADER_SIZE: usize = 16 + 4 + PSAMP_FIXED_FIELDS_SIZE;

/// Reads one datagram that was received with `-R`.  Only the data records that softflowd
/// itself exports are used; the selectionSequenceId is not.
///
/// Original: psamp.c (`recv_psamp()`)
pub fn parse_psamp_datagram(buf: &[u8]) -> PsampDatagram {
    if buf.len() < PSAMP_RECORD_HEADER_SIZE {
        log::debug!(
            "recv_psamp: recvsize: {} is shorter than needed size",
            buf.len()
        );
        return PsampDatagram::Invalid;
    }
    let be16 = |at: usize| u16::from_be_bytes([buf[at], buf[at + 1]]);
    let be32 = |at: usize| u32::from_be_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]);
    if be16(0) != 10 {
        return PsampDatagram::Invalid;
    }
    if be16(16) != PSAMP_SOFTFLOWD_TEMPLATE_ID {
        return PsampDatagram::Other;
    }
    // The NTP time as C reads it back (conv_ntp_to_unix()): the seconds are 32 bits
    // wide, and the fraction is cut, not rounded.
    let timestamp = TimeVal {
        tv_sec: be32(28).wrapping_sub(0x83AA_7E80) as i64,
        tv_usec: (be32(32) as f64 * 1.0e6 / 4_294_967_296.0) as i32,
    };
    let orig_len = be16(36) as u32;
    // The frame section cannot be longer than what was received.
    let caplen = orig_len.min((buf.len() - PSAMP_RECORD_HEADER_SIZE) as u32);
    PsampDatagram::Packet {
        timestamp,
        caplen,
        orig_len,
        offset: PSAMP_RECORD_HEADER_SIZE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PSAMP message as C writes it: the NTP fraction of C is (usec + 1) * 2^32 / 10^6.
    fn message(seconds: u32, fraction: u32, octets: u16, frame: &[u8]) -> Vec<u8> {
        let mut m = vec![0, 10, 5, 148, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(&PSAMP_SOFTFLOWD_TEMPLATE_ID.to_be_bytes());
        m.extend_from_slice(&[5, 132]);
        m.extend_from_slice(&7u64.to_be_bytes());
        m.extend_from_slice(&(seconds.wrapping_add(0x83AA_7E80)).to_be_bytes());
        m.extend_from_slice(&fraction.to_be_bytes());
        m.extend_from_slice(&octets.to_be_bytes());
        m.extend_from_slice(frame);
        m
    }

    #[test]
    fn a_data_record_gives_the_packet_and_its_time() {
        // C sends 250000 us as (250000 + 1) * 2^32 / 10^6 and reads it back as 250000.
        let fraction = ((250_001f64) * 4_294_967_296.0 * 1.0e-6) as u32;
        let datagram = message(1_700_000_000, fraction, 60, &[0xab; 100]);
        assert_eq!(
            parse_psamp_datagram(&datagram),
            PsampDatagram::Packet {
                timestamp: TimeVal {
                    tv_sec: 1_700_000_000,
                    tv_usec: 250_000
                },
                caplen: 60,
                orig_len: 60,
                offset: 38,
            }
        );
    }

    #[test]
    fn the_frame_section_is_cut_at_the_end_of_the_datagram() {
        let datagram = message(1_700_000_000, 0, 3000, &[0xab; 100]);
        match parse_psamp_datagram(&datagram) {
            PsampDatagram::Packet {
                caplen, orig_len, ..
            } => assert_eq!((caplen, orig_len), (100, 3000)),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn what_is_not_a_data_record_of_softflowd_is_not_used() {
        // Shorter than the fixed part: C returns -1.
        assert_eq!(
            parse_psamp_datagram(&message(0, 0, 0, &[])[..37]),
            PsampDatagram::Invalid
        );
        // Not IPFIX: -1.
        let mut datagram = message(0, 0, 0, &[]);
        datagram[1] = 9;
        assert_eq!(parse_psamp_datagram(&datagram), PsampDatagram::Invalid);
        // Another set (the template, 2): 0.
        let mut datagram = message(0, 0, 0, &[]);
        datagram[16..18].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(parse_psamp_datagram(&datagram), PsampDatagram::Other);
    }

    #[test]
    fn the_seconds_are_32_bits_wide_as_in_c() {
        // Before 1970 the NTP seconds are less than 0x83AA7E80: C computes in unsigned int.
        let mut datagram = message(0, 0, 0, &[]);
        datagram[28..32].copy_from_slice(&1u32.to_be_bytes());
        match parse_psamp_datagram(&datagram) {
            PsampDatagram::Packet { timestamp, .. } => {
                assert_eq!(timestamp.tv_sec, 1u32.wrapping_sub(0x83AA_7E80) as i64)
            }
            other => panic!("{other:?}"),
        }
    }
}
