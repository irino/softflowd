#![allow(dead_code)]

use nix::time::{ClockId, clock_gettime};
use std::collections::{BTreeMap, HashMap};
use std::hash::{BuildHasher, Hasher};
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TrackLevel {
    IpOnly,
    IpProto,
    IpProtoPort,
    Full,
    FullVlan,
    FullVlanEther,
}

impl TrackLevel {
    /// Parse the argument of `-T` (case-insensitive).
    pub fn from_name(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "ip" => Some(TrackLevel::IpOnly),
            "proto" => Some(TrackLevel::IpProto),
            "port" => Some(TrackLevel::IpProtoPort),
            "full" => Some(TrackLevel::Full),
            "vlan" => Some(TrackLevel::FullVlan),
            "ether" => Some(TrackLevel::FullVlanEther),
            _ => None,
        }
    }

    pub fn to_str(self) -> &'static str {
        match self {
            TrackLevel::IpOnly => "ip",
            TrackLevel::IpProto => "proto",
            TrackLevel::IpProtoPort => "port",
            TrackLevel::Full => "full",
            TrackLevel::FullVlan => "vlan",
            TrackLevel::FullVlanEther => "ether",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimeVal {
    pub tv_sec: i64,
    pub tv_usec: i32,
}

impl TimeVal {
    pub fn zero() -> Self {
        TimeVal {
            tv_sec: 0,
            tv_usec: 0,
        }
    }

    pub fn sub_ms(&self, other: &TimeVal) -> u32 {
        let mut sec = self.tv_sec - other.tv_sec;
        let mut usec = self.tv_usec - other.tv_usec;
        if usec < 0 {
            usec += 1_000_000;
            sec -= 1;
        }
        if sec < 0 {
            0
        } else {
            (sec * 1000) as u32 + (usec / 1000) as u32
        }
    }
}

/// A fast hasher for the flow table (multiply and rotate, as the FxHash of rustc).
///
/// The standard SipHash took 41 % of the instructions of a replay: a FlowKey has
/// many small fields and is hashed for every packet.  A flow key is not secret,
/// so the table is seeded at random (FlowBuildHasher) against hash flooding.
#[derive(Clone, Copy, Debug)]
pub struct FlowHasher {
    hash: u64,
}

const FLOW_HASH_K: u64 = 0x517c_c1b7_2722_0a95;

impl FlowHasher {
    /// A hasher with a fixed seed: for the slot of the hash lookup modes, which
    /// must be the same in every run.
    pub fn with_seed(seed: u64) -> Self {
        FlowHasher { hash: seed }
    }

    #[inline]
    fn add(&mut self, word: u64) {
        self.hash = (self.hash.rotate_left(5) ^ word).wrapping_mul(FLOW_HASH_K);
    }
}

impl Hasher for FlowHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut b = bytes;
        while b.len() >= 8 {
            self.add(u64::from_le_bytes([
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            ]));
            b = &b[8..];
        }
        if b.len() >= 4 {
            self.add(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64);
            b = &b[4..];
        }
        if b.len() >= 2 {
            self.add(u16::from_le_bytes([b[0], b[1]]) as u64);
            b = &b[2..];
        }
        if let Some(&x) = b.first() {
            self.add(x as u64);
        }
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.add(i as u64);
    }

    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.add(i as u64);
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.add(i as u64);
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.add(i);
    }

    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.add(i as u64);
    }

    #[inline]
    fn finish(&self) -> u64 {
        // The low bits select the bucket of the table: mix them.
        self.hash.rotate_left(26)
    }
}

/// The hasher builder of the flow tables: FlowHasher with a seed that is chosen
/// at random when the table is made.
#[derive(Clone, Debug)]
pub struct FlowBuildHasher {
    seed: u64,
}

impl Default for FlowBuildHasher {
    fn default() -> Self {
        FlowBuildHasher {
            seed: std::collections::hash_map::RandomState::new().hash_one(0u64),
        }
    }
}

impl BuildHasher for FlowBuildHasher {
    type Hasher = FlowHasher;

    fn build_hasher(&self) -> FlowHasher {
        FlowHasher::with_seed(self.seed)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FlowKey {
    pub af: u16, // libc::AF_INET (2) or libc::AF_INET6 (10)
    pub protocol: u8,
    pub addr: [IpAddr; 2],      // addr[0] <= addr[1]
    pub port: [u16; 2],         // Canonical matching addr
    pub vlanid: [u16; 2],       // Canonical matching addr
    pub ethermac: [[u8; 6]; 2], // Canonical matching addr
    pub mpls_label_depth: u32,
    pub mpls_labels: [u32; 10],
}

/// The hash is the same for equal keys, as `Eq` needs, and it hashes the labels
/// that are used only (`mpls_label_depth` of the 10): the key is hashed for every
/// packet.
impl std::hash::Hash for FlowKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let depth = (self.mpls_label_depth as usize).min(self.mpls_labels.len());
        // The fields are packed into a few words: every word is a step of the hash.
        state.write_u64(
            u64::from(self.af)
                | (u64::from(self.protocol) << 16)
                | (u64::from(self.mpls_label_depth) << 24),
        );
        match (&self.addr[0], &self.addr[1]) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                state.write_u64((u64::from(u32::from(*a)) << 32) | u64::from(u32::from(*b)));
            }
            (a, b) => {
                for addr in [a, b] {
                    match addr {
                        IpAddr::V4(v4) => state.write_u32(u32::from(*v4)),
                        IpAddr::V6(v6) => state.write_u128(u128::from(*v6)),
                    }
                }
            }
        }
        state.write_u64(
            u64::from(self.port[0])
                | (u64::from(self.port[1]) << 16)
                | (u64::from(self.vlanid[0]) << 32)
                | (u64::from(self.vlanid[1]) << 48),
        );
        let [m0, m1] = &self.ethermac;
        state.write_u64(u64::from_le_bytes([
            m0[0], m0[1], m0[2], m0[3], m0[4], m0[5], m1[0], m1[1],
        ]));
        state.write_u32(u32::from_le_bytes([m1[2], m1[3], m1[4], m1[5]]));
        for label in &self.mpls_labels[..depth] {
            state.write_u32(*label);
        }
    }
}

impl FlowKey {
    // The arguments mirror the C version, which passes the same values.
    #[allow(clippy::too_many_arguments)]
    pub fn canonical(
        af: u16,
        protocol: u8,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        src_vlan: u16,
        dst_vlan: u16,
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        mpls_labels: &[u32],
        track_level: TrackLevel,
    ) -> (Self, usize) {
        // Check which direction is index 0 or 1
        let a_is_lower = src_ip < dst_ip || (src_ip == dst_ip && src_port <= dst_port);
        let ndx = if a_is_lower { 0 } else { 1 };

        let mut addr = [src_ip, dst_ip];
        let mut port = [src_port, dst_port];
        let mut vlanid = [src_vlan, dst_vlan];
        let mut ethermac = [src_mac, dst_mac];

        if !a_is_lower {
            addr = [dst_ip, src_ip];
            port = [dst_port, src_port];
            vlanid = [dst_vlan, src_vlan];
            ethermac = [dst_mac, src_mac];
        }

        let mut key = FlowKey {
            af,
            protocol: 0,
            addr,
            port: [0, 0],
            vlanid: [0, 0],
            ethermac: [[0; 6]; 2],
            mpls_label_depth: 0,
            mpls_labels: [0; 10],
        };

        if track_level >= TrackLevel::IpProto {
            key.protocol = protocol;
        }
        if track_level >= TrackLevel::IpProtoPort {
            key.port = port;
        }
        if track_level >= TrackLevel::FullVlan {
            key.vlanid = vlanid;
        }
        if track_level >= TrackLevel::FullVlanEther {
            key.ethermac = ethermac;
        }

        let depth = mpls_labels.len().min(10);
        key.mpls_label_depth = depth as u32;
        key.mpls_labels[..depth].copy_from_slice(&mpls_labels[..depth]);

        (key, ndx)
    }

    pub fn hash_index(&self, nbuckets: u32) -> u32 {
        use std::hash::Hash;
        let mut hasher = FlowHasher::with_seed(0);
        self.hash(&mut hasher);
        (hasher.finish() as u32) & (nbuckets.saturating_sub(1))
    }
}

/// IPFIX flowEndReason values (information element 136, IANA IPFIX registry).
///
/// Original: `IPFIX_flowEndReason_*` in `ipfix.h` of the C version.
pub const FLOW_END_REASON_IDLE_TIMEOUT: u8 = 0x01;
/// flowEndReason: active timeout.
pub const FLOW_END_REASON_ACTIVE_TIMEOUT: u8 = 0x02;
/// flowEndReason: end of flow detected (TCP RST or both FINs).
pub const FLOW_END_REASON_END_OF_FLOW: u8 = 0x03;
/// flowEndReason: forced end.
pub const FLOW_END_REASON_FORCE_END: u8 = 0x04;
/// flowEndReason: lack of resources.
pub const FLOW_END_REASON_LACK_OF_RESOURCE: u8 = 0x05;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExpiryReason {
    General = 0,
    Tcp = 1,
    TcpRst = 2,
    TcpFin = 3,
    Udp = 4,
    Icmp = 5,
    MaxLife = 6,
    OverBytes = 7,
    Overflows = 8,
    Flush = 9,
    Collision = 10,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExpiryKey {
    pub expires_at: u32, // tv_sec
    pub flow_seq: u64,
}

#[derive(Clone, Debug)]
pub struct Flow {
    pub flow_seq: u64,
    pub flow_start: TimeVal,
    pub flow_last: TimeVal,
    pub octets: [u32; 2],
    pub packets: [u32; 2],
    pub tcp_flags: [u8; 2],
    pub tos: [u8; 2],
    pub ip6_flowlabel: [u32; 2],
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub flow_end_reason: u8,
    /// Shared with the tree of the expiries, so that a move in the tree does not copy the key.
    pub key: std::sync::Arc<FlowKey>,
    pub expiry_key: Option<ExpiryKey>,
    pub expiry_reason: ExpiryReason,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Statistic {
    pub min: f64,
    pub mean: f64,
    pub max: f64,
}

impl Statistic {
    pub fn update(&mut self, new_val: f64, n: f64) {
        if n == 1.0 {
            self.min = new_val;
            self.mean = new_val;
            self.max = new_val;
        } else {
            self.min = self.min.min(new_val);
            self.max = self.max.max(new_val);
            self.mean = self.mean + ((new_val - self.mean) / n);
        }
    }
}

#[derive(Clone, Debug)]
pub struct FlowTrackParameters {
    pub full_l4hdr_check: bool,
    pub num_flows: u32,
    pub max_flows: u32,
    pub next_flow_seq: u64,
    pub system_boot_time: TimeVal,
    pub track_level: TrackLevel,

    // Timeouts in seconds
    pub tcp_timeout: i32,
    pub tcp_rst_timeout: i32,
    pub tcp_fin_timeout: i32,
    pub udp_timeout: i32,
    pub icmp_timeout: i32,
    pub general_timeout: i32,
    pub maximum_lifetime: i32,
    pub expiry_interval: i32,

    // Statistics
    pub total_packets: u64,
    pub non_sampled_packets: u64,
    pub frag_packets: u64,
    pub non_ip_packets: u64,
    pub bad_packets: u64,
    pub flows_expired: u64,
    pub flows_exported: u64,
    pub flows_dropped: u64,
    pub flows_force_expired: u64,
    pub packets_sent: u64,
    pub records_sent: u64,

    pub duration: Statistic,
    pub octets: Statistic,
    pub packets: Statistic,

    pub flows_pp: [u64; 256],
    pub octets_pp: [u64; 256],
    pub packets_pp: [u64; 256],
    pub duration_pp: [Statistic; 256],

    // Expiry reasons counts
    pub expired_general: u64,
    pub expired_tcp: u64,
    pub expired_tcp_rst: u64,
    pub expired_tcp_fin: u64,
    pub expired_udp: u64,
    pub expired_icmp: u64,
    pub expired_maxlife: u64,
    pub expired_overbytes: u64,
    pub expired_maxflows: u64,
    pub expired_flush: u64,
    pub expired_collision: u64,

    // Options
    pub sample_rate: u32,
    pub metering_process_id: u32,
    pub interface_name: String,
    pub exporter_ip: Option<IpAddr>,

    // Optional MAC address used to determine IPFIX flowDirection
    pub direction_mac: Option<[u8; 6]>,
    pub direction_mac_set: bool,

    pub bidirection: bool,
    pub time_format: u8,
    pub pcap_buffer_size: usize,
    pub gauge_clock: bool,
    pub max_num_label: u8,
    pub boot_time_reinit: u64,
    pub adjust_time: bool,
    pub is_psamp: bool,
    pub use_thread: bool,
    pub last_packet_time: TimeVal,
    pub export_clocks: i64,
    pub export_calls: u64,
}

impl Default for FlowTrackParameters {
    fn default() -> Self {
        FlowTrackParameters {
            full_l4hdr_check: false,
            num_flows: 0,
            max_flows: 8192,
            next_flow_seq: 1,
            system_boot_time: TimeVal::zero(),
            track_level: TrackLevel::Full,
            tcp_timeout: 3600,
            tcp_rst_timeout: 120,
            tcp_fin_timeout: 300,
            udp_timeout: 300,
            icmp_timeout: 300,
            general_timeout: 3600,
            maximum_lifetime: 3600 * 24 * 7,
            expiry_interval: 60,
            total_packets: 0,
            non_sampled_packets: 0,
            frag_packets: 0,
            non_ip_packets: 0,
            bad_packets: 0,
            flows_expired: 0,
            flows_exported: 0,
            flows_dropped: 0,
            flows_force_expired: 0,
            packets_sent: 0,
            records_sent: 0,
            duration: Statistic::default(),
            octets: Statistic::default(),
            packets: Statistic::default(),
            flows_pp: [0; 256],
            octets_pp: [0; 256],
            packets_pp: [0; 256],
            duration_pp: [Statistic::default(); 256],
            expired_general: 0,
            expired_tcp: 0,
            expired_tcp_rst: 0,
            expired_tcp_fin: 0,
            expired_udp: 0,
            expired_icmp: 0,
            expired_maxlife: 0,
            expired_overbytes: 0,
            expired_maxflows: 0,
            expired_flush: 0,
            expired_collision: 0,
            sample_rate: 0,
            metering_process_id: std::process::id(),
            interface_name: String::new(),
            exporter_ip: None,
            direction_mac: None,
            direction_mac_set: false,
            bidirection: false,
            time_format: 0,
            pcap_buffer_size: 0,
            gauge_clock: false,
            max_num_label: 0,
            boot_time_reinit: 0,
            adjust_time: false,
            is_psamp: false,
            use_thread: false,
            last_packet_time: TimeVal::zero(),
            export_clocks: 0,
            export_calls: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowLookupMode {
    Tree,
    HashTree,
    Hash,
}

/// Return the CPU time of the process in microseconds (the unit of clock() with CLOCKS_PER_SEC = 1000000),
/// using nix::time::clock_gettime(ClockId::CLOCK_PROCESS_CPUTIME_ID).
pub fn cpu_clock() -> libc::clock_t {
    let ts = clock_gettime(ClockId::CLOCK_PROCESS_CPUTIME_ID)
        .expect("clock_gettime(CLOCK_PROCESS_CPUTIME_ID) failed");
    (ts.tv_sec() as libc::clock_t) * 1_000_000 + (ts.tv_nsec() as libc::clock_t) / 1_000
}

impl FlowLookupMode {
    /// Parse the argument of `-F` (case-insensitive).
    pub fn from_name(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "tree" => Some(FlowLookupMode::Tree),
            "hash-tree" => Some(FlowLookupMode::HashTree),
            "hash" => Some(FlowLookupMode::Hash),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            FlowLookupMode::Tree => "tree",
            FlowLookupMode::HashTree => "hash-tree",
            FlowLookupMode::Hash => "hash",
        }
    }
}

pub struct FlowTracker {
    pub flows: HashMap<FlowKey, Flow, FlowBuildHasher>,
    pub expiries: BTreeMap<ExpiryKey, std::sync::Arc<FlowKey>>,
    pub param: FlowTrackParameters,
    pub flow_lookup: FlowLookupMode,
    pub flow_slots: HashMap<u32, FlowKey, FlowBuildHasher>,
    pub nbuckets: u32,
}

impl FlowTracker {
    pub fn new(max_flows: u32) -> Self {
        let param = FlowTrackParameters {
            max_flows,
            ..Default::default()
        };
        // Compute nbuckets as power of two >= max_flows
        let mut nbuckets = 1024u32;
        while nbuckets < max_flows && nbuckets < (1 << 24) {
            nbuckets <<= 1;
        }
        FlowTracker {
            // The table is made for -m flows (at most 32768 at once): growing it moves and
            // hashes every flow again, once for each doubling, while the first flows arrive.
            // The memory of the entries is used when a flow comes, not when the table is made.
            flows: HashMap::with_capacity_and_hasher(
                max_flows.min(1 << 15) as usize,
                FlowBuildHasher::default(),
            ),
            expiries: BTreeMap::new(),
            param,
            flow_lookup: FlowLookupMode::HashTree,
            flow_slots: HashMap::default(),
            nbuckets,
        }
    }

    pub fn set_flow_lookup(&mut self, mode: FlowLookupMode) {
        self.flow_lookup = mode;
        let mut want = self.param.max_flows as u64;
        if mode == FlowLookupMode::Hash {
            want *= 2;
        }
        let mut nbuckets = 1u64;
        if mode == FlowLookupMode::Tree {
            nbuckets = 1;
        } else {
            while nbuckets < want && nbuckets < (1 << 24) {
                nbuckets <<= 1;
            }
        }
        self.nbuckets = nbuckets as u32;
    }

    pub fn table_usage(&self) -> (u32, u32) {
        if self.flow_lookup == FlowLookupMode::Hash {
            let used = self
                .flow_slots
                .values()
                .filter(|k| self.flows.contains_key(*k))
                .count() as u32;
            let maxdepth = if used > 0 { 1 } else { 0 };
            (used, maxdepth)
        } else if self.flow_lookup == FlowLookupMode::Tree {
            let used = self.flows.len() as u32;
            let maxdepth = used;
            (used, maxdepth)
        } else {
            // HashTree
            let mut counts = HashMap::new();
            for key in self.flows.keys() {
                let bucket = key.hash_index(self.nbuckets);
                *counts.entry(bucket).or_insert(0usize) += 1;
            }
            let used = counts.len() as u32;
            let maxdepth = counts.values().cloned().max().unwrap_or(0) as u32;
            (used, maxdepth)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_clock_monotonic() {
        let t1 = cpu_clock();
        let mut sum: u64 = 0;
        for i in 0..100000 {
            sum = sum.wrapping_add(i);
        }
        let _ = sum;
        let t2 = cpu_clock();
        assert!(t2 >= t1);
    }
}
