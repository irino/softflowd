use std::net::IpAddr;
use std::collections::{BTreeMap, HashMap};

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
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "ip" => Some(TrackLevel::IpOnly),
            "proto" => Some(TrackLevel::IpProto),
            "full" => Some(TrackLevel::Full),
            "vlan" => Some(TrackLevel::FullVlan),
            "ether" => Some(TrackLevel::FullVlanEther),
            _ => None,
        }
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            TrackLevel::IpOnly => "ip",
            TrackLevel::IpProto => "proto",
            TrackLevel::IpProtoPort => "full", // Historically "full" maps to IpProtoPort for key representation
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
        TimeVal { tv_sec: 0, tv_usec: 0 }
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

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowKey {
    pub af: u16,                // libc::AF_INET (2) or libc::AF_INET6 (10)
    pub protocol: u8,
    pub addr: [IpAddr; 2],      // addr[0] <= addr[1]
    pub port: [u16; 2],         // Canonical matching addr
    pub vlanid: [u16; 2],       // Canonical matching addr
    pub ethermac: [[u8; 6]; 2], // Canonical matching addr
    pub mpls_label_depth: u32,
    pub mpls_labels: [u32; 10],
}

impl FlowKey {
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
        let ndx = if src_ip > dst_ip { 1 } else { 0 };

        let mut addr = [src_ip, dst_ip];
        let mut port = [src_port, dst_port];
        let mut vlanid = [src_vlan, dst_vlan];
        let mut ethermac = [src_mac, dst_mac];

        if ndx == 1 {
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
        for i in 0..depth {
            key.mpls_labels[i] = mpls_labels[i];
        }

        (key, ndx)
    }
}

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
    pub flow_end_reason: u8,
    pub key: FlowKey,
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

    // Options
    pub sample_rate: u32,
    pub metering_process_id: u32,
    pub interface_name: String,
    pub exporter_ip: Option<IpAddr>,
    
    pub bidirection: bool,
    pub adjust_time: bool,
    pub is_psamp: bool,
    pub max_num_label: u8,
    pub last_packet_time: TimeVal,
}

impl Default for FlowTrackParameters {
    fn default() -> Self {
        FlowTrackParameters {
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
            sample_rate: 0,
            metering_process_id: std::process::id(),
            interface_name: String::new(),
            exporter_ip: None,
            bidirection: false,
            adjust_time: false,
            is_psamp: false,
            max_num_label: 0,
            last_packet_time: TimeVal::zero(),
        }
    }
}

pub struct FlowTracker {
    pub flows: HashMap<FlowKey, Flow>,
    pub expiries: BTreeMap<ExpiryKey, FlowKey>,
    pub param: FlowTrackParameters,
}

impl FlowTracker {
    pub fn new(max_flows: u32) -> Self {
        let mut param = FlowTrackParameters::default();
        param.max_flows = max_flows;
        FlowTracker {
            flows: HashMap::new(),
            expiries: BTreeMap::new(),
            param,
        }
    }
}
