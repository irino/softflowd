use std::fs;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

fn ip_checksum(hdr: &[u8]) -> u16 {
    let mut data = hdr.to_vec();
    if !data.len().is_multiple_of(2) {
        data.push(0);
    }
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let val = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum += val;
    }
    while (sum >> 16) != 0 {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    !sum as u16
}

fn pcap_global_header() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out
}

fn pcap_rec(ts: f64, data: &[u8]) -> Vec<u8> {
    let sec = ts as u32;
    let usec = ((ts - (sec as f64)) * 1_000_000.0) as u32;
    let mut out = Vec::new();
    out.extend_from_slice(&sec.to_le_bytes());
    out.extend_from_slice(&usec.to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
    out
}

fn eth_hdr(smac: &[u8], dmac: &[u8], ethertype: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(dmac);
    out.extend_from_slice(smac);
    out.extend_from_slice(&ethertype.to_be_bytes());
    out
}

fn parse_mac(s: &str) -> [u8; 6] {
    let parts: Vec<u8> = s
        .split(':')
        .map(|p| u8::from_str_radix(p, 16).unwrap())
        .collect();
    [parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]]
}

fn ip_hdr(
    src: std::net::Ipv4Addr,
    dst: std::net::Ipv4Addr,
    proto: u8,
    payload_len: u16,
    ident: u16,
) -> Vec<u8> {
    let total_len = 20 + payload_len;
    let mut hdr = Vec::new();
    hdr.push(0x45);
    hdr.push(0);
    hdr.extend_from_slice(&total_len.to_be_bytes());
    hdr.extend_from_slice(&ident.to_be_bytes());
    hdr.extend_from_slice(&0u16.to_be_bytes());
    hdr.push(64);
    hdr.push(proto);
    hdr.extend_from_slice(&0u16.to_be_bytes()); // csum placeholder
    hdr.extend_from_slice(&src.octets());
    hdr.extend_from_slice(&dst.octets());

    let csum = ip_checksum(&hdr);
    hdr[10..12].copy_from_slice(&csum.to_be_bytes());
    hdr
}

fn tcp_hdr(sport: u16, dport: u16, flags: &str) -> Vec<u8> {
    let f = match flags {
        "S" => 0x02,
        "SA" => 0x12,
        "A" => 0x10,
        "F" => 0x01,
        "FA" => 0x11,
        "PA" => 0x18,
        "R" => 0x04,
        _ => 0x10,
    };
    let mut out = Vec::new();
    out.extend_from_slice(&sport.to_be_bytes());
    out.extend_from_slice(&dport.to_be_bytes());
    out.extend_from_slice(&1000u32.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.push(5 << 4);
    out.push(f);
    out.extend_from_slice(&8192u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

fn udp_hdr(sport: u16, dport: u16, payload_len: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&sport.to_be_bytes());
    out.extend_from_slice(&dport.to_be_bytes());
    out.extend_from_slice(&(8 + payload_len).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

fn ip6_hdr(
    src: std::net::Ipv6Addr,
    dst: std::net::Ipv6Addr,
    next_header: u8,
    payload_len: u16,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0x60000000u32.to_be_bytes());
    out.extend_from_slice(&payload_len.to_be_bytes());
    out.push(next_header);
    out.push(64);
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());
    out
}

fn icmp_hdr() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[8, 0]);
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out
}

const TCP_ENDINGS: &[&[(&str, Option<bool>)]] = &[
    &[
        ("S", Some(false)),
        ("PA", Some(false)),
        ("PA", Some(false)),
        ("PA", Some(false)),
        ("PA", Some(false)),
        ("F", Some(false)),
    ],
    &[
        ("S", Some(false)),
        ("SA", Some(true)),
        ("PA", Some(false)),
        ("PA", Some(true)),
        ("FA", Some(false)),
        ("FA", Some(true)),
    ],
    &[
        ("S", Some(false)),
        ("SA", Some(true)),
        ("PA", Some(false)),
        ("PA", Some(true)),
        ("PA", Some(false)),
        ("R", None),
    ],
];

fn generate_smoke_pcap_data(ipv6: bool, n_flows: usize) -> Vec<u8> {
    let smac = parse_mac("02:00:00:00:00:01");
    let dmac = parse_mac("02:00:00:00:00:02");
    let pkts_per_flow = 6;
    let mut t = 1_000_000.0;
    let mut out = pcap_global_header();
    let mut ident = 0u16;
    let protos = ["tcp", "udp", "icmp"];

    for f in 0..n_flows {
        let (src_ip_v4, dst_ip_v4, src_ip_v6, dst_ip_v6);
        let zero_v4 = std::net::Ipv4Addr::UNSPECIFIED;
        let zero_v6 = std::net::Ipv6Addr::UNSPECIFIED;
        if ipv6 {
            src_ip_v6 = format!("2001:db8::{:x}", f + 1)
                .parse::<std::net::Ipv6Addr>()
                .unwrap();
            dst_ip_v6 = format!("2001:db8:1::{:x}", f + 1)
                .parse::<std::net::Ipv6Addr>()
                .unwrap();
            src_ip_v4 = zero_v4;
            dst_ip_v4 = zero_v4;
        } else {
            src_ip_v4 = std::net::Ipv4Addr::new(10, 0, ((f >> 8) & 0xff) as u8, (f & 0xff) as u8);
            dst_ip_v4 = std::net::Ipv4Addr::new(172, 16, ((f >> 8) & 0xff) as u8, (f & 0xff) as u8);
            src_ip_v6 = zero_v6;
            dst_ip_v6 = zero_v6;
        }
        let sport = 1024 + (f % 60000) as u16;
        let dport = match f % 4 {
            0 => 80,
            1 => 443,
            2 => 22,
            _ => 53,
        };
        let proto_choice = protos[f % 3];

        for k in 0..pkts_per_flow {
            t += 0.01;
            let payload_len = (f % 32) as u16;
            let payload = vec![b'x'; payload_len as usize];
            let mut from_server = false;
            let flags;

            let l4 = if proto_choice == "tcp" {
                let ending = TCP_ENDINGS[(f / 3) % 3];
                let (fl, fs_opt) = ending[k];
                flags = fl;
                from_server = match fs_opt {
                    Some(b) => b,
                    None => ((f / 9) % 2) != 0,
                };
                let (psport, pdport) = if from_server {
                    (dport, sport)
                } else {
                    (sport, dport)
                };
                let mut p = tcp_hdr(psport, pdport, flags);
                p.extend_from_slice(&payload);
                p
            } else if proto_choice == "udp" {
                let (psport, pdport) = (sport, dport);
                let mut p = udp_hdr(psport, pdport, payload_len);
                p.extend_from_slice(&payload);
                p
            } else if ipv6 {
                let mut p = vec![128, 0, 0, 0, 1, 0, 1, 0];
                p.extend_from_slice(&payload);
                p
            } else {
                let mut p = icmp_hdr();
                p.extend_from_slice(&payload);
                p
            };

            let ip_bytes = if ipv6 {
                let next_header = if proto_choice == "tcp" {
                    6
                } else if proto_choice == "udp" {
                    17
                } else {
                    58
                };
                let psrc = if from_server { dst_ip_v6 } else { src_ip_v6 };
                let pdst = if from_server { src_ip_v6 } else { dst_ip_v6 };
                ip6_hdr(psrc, pdst, next_header, l4.len() as u16)
            } else {
                let proto_num = if proto_choice == "tcp" {
                    6
                } else if proto_choice == "udp" {
                    17
                } else {
                    1
                };
                let psrc = if from_server { dst_ip_v4 } else { src_ip_v4 };
                let pdst = if from_server { src_ip_v4 } else { dst_ip_v4 };
                let ib = ip_hdr(psrc, pdst, proto_num, l4.len() as u16, ident);
                ident = ident.wrapping_add(1);
                ib
            };

            let pmacs = if from_server {
                (dmac.as_slice(), smac.as_slice())
            } else {
                (smac.as_slice(), dmac.as_slice())
            };
            let ethertype = if ipv6 { 0x86DD } else { 0x0800 };
            let mut frame = eth_hdr(pmacs.0, pmacs.1, ethertype);
            frame.extend_from_slice(&ip_bytes);
            frame.extend_from_slice(&l4);
            out.extend_from_slice(&pcap_rec(t, &frame));
        }
    }
    out
}

fn generate_loopback_pcap_data(header: &[u8]) -> Vec<u8> {
    let eth = |v6: bool| -> Vec<u8> {
        let mut m = vec![2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2];
        if v6 {
            m.extend_from_slice(&[0x86, 0xdd]);
        } else {
            m.extend_from_slice(&[0x08, 0x00]);
        }
        m
    };

    let frame = |v6: bool, src: &str, dst: &str, proto: u8, payload: &[u8]| -> Vec<u8> {
        let mut f = eth(v6);
        if v6 {
            let s_ip = src.parse::<std::net::Ipv6Addr>().unwrap();
            let d_ip = dst.parse::<std::net::Ipv6Addr>().unwrap();
            f.extend_from_slice(&0x60000000u32.to_be_bytes());
            f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            f.push(proto);
            f.push(64);
            f.extend_from_slice(&s_ip.octets());
            f.extend_from_slice(&d_ip.octets());
        } else {
            let s_ip = src.parse::<std::net::Ipv4Addr>().unwrap();
            let d_ip = dst.parse::<std::net::Ipv4Addr>().unwrap();
            let ib = ip_hdr(s_ip, d_ip, proto, payload.len() as u16, 0);
            f.extend_from_slice(&ib);
        }
        f.extend_from_slice(payload);
        f
    };

    let udp = |sport: u16, dport: u16, size: usize| -> Vec<u8> {
        let mut u = Vec::new();
        u.extend_from_slice(&sport.to_be_bytes());
        u.extend_from_slice(&dport.to_be_bytes());
        u.extend_from_slice(&(8 + size as u16).to_be_bytes());
        u.extend_from_slice(&0u16.to_be_bytes());
        u.extend(vec![b'x'; size]);
        u
    };

    let tcp = |sport: u16, dport: u16, flags: u8| -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&sport.to_be_bytes());
        t.extend_from_slice(&dport.to_be_bytes());
        t.extend_from_slice(&1u32.to_be_bytes());
        t.extend_from_slice(&1u32.to_be_bytes());
        t.push(0x50);
        t.push(flags);
        t.extend_from_slice(&8192u16.to_be_bytes());
        t.extend_from_slice(&0u16.to_be_bytes());
        t.extend_from_slice(&0u16.to_be_bytes());
        t
    };

    let icmp = |kind: u8, _v6: bool| -> Vec<u8> {
        let mut i = Vec::new();
        i.push(kind);
        i.push(0);
        i.extend_from_slice(&0u16.to_be_bytes());
        i.extend_from_slice(&1u16.to_be_bytes());
        i.extend_from_slice(&1u16.to_be_bytes());
        i.extend(vec![b'y'; 8]);
        i
    };

    let mut frames = Vec::new();
    for (v6, same, other) in [(false, "127.0.0.1", "127.0.0.2"), (true, "::1", "::2")] {
        let add = |proto: u8, payload: &[u8], src: &str, dst: &str, fs: &mut Vec<Vec<u8>>| {
            fs.push(frame(v6, src, dst, proto, payload));
        };
        for (high, low) in [(40000, 53), (53, 40000)] {
            add(17, &udp(high, low, 20), same, same, &mut frames);
            add(17, &udp(low, high, 20), same, same, &mut frames);
            add(17, &udp(high, low, 20), same, same, &mut frames);
            add(17, &udp(low, high, 5), same, same, &mut frames);
        }
        add(6, &tcp(50000, 80, 0x02), same, same, &mut frames);
        add(6, &tcp(80, 50000, 0x12), same, same, &mut frames);
        add(6, &tcp(50000, 80, 0x10), same, same, &mut frames);
        add(6, &tcp(81, 50001, 0x02), same, same, &mut frames);
        add(6, &tcp(50001, 81, 0x12), same, same, &mut frames);
        add(6, &tcp(81, 50001, 0x10), same, same, &mut frames);
        add(6, &tcp(7000, 7000, 0x02), same, same, &mut frames);
        add(6, &tcp(7000, 7000, 0x10), same, same, &mut frames);
        add(
            if v6 { 58 } else { 1 },
            &icmp(if v6 { 128 } else { 8 }, v6),
            same,
            same,
            &mut frames,
        );
        add(
            if v6 { 58 } else { 1 },
            &icmp(if v6 { 129 } else { 0 }, v6),
            same,
            same,
            &mut frames,
        );
        add(17, &udp(40001, 53, 20), other, same, &mut frames);
        add(17, &udp(53, 40001, 20), same, other, &mut frames);
    }

    let mut out = header.to_vec();
    for (n, f) in frames.iter().enumerate() {
        let ts = 1_000_000.0 + (n / 10) as f64;
        let us = ((n % 10) * 1000 + 10) as u32;
        let mut rec = Vec::new();
        rec.extend_from_slice(&(ts as u32).to_le_bytes());
        rec.extend_from_slice(&us.to_le_bytes());
        rec.extend_from_slice(&(f.len() as u32).to_le_bytes());
        rec.extend_from_slice(&(f.len() as u32).to_le_bytes());
        rec.extend_from_slice(f);
        out.extend_from_slice(&rec);
    }
    out
}

fn parse_pcap_packets(data: &[u8]) -> Vec<(u32, u32, u32, Vec<u8>)> {
    let mut off = 24;
    let mut pkts = Vec::new();
    while off + 16 <= data.len() {
        let sec = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        let usec = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap());
        let caplen = u32::from_le_bytes(data[off + 8..off + 12].try_into().unwrap());
        let origlen = u32::from_le_bytes(data[off + 12..off + 16].try_into().unwrap());
        let pkt = data[off + 16..off + 16 + caplen as usize].to_vec();
        pkts.push((sec, usec, origlen, pkt));
        off += 16 + caplen as usize;
    }
    pkts
}

fn generate_pcaps(tmp_dir: &Path) -> std::collections::HashMap<String, PathBuf> {
    let smoke_data = generate_smoke_pcap_data(false, 40);
    let smoke_path = tmp_dir.join("smoke.pcap");
    fs::write(&smoke_path, &smoke_data).unwrap();

    let smoke6_data = generate_smoke_pcap_data(true, 40);
    let smoke6_path = tmp_dir.join("smoke6.pcap");
    fs::write(&smoke6_path, &smoke6_data).unwrap();

    // vlan
    let mut vlan_out = smoke_data[..24].to_vec();
    for (n, (sec, usec, origlen, pkt)) in parse_pcap_packets(&smoke_data).into_iter().enumerate() {
        let vid = 100 + (n % 3) * 7 + (if n % 5 == 0 { 0x2000 } else { 0 });
        let mut p = pkt;
        if n % 2 == 0 && p.len() >= 6 {
            p[0..6].copy_from_slice(&[2, 0, 0, 0, 0, (0x10 + n % 4) as u8]);
        }
        let mut vlan_pkt = Vec::new();
        vlan_pkt.extend_from_slice(&p[0..12]);
        vlan_pkt.extend_from_slice(&0x8100u16.to_be_bytes());
        vlan_pkt.extend_from_slice(&(vid as u16).to_be_bytes());
        vlan_pkt.extend_from_slice(&p[12..]);
        vlan_out.extend_from_slice(&sec.to_le_bytes());
        vlan_out.extend_from_slice(&usec.to_le_bytes());
        vlan_out.extend_from_slice(&(vlan_pkt.len() as u32).to_le_bytes());
        vlan_out.extend_from_slice(&(origlen + 4).to_le_bytes());
        vlan_out.extend_from_slice(&vlan_pkt);
    }
    let vlan_path = tmp_dir.join("vlan.pcap");
    fs::write(&vlan_path, &vlan_out).unwrap();

    // slow
    let mut slow_out = smoke_data[..24].to_vec();
    for (n, (_, usec, origlen, pkt)) in parse_pcap_packets(&smoke_data).into_iter().enumerate() {
        let sec = 1_000_000 + (n as u32) * 10;
        slow_out.extend_from_slice(&sec.to_le_bytes());
        slow_out.extend_from_slice(&usec.to_le_bytes());
        slow_out.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
        slow_out.extend_from_slice(&origlen.to_le_bytes());
        slow_out.extend_from_slice(&pkt);
    }
    let slow_path = tmp_dir.join("slow.pcap");
    fs::write(&slow_path, &slow_out).unwrap();

    // many
    let mut many_out = smoke_data[..24].to_vec();
    for i in 0..600 {
        let eth = {
            let mut e = vec![2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2];
            e.extend_from_slice(&[0x08, 0x00]);
            e
        };
        let payload = vec![b'x'; 20];
        let udp = udp_hdr(1000 + i as u16, 53, 20);
        let src_ip = std::net::Ipv4Addr::new(10, 0, (i / 250) as u8, (i % 250) as u8);
        let dst_ip = std::net::Ipv4Addr::new(10, 1, 0, 1);
        let ip = ip_hdr(src_ip, dst_ip, 17, (8 + payload.len()) as u16, i as u16);
        let mut frame = eth;
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&udp);
        frame.extend_from_slice(&payload);
        let ts = 1_000_000 + i as u32;
        let us = (i * 1000) as u32;
        many_out.extend_from_slice(&ts.to_le_bytes());
        many_out.extend_from_slice(&us.to_le_bytes());
        many_out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        many_out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        many_out.extend_from_slice(&frame);
    }
    let many_path = tmp_dir.join("many.pcap");
    fs::write(&many_path, &many_out).unwrap();

    // loopback
    let loopback_data = generate_loopback_pcap_data(&smoke_data[..24]);
    let loopback_path = tmp_dir.join("loopback.pcap");
    fs::write(&loopback_path, &loopback_data).unwrap();

    let mut map = std::collections::HashMap::new();
    map.insert("smoke".to_string(), smoke_path);
    map.insert("smoke6".to_string(), smoke6_path);
    map.insert("vlan".to_string(), vlan_path);
    map.insert("slow".to_string(), slow_path);
    map.insert("many".to_string(), many_path);
    map.insert("loopback".to_string(), loopback_path);
    map
}

fn gen_matrix_args() -> Vec<Vec<String>> {
    let b_opts = vec![vec![], vec!["-b".to_string()]];
    let h_opts = vec![
        vec![],
        vec!["-H".to_string(), "02:00:00:00:00:01".to_string()],
    ];
    let t_opts = vec![
        vec!["-T".to_string(), "ether".to_string()],
        vec!["-T".to_string(), "vlan".to_string()],
        vec!["-T".to_string(), "full".to_string()],
    ];
    let e_opts = vec![
        vec![],
        vec!["-e".to_string(), "192.0.2.1".to_string()],
        vec!["-e".to_string(), "2001:db8::1".to_string()],
    ];
    let s_opts = vec![vec![], vec!["-s".to_string(), "10".to_string()]];
    let a_opts = vec![vec![], vec!["-A".to_string(), "micro".to_string()]];
    let x_opts = vec![vec![], vec!["-x".to_string(), "2".to_string()]];

    let mut matrix = Vec::new();
    for b in &b_opts {
        for h in &h_opts {
            for t in &t_opts {
                for e in &e_opts {
                    for s in &s_opts {
                        for a in &a_opts {
                            for x in &x_opts {
                                let mut args = Vec::new();
                                args.extend(b.clone());
                                args.extend(h.clone());
                                args.extend(t.clone());
                                args.extend(e.clone());
                                args.extend(s.clone());
                                args.extend(a.clone());
                                args.extend(x.clone());
                                if !matrix.contains(&args) {
                                    matrix.push(args);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    matrix
}

fn get_parity_args(version: &str) -> Vec<Vec<String>> {
    let matrix = gen_matrix_args();
    let matrix_step: Vec<Vec<String>> = matrix.into_iter().step_by(16).collect();

    match version {
        "1" => vec![
            vec![],
            vec!["-m".to_string(), "5".to_string()],
            vec![
                "-t".to_string(),
                "maxlife=1".to_string(),
                "-m".to_string(),
                "7".to_string(),
            ],
            vec!["-s".to_string(), "10".to_string()],
        ],
        "5" => vec![
            vec![],
            vec!["-m".to_string(), "5".to_string()],
            vec![
                "-t".to_string(),
                "maxlife=1".to_string(),
                "-m".to_string(),
                "7".to_string(),
            ],
            vec!["-s".to_string(), "10".to_string()],
            vec!["-T".to_string(), "ether".to_string()],
            vec!["-x".to_string(), "2".to_string()],
        ],
        "9" | "10" => {
            let mut list = vec![
                vec![],
                vec!["-m".to_string(), "5".to_string()],
                vec![
                    "-t".to_string(),
                    "maxlife=1".to_string(),
                    "-m".to_string(),
                    "7".to_string(),
                ],
            ];
            list.extend(matrix_step);
            list
        }
        _ => vec![vec![]],
    }
}

fn export_datagrams(binary: &Path, pcap: &Path, version: &str, extra: &[String]) -> Vec<Vec<u8>> {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    socket
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();

    let mut cmd = Command::new(binary);
    cmd.arg("-r")
        .arg(pcap)
        .arg("-n")
        .arg(format!("127.0.0.1:{port}"))
        .arg("-v")
        .arg(version)
        .arg("-a");
    for ext in extra {
        cmd.arg(ext);
    }
    cmd.stdout(Stdio::null()).stderr(Stdio::null());

    let _ = cmd.status();

    let mut datagrams = Vec::new();
    let mut buf = [0u8; 65535];
    while let Ok(n) = socket.recv(&mut buf) {
        datagrams.push(buf[..n].to_vec());
    }
    datagrams
}

fn datagrams_differ(a: &[Vec<u8>], b: &[Vec<u8>], version: &str) -> Option<String> {
    if a.len() != b.len() {
        return Some(format!("{} datagrams from A, {} from B", a.len(), b.len()));
    }
    for (n, (x, y)) in a.iter().zip(b.iter()).enumerate() {
        if x.len() != y.len() {
            return Some(format!(
                "datagram {n}: {} bytes from A, {} bytes from B",
                x.len(),
                y.len()
            ));
        }
        let diff: Vec<usize> = x
            .iter()
            .zip(y.iter())
            .enumerate()
            .filter_map(|(i, (u, v))| if u != v { Some(i) } else { None })
            .collect();
        if diff.is_empty() {
            continue;
        }
        if version == "10" && diff.last().unwrap() - diff.first().unwrap() <= 3 {
            continue;
        }
        return Some(format!(
            "datagram {n}: bytes differ at offsets {:?}",
            &diff[..std::cmp::min(diff.len(), 8)]
        ));
    }
    None
}

fn get_binary_path() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("target/debug/rsoftflowd"))
}

pub fn run_save_golden(dir_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    let dir = Path::new(dir_str);
    fs::create_dir_all(dir)?;

    let tmp_path =
        std::env::temp_dir().join(format!("rsoftflowd_golden_save_{}", std::process::id()));
    fs::create_dir_all(&tmp_path)?;
    let pcaps = generate_pcaps(&tmp_path);
    let binary = get_binary_path();

    let pcaps_order = ["smoke", "smoke6", "vlan", "slow", "many", "loopback"];
    let versions = ["1", "5", "9", "10"];

    for name in &pcaps_order {
        let pcap = &pcaps[*name];
        for version in &versions {
            for extra in get_parity_args(version) {
                let case_text = format!(
                    "{} -v {} -a{}",
                    name,
                    version,
                    if extra.is_empty() {
                        "".to_string()
                    } else {
                        format!(" {}", extra.join(" "))
                    }
                );
                let datagrams = export_datagrams(&binary, pcap, version, &extra);
                let mut content = String::new();
                for dg in datagrams {
                    content.push_str(&dg.iter().map(|b| format!("{:02x}", b)).collect::<String>());
                    content.push('\n');
                }
                fs::write(dir.join(&case_text), content)?;
            }
        }
    }
    let _ = fs::remove_dir_all(&tmp_path);
    println!("Saved golden datagrams to {}", dir_str);
    Ok(())
}

pub fn run_check_golden(dir_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    let dir = Path::new(dir_str);
    let tmp_path =
        std::env::temp_dir().join(format!("rsoftflowd_golden_check_{}", std::process::id()));
    fs::create_dir_all(&tmp_path)?;
    let pcaps = generate_pcaps(&tmp_path);
    let binary = get_binary_path();

    let pcaps_order = ["smoke", "smoke6", "vlan", "slow", "many", "loopback"];
    let versions = ["1", "5", "9", "10"];
    let mut ok = true;

    for name in &pcaps_order {
        let pcap = &pcaps[*name];
        for version in &versions {
            for extra in get_parity_args(version) {
                let case_text = format!(
                    "{} -v {} -a{}",
                    name,
                    version,
                    if extra.is_empty() {
                        "".to_string()
                    } else {
                        format!(" {}", extra.join(" "))
                    }
                );
                let golden_path = dir.join(&case_text);
                if !golden_path.exists() {
                    eprintln!("Missing golden file for case: {}", case_text);
                    ok = false;
                    continue;
                }
                let golden_content = fs::read_to_string(&golden_path)?;
                let expected_datagrams: Vec<Vec<u8>> = golden_content
                    .lines()
                    .filter(|l| !l.is_empty())
                    .map(hex_decode)
                    .collect();

                let actual_datagrams = export_datagrams(&binary, pcap, version, &extra);

                if let Some(why) = datagrams_differ(&expected_datagrams, &actual_datagrams, version)
                {
                    eprintln!("CHECK FAILED for {case_text}: {why}");
                    ok = false;
                }
            }
        }
    }

    let _ = fs::remove_dir_all(&tmp_path);

    if ok {
        println!("Golden check passed: no difference found.");
        Ok(())
    } else {
        eprintln!("Golden check FAILED.");
        std::process::exit(1);
    }
}

fn hex_decode(s: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut chars = s.chars();
    while let (Some(c1), Some(c2)) = (chars.next(), chars.next()) {
        let s = format!("{c1}{c2}");
        if let Ok(b) = u8::from_str_radix(&s, 16) {
            bytes.push(b);
        }
    }
    bytes
}
