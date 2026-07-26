use std::net::{UdpSocket, TcpStream};
use std::os::unix::io::{AsRawFd, RawFd};
use crate::common::{Flow, FlowTrackParameters, TimeVal};
pub mod netflow1;
pub mod netflow5;
pub mod netflow9;
pub mod ipfix;
pub mod psamp;

pub enum ExportSocket {
    Udp(UdpSocket),
    Tcp(TcpStream),
}

impl ExportSocket {
    pub fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            ExportSocket::Udp(s) => s.send(buf),
            ExportSocket::Tcp(s) => {
                use std::io::Write;
                let mut s_ref = s;
                s_ref.write_all(buf)?;
                Ok(buf.len())
            }
        }
    }
}

impl AsRawFd for ExportSocket {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            ExportSocket::Udp(s) => s.as_raw_fd(),
            ExportSocket::Tcp(s) => s.as_raw_fd(),
        }
    }
}

pub struct Destination {
    pub socket: ExportSocket,
    pub arg: String,
}

pub struct NetflowTarget {
    pub destinations: Vec<Destination>,
    pub version: u16,
    pub is_loadbalance: bool,
}

impl NetflowTarget {
    pub fn send_multi_destinations(&self, packet: &[u8], sent_counter: &mut u64) -> std::io::Result<()> {
        if self.destinations.is_empty() {
            return Ok(());
        }

        if self.is_loadbalance {
            let idx = (*sent_counter % self.destinations.len() as u64) as usize;
            self.destinations[idx].socket.send(packet)?;
        } else {
            for dest in &self.destinations {
                // Clear errors on the socket if any, similar to getsockopt(SO_ERROR)
                let _ = dest.socket.send(packet);
            }
        }
        *sent_counter += 1;
        Ok(())
    }
}

pub struct SendParameter<'a> {
    pub flows: &'a [&'a Flow],
    pub target: &'a NetflowTarget,
    pub ifidx: u16,
    pub param: &'a mut FlowTrackParameters,
    pub verbose: bool,
}

pub fn send_flows(sp: SendParameter) -> i32 {
    match sp.target.version {
        1 => netflow1::send_netflow_v1(sp),
        5 => netflow5::send_netflow_v5(sp),
        9 => netflow9::send_netflow_v9(sp),
        10 => ipfix::send_ipfix(sp),
        _ => -1,
    }
}

pub fn get_active_now(param: &FlowTrackParameters) -> TimeVal {
    if param.adjust_time {
        param.last_packet_time
    } else {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        TimeVal {
            tv_sec: now.as_secs() as i64,
            tv_usec: now.subsec_micros() as i32,
        }
    }
}
