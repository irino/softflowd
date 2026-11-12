use crate::common::{ExpiryReason, Flow, FlowTracker};

/// Accumulates statistics for an expired flow.
///
/// Original: stats.c, accumulate_stats()
pub fn accumulate_stats(tracker: &mut FlowTracker, flow: &Flow) {
    tracker.param.flows_expired += 1;
    tracker.param.flows_pp[flow.key.protocol as usize % 256] += 1;

    let duration_sec = (flow.flow_last.tv_sec - flow.flow_start.tv_sec) as f64
        + ((flow.flow_last.tv_usec - flow.flow_start.tv_usec) as f64 / 1_000_000.0);
    let duration_sec = duration_sec.max(0.0);

    let n = tracker.param.flows_expired as f64;
    tracker.param.duration.update(duration_sec, n);

    let proto_n = tracker.param.flows_pp[flow.key.protocol as usize % 256] as f64;
    tracker.param.duration_pp[flow.key.protocol as usize % 256].update(duration_sec, proto_n);

    let octets = (flow.octets[0] + flow.octets[1]) as f64;
    tracker.param.octets.update(octets, n);
    tracker.param.octets_pp[flow.key.protocol as usize % 256] += octets as u64;

    let packets = (flow.packets[0] + flow.packets[1]) as f64;
    tracker.param.packets.update(packets, n);
    tracker.param.packets_pp[flow.key.protocol as usize % 256] += packets as u64;

    // Expiry reasons
    match flow.expiry_reason {
        ExpiryReason::General => tracker.param.expired_general += 1,
        ExpiryReason::Tcp => tracker.param.expired_tcp += 1,
        ExpiryReason::TcpRst => tracker.param.expired_tcp_rst += 1,
        ExpiryReason::TcpFin => tracker.param.expired_tcp_fin += 1,
        ExpiryReason::Udp => tracker.param.expired_udp += 1,
        ExpiryReason::Icmp => tracker.param.expired_icmp += 1,
        ExpiryReason::MaxLife => tracker.param.expired_maxlife += 1,
        ExpiryReason::OverBytes => tracker.param.expired_overbytes += 1,
        ExpiryReason::Overflows => tracker.param.expired_maxflows += 1,
        ExpiryReason::Flush => tracker.param.expired_flush += 1,
        ExpiryReason::Collision => tracker.param.expired_collision += 1,
    }
}
