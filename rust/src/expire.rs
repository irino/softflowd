use crate::common::{
    ExpiryKey, ExpiryReason, FLOW_END_REASON_ACTIVE_TIMEOUT, FLOW_END_REASON_END_OF_FLOW,
    FLOW_END_REASON_IDLE_TIMEOUT, FLOW_END_REASON_LACK_OF_RESOURCE, Flow, FlowKey, FlowLookupMode,
    FlowTracker,
};
use crate::control::format_flow;
use crate::exporter::{NetflowTarget, SendParameter, send_flows};
use crate::stats::accumulate_stats;

/// Recompute when a flow expires and update its expiry event.
///
/// Original: expire.c, flow_update_expiry()
pub fn update_flow_expiry(
    expiries: &mut std::collections::BTreeMap<ExpiryKey, FlowKey>,
    param: &crate::common::FlowTrackParameters,
    flow: &mut Flow,
) {
    if let Some(old_expiry) = flow.expiry_key {
        expiries.remove(&old_expiry);
    }

    let mut expires_at = flow.flow_last.tv_sec as u32 + param.general_timeout as u32;
    let mut reason = ExpiryReason::General;
    // A flow that matches no branch below ends by the general timeout.
    flow.flow_end_reason = FLOW_END_REASON_IDLE_TIMEOUT;

    // Standard flow expiry logic
    if flow.octets[0] > (1 << 31) || flow.octets[1] > (1 << 31) {
        expires_at = 0; // immediate
        reason = ExpiryReason::OverBytes;
        flow.flow_end_reason = FLOW_END_REASON_LACK_OF_RESOURCE;
    } else if param.maximum_lifetime != 0
        && (flow.flow_last.tv_sec - flow.flow_start.tv_sec) as i32 > param.maximum_lifetime
    {
        expires_at = 0;
        reason = ExpiryReason::MaxLife;
        flow.flow_end_reason = FLOW_END_REASON_ACTIVE_TIMEOUT;
    } else if flow.key.protocol == 6 {
        // TCP
        let rst = (flow.tcp_flags[0] & 0x04) != 0 || (flow.tcp_flags[1] & 0x04) != 0;
        let fin = ((flow.tcp_flags[0] & 0x01) != 0) && ((flow.tcp_flags[1] & 0x01) != 0);

        if rst && param.tcp_rst_timeout > 0 {
            expires_at = flow.flow_last.tv_sec as u32 + param.tcp_rst_timeout as u32;
            reason = ExpiryReason::TcpRst;
            flow.flow_end_reason = FLOW_END_REASON_END_OF_FLOW;
        } else if fin && param.tcp_fin_timeout > 0 {
            expires_at = flow.flow_last.tv_sec as u32 + param.tcp_fin_timeout as u32;
            reason = ExpiryReason::TcpFin;
            flow.flow_end_reason = FLOW_END_REASON_END_OF_FLOW;
        } else if param.tcp_timeout > 0 {
            expires_at = flow.flow_last.tv_sec as u32 + param.tcp_timeout as u32;
            reason = ExpiryReason::Tcp;
            flow.flow_end_reason = FLOW_END_REASON_IDLE_TIMEOUT;
        }
    } else if flow.key.protocol == 17 && param.udp_timeout > 0 {
        expires_at = flow.flow_last.tv_sec as u32 + param.udp_timeout as u32;
        reason = ExpiryReason::Udp;
        flow.flow_end_reason = FLOW_END_REASON_IDLE_TIMEOUT;
    } else if (flow.key.protocol == 1 || flow.key.protocol == 58) && param.icmp_timeout > 0 {
        expires_at = flow.flow_last.tv_sec as u32 + param.icmp_timeout as u32;
        reason = ExpiryReason::Icmp;
        flow.flow_end_reason = FLOW_END_REASON_IDLE_TIMEOUT;
    }

    if param.maximum_lifetime != 0 && expires_at != 0 {
        let max_expiry = flow.flow_start.tv_sec as u32 + param.maximum_lifetime as u32;
        expires_at = expires_at.min(max_expiry);
    }

    let new_expiry = ExpiryKey {
        expires_at,
        flow_seq: flow.flow_seq,
    };
    flow.expiry_key = Some(new_expiry);
    flow.expiry_reason = reason;

    expiries.insert(new_expiry, flow.key.clone());
}

/// Evict the oldest flow when the flow table is full.
///
/// Original: expire.c, force_expire()
pub fn evict_oldest_flow(tracker: &mut FlowTracker, targets: &NetflowTarget, ifidx: u16) {
    if let Some((&expiry_key, flow_key)) = tracker.expiries.iter().next() {
        let flow_key = flow_key.clone();
        if let Some(mut flow) = tracker.flows.remove(&flow_key) {
            tracker.expiries.remove(&expiry_key);
            if tracker.flow_lookup == FlowLookupMode::Hash {
                let slot = flow.key.hash_index(tracker.nbuckets);
                if tracker.flow_slots.get(&slot) == Some(&flow_key) {
                    tracker.flow_slots.remove(&slot);
                }
            }
            tracker.param.flows_force_expired += 1;
            flow.expiry_reason = ExpiryReason::Overflows;
            flow.flow_end_reason = FLOW_END_REASON_LACK_OF_RESOURCE;
            // Accumulate statistics
            accumulate_stats(tracker, &flow);
            log::debug!("EXPIRED: {} ({:p})", format_flow(&flow), &flow);
            let flow_refs = vec![&flow];
            let sp = SendParameter {
                flows: &flow_refs,
                target: targets,
                ifidx,
                param: &mut tracker.param,
                verbose: true,
            };
            let _ = send_flows(sp);
        }
    }
}

/// Scan the tree of expiry events and process expired flows.
///
/// Original: expire.c, check_expired()
pub fn scan_expiries(
    tracker: &mut FlowTracker,
    targets: &NetflowTarget,
    force_all: bool,
    ifidx: u16,
) -> usize {
    log::debug!(
        "Starting expiry scan: mode {}",
        if force_all { 1 } else { 0 }
    );

    let now_sec = if tracker.param.adjust_time && tracker.param.last_packet_time.tv_sec > 0 {
        tracker.param.last_packet_time.tv_sec as u32
    } else {
        match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs() as u32,
            Err(_) => 0,
        }
    };

    let mut expired_keys = Vec::new();
    for (&exp_key, flow_key) in &tracker.expiries {
        if force_all || exp_key.expires_at == 0 || exp_key.expires_at <= now_sec {
            expired_keys.push((exp_key, flow_key.clone()));
        } else {
            // Since BTreeMap is sorted, we can stop at first non-expired flow!
            if !force_all {
                break;
            }
        }
    }

    let mut expired_flows = Vec::new();
    for (exp_key, flow_key) in &expired_keys {
        if let Some(mut flow) = tracker.flows.remove(flow_key) {
            tracker.expiries.remove(exp_key);
            if tracker.flow_lookup == FlowLookupMode::Hash {
                let slot = flow.key.hash_index(tracker.nbuckets);
                if tracker.flow_slots.get(&slot) == Some(flow_key) {
                    tracker.flow_slots.remove(&slot);
                }
            }
            if force_all {
                flow.expiry_reason = ExpiryReason::Flush;
            }
            log::debug!(
                "Queuing flow seq:{} ({:p}) for expiry reason {:?}",
                flow.flow_seq,
                &flow,
                flow.expiry_reason
            );
            accumulate_stats(tracker, &flow);
            expired_flows.push(flow);
        }
    }

    let count = expired_flows.len();
    log::debug!("Finished scan {} flow(s) to be evicted", count);

    if count > 0 {
        for flow in &expired_flows {
            log::debug!("EXPIRED: {} ({:p})", format_flow(flow), flow);
        }

        // Convert to array of refs
        let flow_refs: Vec<&Flow> = expired_flows.iter().collect();
        let sp = SendParameter {
            flows: &flow_refs,
            target: targets,
            ifidx,
            param: &mut tracker.param,
            verbose: true,
        };
        let _ = send_flows(sp);
    }

    count
}

/// Expire all flows.
///
/// Original: expire.c, expire_all_flows()
pub fn expire_all_flows(tracker: &mut FlowTracker, targets: &NetflowTarget, ifidx: u16) -> usize {
    scan_expiries(tracker, targets, true, ifidx)
}

/// Flush all flows.
///
/// Original: expire.c, flush_all_flows()
pub fn flush_all_flows(tracker: &mut FlowTracker, targets: &NetflowTarget, ifidx: u16) {
    expire_all_flows(tracker, targets, ifidx);
}
