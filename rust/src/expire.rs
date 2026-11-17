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

/// Which flows `scan_expiries()` expires.
///
/// Original: softflowd.h, CE_EXPIRE_NORMAL, CE_EXPIRE_ALL and CE_EXPIRE_FORCED
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpireMode {
    /// Flows whose expiry time has passed, and the forced ones.
    Normal,
    /// Every flow.
    All,
    /// Only the forced ones (`expires_at == 0`), as with `-r`.
    Forced,
}

impl ExpireMode {
    /// The number the C version uses, as it appears in the debug log.
    pub fn c_value(self) -> i32 {
        match self {
            ExpireMode::Normal => 0,
            ExpireMode::All => -1,
            ExpireMode::Forced => 1,
        }
    }
}

/// Scan the tree of expiry events and process expired flows.
///
/// Original: expire.c, check_expired()
pub fn scan_expiries(
    tracker: &mut FlowTracker,
    targets: &NetflowTarget,
    mode: ExpireMode,
    ifidx: u16,
) -> usize {
    log::debug!("Starting expiry scan: mode {}", mode.c_value());
    let force_all = mode == ExpireMode::All;

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
        if force_all
            || exp_key.expires_at == 0
            || (mode != ExpireMode::Forced && exp_key.expires_at < now_sec)
        {
            expired_keys.push((exp_key, flow_key.clone()));
        } else {
            // The tree is sorted by the expiry time, so the rest is not expired.
            break;
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
            // As in C: a flow that has lived as long as the maximum lifetime
            // is counted as such, and the log line comes before the flush mark.
            let max_life = tracker.param.maximum_lifetime;
            if max_life != 0 && (flow.flow_last.tv_sec - flow.flow_start.tv_sec) as i32 >= max_life
            {
                flow.expiry_reason = ExpiryReason::MaxLife;
            }
            log::debug!(
                "Queuing flow seq:{} ({:p}) for expiry reason {}",
                flow.flow_seq,
                &flow,
                flow.expiry_reason as i32
            );
            if force_all {
                flow.expiry_reason = ExpiryReason::Flush;
            }
            accumulate_stats(tracker, &flow);
            expired_flows.push(flow);
        }
    }

    let count = expired_flows.len();
    log::debug!("Finished scan {} flow(s) to be evicted", count);

    if count > 0 {
        // Convert to array of refs
        let flow_refs: Vec<&Flow> = expired_flows.iter().collect();
        let sp = SendParameter {
            flows: &flow_refs,
            target: targets,
            ifidx,
            param: &mut tracker.param,
            verbose: true,
        };
        let r = send_flows(sp);
        log::debug!("sent {} netflow packets", r);
        // Each flow counts as two records in C.
        if r <= 0 {
            tracker.param.flows_dropped += count as u64 * 2;
        }
        // As in C, the flows are logged after they are sent.
        for flow in &expired_flows {
            log::debug!("EXPIRED: {} ({:p})", format_flow(flow), flow);
        }
    }

    count
}

/// Mark the `num_to_expire` flows that expire first as overflowing, so that the
/// next scan expires them.  The flowEndReason of the flows is not changed, as
/// in C.
///
/// Original: expire.c, force_expire()
pub fn force_expire(tracker: &mut FlowTracker, num_to_expire: usize) {
    log::debug!("Forcing expiry of {} flows", num_to_expire);
    let keys: Vec<(ExpiryKey, FlowKey)> = tracker
        .expiries
        .iter()
        .take(num_to_expire)
        .map(|(k, f)| (*k, f.clone()))
        .collect();
    if keys.len() < num_to_expire {
        log::error!(
            "Needed to expire {} flows, but only {} active",
            num_to_expire,
            keys.len()
        );
    }
    for (old_key, flow_key) in &keys {
        tracker.expiries.remove(old_key);
        let new_key = ExpiryKey {
            expires_at: 0,
            flow_seq: old_key.flow_seq,
        };
        if let Some(flow) = tracker.flows.get_mut(flow_key) {
            flow.expiry_key = Some(new_key);
            flow.expiry_reason = ExpiryReason::Overflows;
        }
        tracker.expiries.insert(new_key, flow_key.clone());
    }
    tracker.param.flows_force_expired += keys.len() as u64;
}

/// The time in milliseconds that C waits (the timeout of `poll()`) until the
/// flow that expires first is due, 0 when it is due now, `None` when there is no
/// flow.  C looks at the expiry only when `poll()` returns (a packet, or this
/// timeout), so an idle flow is exported up to a second after its second.
///
/// Original: expire.c, next_expire()
pub fn next_expire(tracker: &FlowTracker) -> Option<u64> {
    let (key, _) = tracker.expiries.iter().next()?;
    let mut expires_at = key.expires_at;
    // Do not cluster urgent expiries
    if expires_at == 0 {
        return Some(0);
    }
    // Cluster expiries by expiry_interval
    let interval = tracker.param.expiry_interval as u32;
    if interval > 1 {
        let fudge = expires_at % interval;
        if fudge > 0 {
            expires_at += interval - fudge;
        }
    }
    let now_sec = if tracker.param.adjust_time && tracker.param.last_packet_time.tv_sec > 0 {
        tracker.param.last_packet_time.tv_sec as u32
    } else {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0)
    };
    if expires_at < now_sec {
        return Some(0);
    }
    Some(999 + (expires_at - now_sec) as u64 * 1000)
}

/// Whether the flow that expires first is due now (C: `next_expire() == 0`).
pub fn next_expire_is_now(tracker: &FlowTracker) -> bool {
    next_expire(tracker) == Some(0)
}

/// Expire the flows over `-m`: scan, force-expire the oldest flows over the
/// limit, and scan again, until the table is within the limit.  The flows
/// leave in one export call per scan, so they share datagrams.
///
/// Original: softflowd.c, the `expiry_check` loop of the main loop
pub fn expire_over_limit(
    tracker: &mut FlowTracker,
    targets: &NetflowTarget,
    mode: ExpireMode,
    ifidx: u16,
) {
    loop {
        scan_expiries(tracker, targets, mode, ifidx);
        let max = tracker.param.max_flows as usize;
        if tracker.flows.len() <= max {
            break;
        }
        force_expire(tracker, tracker.flows.len() - max);
    }
}

/// Expire all flows.
///
/// Original: expire.c, expire_all_flows()
pub fn expire_all_flows(tracker: &mut FlowTracker, targets: &NetflowTarget, ifidx: u16) -> usize {
    scan_expiries(tracker, targets, ExpireMode::All, ifidx)
}

/// Flush all flows.
///
/// Original: expire.c, flush_all_flows()
pub fn flush_all_flows(tracker: &mut FlowTracker, targets: &NetflowTarget, ifidx: u16) {
    expire_all_flows(tracker, targets, ifidx);
}
