//! The modes of `scan_expiries()` (D24): normal, all and forced, as the
//! CE_EXPIRE_NORMAL, CE_EXPIRE_ALL and CE_EXPIRE_FORCED of the C version.

mod common;

use rsoftflowd::common::{ExpiryKey, FlowTracker, TimeVal};
use rsoftflowd::expire::{ExpireMode, scan_expiries};
use rsoftflowd::exporter::NetflowTarget;

const NOW: i64 = 1_600_000_000;

// A tracker with three flows that expire at `forced` (0), NOW - 1 (passed),
// NOW (this very second) and NOW + 10 (later).
fn tracker_with_flows() -> FlowTracker {
    let mut tracker = FlowTracker::new(100);
    tracker.param.adjust_time = true;
    tracker.param.last_packet_time = TimeVal {
        tv_sec: NOW,
        tv_usec: 0,
    };
    for (seq, expires_at) in [0u32, (NOW - 1) as u32, NOW as u32, (NOW + 10) as u32]
        .into_iter()
        .enumerate()
    {
        let mut flow = common::make_dummy_flow();
        std::sync::Arc::make_mut(&mut flow.key).port[0] = 1000 + seq as u16;
        flow.flow_seq = seq as u64;
        let ek = ExpiryKey {
            expires_at,
            flow_seq: flow.flow_seq,
        };
        flow.expiry_key = Some(ek);
        tracker.expiries.insert(ek, flow.key.clone());
        tracker.flows.insert((*flow.key).clone(), flow);
    }
    tracker
}

fn no_target() -> NetflowTarget {
    NetflowTarget {
        destinations: vec![],
        version: 9,
        is_loadbalance: false,
    }
}

#[test]
fn test_d24_mode_numbers_are_the_ones_of_c() {
    assert_eq!(ExpireMode::Normal.c_value(), 0);
    assert_eq!(ExpireMode::All.c_value(), -1);
    assert_eq!(ExpireMode::Forced.c_value(), 1);
}

#[test]
fn test_d24_normal_mode_expires_forced_and_passed_flows_but_not_this_second() {
    let mut t = tracker_with_flows();
    // C: expires_at < now, so the flow of this very second stays.
    assert_eq!(
        scan_expiries(&mut t, &no_target(), ExpireMode::Normal, 1),
        2
    );
    assert_eq!(t.flows.len(), 2);
}

#[test]
fn test_d24_forced_mode_expires_only_forced_flows() {
    let mut t = tracker_with_flows();
    assert_eq!(
        scan_expiries(&mut t, &no_target(), ExpireMode::Forced, 1),
        1
    );
    assert_eq!(t.flows.len(), 3);
}

#[test]
fn test_d24_all_mode_expires_every_flow() {
    let mut t = tracker_with_flows();
    assert_eq!(scan_expiries(&mut t, &no_target(), ExpireMode::All, 1), 4);
    assert!(t.flows.is_empty());
}

// -------------------------------------------------------------
// D36: the time that C waits until the next expiry (the timeout of poll())
// -------------------------------------------------------------
use rsoftflowd::expire::next_expire;

#[test]
fn test_d36_next_expire_is_like_c() {
    let mut t = FlowTracker::new(100);
    t.param.adjust_time = true;
    t.param.expiry_interval = 1; // no clustering
    t.param.last_packet_time = TimeVal {
        tv_sec: NOW,
        tv_usec: 0,
    };
    // No flow: indefinite.
    assert_eq!(next_expire(&t), None);
    fn add(t: &mut FlowTracker, expires_at: u32, seq: u64) {
        let mut flow = common::make_dummy_flow();
        std::sync::Arc::make_mut(&mut flow.key).port[0] = 2000 + seq as u16;
        flow.flow_seq = seq;
        let ek = ExpiryKey {
            expires_at,
            flow_seq: seq,
        };
        flow.expiry_key = Some(ek);
        t.expiries.insert(ek, flow.key.clone());
        t.flows.insert((*flow.key).clone(), flow);
    }
    // 3 s from now: 999 + 3000 ms (C waits up to a second more than the time).
    add(&mut t, (NOW + 3) as u32, 1);
    assert_eq!(next_expire(&t), Some(999 + 3000));
    // The very second is not yet due (C: expires_at < now).
    add(&mut t, NOW as u32, 2);
    assert_eq!(next_expire(&t), Some(999));
    // Passed, and a forced flow: due now.
    add(&mut t, (NOW - 1) as u32, 3);
    assert_eq!(next_expire(&t), Some(0));
}
