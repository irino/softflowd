//! flowDirection of the IPFIX records (D33): 0 is ingress and 1 is egress, as in
//! RFC 7011 and in C.

mod common;

use rsoftflowd::common::{FlowTracker, TrackLevel};
use rsoftflowd::exporter::export_common::{
    IPFIX_FLOWDIRECTION_EGRESS, IPFIX_FLOWDIRECTION_INGRESS, ipfix_flow_direction,
};

const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];

fn tracker() -> FlowTracker {
    let mut t = FlowTracker::new(10);
    t.param.track_level = TrackLevel::FullVlanEther;
    t.param.direction_mac = Some(MAC);
    t.param.direction_mac_set = true;
    t
}

#[test]
fn test_d33_direction_values_are_those_of_rfc_7011() {
    assert_eq!(IPFIX_FLOWDIRECTION_INGRESS, 0);
    assert_eq!(IPFIX_FLOWDIRECTION_EGRESS, 1);
}

#[test]
fn test_d33_direction_mac_gives_egress_or_ingress() {
    let t = tracker();
    let mut flow = common::make_dummy_flow();
    // The source MAC of endpoint 0 is the direction MAC: egress.
    std::sync::Arc::make_mut(&mut flow.key).ethermac = [MAC, [9; 6]];
    assert_eq!(
        ipfix_flow_direction(&flow, 0, &t.param),
        IPFIX_FLOWDIRECTION_EGRESS
    );
    // The other MAC of endpoint 0 is the direction MAC: ingress (it was 2).
    std::sync::Arc::make_mut(&mut flow.key).ethermac = [[9; 6], MAC];
    assert_eq!(
        ipfix_flow_direction(&flow, 0, &t.param),
        IPFIX_FLOWDIRECTION_INGRESS
    );
    // Neither: the endpoint index.
    std::sync::Arc::make_mut(&mut flow.key).ethermac = [[9; 6], [8; 6]];
    assert_eq!(ipfix_flow_direction(&flow, 1, &t.param), 1);
}
