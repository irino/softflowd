//! Texts of the control socket replies that must be the same as in C (D28).

use rsoftflowd::common::FlowTracker;
use rsoftflowd::control::render_timeouts;

#[test]
fn test_d28_timeouts_text_is_right_aligned_like_c() {
    let t = FlowTracker::new(100);
    let s = render_timeouts(&t);
    assert_eq!(s.lines().count(), 8);
    assert!(s.starts_with("           TCP timeout: 3600s\n  TCP post-RST timeout: 120s\n"));
    assert!(s.ends_with("       Expiry interval: 60s\n"));
    // All labels end in the same column.
    for line in s.lines() {
        assert_eq!(line.find(':'), Some(22), "{line}");
    }
}

#[test]
fn test_d28_ctl_connect_error_is_like_c() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_rsoftflowctl"))
        .args(["-c", "/nonexistent/ctl.sock", "dump-flows"])
        .output()
        .expect("Failed to execute rsoftflowctl");
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        err.trim_end(),
        "ctl connect(\"/nonexistent/ctl.sock\") error: No such file or directory"
    );
}
