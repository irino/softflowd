//! The exit status after a command of the control socket (D45).  As C does: the loop is left
//! with the return value of the control socket, so `softflowctl shutdown` and `exit` end the
//! program with 1; a signal (SIGTERM, SIGINT) ends it with 0.

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn start(tag: &str) -> (Child, std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("rsoftflowd_d45_{tag}_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ctl = dir.join("ctl");
    let child = Command::new(env!("CARGO_BIN_EXE_rsoftflowd"))
        .args(["-d", "-R", "0", "-n", "127.0.0.1:9"])
        .arg("-p")
        .arg(dir.join("pid"))
        .arg("-c")
        .arg(&ctl)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to execute rsoftflowd");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ctl.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(ctl.exists(), "the control socket did not appear");
    (child, ctl, dir)
}

fn wait(mut child: Child, dir: std::path::PathBuf) -> Option<i32> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.code();
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("rsoftflowd did not exit");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let _ = std::fs::remove_dir_all(dir);
    status
}

fn control(command: &str, tag: &str) -> Option<i32> {
    let (child, ctl, dir) = start(tag);
    let out = Command::new(env!("CARGO_BIN_EXE_rsoftflowctl"))
        .arg("-c")
        .arg(&ctl)
        .arg(command)
        .output()
        .expect("Failed to execute rsoftflowctl");
    assert!(out.status.success(), "{out:?}");
    wait(child, dir)
}

#[test]
fn test_d45_control_shutdown_exits_with_1() {
    assert_eq!(control("shutdown", "shutdown"), Some(1));
}

#[test]
fn test_d45_control_exit_exits_with_1() {
    assert_eq!(control("exit", "exit"), Some(1));
}

#[test]
fn test_d45_signals_exit_with_0() {
    for (signal, tag) in [(libc::SIGTERM, "term"), (libc::SIGINT, "int")] {
        let (child, _ctl, dir) = start(tag);
        // The handlers are installed before the start-up log lines; the control socket
        // is made earlier, so wait a moment.
        std::thread::sleep(Duration::from_millis(300));
        unsafe { libc::kill(child.id() as i32, signal) };
        assert_eq!(wait(child, dir), Some(0), "signal {signal}");
    }
}
