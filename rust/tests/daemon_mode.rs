//! A daemon (no -d, -D or -r) after its fork (D47).  A thread does not survive a fork, so the
//! threads of the control socket and of the packet source have to be started after it.  Before
//! D47 the control socket of a daemon did not answer, and a daemon that read an interface
//! exported nothing.

use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct Daemon {
    pid: i32,
    ctl: PathBuf,
    dir: PathBuf,
}

impl Daemon {
    /// Starts the daemon (the program returns when it has forked), and waits for its pid file.
    fn start(tag: &str, source: &[&str], collector: u16, extra: &[&str]) -> Daemon {
        let dir = std::env::temp_dir().join(format!("rsoftflowd_d47_{tag}_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // A daemon of root runs as nobody: the directory has to let it in.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        }
        let ctl = dir.join("ctl");
        let pidfile = dir.join("pid");
        let status = Command::new(env!("CARGO_BIN_EXE_rsoftflowd"))
            .args(source)
            .args(["-v", "5", "-n", &format!("127.0.0.1:{collector}")])
            .arg("-p")
            .arg(&pidfile)
            .arg("-c")
            .arg(&ctl)
            .args(extra)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("Failed to execute rsoftflowd");
        assert!(status.success(), "the daemon did not start: {status}");
        let deadline = Instant::now() + Duration::from_secs(5);
        let pid = loop {
            if let Some(pid) = std::fs::read_to_string(&pidfile)
                .ok()
                .and_then(|s| s.trim().parse::<i32>().ok())
            {
                break pid;
            }
            assert!(Instant::now() < deadline, "no pid file");
            std::thread::sleep(Duration::from_millis(50));
        };
        // The control socket is made before the fork; let the threads start.
        std::thread::sleep(Duration::from_millis(500));
        Daemon { pid, ctl, dir }
    }

    /// Runs `rsoftflowctl`, and fails if it does not return in 5 s (it has no timeout of its
    /// own, and waits for ever for a daemon that does not answer).
    fn control(&self, command: &str) -> String {
        let mut child = Command::new(env!("CARGO_BIN_EXE_rsoftflowctl"))
            .arg("-c")
            .arg(&self.ctl)
            .arg(command)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to execute rsoftflowctl");
        let deadline = Instant::now() + Duration::from_secs(5);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() > deadline {
                let _ = child.kill();
                panic!("{command}: the control socket of the daemon does not answer");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "{command}: {out:?}");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // Whatever the test did, the daemon must not stay.
        unsafe { libc::kill(self.pid, libc::SIGKILL) };
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// One PSAMP data record with an Ethernet/IPv4/UDP frame (the record of C).
fn psamp_udp_datagram() -> Vec<u8> {
    let mut frame = vec![0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01, 0x08, 0x00];
    frame.extend_from_slice(&[
        0x45, 0, 0, 32, 0, 1, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
    ]);
    frame.extend_from_slice(&[0x07, 0xd0, 0, 53, 0, 12, 0, 0, b'a', b'b', b'c', b'd']);
    let mut datagram = vec![
        0, 10, 0x05, 0x94, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0c, 0x00,
    ];
    datagram.extend_from_slice(&[0x05, 0x84]);
    datagram.extend_from_slice(&1u64.to_be_bytes());
    datagram.extend_from_slice(&(1_700_000_000u32 + 0x83AA_7E80).to_be_bytes());
    datagram.extend_from_slice(&[0, 0, 0, 0]);
    datagram.extend_from_slice(&(frame.len() as u16).to_be_bytes());
    datagram.extend_from_slice(&frame);
    datagram.resize(1428, 0);
    datagram
}

fn free_udp_port() -> u16 {
    let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
    probe.local_addr().unwrap().port()
}

#[test]
fn test_d47_control_socket_of_a_daemon_answers() {
    let collector = UdpSocket::bind("127.0.0.1:0").unwrap();
    let daemon = Daemon::start(
        "ctl",
        &["-R", "0"],
        collector.local_addr().unwrap().port(),
        &[],
    );
    let statistics = daemon.control("statistics");
    assert!(
        statistics.contains("Accumulated statistics"),
        "{statistics:?}"
    );
    daemon.control("shutdown");
    let deadline = Instant::now() + Duration::from_secs(5);
    // A process that is gone, or a zombie that nobody has collected yet, has ended.
    while Instant::now() < deadline && !ended(daemon.pid) {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(ended(daemon.pid), "the daemon did not end after shutdown");
}

fn ended(pid: i32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/status")) {
        Ok(status) => status
            .lines()
            .find(|l| l.starts_with("State:"))
            .is_some_and(|l| l.contains('Z')),
        Err(_) => true,
    }
}

#[test]
fn test_d47_daemon_reads_the_psamp_port_and_exports() {
    let collector = UdpSocket::bind("127.0.0.1:0").unwrap();
    collector
        .set_read_timeout(Some(Duration::from_millis(1500)))
        .unwrap();
    let port = free_udp_port();
    let daemon = Daemon::start(
        "psamp",
        &["-R", &port.to_string()],
        collector.local_addr().unwrap().port(),
        &[],
    );
    let datagram = psamp_udp_datagram();
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    sender.send_to(&datagram, ("127.0.0.1", port)).unwrap();
    std::thread::sleep(Duration::from_millis(500));

    daemon.control("expire-all");
    let mut buf = [0u8; 2048];
    let received = collector
        .recv(&mut buf)
        .expect("the daemon exported nothing");
    assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 5);
    assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 1, "one flow");
    daemon.control("shutdown");
    assert_eq!(received, 24 + 48);
}

/// A daemon of root that reads an interface: needs root, and the loopback interface.
#[test]
fn test_d47_daemon_reads_an_interface_and_exports() {
    if unsafe { libc::geteuid() } != 0 || !Path::new("/sys/class/net/lo").exists() {
        eprintln!("skipped: needs root and the interface lo");
        return;
    }
    let collector = UdpSocket::bind("127.0.0.1:0").unwrap();
    collector
        .set_read_timeout(Some(Duration::from_millis(1500)))
        .unwrap();
    let daemon = Daemon::start(
        "lo",
        &["-i", "lo"],
        collector.local_addr().unwrap().port(),
        &["udp and dst port 41047"],
    );
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    for _ in 0..5 {
        sender.send_to(&[b'x'; 40], "127.0.0.1:41047").unwrap();
    }
    std::thread::sleep(Duration::from_millis(500));
    daemon.control("expire-all");
    let mut buf = [0u8; 2048];
    let received = collector
        .recv(&mut buf)
        .expect("the daemon exported nothing");
    assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 5);
    // The 5 packets are one flow.
    assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 1);
    assert_eq!(u32::from_be_bytes([buf[40], buf[41], buf[42], buf[43]]), 5);
    daemon.control("shutdown");
    assert_eq!(received, 24 + 48);
}

/// The privileges of a daemon of root (D48), as C drops them: the user `nobody`, the group of
/// `nobody` only, and `/var/empty` as the root directory.  Needs root and `/var/empty`.
#[test]
fn test_d48_daemon_of_root_drops_privileges_like_c() {
    if unsafe { libc::geteuid() } != 0 || !Path::new("/var/empty").is_dir() {
        eprintln!("skipped: needs root and /var/empty");
        return;
    }
    let nobody = nix::unistd::User::from_name("nobody").unwrap().unwrap();
    let collector = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = free_udp_port();
    let daemon = Daemon::start(
        "privs",
        &["-R", &port.to_string()],
        collector.local_addr().unwrap().port(),
        &[],
    );
    let status = std::fs::read_to_string(format!("/proc/{}/status", daemon.pid)).unwrap();
    let field = |name: &str| -> Vec<String> {
        status
            .lines()
            .find(|l| l.starts_with(name))
            .unwrap()
            .split_whitespace()
            .skip(1)
            .map(str::to_string)
            .collect()
    };
    let (uid, gid) = (nobody.uid.to_string(), nobody.gid.to_string());
    assert_eq!(field("Uid:"), vec![uid; 4]);
    assert_eq!(field("Gid:"), vec![gid.clone(); 4]);
    // No other group (the old code kept none either, but as root it had group 0).
    assert_eq!(field("Groups:"), vec![gid]);
    assert_eq!(
        std::fs::read_link(format!("/proc/{}/root", daemon.pid)).unwrap(),
        Path::new("/var/empty")
    );
    // C writes "Unknown (17)" for every protocol in this root directory, because the name
    // service cannot be loaded there; /etc/protocols is read before the chroot (D48), and
    // the name is udp.
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    sender
        .send_to(&psamp_udp_datagram(), ("127.0.0.1", port))
        .unwrap();
    std::thread::sleep(Duration::from_millis(500));
    daemon.control("expire-all");
    let statistics = daemon.control("statistics");
    assert!(statistics.contains("udp (17):"), "{statistics}");
    daemon.control("shutdown");
}
