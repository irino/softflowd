//! The errors of the command line are written as the C version writes them (D26): the message,
//! then the usage text of C, on standard error, and the exit status 1; `-h` writes the usage and
//! exits with 0.

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rsoftflowd"))
        .args(args)
        .output()
        .expect("Failed to execute rsoftflowd")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn test_d26_help_writes_the_usage_of_c_to_stderr_and_exits_with_0() {
    for flag in ["-h", "--help"] {
        let out = run(&[flag]);
        assert_eq!(out.status.code(), Some(0), "{flag}");
        assert!(out.stdout.is_empty(), "{flag}: {out:?}");
        let text = stderr(&out);
        assert!(
            text.starts_with(
                "Usage: rsoftflowd [options] [bpf_program]\nThis is rsoftflowd version "
            ),
            "{flag}: {text}"
        );
        assert_eq!(text.lines().count(), 67, "{flag}");
    }
}

#[test]
fn test_d26_unknown_option_is_written_like_getopt_and_has_the_usage() {
    let out = run(&["-z"]);
    assert_eq!(out.status.code(), Some(1));
    let text = stderr(&out);
    assert!(
        text.contains(": invalid option -- 'z'\nInvalid commandline option.\nUsage: rsoftflowd "),
        "{text}"
    );
    let out = run(&["--bogus"]);
    assert!(
        stderr(&out).contains(": unrecognized option '--bogus'\nInvalid commandline option.\n")
    );
}

#[test]
fn test_d26_missing_value_and_invalid_values_have_the_text_of_c() {
    let text = stderr(&run(&["-i"]));
    assert!(
        text.contains(": option requires an argument -- 'i'\nInvalid commandline option.\nUsage:"),
        "{text}"
    );

    let text = stderr(&run(&["-T", "bogus", "-r", "x.pcap"]));
    assert!(
        text.starts_with("Unknown flow tracking level\nUsage: rsoftflowd "),
        "{text}"
    );

    let out = run(&["-m", "0", "-r", "x.pcap"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).starts_with("Invalid maximum flows\n\nUsage: rsoftflowd "));

    // C: no usage after the version.
    let out = run(&["-v", "99", "-r", "x.pcap"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(stderr(&out), "Invalid NetFlow version\n");
}

#[test]
fn test_d26_no_packet_source_and_source_given_twice() {
    let text = stderr(&run(&[]));
    assert!(
        text.starts_with("-i, -r or -R option not specified.\nUsage: rsoftflowd "),
        "{text}"
    );
    let text = stderr(&run(&["-r", "a.pcap", "-r", "b.pcap"]));
    assert!(
        text.starts_with("Packet source already specified.\n\nUsage: rsoftflowd "),
        "{text}"
    );
}

#[test]
fn test_d26_a_word_that_begins_with_a_dash_is_the_value_of_an_option() {
    // getopt() takes the next word as the value: -r reads the file "-n".
    let out = run(&["-r", "-n", "127.0.0.1:9"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        stderr(&out),
        "pcap_open_offline(-n): -n: No such file or directory\n"
    );
}
