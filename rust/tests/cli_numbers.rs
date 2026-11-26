//! The numbers of the command line (D34): as in the C version, the whole argument is a decimal
//! number, with an optional "+" (and "-" for `-L`), and any other argument is an error with the
//! message of C.  Before D34 the C version read "5x" as 5 and "abc" as 0 (`atoi`).

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rsoftflowd"))
        .args(args)
        .args(["-n", "127.0.0.1:9", "-r", "x.pcap"])
        .output()
        .expect("Failed to execute rsoftflowd")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The argument is refused: the message, then the usage, and the exit status 1.
fn assert_refused(option: &str, value: &str, message: &str) {
    let out = run(&[option, value]);
    assert_eq!(out.status.code(), Some(1), "{option} {value:?}");
    let text = stderr(&out);
    assert!(
        text.starts_with(&format!("{message}Usage: rsoftflowd ")),
        "{option} {value:?}: {text}"
    );
}

/// The argument is taken: the program goes on to the file, which is not there.
fn assert_accepted(option: &str, value: &str) {
    let out = run(&[option, value]);
    assert_eq!(out.status.code(), Some(1), "{option} {value:?}");
    let text = stderr(&out);
    assert!(
        text.starts_with("pcap_open_offline(x.pcap): "),
        "{option} {value:?}: {text}"
    );
}

#[test]
fn test_d34_a_number_with_anything_but_digits_is_refused() {
    let cases: &[(&str, &[&str], &str)] = &[
        (
            "-m",
            &["5x", " 5", "abc", "0", "-3", "4294967296", ""],
            "Invalid maximum flows\n\n",
        ),
        (
            "-L",
            &["5x", "abc", "256", "-1", ""],
            "Invalid hop limit\n\n",
        ),
        (
            "-x",
            &["3x", "abc", "0", "11", ""],
            "Invalid number of MPLS label (1 to 10)\n\n",
        ),
        ("-s", &["3x", "abc", "-1", ""], "Invalid sampling rate\n\n"),
        (
            "-B",
            &["5x", "abc", "-1", "2147483648", ""],
            "Invalid pcap buffer size\n\n",
        ),
        (
            "-C",
            &["5x", "abc", "-1", "2147483648", ""],
            "Invalid capture length\n\n",
        ),
        // C went on with the default port for a port out of range.
        (
            "-R",
            &["abc", "65536", "99999", "-1", ""],
            "Invalid -R port\n\n",
        ),
        (
            "-I",
            &["5x", "5dd", "5 d"],
            "Invalid unit in boot_time_reinit (d, h, m or s)\n",
        ),
        (
            "-I",
            &["-5", "+5", "abc", " 5", ""],
            "No digits were found in boot_time_reinit\n",
        ),
    ];
    for (option, values, message) in cases {
        for value in *values {
            assert_refused(option, value, message);
        }
    }
}

#[test]
fn test_d34_the_version_is_a_plain_number() {
    for value in ["09", "+5", "9x", "5.0", "abc", ""] {
        let out = run(&["-v", value]);
        assert_eq!(out.status.code(), Some(1), "-v {value:?}");
        // No usage after the version, as in C.
        assert_eq!(stderr(&out), "Invalid NetFlow version\n", "-v {value:?}");
    }
    for value in ["1", "5", "9", "10"] {
        assert_accepted("-v", value);
    }
}

#[test]
fn test_d34_a_plus_sign_zeros_and_the_units_are_taken() {
    for (option, value) in [
        ("-m", "+5"),
        ("-m", "007"),
        ("-s", "+3"),
        ("-s", "0"),
        ("-L", "+5"),
        ("-L", "-0"),
        ("-x", "03"),
        ("-B", "+5"),
        ("-C", "+5"),
        ("-R", "0"),
        ("-I", "5"),
        ("-I", "5s"),
        ("-I", "5S"),
        ("-I", "5m"),
        ("-I", "5H"),
        ("-I", "5d"),
    ] {
        assert_accepted(option, value);
    }
}
