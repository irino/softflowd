//! The usage text of the C version and the exit with it.
//!
//! Original: options.c, `usage()` and `die_usage()`.  The text is `usage.txt`, made by
//! `tools/gen_usage_rs.py` from the output of `softflowd -h` (the default configuration of the
//! C version); `{prog}` and `{version}` are the name and the version of this program.

/// The name of this program, as `PROGNAME` in the C version.
pub const PROGNAME: &str = "rsoftflowd";
/// The version of this program, as `PROGVER` in the C version.
pub const PROGVER: &str = env!("CARGO_PKG_VERSION");

const USAGE_C: &str = include_str!("usage.txt");

/// The usage text, as `usage()` writes it to standard error.
pub fn usage_text() -> String {
    USAGE_C
        .replace("{prog}", PROGNAME)
        .replace("{version}", PROGVER)
}

/// Writes the usage text to standard error.
pub fn print_usage() {
    eprint!("{}", usage_text());
}

/// Writes the message and the usage text to standard error and exits with 1.
///
/// The message ends with the newline (or two) that C has in the same place.
pub fn die_usage(message: &str) -> ! {
    eprint!("{message}");
    print_usage();
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_text_is_the_text_of_c() {
        let text = usage_text();
        assert!(text.starts_with("Usage: rsoftflowd [options] [bpf_program]\n"));
        assert!(text.contains("This is rsoftflowd version 0.1.0. Valid commandline options:\n"));
        assert!(!text.contains("{prog}") && !text.contains("{version}"));
        assert_eq!(text.lines().count(), 67);
        assert!(text.ends_with("(default     60)\n\n"));
    }
}
