//! The errors of the command line of rsoftflowd, in the text of the C version.
//!
//! This is a module of the library and not of `opts.rs`: `build.rs` includes `opts.rs` to make the
//! manual page and does not have the rest of the crate.

use clap::error::{ContextKind, ContextValue, ErrorKind};
use clap::{CommandFactory, FromArgMatches};

use crate::opts::RsoftflowdArgs;
use crate::usage::{PROGNAME, die_usage, print_usage};

/// Parses the command line of rsoftflowd, and writes the errors as the C version does.
///
/// Original: softflowd.c / options.c, getopt_long() and die_usage().  clap finds the
/// error; the text, the usage and the exit status are those of C:
///
/// - an option that takes a value takes the next word, also one that begins with "-",
///   as getopt() does;
/// - `-h` writes the usage to standard error and exits with 0;
/// - the other errors write the message and the usage and exit with 1.
pub fn parse_daemon_args_or_exit() -> RsoftflowdArgs {
    let command = RsoftflowdArgs::command().mut_args(|arg| {
        // The words of the filter (the positional argument) are not options' values: a word
        // that begins with "-" there is an option, as in getopt().
        if !arg.is_positional() && arg.get_action().takes_values() {
            arg.allow_hyphen_values(true)
        } else {
            arg
        }
    });
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    match command.clone().try_get_matches_from(&argv) {
        Ok(mut matches) => {
            // The positions are read before the values are taken out of the matches.
            let ctl_before_read = matches
                .index_of("ctlsock")
                .zip(matches.index_of("pcap_file"))
                .is_some_and(|(c, r)| c < r);
            match RsoftflowdArgs::from_arg_matches_mut(&mut matches) {
                Ok(mut args) => {
                    // C: -r switches the control socket off, so a -c before it has no effect.
                    if ctl_before_read {
                        args.ctlsock = Some("none".to_string());
                    }
                    args
                }
                Err(e) => e.exit(),
            }
        }
        Err(e) => die_clap_error(&command, &e, &argv),
    }
}

/// The long name in the text of a clap error ("--read <pcap_file>" is "read").
fn clap_error_long_name(e: &clap::Error) -> Option<String> {
    match e.get(ContextKind::InvalidArg) {
        Some(ContextValue::String(text)) => {
            let long = text.strip_prefix("--")?;
            Some(long.split([' ', '=']).next()?.to_string())
        }
        _ => None,
    }
}

/// Writes the C text of an error that clap found, and exits.
fn die_clap_error(command: &clap::Command, e: &clap::Error, argv: &[std::ffi::OsString]) -> ! {
    let prog = argv.first().map_or_else(
        || PROGNAME.to_string(),
        |a| a.to_string_lossy().into_owned(),
    );
    let long = clap_error_long_name(e);
    match e.kind() {
        // -h: C writes the usage to standard error and exits with 0.
        ErrorKind::DisplayHelp => {
            print_usage();
            std::process::exit(0);
        }
        ErrorKind::DisplayVersion => e.exit(),
        ErrorKind::UnknownArgument => {
            let arg = match e.get(ContextKind::InvalidArg) {
                Some(ContextValue::String(text)) => text.clone(),
                _ => String::new(),
            };
            if let Some(long) = arg.strip_prefix("--") {
                eprintln!("{prog}: unrecognized option '--{long}'");
            } else {
                let c = arg.trim_start_matches('-').chars().next().unwrap_or('?');
                eprintln!("{prog}: invalid option -- '{c}'");
            }
            die_usage("Invalid commandline option.\n");
        }
        ErrorKind::ArgumentConflict => {
            // A source (-i, -r, -R) that is given twice, or two sources.
            if matches!(long.as_deref(), Some("interface" | "read" | "psamp-port")) {
                die_usage("Packet source already specified.\n\n");
            }
            exit_with(e)
        }
        ErrorKind::InvalidValue | ErrorKind::ValueValidation | ErrorKind::WrongNumberOfValues => {
            let Some(long) = long else { exit_with(e) };
            let value_missing = !matches!(
                e.get(ContextKind::InvalidValue),
                Some(ContextValue::String(v)) if !v.is_empty()
            );
            if value_missing {
                // getopt(): the option is the last word.
                let arg = command
                    .get_arguments()
                    .find(|a| a.get_long() == Some(long.as_str()));
                if argv
                    .last()
                    .is_some_and(|w| w.to_string_lossy().starts_with("--"))
                {
                    eprintln!("{prog}: option '--{long}' requires an argument");
                } else if let Some(short) = arg.and_then(|a| a.get_short()) {
                    eprintln!("{prog}: option requires an argument -- '{short}'");
                }
                die_usage("Invalid commandline option.\n");
            }
            match long.as_str() {
                "track" => die_usage("Unknown flow tracking level\n"),
                "export-protocol" => die_usage("Unknown transport layer protocol\n"),
                "flow-lookup" => die_usage("Invalid flow lookup mode\n\n"),
                "absolute-time" => die_usage("Unknown time format\n"),
                "max-flows" => die_usage("Invalid maximum flows\n\n"),
                "hoplimit" => die_usage("Invalid hop limit\n\n"),
                "netflow-version" => {
                    eprintln!("Invalid NetFlow version");
                    std::process::exit(1);
                }
                _ => exit_with(e),
            }
        }
        _ => exit_with(e),
    }
}

/// Writes the error as clap does and exits with 1 (clap exits with 2).
///
/// C accepts some of the values that clap refuses (a number with letters after it, for
/// example): they are a difference of this version that is kept, see D34.
fn exit_with(e: &clap::Error) -> ! {
    let _ = e.print();
    std::process::exit(1);
}
