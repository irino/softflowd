use clap::Parser;
use rsoftflowd::opts::RsoftflowctlArgs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = RsoftflowctlArgs::parse();

    let mut stream = match UnixStream::connect(&args.ctlsock) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("rsoftflowctl: ctl connect(\"{}\") error: {}", args.ctlsock, e);
            std::process::exit(1);
        }
    };

    if let Err(e) = stream.write_all(format!("{}\n", args.command).as_bytes()) {
        eprintln!("rsoftflowctl: write error: {}", e);
        std::process::exit(1);
    }

    let mut response = String::new();
    if let Err(e) = stream.read_to_string(&mut response) {
        eprintln!("rsoftflowctl: read error: {}", e);
        std::process::exit(1);
    }

    print!("{}", response);
    Ok(())
}
