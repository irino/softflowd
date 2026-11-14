use crate::exporter::{Destination, ExportSocket, NetflowTarget};
use crate::opts::RsoftflowdArgs;
use std::net::ToSocketAddrs;

/// Create the export targets and sockets.
///
/// Original: netsock.c (`connsock()`), softflowd.c target setup.
pub fn setup_export_targets(args: &RsoftflowdArgs, targets: &mut NetflowTarget, is_ntopng: bool) {
    if let Some(ref col_str) = args.collector {
        for addr_str in col_str.split(',') {
            let addr_str = addr_str.trim();
            if addr_str.is_empty() {
                continue;
            }
            if is_ntopng {
                #[cfg(feature = "ntopng")]
                {
                    match zmq::Context::new() {
                        context => match context.socket(zmq::PUB) {
                            Ok(socket) => {
                                let connect_str = format!("tcp://{}", addr_str);
                                log::info!("Connecting ZMQ socket '{}'", connect_str);
                                if let Err(e) = socket.connect(&connect_str) {
                                    log::error!(
                                        "Failed to connect ZMQ socket {}: {}",
                                        connect_str,
                                        e
                                    );
                                    std::process::exit(1);
                                }
                                targets.destinations.push(Destination {
                                    socket: ExportSocket::Zmq { context, socket },
                                    arg: addr_str.to_string(),
                                });
                            }
                            Err(e) => {
                                log::error!("Failed to create ZMQ socket: {}", e);
                                std::process::exit(1);
                            }
                        },
                    }
                }
                #[cfg(not(feature = "ntopng"))]
                {
                    eprintln!("ntopng export not enabled\n");
                    std::process::exit(1);
                }
            } else {
                match addr_str.to_socket_addrs() {
                    Ok(mut addrs) => {
                        if let Some(socket_addr) = addrs.next() {
                            let proto = args.transport_protocol.to_lowercase();
                            let socket = match proto.as_str() {
                                "tcp" => match std::net::TcpStream::connect(socket_addr) {
                                    Ok(s) => ExportSocket::Tcp(s),
                                    Err(e) => {
                                        log::error!(
                                            "Failed to connect to TCP collector {}: {}",
                                            socket_addr,
                                            e
                                        );
                                        std::process::exit(1);
                                    }
                                },
                                _ => {
                                    // Default UDP
                                    let s = std::net::UdpSocket::bind("0.0.0.0:0")
                                        .expect("Failed to bind UDP socket");
                                    if let Some(hl) = args.hoplimit {
                                        let _ = s.set_ttl(hl as u32);
                                    }
                                    if let Err(e) = s.connect(socket_addr) {
                                        log::error!(
                                            "Failed to connect UDP collector {}: {}",
                                            socket_addr,
                                            e
                                        );
                                        std::process::exit(1);
                                    }

                                    // Bind to specific device if requested (Linux only)
                                    #[cfg(target_os = "linux")]
                                    if let Some(ref send_if) = args.send_interface
                                        && let Err(e) = nix::sys::socket::setsockopt(
                                            &s,
                                            nix::sys::socket::sockopt::BindToDevice,
                                            &std::ffi::OsString::from(send_if),
                                        )
                                    {
                                        log::error!(
                                            "Failed to bind to interface {}: {}",
                                            send_if,
                                            e
                                        );
                                        std::process::exit(1);
                                    }

                                    ExportSocket::Udp(s)
                                }
                            };
                            targets.destinations.push(Destination {
                                socket,
                                arg: addr_str.to_string(),
                            });
                        }
                    }
                    Err(e) => {
                        log::error!("Failed to resolve collector address {}: {}", addr_str, e);
                        std::process::exit(1);
                    }
                }
            }
        }
    }
}
