//! The in-sandbox relay: a loopback TCP listener that forwards every
//! connection to the proxy's Unix socket.
//!
//! The sandbox's network namespace has no route anywhere; the proxy lives
//! outside and is reachable only through its socket file. HTTP clients
//! want a TCP proxy address, so init listens on `127.0.0.1:port` and pipes
//! bytes across. Path-based Unix sockets are not scoped to network
//! namespaces, which is what makes this work.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;

use tokio::net::{TcpListener, UnixStream};

/// Bind the listener now (so a failure is reported before the command
/// starts) and serve it on a background thread for the life of init.
pub fn start(port: u16, socket: PathBuf) -> Result<(), String> {
    let std_listener = std::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
        .map_err(|e| format!("relay bind 127.0.0.1:{port}: {e}"))?;
    std_listener
        .set_nonblocking(true)
        .map_err(|e| format!("relay nonblocking: {e}"))?;
    std::thread::Builder::new()
        .name("agentkeep-relay".into())
        .spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            rt.block_on(async move {
                let Ok(listener) = TcpListener::from_std(std_listener) else {
                    return;
                };
                loop {
                    let Ok((mut client, _)) = listener.accept().await else {
                        continue;
                    };
                    let socket = socket.clone();
                    tokio::spawn(async move {
                        let Ok(mut upstream) = UnixStream::connect(&socket).await else {
                            return;
                        };
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                    });
                }
            });
        })
        .map_err(|e| format!("relay thread: {e}"))?;
    Ok(())
}
