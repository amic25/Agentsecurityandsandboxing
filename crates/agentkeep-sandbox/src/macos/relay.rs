//! The supervisor-side relay: a loopback TCP listener that forwards every
//! connection to the egress proxy's Unix socket.
//!
//! On Linux the relay runs inside the sandbox's private network namespace.
//! macOS has no network namespace, so the relay runs in the supervisor, on
//! the host's loopback, on a port chosen by the kernel. The Seatbelt profile
//! lets the sandbox connect to that one port and nothing else; the proxy
//! behind it enforces the domain allowlist and DLP. Any local process of the
//! host can also connect to the port, which gives it the same policy-checked
//! egress the agent has and nothing more (documented in `limitations.md`).
//!
//! Plain threads and blocking I/O: an agent opens a handful of proxy
//! connections, and this keeps the supervisor free of an async runtime
//! before the proxy itself starts.

use std::io;
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

/// A running relay. Stops accepting when dropped; connections already
/// established run until either side closes.
#[derive(Debug)]
pub struct Relay {
    port: u16,
    stop: Arc<AtomicBool>,
}

impl Relay {
    /// Bind `127.0.0.1:0` now, so the port is known before the profile is
    /// written, and serve it on a background thread.
    pub fn start(upstream: PathBuf) -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        thread::Builder::new()
            .name("agentkeep-relay".into())
            .spawn(move || {
                for conn in listener.incoming() {
                    if flag.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(client) = conn else { continue };
                    let upstream = upstream.clone();
                    let _ = thread::Builder::new()
                        .name("agentkeep-relay-conn".into())
                        .spawn(move || pipe(client, &upstream));
                }
            })?;
        Ok(Self { port, stop })
    }

    /// The loopback port the sandbox must use.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the blocking accept so the thread sees the flag.
        let _ = TcpStream::connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port));
    }
}

fn pipe(client: TcpStream, upstream: &std::path::Path) {
    let Ok(server) = UnixStream::connect(upstream) else {
        let _ = client.shutdown(Shutdown::Both);
        return;
    };
    let (Ok(mut client_r), Ok(mut server_w)) = (client.try_clone(), server.try_clone()) else {
        return;
    };
    let up = thread::spawn(move || {
        let _ = io::copy(&mut client_r, &mut server_w);
        let _ = server_w.shutdown(Shutdown::Write);
    });
    let (mut server_r, mut client_w) = (server, client);
    let _ = io::copy(&mut server_r, &mut client_w);
    let _ = client_w.shutdown(Shutdown::Write);
    let _ = up.join();
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;

    use super::*;

    #[test]
    fn forwards_both_directions_and_half_close() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("proxy.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut line = [0u8; 6];
            s.read_exact(&mut line).unwrap();
            let line = String::from_utf8_lossy(&line).into_owned();
            s.write_all(format!("echo {line}").as_bytes()).unwrap();
            // Read to EOF: the client's half-close must arrive.
            let mut rest = Vec::new();
            s.read_to_end(&mut rest).unwrap();
            rest
        });
        let relay = Relay::start(sock).unwrap();
        assert_ne!(relay.port(), 0);
        let mut c = TcpStream::connect(("127.0.0.1", relay.port())).unwrap();
        c.write_all(b"hello\nmore").unwrap();
        c.shutdown(Shutdown::Write).unwrap();
        let mut got = String::new();
        c.read_to_string(&mut got).unwrap();
        assert_eq!(got, "echo hello\n");
        assert_eq!(server.join().unwrap(), b"more");
    }

    #[test]
    fn missing_upstream_closes_the_client() {
        let dir = tempfile::tempdir().unwrap();
        let relay = Relay::start(dir.path().join("none.sock")).unwrap();
        let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, relay.port());
        let mut c = TcpStream::connect(addr).unwrap();
        let mut buf = Vec::new();
        let n = c.read_to_end(&mut buf).unwrap_or(0);
        assert_eq!(n, 0);
    }
}
