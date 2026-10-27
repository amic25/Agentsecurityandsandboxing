//! Proxy latency benchmark against the PLAN budget (< 5 ms p50 added).
//!
//! Starts a local plain origin, a local TLS origin and the proxy in this
//! process (the proxy on its own runtime, exactly as `agentkeep run` starts
//! it, with every event redacted and written to a real hash-chained audit
//! log), then
//! sends N sequential requests per scenario and reports the latency the
//! proxy adds over talking to the origin directly.
//!
//! Each sample is one `POST` with an N-byte body answered by an N-byte
//! body, on a fresh connection (TCP, plus the TLS handshake for HTTPS), so
//! it includes everything the proxy does per request: the policy hook,
//! name resolution, the origin connection, leaf-certificate lookup, DLP on
//! the request line, headers and every body chunk, and the copy back.
//! Direct and proxied samples are interleaved and paired, and the
//! "added" columns are quantiles of the per-pair difference.
//!
//! No traffic leaves the machine. Run in release mode:
//! `benches/proxy.sh` or
//! `cargo run --release -p agentkeep-proxy --example latency -- [small_n] [large_n]`.

#![forbid(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    missing_docs
)]

#[cfg(unix)]
mod bench {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use agentkeep_proxy::{Config, Hooks, State, Verdict};

    /// Benign body text: realistic bytes for the DLP regexes, no secrets.
    const LOREM: &[u8] = b"fn main() { let answer = compute(42); println!(\"{answer}\"); } // lorem ipsum dolor sit amet, consectetur adipiscing elit\n";

    fn body(n: usize) -> Vec<u8> {
        LOREM.iter().copied().cycle().take(n).collect()
    }

    /// Allow everything; redact every event and log it to a real audit
    /// writer, as the CLI does.
    struct BenchHooks {
        log: Mutex<agentkeep_audit::Writer>,
        redactor: agentkeep_proxy::dlp::Scanner,
    }

    fn redact(r: &agentkeep_proxy::dlp::Scanner, v: &mut serde_json::Value) {
        match v {
            serde_json::Value::String(s) => {
                if let Some(clean) = r.redact(s) {
                    *s = clean;
                }
            }
            serde_json::Value::Array(items) => items.iter_mut().for_each(|i| redact(r, i)),
            serde_json::Value::Object(map) => map.values_mut().for_each(|i| redact(r, i)),
            _ => {}
        }
    }

    impl Hooks for BenchHooks {
        fn decide(&self, _host: &str, _port: u16) -> Verdict {
            Verdict::Allow {
                rule: Some("bench".into()),
            }
        }
        fn ask(&self, _prompt: &str, _rule: &str) -> bool {
            false
        }
        fn log(&self, kind: &str, mut data: serde_json::Value) {
            redact(&self.redactor, &mut data);
            if let Ok(mut w) = self.log.lock() {
                let _ = w.append(kind, data);
            }
        }
    }

    // ---- origins ---------------------------------------------------------

    /// Answer `POST` requests with a body as long as the one received, on a
    /// keep-alive connection.
    fn serve<S: Read + Write>(mut s: S) {
        let mut buf = Vec::new();
        let mut tmp = vec![0u8; 64 * 1024];
        loop {
            let end = loop {
                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break i + 4;
                }
                match s.read(&mut tmp) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                }
            };
            let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            while buf.len() < end + len {
                match s.read(&mut tmp) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                }
            }
            buf.drain(..end + len);
            let reply = body(len);
            let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\n\r\n");
            if s.write_all(head.as_bytes()).is_err() || s.write_all(&reply).is_err() {
                return;
            }
            let _ = s.flush();
        }
    }

    fn start_plain_origin() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        thread::spawn(move || {
            for s in l.incoming().flatten() {
                let _ = s.set_nodelay(true);
                thread::spawn(move || serve(s));
            }
        });
        port
    }

    /// TLS origin with a self-signed certificate for `localhost`; returns the
    /// port and the certificate PEM path.
    fn start_tls_origin(dir: &Path) -> (u16, PathBuf) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let pem = dir.join("origin.pem");
        std::fs::write(&pem, cert.pem()).unwrap();
        let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()),
        );
        let cfg = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key_der)
            .unwrap(),
        );
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        thread::spawn(move || {
            for s in l.incoming().flatten() {
                let _ = s.set_nodelay(true);
                let cfg = Arc::clone(&cfg);
                thread::spawn(move || {
                    let conn = rustls::ServerConnection::new(cfg).unwrap();
                    serve(rustls::StreamOwned::new(conn, s));
                });
            }
        });
        (port, pem)
    }

    // ---- client ------------------------------------------------------------

    fn tls_client(trust_pem: &str) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_pki_types::pem::PemObject::pem_slice_iter(trust_pem.as_bytes()) {
            let c: rustls_pki_types::CertificateDer<'static> = c.unwrap();
            roots.add(c).unwrap();
        }
        Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
        )
    }

    /// Send one request and read the whole response; panics on anything but
    /// a complete `200` so a broken path can never look fast.
    fn exchange<S: Read + Write>(s: &mut S, target: &str, host: &str, payload: &[u8]) {
        let head = format!(
            "POST {target} HTTP/1.1\r\nHost: {host}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            payload.len()
        );
        s.write_all(head.as_bytes()).unwrap();
        s.write_all(payload).unwrap();
        s.flush().unwrap();
        let mut buf = Vec::with_capacity(payload.len() + 256);
        let mut tmp = vec![0u8; 64 * 1024];
        let end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            let n = s.read(&mut tmp).unwrap();
            assert!(n > 0, "connection closed before the response head");
            buf.extend_from_slice(&tmp[..n]);
        };
        let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
        assert!(
            head.starts_with("http/1.1 200"),
            "unexpected response: {head}"
        );
        let len: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse().ok())
            .expect("content-length");
        assert_eq!(len, payload.len(), "body length");
        while buf.len() < end + len {
            let n = s.read(&mut tmp).unwrap();
            assert!(n > 0, "connection closed mid-body");
            buf.extend_from_slice(&tmp[..n]);
        }
    }

    /// Send `CONNECT` and consume the `200`.
    fn connect(socket: &Path, authority: &str) -> UnixStream {
        let mut s = UnixStream::connect(socket).unwrap();
        write!(
            s,
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"
        )
        .unwrap();
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            s.read_exact(&mut b).unwrap();
            head.push(b[0]);
        }
        assert!(head.starts_with(b"HTTP/1.1 200"), "CONNECT refused");
        s
    }

    fn tls_over<S: Read + Write>(
        cfg: &Arc<rustls::ClientConfig>,
        io: S,
    ) -> rustls::StreamOwned<rustls::ClientConnection, S> {
        let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
        rustls::StreamOwned::new(
            rustls::ClientConnection::new(Arc::clone(cfg), name).unwrap(),
            io,
        )
    }

    #[derive(Clone, Copy)]
    enum Route {
        PlainDirect,
        PlainProxied,
        TlsDirect,
        TlsInspected,
        TlsPassthrough,
    }

    struct Bench {
        socket: PathBuf,
        plain_port: u16,
        tls_port: u16,
        origin_trust: Arc<rustls::ClientConfig>,
        session_trust: Arc<rustls::ClientConfig>,
    }

    impl Bench {
        /// One request on a fresh connection; returns its wall time.
        fn once(&self, path: Route, payload: &[u8]) -> Duration {
            let start = Instant::now();
            match path {
                Route::PlainDirect => {
                    let mut s = TcpStream::connect(("127.0.0.1", self.plain_port)).unwrap();
                    s.set_nodelay(true).unwrap();
                    exchange(&mut s, "/echo", "127.0.0.1", payload);
                }
                Route::PlainProxied => {
                    let mut s = UnixStream::connect(&self.socket).unwrap();
                    let target = format!("http://127.0.0.1:{}/echo", self.plain_port);
                    exchange(&mut s, &target, "127.0.0.1", payload);
                }
                Route::TlsDirect => {
                    let s = TcpStream::connect(("127.0.0.1", self.tls_port)).unwrap();
                    s.set_nodelay(true).unwrap();
                    exchange(
                        &mut tls_over(&self.origin_trust, s),
                        "/echo",
                        "localhost",
                        payload,
                    );
                }
                Route::TlsInspected => {
                    let s = connect(&self.socket, &format!("localhost:{}", self.tls_port));
                    exchange(
                        &mut tls_over(&self.session_trust, s),
                        "/echo",
                        "localhost",
                        payload,
                    );
                }
                Route::TlsPassthrough => {
                    // Same origin, named by address: only `127.0.0.1:port`
                    // is a passthrough rule. The client still sends SNI
                    // `localhost` and sees the origin's own certificate.
                    let s = connect(&self.socket, &format!("127.0.0.1:{}", self.tls_port));
                    exchange(
                        &mut tls_over(&self.origin_trust, s),
                        "/echo",
                        "localhost",
                        payload,
                    );
                }
            }
            start.elapsed()
        }
    }

    fn quantile(sorted: &[f64], q: f64) -> f64 {
        if sorted.is_empty() {
            return f64::NAN;
        }
        let idx = ((sorted.len() - 1) as f64 * q).round() as usize;
        sorted[idx]
    }

    fn ms(d: Duration) -> f64 {
        d.as_secs_f64() * 1000.0
    }

    /// Interleave direct and proxied samples and report quantiles of each and
    /// of the paired difference.
    fn scenario(
        bench: &Bench,
        name: &str,
        direct: Route,
        proxied: Route,
        size: usize,
        samples: usize,
    ) {
        let payload = body(size);
        for _ in 0..(samples / 10).max(3) {
            bench.once(direct, &payload);
            bench.once(proxied, &payload);
        }
        let mut base = Vec::with_capacity(samples);
        let mut via = Vec::with_capacity(samples);
        let mut added = Vec::with_capacity(samples);
        for _ in 0..samples {
            let without = ms(bench.once(direct, &payload));
            let with = ms(bench.once(proxied, &payload));
            base.push(without);
            via.push(with);
            added.push(with - without);
        }
        for v in [&mut base, &mut via, &mut added] {
            v.sort_by(f64::total_cmp);
        }
        println!(
            "| {name} | {} | {samples} | {:.2} / {:.2} | {:.2} / {:.2} | **{:.2}** / {:.2} |",
            if size >= 1 << 20 { "1 MiB" } else { "1 KiB" },
            quantile(&base, 0.5),
            quantile(&base, 0.95),
            quantile(&via, 0.5),
            quantile(&via, 0.95),
            quantile(&added, 0.5),
            quantile(&added, 0.95),
        );
    }

    pub fn main() {
        let mut args = std::env::args().skip(1);
        let small_n: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(300);
        let large_n: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(40);
        if cfg!(debug_assertions) {
            eprintln!("warning: debug build; numbers are meaningless. Use --release.");
        }

        let dir = tempfile::tempdir().unwrap();
        let plain_port = start_plain_origin();
        let (tls_port, origin_pem) = start_tls_origin(dir.path());

        let writer = agentkeep_audit::Writer::create(&dir.path().join("audit")).unwrap();
        let dlp = Config::default().dlp;
        let hooks = Arc::new(BenchHooks {
            log: Mutex::new(writer),
            redactor: agentkeep_proxy::dlp::Scanner::new(&dlp),
        });
        let config = Config {
            dlp,
            allow_private: true,
            trusted_cas: vec![origin_pem.clone()],
            passthrough: vec![format!("127.0.0.1:{tls_port}")],
            ..Config::default()
        };
        let state = State::new(config, hooks).unwrap();
        assert!(
            state.config.tls_inspect && state.scanner.is_some(),
            "inspection and DLP must be on"
        );
        let session_ca = state.ca_pem().to_string();
        let socket = dir.path().join("proxy.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let _proxy = agentkeep_proxy::spawn(state, listener).unwrap();

        let origin_text = std::fs::read_to_string(&origin_pem).unwrap();
        let b = Bench {
            socket,
            plain_port,
            tls_port,
            origin_trust: tls_client(&origin_text),
            session_trust: tls_client(&session_ca),
        };

        println!(
            "agentkeep proxy latency: {small_n} samples at 1 KiB, {large_n} at 1 MiB, fresh connection per request, milliseconds"
        );
        println!();
        println!("| Path | Body | n | direct p50 / p95 | proxied p50 / p95 | added p50 / p95 |");
        println!("|---|---|---|---|---|---|");
        for (size, n) in [(1024, small_n), (1 << 20, large_n)] {
            scenario(
                &b,
                "plain HTTP, forward proxy (DLP)",
                Route::PlainDirect,
                Route::PlainProxied,
                size,
                n,
            );
            scenario(
                &b,
                "HTTPS, CONNECT inspected (TLS + DLP)",
                Route::TlsDirect,
                Route::TlsInspected,
                size,
                n,
            );
            scenario(
                &b,
                "HTTPS, CONNECT passthrough",
                Route::TlsDirect,
                Route::TlsPassthrough,
                size,
                n,
            );
        }
    }
}

fn main() {
    #[cfg(unix)]
    bench::main();
    #[cfg(not(unix))]
    eprintln!("the proxy listens on a Unix socket; this benchmark runs on Unix hosts only");
}
