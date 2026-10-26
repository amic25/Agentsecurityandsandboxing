//! End-to-end proxy tests against local origins: plain HTTP, TLS with
//! inspection, TLS passthrough, policy denial and DLP blocking. No traffic
//! leaves the machine.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use agentkeep_proxy::{BoundSecret, Config, DlpConfig, Hooks, State, Verdict};

struct TestHooks {
    allow: Vec<String>,
    log: Mutex<Vec<(String, serde_json::Value)>>,
}

impl Hooks for TestHooks {
    fn decide(&self, host: &str, _port: u16) -> Verdict {
        if self.allow.iter().any(|h| h == host) {
            Verdict::Allow {
                rule: Some("test".into()),
            }
        } else {
            Verdict::Deny {
                rule: "test deny".into(),
            }
        }
    }
    fn ask(&self, _prompt: &str, _rule: &str) -> bool {
        false
    }
    fn log(&self, kind: &str, data: serde_json::Value) {
        self.log.lock().unwrap().push((kind.to_string(), data));
    }
}

impl TestHooks {
    fn kinds(&self) -> Vec<String> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .map(|(k, _)| k.clone())
            .collect()
    }
    fn find(&self, kind: &str) -> Option<serde_json::Value> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .find(|(k, _)| k == kind)
            .map(|(_, v)| v.clone())
    }
}

/// Read one HTTP/1.1 request (headers + Content-Length body) and echo it.
fn serve_echo<S: Read + Write>(mut s: S) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        let n = match s.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let len: usize = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse().unwrap_or(0))
        })
        .unwrap_or(0);
    while buf.len() < header_end + len {
        let n = match s.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        buf.extend_from_slice(&tmp[..n]);
    }
    let body = String::from_utf8_lossy(&buf[header_end..header_end + len]).to_string();
    let first = head.lines().next().unwrap_or("").to_string();
    let reply = format!("echo:{first} body={body}");
    let _ = write!(
        s,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
        reply.len()
    );
    let _ = s.flush();
}

fn start_plain_origin() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming().flatten() {
            thread::spawn(move || serve_echo(s));
        }
    });
    addr
}

/// A TLS origin with its own self-signed certificate; returns the address
/// and the PEM path to trust.
fn start_tls_origin(dir: &std::path::Path) -> (SocketAddr, PathBuf) {
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let pem_path = dir.join("origin.pem");
    std::fs::write(&pem_path, cert.pem()).unwrap();
    let certs = vec![cert.der().clone()];
    let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(
        rustls_pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()),
    );
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, key_der)
    .unwrap();
    let cfg = Arc::new(cfg);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming().flatten() {
            let cfg = Arc::clone(&cfg);
            thread::spawn(move || {
                let conn = rustls::ServerConnection::new(cfg).unwrap();
                let tls = rustls::StreamOwned::new(conn, s);
                serve_echo(tls);
            });
        }
    });
    (addr, pem_path)
}

struct Proxy {
    _dir: tempfile::TempDir,
    socket: PathBuf,
    hooks: Arc<TestHooks>,
    state: Arc<State>,
    _handle: agentkeep_proxy::ProxyHandle,
}

fn start_proxy(mut config: Config, allow: &[&str], trusted: Option<PathBuf>) -> Proxy {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("proxy.sock");
    config.allow_private = true;
    config.trusted_cas = trusted.into_iter().collect();
    let hooks = Arc::new(TestHooks {
        allow: allow.iter().map(ToString::to_string).collect(),
        log: Mutex::new(Vec::new()),
    });
    let state = State::new(config, hooks.clone()).unwrap();
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let handle = agentkeep_proxy::spawn(Arc::clone(&state), listener).unwrap();
    Proxy {
        _dir: dir,
        socket,
        hooks,
        state,
        _handle: handle,
    }
}

fn raw(socket: &PathBuf, request: &str) -> String {
    let mut s = UnixStream::connect(socket).unwrap();
    s.set_read_timeout(Some(std::time::Duration::from_secs(20)))
        .unwrap();
    s.write_all(request.as_bytes()).unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out
}

fn client_tls_config(trust_pem: &str) -> Arc<rustls::ClientConfig> {
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

/// CONNECT through the proxy, then speak TLS to whatever answers.
fn connect_tls(socket: &PathBuf, host: &str, port: u16, trust_pem: &str, request: &str) -> String {
    let mut s = UnixStream::connect(socket).unwrap();
    s.set_read_timeout(Some(std::time::Duration::from_secs(20)))
        .unwrap();
    write!(
        s,
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
    )
    .unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        s.read_exact(&mut b).unwrap();
        head.push(b[0]);
    }
    let head = String::from_utf8_lossy(&head).to_string();
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let cfg = client_tls_config(trust_pem);
    let name = rustls_pki_types::ServerName::try_from(host.to_string()).unwrap();
    let conn = rustls::ClientConnection::new(cfg, name).unwrap();
    let mut tls = rustls::StreamOwned::new(conn, s);
    tls.write_all(request.as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = tls.read_to_end(&mut out);
    String::from_utf8_lossy(&out).to_string()
}

#[test]
fn plain_http_is_forwarded_and_logged() {
    let origin = start_plain_origin();
    let p = start_proxy(Config::default(), &["127.0.0.1"], None);
    let out = raw(&p.socket, &format!("GET http://127.0.0.1:{}/hello HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n", origin.port(), origin.port()));
    assert!(out.contains("HTTP/1.1 200"), "{out}");
    assert!(out.contains("echo:GET /hello HTTP/1.1"), "{out}");
    let req = p.hooks.find("net.request").unwrap();
    assert_eq!(req["status"], 200);
    assert_eq!(req["inspected"], true);
}

#[test]
fn denied_host_gets_403_without_connecting() {
    let origin = start_plain_origin();
    let p = start_proxy(Config::default(), &["allowed.example"], None);
    let out = raw(
        &p.socket,
        &format!(
            "GET http://127.0.0.1:{}/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            origin.port()
        ),
    );
    assert!(out.starts_with("HTTP/1.1 403"), "{out}");
    assert!(out.contains("denied by policy"), "{out}");
    assert!(p.hooks.kinds().contains(&"net.deny".to_string()));
    assert!(!p.hooks.kinds().contains(&"net.request".to_string()));
}

#[test]
fn origin_form_requests_are_rejected() {
    let p = start_proxy(Config::default(), &[], None);
    let out = raw(
        &p.socket,
        "GET /x HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
    );
    assert!(out.starts_with("HTTP/1.1 400"), "{out}");
}

#[test]
fn dlp_blocks_secret_in_header_before_connecting() {
    let origin = start_plain_origin();
    let p = start_proxy(Config::default(), &["127.0.0.1"], None);
    let out = raw(&p.socket, &format!("GET http://127.0.0.1:{}/ HTTP/1.1\r\nHost: x\r\nAuthorization: token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij0\r\nConnection: close\r\n\r\n", origin.port()));
    assert!(out.starts_with("HTTP/1.1 403"), "{out}");
    assert!(out.contains("github_token"), "{out}");
    let block = p.hooks.find("dlp.block").unwrap();
    assert_eq!(block["detector"], "github_token");
    assert!(
        !block["sample"]
            .as_str()
            .unwrap()
            .contains("ABCDEFGHIJKLMNOP"),
        "sample leaks"
    );
    assert!(!p.hooks.kinds().contains(&"net.request".to_string()));
}

#[test]
fn dlp_blocks_secret_in_body_stream() {
    let origin = start_plain_origin();
    let p = start_proxy(Config::default(), &["127.0.0.1"], None);
    let body = "note=please keep AKIAIOSFODNN7EXAMPLE safe";
    let out = raw(&p.socket, &format!("POST http://127.0.0.1:{}/upload HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", origin.port(), body.len()));
    assert!(out.starts_with("HTTP/1.1 403"), "{out}");
    assert!(out.contains("aws_access_key_id"), "{out}");
}

#[test]
fn dlp_lets_clean_bodies_and_reports_jwts() {
    let origin = start_plain_origin();
    let p = start_proxy(Config::default(), &["127.0.0.1"], None);
    let body = "hello world, nothing secret here";
    let out = raw(&p.socket, &format!("POST http://127.0.0.1:{}/ HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJlLXNpZ25hdHVyZQ\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", origin.port(), body.len()));
    assert!(out.contains("HTTP/1.1 200"), "{out}");
    assert!(out.contains(body), "{out}");
    assert_eq!(p.hooks.find("dlp.report").unwrap()["detector"], "jwt");
}

#[test]
fn bound_secret_is_blocked_when_misrouted() {
    let origin = start_plain_origin();
    let key = "sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKE";
    let cfg = Config {
        dlp: DlpConfig {
            enabled: true,
            bound_secrets: vec![BoundSecret {
                name: "ANTHROPIC_API_KEY".into(),
                value: key.into(),
                domains: vec!["api.anthropic.com".into()],
            }],
            ..Default::default()
        },
        ..Config::default()
    };
    let p = start_proxy(cfg, &["127.0.0.1"], None);
    let out = raw(&p.socket, &format!("GET http://127.0.0.1:{}/ HTTP/1.1\r\nHost: x\r\nx-api-key: {key}\r\nConnection: close\r\n\r\n", origin.port()));
    assert!(out.starts_with("HTTP/1.1 403"), "{out}");
    assert!(
        out.contains("bound_secret_misrouted:ANTHROPIC_API_KEY"),
        "{out}"
    );
}

#[test]
fn connect_is_inspected_and_forwarded_over_tls() {
    let dir = tempfile::tempdir().unwrap();
    let (origin, origin_pem) = start_tls_origin(dir.path());
    let cfg = Config::default();
    let p = start_proxy(cfg, &["localhost"], Some(origin_pem));
    let ca_pem = p.state.ca_pem().to_string();
    let out = connect_tls(
        &p.socket,
        "localhost",
        origin.port(),
        &ca_pem,
        "GET /secure HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(out.contains("HTTP/1.1 200"), "{out}");
    assert!(out.contains("echo:GET /secure HTTP/1.1"), "{out}");
    let req = p.hooks.find("net.request").unwrap();
    assert_eq!(req["inspected"], true);
    assert_eq!(req["tls"], true);
}

#[test]
fn connect_inspection_blocks_secrets_inside_tls() {
    let dir = tempfile::tempdir().unwrap();
    let (origin, origin_pem) = start_tls_origin(dir.path());
    let cfg = Config::default();
    let p = start_proxy(cfg, &["localhost"], Some(origin_pem));
    let ca_pem = p.state.ca_pem().to_string();
    let body = "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKE\n-----END OPENSSH PRIVATE KEY-----";
    let out = connect_tls(&p.socket, "localhost", origin.port(), &ca_pem, &format!("POST /leak HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()));
    assert!(out.contains("HTTP/1.1 403"), "{out}");
    assert!(out.contains("private_key_pem"), "{out}");
}

#[test]
fn passthrough_hosts_are_tunnelled_unscanned() {
    let dir = tempfile::tempdir().unwrap();
    let (origin, origin_pem) = start_tls_origin(dir.path());
    let origin_pem_text = std::fs::read_to_string(&origin_pem).unwrap();
    let cfg = Config {
        passthrough: vec!["localhost".into()],
        ..Config::default()
    };
    let p = start_proxy(cfg, &["localhost"], Some(origin_pem));
    // The client trusts the origin's own certificate: no interception.
    let out = connect_tls(
        &p.socket,
        "localhost",
        origin.port(),
        &origin_pem_text,
        "GET /raw HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(out.contains("echo:GET /raw"), "{out}");
    let t = p.hooks.find("net.tunnel").unwrap();
    assert_eq!(t["inspected"], false);
    assert!(p.hooks.find("net.request").is_none());
}

#[test]
fn connect_to_denied_host_is_refused() {
    let p = start_proxy(Config::default(), &[], None);
    let out = raw(
        &p.socket,
        "CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n",
    );
    assert!(out.starts_with("HTTP/1.1 403"), "{out}");
}

#[test]
fn private_addresses_are_refused_unless_allowed() {
    let origin = start_plain_origin();
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("p.sock");
    let hooks = Arc::new(TestHooks {
        allow: vec!["127.0.0.1".into()],
        log: Mutex::new(Vec::new()),
    });
    let state = State::new(
        Config {
            allow_private: false,
            ..Config::default()
        },
        hooks.clone(),
    )
    .unwrap();
    let _h = agentkeep_proxy::spawn(
        state,
        std::os::unix::net::UnixListener::bind(&socket).unwrap(),
    )
    .unwrap();
    let out = raw(
        &socket,
        &format!(
            "GET http://127.0.0.1:{}/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            origin.port()
        ),
    );
    assert!(out.starts_with("HTTP/1.1 502"), "{out}");
    assert!(out.contains("non-public"), "{out}");
    let _ = TcpStream::connect(origin); // keep the origin thread alive until here
}

/// A plain origin that records every byte it is sent.
fn start_recording_origin() -> (SocketAddr, Arc<Mutex<Vec<u8>>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    thread::spawn(move || {
        for s in l.incoming().flatten() {
            let seen = Arc::clone(&record);
            thread::spawn(move || serve_echo(Recorder { inner: s, seen }));
        }
    });
    (addr, seen)
}

struct Recorder {
    inner: TcpStream,
    seen: Arc<Mutex<Vec<u8>>>,
}

impl Read for Recorder {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.seen.lock().unwrap().extend_from_slice(&buf[..n]);
        Ok(n)
    }
}

impl Write for Recorder {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// CONNECT, then send `payload` raw inside the tunnel and read to the end.
/// Returns the proxy's CONNECT response head and whatever followed.
fn connect_raw(socket: &PathBuf, host: &str, port: u16, payload: &[u8]) -> (String, String) {
    let mut s = UnixStream::connect(socket).unwrap();
    s.set_read_timeout(Some(std::time::Duration::from_secs(20)))
        .unwrap();
    write!(
        s,
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
    )
    .unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read_exact(&mut b).is_err() {
            break;
        }
        head.push(b[0]);
    }
    let _ = s.write_all(payload);
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    (
        String::from_utf8_lossy(&head).to_string(),
        String::from_utf8_lossy(&out).to_string(),
    )
}

#[test]
fn plaintext_http_inside_connect_is_scanned_on_any_port() {
    // Regression (N2): tunnels on ports other than 443/8443 used to be
    // relayed unscanned, so `CONNECT allowed.host:80` carried secrets past
    // the DLP layer.
    let (origin, seen) = start_recording_origin();
    let p = start_proxy(Config::default(), &["127.0.0.1"], None);
    let secret = "AKIAIOSFODNN7EXAMPLE";
    let (head, out) = connect_raw(
        &p.socket,
        "127.0.0.1",
        origin.port(),
        format!("GET /?k={secret} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(out.starts_with("HTTP/1.1 403"), "{out}");
    assert!(out.contains("aws_access_key_id"), "{out}");
    assert_eq!(p.hooks.find("dlp.block").unwrap()["location"], "url");
    let (_, out) = connect_raw(
        &p.socket,
        "127.0.0.1",
        origin.port(),
        b"GET /clean HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
    );
    assert!(out.contains("echo:GET /clean"), "{out}");
    let req = p.hooks.find("net.request").unwrap();
    assert_eq!(req["inspected"], true, "{req}");
    assert_eq!(req["tls"], false, "{req}");
    let seen = String::from_utf8_lossy(&seen.lock().unwrap()).to_string();
    assert!(seen.contains("GET /clean"), "{seen}");
    assert!(
        !seen.contains(secret),
        "origin received the secret:\n{seen}"
    );
}

#[test]
fn unscannable_tunnel_is_refused_unless_passthrough() {
    let (origin, seen) = start_recording_origin();
    let p = start_proxy(Config::default(), &["127.0.0.1"], None);
    let (head, out) = connect_raw(
        &p.socket,
        "127.0.0.1",
        origin.port(),
        b"\x00\x01opaque AKIAIOSFODNN7EXAMPLE",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(out.is_empty(), "{out}");
    let deny = p.hooks.find("net.deny").unwrap();
    assert!(
        deny["rule"]
            .as_str()
            .unwrap()
            .contains("neither TLS nor HTTP"),
        "{deny}"
    );
    assert!(seen.lock().unwrap().is_empty(), "origin was contacted");

    // The same bytes are tunnelled, and logged unscanned, for passthrough.
    let p = start_proxy(
        Config {
            passthrough: vec!["127.0.0.1".into()],
            ..Config::default()
        },
        &["127.0.0.1"],
        None,
    );
    let _ = connect_raw(
        &p.socket,
        "127.0.0.1",
        origin.port(),
        b"\x00\x01opaque\r\n\r\n",
    );
    assert_eq!(p.hooks.find("net.tunnel").unwrap()["inspected"], false);
}

#[test]
fn sniffing_classifies_first_bytes() {
    use agentkeep_proxy::server::{sniff, Sniffed};
    assert_eq!(sniff(0x16), Sniffed::Tls);
    for b in b"GPDHOCT" {
        assert_eq!(sniff(*b), Sniffed::Http);
    }
    for b in [0u8, 0x80, b'g', b'{', b'\r'] {
        assert_eq!(sniff(b), Sniffed::Other);
    }
}
