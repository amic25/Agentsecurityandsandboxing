//! Connection handling: proxy requests, `CONNECT` tunnels, forwarding.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::{
    HeaderName, CONNECTION, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, UPGRADE,
};
use http::{Method, Request, Response, StatusCode, Uri};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming};
use hyper::service::service_fn;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::dlp::{Action, BodyScanner, Finding};
use crate::hosts::{is_non_public, pattern_matches, split_host_port};
use crate::{State, Verdict};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type OutBody = BoxBody<Bytes, BoxError>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

fn text_response(status: StatusCode, text: impl Into<Bytes>) -> Response<OutBody> {
    let body = Full::new(text.into())
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .header("x-agentkeep", "1")
        .body(body)
        .unwrap_or_else(|_| {
            Response::new(
                Full::new(Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
        })
}

/// Serve one client connection from the Unix socket.
pub async fn handle_connection(state: Arc<State>, stream: tokio::net::UnixStream) {
    let io = TokioIo::new(stream);
    let svc = service_fn(move |req| {
        let state = Arc::clone(&state);
        async move { Ok::<_, std::convert::Infallible>(outer_request(state, req).await) }
    });
    let conn = hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(false)
        .serve_connection(io, svc)
        .with_upgrades();
    let _ = conn.await;
}

async fn outer_request(state: Arc<State>, req: Request<Incoming>) -> Response<OutBody> {
    if req.method() == Method::CONNECT {
        return handle_connect(state, req).await;
    }
    let Some(authority) = req.uri().authority().map(|a| a.as_str().to_string()) else {
        return text_response(
            StatusCode::BAD_REQUEST,
            "agentkeep: this is a proxy; requests must use absolute-form URLs or CONNECT\n",
        );
    };
    let https = req.uri().scheme_str() == Some("https");
    let Some((host, port)) = split_host_port(&authority, if https { 443 } else { 80 }) else {
        return text_response(StatusCode::BAD_REQUEST, "agentkeep: bad authority\n");
    };
    if let Err(resp) = authorize(&state, &host, port).await {
        return resp;
    }
    forward(state, req, host, port, https, false).await
}

/// Allow, or produce the 403 that explains why not.
async fn authorize(state: &Arc<State>, host: &str, port: u16) -> Result<(), Response<OutBody>> {
    let verdict = state.hooks.decide(host, port);
    let (allowed, rule) = match verdict {
        Verdict::Allow { rule } => (true, rule.unwrap_or_default()),
        Verdict::Deny { rule } => (false, rule),
        Verdict::Ask { rule, prompt } => {
            if let Some(cached) = state.asked.get(host) {
                (cached, format!("{rule} (remembered)"))
            } else {
                let hooks = Arc::clone(&state.hooks);
                let (p, r) = (prompt.clone(), rule.clone());
                hooks.log(
                    "approval.request",
                    serde_json::json!({ "prompt": p, "rule": r, "host": host, "port": port }),
                );
                let answer = tokio::task::spawn_blocking(move || hooks.ask(&p, &r))
                    .await
                    .unwrap_or(false);
                state.hooks.log(
                    "approval.response",
                    serde_json::json!({ "rule": rule, "approved": answer, "host": host }),
                );
                state.asked.put(host, answer);
                (answer, rule)
            }
        }
    };
    if allowed {
        return Ok(());
    }
    state.hooks.log(
        "net.deny",
        serde_json::json!({ "host": host, "port": port, "rule": rule }),
    );
    Err(text_response(
        StatusCode::FORBIDDEN,
        format!("agentkeep: connection to {host}:{port} denied by policy ({rule})\n"),
    ))
}

fn is_passthrough(state: &State, host: &str, port: u16) -> bool {
    state
        .config
        .passthrough
        .iter()
        .any(|p| pattern_matches(p, host, port))
}

async fn handle_connect(state: Arc<State>, mut req: Request<Incoming>) -> Response<OutBody> {
    let Some(authority) = req.uri().authority().map(|a| a.as_str().to_string()) else {
        return text_response(
            StatusCode::BAD_REQUEST,
            "agentkeep: CONNECT needs host:port\n",
        );
    };
    let Some((host, port)) = split_host_port(&authority, 443) else {
        return text_response(
            StatusCode::BAD_REQUEST,
            "agentkeep: bad CONNECT authority\n",
        );
    };
    if let Err(mut resp) = authorize(&state, &host, port).await {
        // A refused tunnel has nothing further to say on this connection.
        resp.headers_mut()
            .insert(CONNECTION, http::HeaderValue::from_static("close"));
        return resp;
    }
    // What the tunnel carries is decided by its first bytes, not by the
    // port: a port list let `CONNECT allowed.host:80` plus plaintext HTTP,
    // or TLS on any port but 443/8443, leave without a scan (N2).
    let inspect = state.config.tls_inspect && !is_passthrough(&state, &host, port);
    let on_upgrade = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                let io = TokioIo::new(upgraded);
                if inspect {
                    sniffed_tunnel(state, io, host, port).await;
                } else {
                    passthrough_tunnel(state, io, host, port).await;
                }
            }
            Err(e) => state.hooks.log(
                "proxy.error",
                serde_json::json!({ "error": format!("upgrade: {e}") }),
            ),
        }
    });
    text_response(StatusCode::OK, "")
}

async fn passthrough_tunnel<C>(state: Arc<State>, mut client: C, host: String, port: u16)
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let mut origin = match connect_origin(&state, &host, port).await {
        Ok(s) => s,
        Err(e) => {
            state.hooks.log(
                "net.error",
                serde_json::json!({ "host": host, "port": port, "error": e }),
            );
            return;
        }
    };
    state.hooks.log(
        "net.tunnel",
        serde_json::json!({ "host": host, "port": port, "inspected": false }),
    );
    let result = tokio::io::copy_bidirectional(&mut client, &mut origin).await;
    let (up, down) = result.unwrap_or((0, 0));
    state.hooks.log("net.tunnel.end", serde_json::json!({ "host": host, "port": port, "bytes_out": up, "bytes_in": down, "inspected": false }));
}

/// What the first byte of a tunnel says it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sniffed {
    /// A TLS handshake record: terminate and inspect.
    Tls,
    /// An HTTP/1 request line (method tokens are upper-case ASCII): scan
    /// it like any plain request. Anything else that starts this way is
    /// rejected by the HTTP parser, which is the fail-closed outcome.
    Http,
    /// Neither: cannot be scanned.
    Other,
}

/// Classify a tunnel by its first byte.
pub fn sniff(first: u8) -> Sniffed {
    match first {
        0x16 => Sniffed::Tls,
        b'A'..=b'Z' => Sniffed::Http,
        _ => Sniffed::Other,
    }
}

/// How long a client may stay silent after `200 Connection established`.
/// Server-speaks-first protocols cannot be classified and need passthrough.
const SNIFF_TIMEOUT: Duration = Duration::from_secs(10);

/// An inspected tunnel: TLS is terminated, plaintext HTTP is scanned, and
/// anything else is refused, because forwarding bytes the scanner cannot
/// read would be a silent DLP bypass. Hosts that need other protocols go
/// in `network.passthrough`, where the audit log says they were unscanned.
async fn sniffed_tunnel<C>(state: Arc<State>, mut client: C, host: String, port: u16)
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut first = vec![0u8; 4096];
    let n = match tokio::time::timeout(SNIFF_TIMEOUT, client.read(&mut first)).await {
        Ok(Ok(0) | Err(_)) => return,
        Ok(Ok(n)) => n,
        Err(_) => {
            refuse_tunnel(
                &state,
                &host,
                port,
                "client sent nothing; server-first protocols cannot be inspected",
            );
            return;
        }
    };
    first.truncate(n);
    let kind = sniff(first[0]);
    let client = Rewind::new(Bytes::from(first), client);
    match kind {
        Sniffed::Tls => inspect_tunnel(state, client, host, port).await,
        Sniffed::Http => {
            let svc = service_fn(move |req| {
                let state = Arc::clone(&state);
                let host = host.clone();
                async move {
                    Ok::<_, std::convert::Infallible>(
                        forward(state, req, host, port, false, true).await,
                    )
                }
            });
            let conn = hyper::server::conn::http1::Builder::new()
                .preserve_header_case(true)
                .serve_connection(TokioIo::new(client), svc)
                .with_upgrades();
            let _ = conn.await;
        }
        Sniffed::Other => refuse_tunnel(
            &state,
            &host,
            port,
            "tunnel carries neither TLS nor HTTP and cannot be scanned",
        ),
    }
}

fn refuse_tunnel(state: &State, host: &str, port: u16, why: &str) {
    state.hooks.log(
        "net.deny",
        serde_json::json!({
            "host": host, "port": port,
            "rule": format!("{why}; list the host in network.passthrough to tunnel it unscanned"),
        }),
    );
}

/// A stream with bytes already read from it put back in front.
struct Rewind<S> {
    prefix: Bytes,
    inner: S,
}

impl<S> Rewind<S> {
    fn new(prefix: Bytes, inner: S) -> Self {
        Self { prefix, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Rewind<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.prefix.is_empty() {
            let n = this.prefix.len().min(buf.remaining());
            buf.put_slice(&this.prefix.split_to(n));
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Rewind<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

async fn inspect_tunnel<C>(state: Arc<State>, client: C, host: String, port: u16)
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let acceptor = TlsAcceptor::from(Arc::clone(&state.server_tls));
    let tls = match acceptor.accept(client).await {
        Ok(t) => t,
        Err(e) => {
            state.hooks.log("net.error", serde_json::json!({ "host": host, "port": port, "error": format!("tls accept: {e}"), "hint": "client may pin certificates; add the host to network.passthrough" }));
            return;
        }
    };
    let svc = service_fn(move |req| {
        let state = Arc::clone(&state);
        let host = host.clone();
        async move {
            Ok::<_, std::convert::Infallible>(forward(state, req, host, port, true, true).await)
        }
    });
    let conn = hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .serve_connection(TokioIo::new(tls), svc)
        .with_upgrades();
    let _ = conn.await;
}

/// Resolve and connect, refusing non-public addresses unless allowed. If
/// *any* address is non-public the whole name is refused, which defeats
/// DNS rebinding.
async fn connect_origin(state: &State, host: &str, port: u16) -> Result<TcpStream, String> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("resolve {host}: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("resolve {host}: no addresses"));
    }
    if !state.config.allow_private {
        if let Some(a) = addrs.iter().find(|a| is_non_public(a.ip())) {
            return Err(format!(
                "{host} resolves to non-public address {}; set network.allow_private to permit",
                a.ip()
            ));
        }
    }
    let mut last = String::new();
    for addr in addrs {
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                return Ok(s);
            }
            Ok(Err(e)) => last = e.to_string(),
            Err(_) => last = "connect timed out".into(),
        }
    }
    Err(format!("connect {host}:{port}: {last}"))
}

/// Hop-by-hop headers that must not be forwarded.
fn strip_hop_by_hop(headers: &mut http::HeaderMap) {
    for name in [PROXY_AUTHORIZATION, PROXY_AUTHENTICATE] {
        headers.remove(name);
    }
    if let Ok(pc) = HeaderName::from_bytes(b"proxy-connection") {
        headers.remove(pc);
    }
    // Keep `Connection: Upgrade` for WebSockets; drop plain keep-alive hints.
    let is_upgrade = headers
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().contains("upgrade"));
    if !is_upgrade {
        headers.remove(CONNECTION);
    }
}

fn dlp_block_response(state: &State, host: &str, port: u16, f: &Finding) -> Response<OutBody> {
    state.hooks.log("dlp.block", serde_json::json!({
        "host": host, "port": port, "detector": f.detector, "location": f.location, "sample": f.sample,
    }));
    text_response(
        StatusCode::FORBIDDEN,
        format!(
            "agentkeep: request to {host} blocked: outbound secret detected ({} in {})\n",
            f.detector, f.location
        ),
    )
}

#[allow(clippy::too_many_lines)]
async fn forward(
    state: Arc<State>,
    req: Request<Incoming>,
    host: String,
    port: u16,
    tls: bool,
    in_tunnel: bool,
) -> Response<OutBody> {
    let method = req.method().clone();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map_or_else(|| "/".to_string(), |p| p.as_str().to_string());
    let path_only = req.uri().path().to_string();

    // Secrets in the request line or headers never reach the origin.
    if let Some(scanner) = &state.scanner {
        if let Some(f) = scanner.scan(path_and_query.as_bytes(), &host, port, "url") {
            match f.action {
                Action::Block => return dlp_block_response(&state, &host, port, &f),
                Action::Report => state.hooks.log("dlp.report", serde_json::json!({ "host": host, "detector": f.detector, "location": f.location })),
            }
        }
        for (name, value) in req.headers() {
            if let Some(f) = scanner.scan(value.as_bytes(), &host, port, &format!("header:{name}"))
            {
                match f.action {
                    Action::Block => return dlp_block_response(&state, &host, port, &f),
                    Action::Report => state.hooks.log("dlp.report", serde_json::json!({ "host": host, "detector": f.detector, "location": f.location })),
                }
            }
        }
    }

    let (mut parts, body) = req.into_parts();
    let client_upgrade = parts.extensions.remove::<OnUpgrade>();
    let wants_upgrade = parts.headers.contains_key(UPGRADE);
    strip_hop_by_hop(&mut parts.headers);
    if !parts.headers.contains_key(HOST) {
        let value = if (tls && port == 443) || (!tls && port == 80) {
            host.clone()
        } else {
            format!("{host}:{port}")
        };
        if let Ok(v) = http::HeaderValue::from_str(&value) {
            parts.headers.insert(HOST, v);
        }
    }
    let uri: Uri = match path_and_query.parse() {
        Ok(u) => u,
        Err(_) => return text_response(StatusCode::BAD_REQUEST, "agentkeep: bad request target\n"),
    };
    let blocked = Arc::new(Mutex::new(None::<Finding>));
    let scanned = ScannedBody {
        inner: body,
        scanner: state.scanner.clone(),
        window: BodyScanner::new(),
        host: host.clone(),
        port,
        blocked: Arc::clone(&blocked),
    };
    let mut out = Request::builder().method(parts.method.clone()).uri(uri);
    if let Some(h) = out.headers_mut() {
        *h = parts.headers.clone();
    }
    let out = match out.body(scanned) {
        Ok(r) => r,
        Err(e) => return text_response(StatusCode::BAD_REQUEST, format!("agentkeep: {e}\n")),
    };

    // Connect to the origin.
    let tcp = match connect_origin(&state, &host, port).await {
        Ok(s) => s,
        Err(e) => {
            state.hooks.log(
                "net.error",
                serde_json::json!({ "host": host, "port": port, "error": e }),
            );
            return text_response(StatusCode::BAD_GATEWAY, format!("agentkeep: {e}\n"));
        }
    };
    let response = if tls {
        let Ok(server_name) = rustls_pki_types::ServerName::try_from(host.clone()) else {
            return text_response(StatusCode::BAD_REQUEST, "agentkeep: invalid server name\n");
        };
        let connector = TlsConnector::from(Arc::clone(&state.client_tls));
        match connector.connect(server_name, tcp).await {
            Ok(stream) => send(out, TokioIo::new(stream)).await,
            Err(e) => {
                state.hooks.log("net.error", serde_json::json!({ "host": host, "port": port, "error": format!("tls to origin: {e}") }));
                return text_response(
                    StatusCode::BAD_GATEWAY,
                    format!("agentkeep: TLS to {host} failed: {e}\n"),
                );
            }
        }
    } else {
        send(out, TokioIo::new(tcp)).await
    };

    let mut response = match response {
        Ok(r) => r,
        Err(e) => {
            if let Some(f) = blocked.lock().ok().and_then(|g| g.clone()) {
                return dlp_block_response(&state, &host, port, &f);
            }
            state.hooks.log(
                "net.error",
                serde_json::json!({ "host": host, "port": port, "error": e.to_string() }),
            );
            return text_response(
                StatusCode::BAD_GATEWAY,
                format!("agentkeep: upstream error: {e}\n"),
            );
        }
    };

    state.hooks.log(
        "net.request",
        serde_json::json!({
            "host": host, "port": port, "method": method.as_str(), "path": path_only,
            "status": response.status().as_u16(), "inspected": in_tunnel || !tls, "tls": tls,
        }),
    );

    if response.status() == StatusCode::SWITCHING_PROTOCOLS && wants_upgrade {
        let origin_upgrade = hyper::upgrade::on(&mut response);
        if let Some(client_upgrade) = client_upgrade {
            let st = Arc::clone(&state);
            let h = host.clone();
            tokio::spawn(async move {
                match (client_upgrade.await, origin_upgrade.await) {
                    (Ok(c), Ok(o)) => {
                        let (mut c, mut o) = (TokioIo::new(c), TokioIo::new(o));
                        st.hooks.log("net.tunnel", serde_json::json!({ "host": h, "port": port, "inspected": false, "protocol": "upgrade" }));
                        let r = tokio::io::copy_bidirectional(&mut c, &mut o)
                            .await
                            .unwrap_or((0, 0));
                        st.hooks.log("net.tunnel.end", serde_json::json!({ "host": h, "port": port, "bytes_out": r.0, "bytes_in": r.1, "inspected": false }));
                    }
                    _ => st.hooks.log(
                        "net.error",
                        serde_json::json!({ "host": h, "error": "upgrade failed" }),
                    ),
                }
            });
        }
    }
    response.map(|b| b.map_err(|e| Box::new(e) as BoxError).boxed())
}

async fn send<I>(req: Request<ScannedBody>, io: I) -> Result<Response<Incoming>, BoxError>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .preserve_header_case(true)
        .handshake(io)
        .await?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    Ok(sender.send_request(req).await?)
}

/// A request body that scans every chunk before it is forwarded and fails
/// the stream the moment a blocked secret appears.
struct ScannedBody {
    inner: Incoming,
    scanner: Option<Arc<crate::dlp::Scanner>>,
    window: BodyScanner,
    host: String,
    port: u16,
    blocked: Arc<Mutex<Option<Finding>>>,
}

impl Body for ScannedBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let (Some(scanner), Some(data)) = (&this.scanner, frame.data_ref()) {
                    if let Some(f) = this.window.feed(scanner, data, &this.host, this.port) {
                        if f.action == Action::Block {
                            if let Ok(mut g) = this.blocked.lock() {
                                *g = Some(f);
                            }
                            return Poll::Ready(Some(Err("blocked by agentkeep DLP".into())));
                        }
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(Box::new(e)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}
