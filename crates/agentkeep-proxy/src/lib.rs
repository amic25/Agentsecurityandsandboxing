//! The egress proxy.
//!
//! Every byte that leaves the sandbox passes through here. The proxy
//! listens on a Unix socket (bind-mounted into the sandbox, where a relay
//! exposes it as `127.0.0.1:port`), speaks HTTP/1.1 proxy protocol, and for
//! each destination asks the [`Hooks`] whether the host is allowed. Allowed
//! `CONNECT` tunnels are, by default, terminated with a per-session
//! certificate authority so the plaintext can be scanned for secrets before
//! it is re-encrypted to the origin. Names are resolved here, outside the
//! sandbox, and private address ranges are refused unless the policy says
//! otherwise.
//!
//! The proxy never decides policy itself: decisions, prompts and logging go
//! through [`Hooks`], so the crate stays independent of the policy format
//! and easy to test.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod ca;
pub mod dlp;
pub mod hosts;
// The proxy serves a Unix socket that is bind-mounted into the sandbox;
// there is no Windows sandbox to serve yet.
#[cfg(unix)]
pub mod server;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// The crate version, re-exported so the CLI can report component versions.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Answer to "may the sandbox talk to this host?".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Allowed.
    Allow {
        /// Rule that allowed it, for logs.
        rule: Option<String>,
    },
    /// Refused.
    Deny {
        /// Rule or reason.
        rule: String,
    },
    /// A human decides.
    Ask {
        /// Rule that asked.
        rule: String,
        /// Text for the human.
        prompt: String,
    },
}

/// What the embedding application supplies.
pub trait Hooks: Send + Sync + 'static {
    /// Policy decision for a destination.
    fn decide(&self, host: &str, port: u16) -> Verdict;
    /// Ask a human. May block; the proxy calls it off the async runtime.
    fn ask(&self, prompt: &str, rule: &str) -> bool;
    /// Record an event.
    fn log(&self, kind: &str, data: serde_json::Value);
}

/// A secret the sandbox is allowed to send, but only to certain hosts.
#[derive(Debug, Clone)]
pub struct BoundSecret {
    /// Name, for logs (never the value).
    pub name: String,
    /// The secret itself.
    pub value: String,
    /// Host patterns it may travel to (`host` or `*.suffix`). Empty means
    /// any allowed host.
    pub domains: Vec<String>,
}

/// Data-loss-protection settings.
#[derive(Debug, Clone, Default)]
pub struct DlpConfig {
    /// Master switch.
    pub enabled: bool,
    /// Literal values that must never leave.
    pub block_values: Vec<String>,
    /// Secrets with destination bindings.
    pub bound_secrets: Vec<BoundSecret>,
    /// Detector ids that only log instead of blocking.
    pub report_only: Vec<String>,
}

/// Proxy configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Terminate TLS and scan.
    pub tls_inspect: bool,
    /// Allowed hosts exempt from inspection.
    pub passthrough: Vec<String>,
    /// Ports on which a `CONNECT` tunnel is assumed to carry TLS and is
    /// terminated for inspection. Other ports are tunnelled unscanned.
    pub inspect_ports: Vec<u16>,
    /// Permit destinations in private, loopback and link-local ranges.
    pub allow_private: bool,
    /// Extra PEM files whose certificates are trusted for origins.
    pub trusted_cas: Vec<PathBuf>,
    /// DLP.
    pub dlp: DlpConfig,
    /// Maximum concurrent connections accepted.
    pub max_connections: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tls_inspect: true,
            passthrough: Vec::new(),
            inspect_ports: vec![443, 8443],
            allow_private: false,
            trusted_cas: Vec::new(),
            dlp: DlpConfig {
                enabled: true,
                ..DlpConfig::default()
            },
            max_connections: 1024,
        }
    }
}

/// Errors from starting the proxy.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Certificate authority setup failed.
    #[error("certificate authority: {0}")]
    Ca(String),
    /// TLS configuration failed.
    #[error("tls: {0}")]
    Tls(String),
    /// A trusted CA file could not be read.
    #[error("trusted CA {path}: {message}")]
    TrustedCa {
        /// The file.
        path: PathBuf,
        /// Why.
        message: String,
    },
    /// Runtime or socket failure.
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// Remembered answers to `Ask` verdicts for the session.
#[derive(Debug, Default)]
pub struct AskCache {
    answers: Mutex<HashMap<String, bool>>,
}

#[cfg_attr(not(unix), allow(dead_code))] // used by the Unix-only server
impl AskCache {
    fn get(&self, host: &str) -> Option<bool> {
        self.answers.lock().ok()?.get(host).copied()
    }

    fn put(&self, host: &str, allowed: bool) {
        if let Ok(mut g) = self.answers.lock() {
            g.insert(host.to_string(), allowed);
        }
    }
}

/// Shared state for one proxy instance.
pub struct State {
    /// Configuration.
    pub config: Config,
    /// Embedding hooks.
    pub hooks: Arc<dyn Hooks>,
    /// Session CA and leaf cache.
    pub ca: Arc<ca::Authority>,
    /// Server-side TLS config (minting resolver).
    pub server_tls: Arc<rustls::ServerConfig>,
    /// Client-side TLS config for origins.
    pub client_tls: Arc<rustls::ClientConfig>,
    /// Compiled DLP scanner, if enabled.
    pub scanner: Option<Arc<dlp::Scanner>>,
    /// Remembered `Ask` answers.
    pub asked: AskCache,
}

impl State {
    /// Build the shared state. Generates the session CA.
    pub fn new(config: Config, hooks: Arc<dyn Hooks>) -> Result<Arc<Self>, Error> {
        let ca = Arc::new(ca::Authority::generate()?);
        let server_tls = ca.server_config()?;
        let client_tls = ca::client_config(&config.trusted_cas)?;
        let scanner = config
            .dlp
            .enabled
            .then(|| Arc::new(dlp::Scanner::new(&config.dlp)));
        Ok(Arc::new(Self {
            config,
            hooks,
            ca,
            server_tls,
            client_tls,
            scanner,
            asked: AskCache::default(),
        }))
    }

    /// The session CA certificate, PEM encoded, for the sandbox's trust store.
    pub fn ca_pem(&self) -> &str {
        self.ca.cert_pem()
    }
}

#[cfg(unix)]
/// Run the accept loop until the listener errors. Call inside a tokio
/// runtime. The listener is a std socket so it can be bound before any
/// thread exists and bind-mounted before the sandbox starts.
pub async fn serve(
    state: Arc<State>,
    listener: std::os::unix::net::UnixListener,
) -> std::io::Result<()> {
    listener.set_nonblocking(true)?;
    let listener = tokio::net::UnixListener::from_std(listener)?;
    let permits = Arc::new(tokio::sync::Semaphore::new(state.config.max_connections));
    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = Arc::clone(&permits).acquire_owned().await else {
            break Ok(());
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            server::handle_connection(state, stream).await;
            drop(permit);
        });
    }
}

#[cfg(unix)]
/// Start the proxy on a dedicated thread with its own multi-threaded runtime.
/// Returns once the runtime is up; the proxy runs until the process exits or
/// the returned handle is dropped.
pub fn spawn(
    state: Arc<State>,
    listener: std::os::unix::net::UnixListener,
) -> Result<ProxyHandle, Error> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("agentkeep-proxy")
        .build()?;
    let hooks = Arc::clone(&state.hooks);
    runtime.spawn(async move {
        if let Err(e) = serve(state, listener).await {
            hooks.log("proxy.error", serde_json::json!({ "error": e.to_string() }));
        }
    });
    Ok(ProxyHandle {
        runtime: Some(runtime),
    })
}

/// Keeps the proxy runtime alive; dropping it stops the proxy.
pub struct ProxyHandle {
    runtime: Option<tokio::runtime::Runtime>,
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        if let Some(rt) = self.runtime.take() {
            // Do not wait for in-flight connections: the sandbox is gone.
            rt.shutdown_timeout(std::time::Duration::from_millis(200));
        }
    }
}
