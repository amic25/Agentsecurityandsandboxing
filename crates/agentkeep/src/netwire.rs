//! Wiring between the policy, the approval channel and the egress proxy.

use std::collections::BTreeMap;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use agentkeep_policy::decide::{Compiled, Decision, Request};
use agentkeep_proxy::{BoundSecret, Config, DlpConfig, Hooks, State, Verdict};
use agentkeep_sandbox::ProxyPlan;
use anyhow::{Context, Result};

use crate::approval::Shared;
use crate::load::Loaded;

/// Loopback port the in-sandbox relay listens on.
pub const PROXY_PORT: u16 = 3128;
/// Where the proxy socket and CA bundle appear inside the sandbox.
pub const PROXY_SOCKET: &str = "/run/agentkeep/proxy.sock";
/// See [`PROXY_SOCKET`].
pub const CA_BUNDLE: &str = "/run/agentkeep/ca-bundle.pem";

/// Policy-backed hooks for the proxy.
pub struct PolicyHooks {
    compiled: Compiled,
    approval: Arc<Shared>,
}

impl Hooks for PolicyHooks {
    fn decide(&self, host: &str, port: u16) -> Verdict {
        match self.compiled.decide(&Request::Domain { host, port }) {
            Decision::Allow { rule } => Verdict::Allow { rule },
            Decision::Deny { rule } => Verdict::Deny { rule },
            Decision::Ask { rule, prompt } => Verdict::Ask { rule, prompt },
        }
    }

    fn ask(&self, prompt: &str, rule: &str) -> bool {
        self.approval.ask_human(prompt, rule)
    }

    fn log(&self, kind: &str, data: serde_json::Value) {
        self.approval.log(kind, data);
    }
}

/// Everything prepared before launch; the runtime starts after it.
pub struct Wiring {
    state: Arc<State>,
    listener: Option<UnixListener>,
    /// For the launch plan.
    pub plan: ProxyPlan,
}

impl Wiring {
    /// Start the proxy runtime. Call after the sandbox is launched so the
    /// supervisor is still single-threaded at clone time.
    pub fn start(&mut self) -> Result<agentkeep_proxy::ProxyHandle> {
        let listener = self.listener.take().context("proxy already started")?;
        agentkeep_proxy::spawn(Arc::clone(&self.state), listener).context("start proxy")
    }

    /// Summary for the audit log.
    pub fn describe(&self) -> serde_json::Value {
        let c = &self.state.config;
        serde_json::json!({
            "tls_inspect": c.tls_inspect,
            "passthrough": c.passthrough,
            "allow_private": c.allow_private,
            "dlp_enabled": c.dlp.enabled,
            "bound_secrets": c.dlp.bound_secrets.iter().map(|b| &b.name).collect::<Vec<_>>(),
            "port": PROXY_PORT,
        })
    }
}

/// Default destinations for well-known provider keys passed through `env.pass`
/// when the policy does not bind them explicitly.
fn inferred_domains(name: &str) -> Vec<String> {
    let list: &[&str] = match name {
        "ANTHROPIC_API_KEY" | "ANTHROPIC_AUTH_TOKEN" => &["api.anthropic.com"],
        "OPENAI_API_KEY" => &["api.openai.com"],
        "GEMINI_API_KEY" | "GOOGLE_API_KEY" => {
            &["generativelanguage.googleapis.com", "*.googleapis.com"]
        }
        "OPENROUTER_API_KEY" => &["openrouter.ai"],
        "GROQ_API_KEY" => &["api.groq.com"],
        "MISTRAL_API_KEY" => &["api.mistral.ai"],
        "DEEPSEEK_API_KEY" => &["api.deepseek.com"],
        "XAI_API_KEY" => &["api.x.ai"],
        "GH_TOKEN" | "GITHUB_TOKEN" => &[
            "api.github.com",
            "github.com",
            "*.github.com",
            "*.githubusercontent.com",
        ],
        "HF_TOKEN" | "HUGGING_FACE_HUB_TOKEN" => &["huggingface.co", "*.huggingface.co"],
        "NPM_TOKEN" => &["registry.npmjs.org"],
        _ => &[],
    };
    list.iter().map(ToString::to_string).collect()
}

/// Secrets passed to the agent become bound secrets for the DLP layer.
fn bound_secrets(loaded: &Loaded) -> Vec<BoundSecret> {
    loaded
        .policy
        .env_pass
        .iter()
        .filter_map(|name| {
            let value = std::env::var(name).ok()?;
            if value.len() < 8 {
                return None;
            }
            let domains = loaded
                .policy
                .dlp_provider_domains
                .get(name)
                .cloned()
                .unwrap_or_else(|| inferred_domains(name));
            Some(BoundSecret {
                name: name.clone(),
                value,
                domains,
            })
        })
        .collect()
}

/// The host's CA bundle, if one is where distributions put it.
pub fn system_ca_bundle() -> Option<PathBuf> {
    [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "/etc/ssl/cert.pem",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.is_file())
}

/// The DLP configuration for this session, shared by the proxy (which
/// blocks) and the audit log (which redacts).
pub fn dlp_config(loaded: &Loaded) -> DlpConfig {
    let policy = &loaded.policy;
    DlpConfig {
        enabled: policy.dlp_enabled,
        block_values: policy.dlp_block_values.clone(),
        bound_secrets: bound_secrets(loaded),
        report_only: policy.dlp_report_only.clone(),
    }
}

/// Create the CA, write the bundle, bind the socket. No threads yet.
pub fn prepare(loaded: &Loaded, scratch: &Path, approval: Arc<Shared>) -> Result<Wiring> {
    let policy = &loaded.policy;
    let config = Config {
        tls_inspect: policy.tls_inspect,
        passthrough: policy.passthrough.clone(),
        allow_private: policy.allow_private,
        trusted_cas: policy.trusted_cas.clone(),
        dlp: dlp_config(loaded),
        ..Config::default()
    };
    let hooks = Arc::new(PolicyHooks {
        compiled: loaded.compiled.clone(),
        approval,
    });
    let state = State::new(config, hooks).context("start egress proxy")?;

    // The bundle must contain the system roots too: SSL_CERT_FILE replaces
    // the default store for OpenSSL-based tools, and passthrough hosts
    // present real certificates.
    let mut bundle = system_ca_bundle()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_default();
    if !bundle.ends_with('\n') && !bundle.is_empty() {
        bundle.push('\n');
    }
    bundle.push_str("# agentkeep session CA (ephemeral; valid for this run only)\n");
    bundle.push_str(state.ca_pem());
    let ca_bundle_host = scratch.join("ca-bundle.pem");
    std::fs::write(&ca_bundle_host, bundle).context("write CA bundle")?;

    let host_socket = scratch.join("proxy.sock");
    let listener = UnixListener::bind(&host_socket)
        .with_context(|| format!("bind {}", host_socket.display()))?;

    Ok(Wiring {
        state,
        listener: Some(listener),
        plan: ProxyPlan {
            host_socket,
            sandbox_socket: PathBuf::from(PROXY_SOCKET),
            port: PROXY_PORT,
            ca_bundle_host,
            ca_bundle_sandbox: PathBuf::from(CA_BUNDLE),
        },
    })
}

/// Environment variables that point tools at the proxy and the CA bundle.
pub fn proxy_env(env: &mut BTreeMap<String, String>) {
    let url = format!("http://127.0.0.1:{PROXY_PORT}");
    for k in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        env.insert(k.into(), url.clone());
    }
    for k in ["NO_PROXY", "no_proxy"] {
        env.insert(k.into(), "localhost,127.0.0.1,::1".into());
    }
    for k in [
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
        "GIT_SSL_CAINFO",
        "DENO_CERT",
        "CARGO_HTTP_CAINFO",
        "NIX_SSL_CERT_FILE",
        "AWS_CA_BUNDLE",
        "PIP_CERT",
        "NPM_CONFIG_CAFILE",
    ] {
        env.insert(k.into(), CA_BUNDLE.into());
    }
    // Node's own store is separate from NODE_EXTRA_CA_CERTS; Bun and Deno
    // read SSL_CERT_FILE. Java needs a keystore and is documented as a gap.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_inference() {
        assert_eq!(
            inferred_domains("ANTHROPIC_API_KEY"),
            vec!["api.anthropic.com"]
        );
        assert!(inferred_domains("MY_RANDOM_SECRET").is_empty());
    }

    #[test]
    fn proxy_env_sets_everything() {
        let mut env = BTreeMap::new();
        proxy_env(&mut env);
        assert_eq!(env["HTTPS_PROXY"], "http://127.0.0.1:3128");
        assert_eq!(env["SSL_CERT_FILE"], CA_BUNDLE);
        assert!(env["NO_PROXY"].contains("localhost"));
    }
}
