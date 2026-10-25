//! The per-session certificate authority (threat model N6).
//!
//! A fresh CA key pair is generated for every `agentkeep run` and lives only
//! in this process's memory; the sandbox receives the certificate, never the
//! key. Leaf certificates for inspected hosts are minted on first use and
//! cached for the session.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::Error;

/// The session CA.
pub struct Authority {
    issuer: CertifiedIssuer<'static, KeyPair>,
    cert_pem: String,
    leaves: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl std::fmt::Debug for Authority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authority").finish_non_exhaustive()
    }
}

impl Authority {
    /// Generate a new CA.
    pub fn generate() -> Result<Self, Error> {
        let key = KeyPair::generate().map_err(|e| Error::Ca(e.to_string()))?;
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "agentkeep session CA (ephemeral)");
        dn.push(DnType::OrganizationName, "agentkeep");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let issuer =
            CertifiedIssuer::self_signed(params, key).map_err(|e| Error::Ca(e.to_string()))?;
        let cert_pem = issuer.pem();
        Ok(Self {
            issuer,
            cert_pem,
            leaves: Mutex::new(HashMap::new()),
        })
    }

    /// CA certificate in PEM form.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Mint (or fetch) a leaf certificate for `host`.
    pub fn leaf_for(&self, host: &str) -> Result<Arc<CertifiedKey>, Error> {
        if let Some(k) = self.leaves.lock().ok().and_then(|g| g.get(host).cloned()) {
            return Ok(k);
        }
        let key = KeyPair::generate().map_err(|e| Error::Ca(e.to_string()))?;
        let mut params =
            CertificateParams::new(vec![host.to_string()]).map_err(|e| Error::Ca(e.to_string()))?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params
            .signed_by(&key, &self.issuer)
            .map_err(|e| Error::Ca(e.to_string()))?;
        let chain = vec![cert.der().clone(), self.issuer.der().clone()];
        let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let signing = rustls::crypto::ring::sign::any_supported_type(&private)
            .map_err(|e| Error::Tls(e.to_string()))?;
        let certified = Arc::new(CertifiedKey::new(chain, signing));
        if let Ok(mut g) = self.leaves.lock() {
            g.insert(host.to_string(), Arc::clone(&certified));
        }
        Ok(certified)
    }

    /// Server configuration that mints a certificate for whatever SNI the
    /// client sends. HTTP/1.1 only, so clients inside the tunnel never
    /// negotiate HTTP/2 we would then have to parse.
    pub fn server_config(self: &Arc<Self>) -> Result<Arc<rustls::ServerConfig>, Error> {
        let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Tls(e.to_string()))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Minter {
            ca: Arc::clone(self),
        }));
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(cfg))
    }
}

#[derive(Debug)]
struct Minter {
    ca: Arc<Authority>,
}

impl ResolvesServerCert for Minter {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let host = client_hello.server_name()?;
        self.ca.leaf_for(host).ok()
    }
}

/// Client configuration for connecting to origins: the Mozilla root set
/// plus any extra PEM bundles the policy trusts.
pub fn client_config(extra: &[impl AsRef<Path>]) -> Result<Arc<rustls::ClientConfig>, Error> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for path in extra {
        let path = path.as_ref();
        let pem = std::fs::read(path).map_err(|e| Error::TrustedCa {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;
        let mut added = 0;
        for cert in rustls_pki_types::pem::PemObject::pem_slice_iter(&pem) {
            let cert: CertificateDer<'static> = cert.map_err(|e| Error::TrustedCa {
                path: path.to_path_buf(),
                message: e.to_string(),
            })?;
            roots.add(cert).map_err(|e| Error::TrustedCa {
                path: path.to_path_buf(),
                message: e.to_string(),
            })?;
            added += 1;
        }
        if added == 0 {
            return Err(Error::TrustedCa {
                path: path.to_path_buf(),
                message: "no certificates found".into(),
            });
        }
    }
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| Error::Tls(e.to_string()))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_mints_cached_leaves() {
        let ca = Arc::new(Authority::generate().unwrap());
        assert!(ca.cert_pem().starts_with("-----BEGIN CERTIFICATE-----"));
        let a = ca.leaf_for("api.example.com").unwrap();
        let b = ca.leaf_for("api.example.com").unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(a.cert.len(), 2, "leaf plus CA");
        let _ = ca.server_config().unwrap();
    }

    #[test]
    fn client_config_rejects_bad_ca_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.pem");
        std::fs::write(&p, "not a cert").unwrap();
        assert!(client_config(&[&p]).is_err());
        let none: [&Path; 0] = [];
        assert!(client_config(&none).is_ok());
    }
}
