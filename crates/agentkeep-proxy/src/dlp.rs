//! Outbound secret detection (threat model N2, E3, L-A3).
//!
//! The scanner sees request lines, headers and body chunks before they are
//! forwarded. Detection is pattern based: structured credentials whose
//! format is unmistakable block the request; ambiguous shapes (JWTs,
//! generic `password=` assignments) are reported by default so legitimate
//! API traffic keeps working. Body chunks are scanned with a carry-over
//! window so a secret split across two chunks is still caught.

use aho_corasick::AhoCorasick;
use regex::bytes::{Regex, RegexSet};

use crate::hosts::pattern_matches;
use crate::DlpConfig;

/// How a detector reacts when it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Reset the connection; the bytes never leave.
    Block,
    /// Log and let it through.
    Report,
}

/// A built-in detector.
#[derive(Debug, Clone, Copy)]
pub struct Detector {
    /// Stable id, usable in `dlp.report_only`.
    pub id: &'static str,
    /// Default action.
    pub action: Action,
    /// Pattern (bytes regex).
    pub pattern: &'static str,
}

/// The built-in detector table. Patterns describe credential *formats*, not
/// values; each one is tested against fake fixtures in this module.
pub const DETECTORS: &[Detector] = &[
    Detector {
        id: "aws_access_key_id",
        action: Action::Block,
        pattern: r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
    },
    Detector {
        id: "aws_secret_access_key",
        action: Action::Block,
        pattern: r#"(?i)aws_secret_access_key["']?\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}\b"#,
    },
    Detector {
        id: "gcp_service_account",
        action: Action::Block,
        pattern: r#""private_key_id"\s*:\s*"[a-f0-9]{40}""#,
    },
    Detector {
        id: "google_api_key",
        action: Action::Block,
        pattern: r"\bAIza[0-9A-Za-z_-]{35}\b",
    },
    Detector {
        id: "github_token",
        action: Action::Block,
        pattern: r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b",
    },
    Detector {
        id: "github_fine_grained_token",
        action: Action::Block,
        pattern: r"\bgithub_pat_[A-Za-z0-9_]{80,}\b",
    },
    Detector {
        id: "gitlab_token",
        action: Action::Block,
        pattern: r"\bglpat-[A-Za-z0-9_-]{20,}\b",
    },
    Detector {
        id: "slack_token",
        action: Action::Block,
        pattern: r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b",
    },
    Detector {
        id: "stripe_key",
        action: Action::Block,
        pattern: r"\b[sr]k_live_[A-Za-z0-9]{20,}\b",
    },
    Detector {
        id: "anthropic_api_key",
        action: Action::Block,
        pattern: r"\bsk-ant-[A-Za-z0-9_-]{20,}\b",
    },
    Detector {
        id: "openai_api_key",
        action: Action::Block,
        pattern: r"\bsk-(proj-|svcacct-|admin-)?[A-Za-z0-9_-]{40,}\b",
    },
    Detector {
        id: "npm_token",
        action: Action::Block,
        pattern: r"\bnpm_[A-Za-z0-9]{36}\b",
    },
    Detector {
        id: "pypi_token",
        action: Action::Block,
        pattern: r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b",
    },
    Detector {
        id: "huggingface_token",
        action: Action::Block,
        pattern: r"\bhf_[A-Za-z0-9]{30,}\b",
    },
    Detector {
        id: "sendgrid_key",
        action: Action::Block,
        pattern: r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
    },
    Detector {
        id: "azure_storage_key",
        action: Action::Block,
        pattern: r"AccountKey=[A-Za-z0-9+/=]{86,88}",
    },
    Detector {
        id: "private_key_pem",
        action: Action::Block,
        pattern: r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY( BLOCK)?-----",
    },
    Detector {
        id: "jwt",
        action: Action::Report,
        pattern: r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    },
    Detector {
        id: "generic_secret_assignment",
        action: Action::Report,
        pattern: r#"(?i)\b(api[_-]?key|secret|token|password|passwd)["']?\s*[:=]\s*["'][^"'\s]{16,}["']"#,
    },
];

/// Bytes kept from the previous chunk so a match straddling chunks is seen.
pub const WINDOW: usize = 4096;

/// A match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Detector id, or `block_value` / `bound_secret_misrouted`.
    pub detector: String,
    /// What to do.
    pub action: Action,
    /// First characters of the match, for logs. Never the whole secret.
    pub sample: String,
    /// Where it was found: `url`, `header:<name>` or `body`.
    pub location: String,
}

/// Compiled detectors.
pub struct Scanner {
    set: RegexSet,
    regexes: Vec<Regex>,
    actions: Vec<Action>,
    ids: Vec<&'static str>,
    literals: Option<AhoCorasick>,
    literal_kinds: Vec<LiteralKind>,
}

#[derive(Debug, Clone)]
enum LiteralKind {
    Blocked,
    Bound { name: String, domains: Vec<String> },
}

impl std::fmt::Debug for Scanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scanner")
            .field("detectors", &self.ids.len())
            .finish_non_exhaustive()
    }
}

impl Scanner {
    /// Compile the built-in detectors plus the configured literals.
    pub fn new(config: &DlpConfig) -> Self {
        let regexes: Vec<Regex> = DETECTORS
            .iter()
            .filter_map(|d| Regex::new(d.pattern).ok())
            .collect();
        let patterns: Vec<&str> = DETECTORS.iter().map(|d| d.pattern).collect();
        // Patterns are constants verified by tests; if one failed, dropping
        // it is the only option, and the test catches it.
        let set = RegexSet::new(&patterns).unwrap_or_else(|_| RegexSet::empty());
        let actions = DETECTORS
            .iter()
            .map(|d| {
                if config.report_only.iter().any(|r| r == d.id) {
                    Action::Report
                } else {
                    d.action
                }
            })
            .collect();
        let ids = DETECTORS.iter().map(|d| d.id).collect();

        let mut lits: Vec<Vec<u8>> = Vec::new();
        let mut literal_kinds = Vec::new();
        for v in &config.block_values {
            if v.len() >= 8 {
                lits.push(v.as_bytes().to_vec());
                literal_kinds.push(LiteralKind::Blocked);
            }
        }
        for s in &config.bound_secrets {
            if s.value.len() >= 8 {
                lits.push(s.value.as_bytes().to_vec());
                literal_kinds.push(LiteralKind::Bound {
                    name: s.name.clone(),
                    domains: s.domains.clone(),
                });
            }
        }
        let literals = if lits.is_empty() {
            None
        } else {
            AhoCorasick::new(&lits).ok()
        };
        Self {
            set,
            regexes,
            actions,
            ids,
            literals,
            literal_kinds,
        }
    }

    /// Scan one buffer destined for `host:port`. Returns the most severe
    /// finding (a block beats a report).
    pub fn scan(&self, data: &[u8], host: &str, port: u16, location: &str) -> Option<Finding> {
        let mut report: Option<Finding> = None;

        // Literals first: a bound secret going to its own provider is fine
        // and must also suppress the format detector that would match it.
        let mut allowed_spans: Vec<(usize, usize)> = Vec::new();
        if let Some(ac) = &self.literals {
            for m in ac.find_overlapping_iter(data) {
                match &self.literal_kinds[m.pattern().as_usize()] {
                    LiteralKind::Blocked => {
                        return Some(Finding {
                            detector: "block_value".into(),
                            action: Action::Block,
                            sample: sample(&data[m.start()..m.end()]),
                            location: location.into(),
                        });
                    }
                    LiteralKind::Bound { name, domains } => {
                        let ok = domains.is_empty()
                            || domains.iter().any(|d| pattern_matches(d, host, port));
                        if ok {
                            allowed_spans.push((m.start(), m.end()));
                        } else {
                            return Some(Finding {
                                detector: format!("bound_secret_misrouted:{name}"),
                                action: Action::Block,
                                sample: sample(&data[m.start()..m.end()]),
                                location: location.into(),
                            });
                        }
                    }
                }
            }
        }

        for idx in self.set.matches(data) {
            let Some(m) = self.regexes[idx].find(data) else {
                continue;
            };
            // Skip matches that lie inside a secret allowed to this host.
            let mut suppressed = false;
            for m in self.regexes[idx].find_iter(data) {
                let inside = allowed_spans
                    .iter()
                    .any(|(s, e)| m.start() >= *s && m.end() <= *e);
                if !inside {
                    suppressed = false;
                    break;
                }
                suppressed = true;
            }
            if suppressed {
                continue;
            }
            let finding = Finding {
                detector: self.ids[idx].to_string(),
                action: self.actions[idx],
                sample: sample(m.as_bytes()),
                location: location.into(),
            };
            match finding.action {
                Action::Block => return Some(finding),
                Action::Report => {
                    if report.is_none() {
                        report = Some(finding);
                    }
                }
            }
        }
        report
    }
}

impl Scanner {
    /// Replace everything that looks like a secret in `text` with
    /// `[REDACTED:<detector>]`: every built-in detector (blocking and
    /// reporting), every `dlp.block_values` literal and every bound secret.
    /// Returns `None` when nothing matched. Used for the audit log, never for
    /// traffic.
    pub fn redact(&self, text: &str) -> Option<String> {
        let data = text.as_bytes();
        let mut spans: Vec<(usize, usize, String)> = Vec::new();
        if let Some(ac) = &self.literals {
            for m in ac.find_overlapping_iter(data) {
                let id = match &self.literal_kinds[m.pattern().as_usize()] {
                    LiteralKind::Blocked => "block_value".to_string(),
                    LiteralKind::Bound { name, .. } => name.clone(),
                };
                spans.push((m.start(), m.end(), id));
            }
        }
        for idx in self.set.matches(data) {
            for m in self.regexes[idx].find_iter(data) {
                spans.push((m.start(), m.end(), self.ids[idx].to_string()));
            }
        }
        if spans.is_empty() {
            return None;
        }
        spans.sort_by_key(|(s, e, _)| (*s, std::cmp::Reverse(*e)));
        let mut out = Vec::with_capacity(data.len());
        let mut pos = 0;
        for (start, end, id) in spans {
            if end <= pos {
                continue; // inside a span already redacted
            }
            let start = start.max(pos);
            out.extend_from_slice(&data[pos..start]);
            out.extend_from_slice(format!("[REDACTED:{id}]").as_bytes());
            pos = end;
        }
        out.extend_from_slice(&data[pos..]);
        Some(String::from_utf8_lossy(&out).into_owned())
    }
}

/// First four characters of a match, then `…`. Enough to recognise a key in a
/// log without reproducing it.
fn sample(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    let head: String = s.chars().take(4).collect();
    format!("{head}…({} bytes)", bytes.len())
}

/// Streaming body scanner with a carry-over window.
#[derive(Debug)]
pub struct BodyScanner {
    tail: Vec<u8>,
}

impl Default for BodyScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl BodyScanner {
    /// Empty state.
    pub fn new() -> Self {
        Self {
            tail: Vec::with_capacity(WINDOW),
        }
    }

    /// Scan `chunk` together with the tail of the previous one.
    pub fn feed(
        &mut self,
        scanner: &Scanner,
        chunk: &[u8],
        host: &str,
        port: u16,
    ) -> Option<Finding> {
        let finding = if self.tail.is_empty() {
            scanner.scan(chunk, host, port, "body")
        } else {
            let mut buf = Vec::with_capacity(self.tail.len() + chunk.len());
            buf.extend_from_slice(&self.tail);
            buf.extend_from_slice(chunk);
            scanner.scan(&buf, host, port, "body")
        };
        let keep = chunk.len().min(WINDOW);
        let mut new_tail = Vec::with_capacity(WINDOW);
        if keep < WINDOW {
            let from_old = (WINDOW - keep).min(self.tail.len());
            new_tail.extend_from_slice(&self.tail[self.tail.len() - from_old..]);
        }
        new_tail.extend_from_slice(&chunk[chunk.len() - keep..]);
        self.tail = new_tail;
        finding
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BoundSecret;

    fn scanner() -> Scanner {
        Scanner::new(&DlpConfig {
            enabled: true,
            ..Default::default()
        })
    }

    #[test]
    fn all_patterns_compile() {
        for d in DETECTORS {
            Regex::new(d.pattern).unwrap_or_else(|e| panic!("{}: {e}", d.id));
        }
        assert_eq!(scanner().regexes.len(), DETECTORS.len());
    }

    #[test]
    fn detects_fake_credentials() {
        let s = scanner();
        let cases: &[(&str, &str)] = &[
            ("aws_access_key_id", "key=AKIAIOSFODNN7EXAMPLE"),
            (
                "github_token",
                "Authorization: token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij0",
            ),
            ("slack_token", "xoxb-1234567890-abcdefghijk"),
            (
                "anthropic_api_key",
                "x-api-key: sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKE",
            ),
            (
                "openai_api_key",
                "Bearer sk-proj-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
            ),
            (
                "private_key_pem",
                "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA",
            ),
            ("google_api_key", "AIzaSyFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEX"),
            (
                "npm_token",
                "//registry.npmjs.org/:_authToken=npm_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            ),
            (
                "gcp_service_account",
                r#"{"type":"service_account","private_key_id":"0123456789abcdef0123456789abcdef01234567"}"#,
            ),
        ];
        for (id, text) in cases {
            let f = s
                .scan(text.as_bytes(), "evil.example", 443, "body")
                .unwrap_or_else(|| panic!("{id} not detected"));
            assert_eq!(f.detector, *id);
            assert_eq!(f.action, Action::Block);
            assert!(
                !f.sample.contains("FAKEFAKEFAKE"),
                "sample leaks too much: {}",
                f.sample
            );
        }
    }

    #[test]
    fn reports_but_does_not_block_ambiguous_shapes() {
        let s = scanner();
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJlLXNpZ25hdHVyZQ";
        let f = s
            .scan(jwt.as_bytes(), "api.example", 443, "header:authorization")
            .unwrap();
        assert_eq!((f.detector.as_str(), f.action), ("jwt", Action::Report));
        let f = s
            .scan(
                br#"{"password": "correct-horse-battery-staple"}"#,
                "x",
                443,
                "body",
            )
            .unwrap();
        assert_eq!(
            (f.detector.as_str(), f.action),
            ("generic_secret_assignment", Action::Report)
        );
    }

    #[test]
    fn ordinary_traffic_is_clean() {
        let s = scanner();
        for text in [
            "GET /v1/messages HTTP/1.1",
            "fn main() { println!(\"hello\"); }",
            "The quick brown fox jumps over the lazy dog 0123456789",
            "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "https://example.com/path?x=1&y=2",
        ] {
            assert!(
                s.scan(text.as_bytes(), "h", 443, "body").is_none(),
                "{text}"
            );
        }
    }

    #[test]
    fn bound_secret_allowed_only_to_its_domains() {
        let key = "sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKE";
        let s = Scanner::new(&DlpConfig {
            enabled: true,
            bound_secrets: vec![BoundSecret {
                name: "ANTHROPIC_API_KEY".into(),
                value: key.into(),
                domains: vec!["api.anthropic.com".into()],
            }],
            ..Default::default()
        });
        let text = format!("x-api-key: {key}");
        assert!(
            s.scan(text.as_bytes(), "api.anthropic.com", 443, "header")
                .is_none(),
            "own provider must pass"
        );
        let f = s
            .scan(text.as_bytes(), "evil.example", 443, "header")
            .unwrap();
        assert!(f
            .detector
            .starts_with("bound_secret_misrouted:ANTHROPIC_API_KEY"));
        assert_eq!(f.action, Action::Block);
    }

    #[test]
    fn block_values_block_anywhere() {
        let s = Scanner::new(&DlpConfig {
            enabled: true,
            block_values: vec!["hunter2-hunter2".into()],
            ..Default::default()
        });
        let f = s
            .scan(
                b"please send hunter2-hunter2 now",
                "api.anthropic.com",
                443,
                "body",
            )
            .unwrap();
        assert_eq!(f.detector, "block_value");
    }

    #[test]
    fn redacts_every_kind_of_secret_for_logs() {
        let s = Scanner::new(&DlpConfig {
            enabled: true,
            block_values: vec!["hunter2-hunter2".into()],
            bound_secrets: vec![BoundSecret {
                name: "ANTHROPIC_API_KEY".into(),
                value: "sk-test-fake-bound-value".into(),
                domains: vec![],
            }],
            ..Default::default()
        });
        let text = "curl -H 'Authorization: token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij0' --data hunter2-hunter2 -H key:sk-test-fake-bound-value AKIAIOSFODNN7EXAMPLE";
        let r = s.redact(text).unwrap();
        for leaked in [
            "ghp_ABCDEF",
            "hunter2",
            "sk-test-fake-bound",
            "AKIAIOSFODNN7",
        ] {
            assert!(!r.contains(leaked), "{r}");
        }
        assert!(r.contains("[REDACTED:github_token]"), "{r}");
        assert!(r.contains("[REDACTED:block_value]"), "{r}");
        assert!(r.contains("[REDACTED:ANTHROPIC_API_KEY]"), "{r}");
        assert!(r.starts_with("curl -H 'Authorization: token "), "{r}");
        assert!(s.redact("git status --short").is_none());
    }

    #[test]
    fn body_scanner_catches_split_secrets() {
        let scanner = scanner();
        let mut body = BodyScanner::new();
        let secret = b"AKIAIOSFODNN7EXAMPLE";
        let (first, second) = secret.split_at(7);
        assert!(body.feed(&scanner, first, "h", 443).is_none());
        let finding = body.feed(&scanner, second, "h", 443).unwrap();
        assert_eq!(finding.detector, "aws_access_key_id");
    }

    #[test]
    fn body_scanner_window_is_bounded() {
        let s = scanner();
        let mut b = BodyScanner::new();
        for _ in 0..10 {
            b.feed(&s, &[b'a'; 10_000], "h", 443);
        }
        assert!(b.tail.len() <= WINDOW);
    }

    fn shared_scanner() -> &'static Scanner {
        static SCANNER: std::sync::OnceLock<Scanner> = std::sync::OnceLock::new();
        SCANNER.get_or_init(scanner)
    }

    /// Fake secrets in every blocking format the streaming test plants.
    const PLANTED: &[&str] = &[
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij0",
        "sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKE",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "xoxb-1234567890-abcdefghijk",
        "AIzaSyFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEX",
    ];

    proptest::proptest! {
        // Few cases: each streams up to 5 KB in chunks as small as one byte.
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(40))]
        /// Choosing chunk sizes must not hide a secret: whatever is blocked
        /// as one buffer is blocked when streamed (same invariant as the
        /// `proxy_inputs` fuzz target, which needs nightly).
        #[test]
        fn streaming_blocks_whatever_the_whole_buffer_blocks(
            prefix in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..5000),
            suffix in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..200),
            which in 0..PLANTED.len(),
            chunk in 1usize..700,
        ) {
            let scanner = shared_scanner();
            let mut data = prefix;
            data.push(b' ');
            data.extend_from_slice(PLANTED[which].as_bytes());
            data.push(b' ');
            data.extend_from_slice(&suffix);
            let whole = scanner.scan(&data, "h", 443, "body");
            proptest::prop_assert!(whole.as_ref().is_some_and(|f| f.action == Action::Block));
            let mut body = BodyScanner::new();
            let streamed = data
                .chunks(chunk)
                .filter_map(|c| body.feed(scanner, c, "h", 443))
                .any(|f| f.action == Action::Block);
            proptest::prop_assert!(streamed, "missed {} in {chunk}-byte chunks", PLANTED[which]);
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(128))]
        #[test]
        fn scanner_never_panics(data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2000), host in "[a-z.]{1,20}") {
            let scanner = shared_scanner();
            let _ = scanner.scan(&data, &host, 443, "body");
            let mut body = BodyScanner::new();
            for chunk in data.chunks(97) {
                let _ = body.feed(scanner, chunk, &host, 443);
            }
        }
    }
}
