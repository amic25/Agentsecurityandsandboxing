//! Fuzz what the proxy reads from the sandbox before it decides anything:
//! DLP scanning of arbitrary bytes (whole, and chunked through the
//! streaming window) and destination parsing and matching. Any panic is a
//! bug, and so is a secret the whole-buffer scan blocks but the streaming
//! scan lets through: that would be a DLP bypass by choosing chunk sizes.
#![no_main]

use std::sync::OnceLock;

use agentkeep_proxy::dlp::{Action, BodyScanner, Scanner};
use agentkeep_proxy::hosts::{is_non_public, pattern_matches, split_host_port};
use agentkeep_proxy::{BoundSecret, DlpConfig};
use libfuzzer_sys::fuzz_target;

fn scanner() -> &'static Scanner {
    static SCANNER: OnceLock<Scanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        Scanner::new(&DlpConfig {
            enabled: true,
            block_values: vec!["fuzz-block-value-0001".into()],
            bound_secrets: vec![BoundSecret {
                name: "ANTHROPIC_API_KEY".into(),
                value: "sk-ant-fuzz-fake-0000000000000000".into(),
                domains: vec!["api.anthropic.com".into(), "*.example.com:8443".into()],
            }],
            report_only: vec!["jwt".into()],
        })
    })
}

/// The redacted sample keeps at most four characters of the match.
fn assert_redacted(sample: &str) {
    let head = sample.split('…').next().unwrap_or_default();
    assert!(head.chars().count() <= 4, "sample too long: {sample:?}");
}

fuzz_target!(|data: &[u8]| {
    // The first byte picks the chunk size, so every split point is reachable.
    let Some((&first, rest)) = data.split_first() else {
        return;
    };
    let chunk = usize::from(first).max(1);

    // Destinations: authority, pattern and host separated by NUL.
    let text = String::from_utf8_lossy(rest);
    let mut fields = text.splitn(3, '\0');
    let authority = fields.next().unwrap_or_default();
    let pattern = fields.next().unwrap_or_default();
    let raw_host = fields.next().unwrap_or_default();
    let (host, port) =
        split_host_port(authority, 443).unwrap_or_else(|| ("api.anthropic.com".into(), 443));
    let _ = pattern_matches(pattern, raw_host, port);
    let _ = pattern_matches(pattern, &host, port);
    let _ = pattern_matches(authority, &host, port);
    if let Ok(ip) = host.parse() {
        let _ = is_non_public(ip);
    }

    // DLP: whole buffer, then the same bytes streamed in chunks.
    let scanner = scanner();
    let whole = scanner.scan(rest, &host, port, "body");
    if let Some(f) = &whole {
        assert_redacted(&f.sample);
    }
    let mut body = BodyScanner::new();
    let mut streamed_block = false;
    for piece in rest.chunks(chunk) {
        if let Some(f) = body.feed(scanner, piece, &host, port) {
            assert_redacted(&f.sample);
            streamed_block |= f.action == Action::Block;
        }
    }
    if whole.as_ref().is_some_and(|f| f.action == Action::Block) {
        assert!(
            streamed_block,
            "blocked as a whole but not when streamed in {chunk}-byte chunks: {whole:?}"
        );
    }
});
