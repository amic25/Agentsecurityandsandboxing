//! `detect.json_path`, `detect.yaml_path`, `detect.toml_path`: parse a file,
//! select values with a small path language and test them with predicates.
//!
//! # Parsing
//!
//! - JSON: `serde_json` (recursion limit 128). If strict parsing fails, the
//!   file is parsed again with `//` and `/* */` comments and trailing commas
//!   blanked out, because VS Code and other agent configs are JSONC.
//! - YAML: `serde-saphyr` into `serde_json::Value`, every document of the
//!   stream, with a budget: at most 4 MiB, nesting depth 64, bounded alias
//!   replay (alias bombs fail), bounded node and event counts. Duplicate keys
//!   keep the last value, as most consumers do.
//! - TOML: the `toml` crate (recursion limit 80), datetimes as strings.
//!
//! A file that does not parse yields no match; the engine records the parse
//! error once per file in the report's `errors`.
//!
//! # Paths
//!
//! `$` is the root, `.key` an object member, `["key with spaces"]` the same
//! with any key, `[N]` an array element, `[*]` every array element, `.*`
//! every object value, `..key` every member named `key` at any depth
//! (including directly under the current value).
//!
//! # Predicates
//!
//! Exactly one of `equals: <value>`, `matches: <regex>` (string values),
//! `contains: <value>` (substring of a string, or an equal array element),
//! `exists: true`, `is_true: true`, `any_element_matches: <regex>` (some
//! string element of an array), or the combinators `all: [..]`, `any: [..]`,
//! `not: {..}`.
//!
//! # Locations
//!
//! Parsers here do not keep positions, so a match is located in the text
//! heuristically: walk the concrete path's keys forward through the text
//! (each key searched after the previous one, as a key token followed by
//! `:`, `=`, `.` or `]`), then search for the matched scalar's literal text
//! (quoted, single-quoted or bare) after the last key. For `contains` and
//! `any_element_matches` the matching array element is what is located.
//! If the scalar is not found the key is reported; if no key is found
//! either, line 1.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::ops::Range;

use serde::{Deserialize, Deserializer};
use serde_json::Value;

use super::{Input, Match};
use crate::text::{escape_truncated, LineIndex};

/// YAML documents larger than this are refused before parsing.
pub(crate) const MAX_YAML_BYTES: usize = 4 * 1024 * 1024;

/// A path that fans out further than this stops collecting results.
const MAX_RESULTS: usize = 10_000;

/// Locating a match costs a search through the text, so a detector stops
/// one past the engine's per-rule cap (the engine reports the truncation).
const MAX_MATCHES: usize = crate::engine::MAX_FINDINGS_PER_RULE + 1;

/// A scalar is searched for at most this far after its key; beyond that
/// the key is reported instead.
const SCALAR_WINDOW: usize = 256 * 1024;

/// Values in messages are cut to this many characters.
const MAX_VALUE_CHARS: usize = 100;

/// Which parser a structured detector uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Format {
    Json,
    Yaml,
    Toml,
}

/// The serde-saphyr options every YAML parse in the scanner uses, rule files
/// included: bounded depth, aliases, nodes and documents, no snippets in
/// errors (they would copy hostile text into messages).
pub(crate) fn yaml_options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        budget: serde_saphyr::budget! {
            max_depth: 64,
            max_aliases: 10_000,
            max_anchors: 10_000,
            max_nodes: 250_000,
            max_events: 1_000_000,
            max_documents: 1_024,
            max_total_scalar_bytes: 16 * 1024 * 1024,
            max_merge_keys: 1_000,
        },
        alias_limits: serde_saphyr::alias_limits! {
            max_total_replayed_events: 50_000,
            max_replay_stack_depth: 16,
        },
        duplicate_keys: serde_saphyr::options::DuplicateKeyPolicy::LastWins,
        non_finite_float_policy: serde_saphyr::options::NonFiniteFloatPolicy::AsString,
        with_snippet: false,
    }
}

pub(crate) fn parse_yaml(text: &str) -> Result<Vec<Value>, String> {
    if text.len() > MAX_YAML_BYTES {
        return Err(format!(
            "document is {} bytes, larger than the {} byte limit",
            text.len(),
            MAX_YAML_BYTES
        ));
    }
    serde_saphyr::from_str_multiple_with_options::<Value, Vec<Value>>(text, yaml_options())
        .map_err(|e| e.to_string())
}

pub(crate) fn parse_json(text: &str) -> Result<Value, String> {
    let body = text.strip_prefix('\u{feff}').unwrap_or(text);
    match serde_json::from_str::<Value>(body) {
        Ok(v) => Ok(v),
        Err(strict) => {
            let relaxed = strip_jsonc(body);
            serde_json::from_str::<Value>(&relaxed).map_err(|_| strict.to_string())
        }
    }
}

pub(crate) fn parse_toml(text: &str) -> Result<Value, String> {
    let body = text.strip_prefix('\u{feff}').unwrap_or(text);
    let table: toml::Table = toml::from_str(body).map_err(|e| {
        let message = e.message().trim().to_owned();
        match e.span() {
            Some(span) => {
                let pos = LineIndex::new(body).position(body, span.start);
                format!("line {}, column {}: {message}", pos.line, pos.column)
            }
            None => message,
        }
    })?;
    Ok(toml_table(&table))
}

fn toml_table(table: &toml::Table) -> Value {
    Value::Object(
        table
            .iter()
            .map(|(k, v)| (k.clone(), toml_value(v)))
            .collect(),
    )
}

// Recursion is bounded by the toml parser's own nesting limit.
fn toml_value(v: &toml::Value) -> Value {
    match v {
        toml::Value::String(s) => Value::String(s.clone()),
        toml::Value::Integer(i) => Value::from(*i),
        toml::Value::Float(f) => serde_json::Number::from_f64(*f)
            .map_or_else(|| Value::String(f.to_string()), Value::Number),
        toml::Value::Boolean(b) => Value::Bool(*b),
        toml::Value::Datetime(d) => Value::String(d.to_string()),
        toml::Value::Array(items) => Value::Array(items.iter().map(toml_value).collect()),
        toml::Value::Table(t) => toml_table(t),
    }
}

/// Blank out JSONC comments and trailing commas without moving any byte, so
/// offsets stay valid. Every replaced byte becomes an ASCII space (newlines
/// are kept), so the result is valid UTF-8 whenever the input is.
fn strip_jsonc(text: &str) -> String {
    let mut out = text.as_bytes().to_vec();
    let len = out.len();
    let mut i = 0;
    let mut in_string = false;
    while i < len {
        let b = out[i];
        if in_string {
            match b {
                b'\\' => i += 1,
                b'"' => in_string = false,
                _ => {}
            }
            i += 1;
            continue;
        }
        match (b, out.get(i + 1).copied()) {
            (b'"', _) => {
                in_string = true;
                i += 1;
            }
            (b'/', Some(b'/')) => {
                while i < len && out[i] != b'\n' {
                    out[i] = b' ';
                    i += 1;
                }
            }
            (b'/', Some(b'*')) => {
                out[i] = b' ';
                out[i + 1] = b' ';
                i += 2;
                while i < len {
                    if out[i] == b'*' && out.get(i + 1) == Some(&b'/') {
                        out[i] = b' ';
                        out[i + 1] = b' ';
                        i += 2;
                        break;
                    }
                    if out[i] != b'\n' {
                        out[i] = b' ';
                    }
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    // Trailing commas: a comma followed only by whitespace before } or ].
    let mut in_string = false;
    let mut i = 0;
    while i < len {
        let b = out[i];
        if in_string {
            match b {
                b'\\' => i += 1,
                b'"' => in_string = false,
                _ => {}
            }
        } else if b == b'"' {
            in_string = true;
        } else if b == b',' {
            let next = out[i + 1..].iter().find(|c| !c.is_ascii_whitespace());
            if matches!(next, Some(b'}' | b']')) {
                out[i] = b' ';
            }
        }
        i += 1;
    }
    String::from_utf8(out).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Paths

/// One step of a path expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Segment {
    Key(String),
    Index(usize),
    AnyElement,
    AnyValue,
    Descend(String),
}

/// One step of a concrete location in a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Step {
    Key(String),
    Index(usize),
}

/// A parsed path expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JsonPath {
    segments: Vec<Segment>,
}

impl JsonPath {
    pub(crate) fn parse(src: &str) -> Result<Self, String> {
        let err = |msg: &str| format!("path `{src}`: {msg}");
        let Some(mut rest) = src.strip_prefix('$') else {
            return Err(err("must start with `$`"));
        };
        let mut segments = Vec::new();
        while !rest.is_empty() {
            if let Some(r) = rest.strip_prefix("..") {
                let (key, r) = if r.starts_with('[') {
                    let (seg, r) = parse_bracket(r).map_err(|m| err(&m))?;
                    match seg {
                        Segment::Key(k) => (k, r),
                        _ => return Err(err("`..` must be followed by a key")),
                    }
                } else if r.starts_with('*') {
                    return Err(err("recursive wildcard `..*` is not supported"));
                } else {
                    parse_name(r).map_err(|m| err(&m))?
                };
                segments.push(Segment::Descend(key));
                rest = r;
            } else if let Some(r) = rest.strip_prefix('.') {
                if let Some(r) = r.strip_prefix('*') {
                    segments.push(Segment::AnyValue);
                    rest = r;
                } else {
                    let (key, r) = parse_name(r).map_err(|m| err(&m))?;
                    segments.push(Segment::Key(key));
                    rest = r;
                }
            } else if rest.starts_with('[') {
                let (seg, r) = parse_bracket(rest).map_err(|m| err(&m))?;
                segments.push(seg);
                rest = r;
            } else {
                let c = rest.chars().next().unwrap_or(' ');
                return Err(err(&format!(
                    "unexpected `{c}` at offset {}",
                    src.len() - rest.len()
                )));
            }
        }
        Ok(Self { segments })
    }

    /// Every value the path selects, with its concrete location, in
    /// document order (object keys sorted). Results are de-duplicated.
    pub(crate) fn evaluate<'v>(&self, root: &'v Value) -> Vec<(Vec<Step>, &'v Value)> {
        let mut current: Vec<(Vec<Step>, &'v Value)> = vec![(Vec::new(), root)];
        for segment in &self.segments {
            let mut next: Vec<(Vec<Step>, &'v Value)> = Vec::new();
            let mut seen: HashSet<usize> = HashSet::new();
            let mut push =
                |steps: Vec<Step>, v: &'v Value, next: &mut Vec<(Vec<Step>, &'v Value)>| {
                    if next.len() < MAX_RESULTS && seen.insert(std::ptr::from_ref(v).addr()) {
                        next.push((steps, v));
                    }
                };
            for (steps, value) in &current {
                match (segment, value) {
                    (Segment::Key(k), Value::Object(map)) => {
                        if let Some(child) = map.get(k) {
                            push(with(steps, Step::Key(k.clone())), child, &mut next);
                        }
                    }
                    (Segment::Index(i), Value::Array(items)) => {
                        if let Some(child) = items.get(*i) {
                            push(with(steps, Step::Index(*i)), child, &mut next);
                        }
                    }
                    (Segment::AnyElement, Value::Array(items)) => {
                        for (i, child) in items.iter().enumerate() {
                            push(with(steps, Step::Index(i)), child, &mut next);
                        }
                    }
                    (Segment::AnyValue, Value::Object(map)) => {
                        for (k, child) in map {
                            push(with(steps, Step::Key(k.clone())), child, &mut next);
                        }
                    }
                    (Segment::Descend(key), _) => {
                        // Explicit stack: documents are depth-limited by the
                        // parsers, but this keeps the walk iterative anyway.
                        let mut stack: Vec<(Vec<Step>, &'v Value)> = vec![(steps.clone(), value)];
                        while let Some((path, node)) = stack.pop() {
                            if next.len() >= MAX_RESULTS {
                                break;
                            }
                            match node {
                                Value::Object(map) => {
                                    if let Some(child) = map.get(key) {
                                        push(with(&path, Step::Key(key.clone())), child, &mut next);
                                    }
                                    for (k, child) in map.iter().rev() {
                                        stack.push((with(&path, Step::Key(k.clone())), child));
                                    }
                                }
                                Value::Array(items) => {
                                    for (i, child) in items.iter().enumerate().rev() {
                                        stack.push((with(&path, Step::Index(i)), child));
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
                if next.len() >= MAX_RESULTS {
                    break;
                }
            }
            current = next;
        }
        current
    }
}

fn with(steps: &[Step], step: Step) -> Vec<Step> {
    let mut out = Vec::with_capacity(steps.len() + 1);
    out.extend_from_slice(steps);
    out.push(step);
    out
}

fn parse_name(r: &str) -> Result<(String, &str), String> {
    let end = r
        .find(|c: char| c.is_whitespace() || matches!(c, '.' | '[' | ']' | '"' | '\'' | '*'))
        .unwrap_or(r.len());
    if end == 0 {
        return Err("expected a key name".into());
    }
    Ok((r[..end].to_owned(), &r[end..]))
}

/// Parse `[*]`, `[N]`, `["key"]` or `['key']` at the start of `r`.
fn parse_bracket(r: &str) -> Result<(Segment, &str), String> {
    let inner = r.strip_prefix('[').ok_or("expected `[`")?;
    if let Some(rest) = inner.strip_prefix("*]") {
        return Ok((Segment::AnyElement, rest));
    }
    if let Some(quote) = inner.chars().next().filter(|c| *c == '"' || *c == '\'') {
        let mut key = String::new();
        let mut chars = inner[1..].char_indices();
        while let Some((i, c)) = chars.next() {
            match c {
                '\\' => match chars.next() {
                    Some((_, 'n')) => key.push('\n'),
                    Some((_, 't')) => key.push('\t'),
                    Some((_, e)) => key.push(e),
                    None => return Err("unterminated escape in quoted key".into()),
                },
                c if c == quote => {
                    let after = &inner[1 + i + 1..];
                    let rest = after
                        .strip_prefix(']')
                        .ok_or("expected `]` after quoted key")?;
                    return Ok((Segment::Key(key), rest));
                }
                c => key.push(c),
            }
        }
        return Err("unterminated quoted key".into());
    }
    let end = inner.find(']').ok_or("expected `]`")?;
    let index: usize = inner[..end]
        .parse()
        .map_err(|_| format!("`[{}]` is not `[*]`, `[N]` or a quoted key", &inner[..end]))?;
    Ok((Segment::Index(index), &inner[end + 1..]))
}

fn render_path(steps: &[Step]) -> String {
    let mut out = String::from("$");
    for step in steps {
        match step {
            Step::Key(k) => {
                let plain = !k.is_empty()
                    && k.chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                    && k.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
                if plain {
                    out.push('.');
                    out.push_str(k);
                } else {
                    out.push('[');
                    out.push_str(&serde_json::to_string(k).unwrap_or_default());
                    out.push(']');
                }
            }
            Step::Index(i) => {
                let _ = write!(out, "[{i}]");
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Predicates

/// A predicate as written in a rule.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PredicateSpec {
    #[serde(default, deserialize_with = "present")]
    equals: Option<Value>,
    matches: Option<String>,
    #[serde(default, deserialize_with = "present")]
    contains: Option<Value>,
    exists: Option<bool>,
    is_true: Option<bool>,
    any_element_matches: Option<String>,
    all: Option<Vec<PredicateSpec>>,
    any: Option<Vec<PredicateSpec>>,
    not: Option<Box<PredicateSpec>>,
}

/// Keep an explicit `null` as `Some(Null)` instead of "absent".
fn present<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}

/// A compiled predicate.
#[derive(Debug)]
pub(crate) enum Predicate {
    Equals(Value),
    Matches(::regex::Regex),
    Contains(Value),
    Exists,
    IsTrue,
    AnyElementMatches(::regex::Regex),
    All(Vec<Predicate>),
    Any(Vec<Predicate>),
    Not(Box<Predicate>),
}

impl PredicateSpec {
    pub(crate) fn compile(self) -> Result<Predicate, String> {
        let set = [
            ("equals", self.equals.is_some()),
            ("matches", self.matches.is_some()),
            ("contains", self.contains.is_some()),
            ("exists", self.exists.is_some()),
            ("is_true", self.is_true.is_some()),
            ("any_element_matches", self.any_element_matches.is_some()),
            ("all", self.all.is_some()),
            ("any", self.any.is_some()),
            ("not", self.not.is_some()),
        ];
        let named: Vec<&str> = set.iter().filter(|(_, s)| *s).map(|(n, _)| *n).collect();
        if named.len() != 1 {
            return Err(format!(
                "predicate needs exactly one of equals, matches, contains, exists, is_true, \
                 any_element_matches, all, any, not (found: {})",
                if named.is_empty() {
                    "none".to_owned()
                } else {
                    named.join(", ")
                }
            ));
        }
        let regex = |p: &str, what: &str| {
            super::regex::compile(p, false).map_err(|e| format!("predicate.{what}: {e}"))
        };
        let list = |items: Vec<PredicateSpec>, what: &str| {
            if items.is_empty() {
                return Err(format!("predicate.{what} needs at least one predicate"));
            }
            items
                .into_iter()
                .map(PredicateSpec::compile)
                .collect::<Result<Vec<_>, _>>()
        };
        Ok(if let Some(v) = self.equals {
            Predicate::Equals(v)
        } else if let Some(p) = self.matches {
            Predicate::Matches(regex(&p, "matches")?)
        } else if let Some(v) = self.contains {
            Predicate::Contains(v)
        } else if let Some(flag) = self.exists {
            if !flag {
                return Err(
                    "predicate.exists only supports `true`; select the parent and use \
                            `not` on a member instead"
                        .into(),
                );
            }
            Predicate::Exists
        } else if let Some(flag) = self.is_true {
            if !flag {
                return Err("predicate.is_true only supports `true`; use `equals: false`".into());
            }
            Predicate::IsTrue
        } else if let Some(p) = self.any_element_matches {
            Predicate::AnyElementMatches(regex(&p, "any_element_matches")?)
        } else if let Some(items) = self.all {
            Predicate::All(list(items, "all")?)
        } else if let Some(items) = self.any {
            Predicate::Any(list(items, "any")?)
        } else if let Some(inner) = self.not {
            Predicate::Not(Box::new(inner.compile()?))
        } else {
            return Err("predicate: nothing to test".into());
        })
    }
}

/// A predicate hit. `element` names the array element that made it true,
/// for `contains` and `any_element_matches`, so that element is located.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Hit {
    pub(crate) element: Option<usize>,
}

impl Predicate {
    pub(crate) fn eval(&self, v: &Value) -> Option<Hit> {
        let whole = Some(Hit { element: None });
        match self {
            Predicate::Equals(want) => json_eq(v, want).then_some(Hit { element: None }),
            Predicate::Matches(re) => v
                .as_str()
                .is_some_and(|s| re.is_match(s))
                .then_some(Hit { element: None }),
            Predicate::Contains(want) => match (v, want) {
                (Value::String(s), Value::String(w)) => {
                    s.contains(w.as_str()).then_some(Hit { element: None })
                }
                (Value::Array(items), _) => items
                    .iter()
                    .position(|item| json_eq(item, want))
                    .map(|i| Hit { element: Some(i) }),
                _ => None,
            },
            Predicate::Exists => whole,
            Predicate::IsTrue => (v == &Value::Bool(true)).then_some(Hit { element: None }),
            Predicate::AnyElementMatches(re) => match v {
                Value::Array(items) => items
                    .iter()
                    .position(|item| item.as_str().is_some_and(|s| re.is_match(s)))
                    .map(|i| Hit { element: Some(i) }),
                _ => None,
            },
            Predicate::All(items) => {
                let mut element = None;
                for p in items {
                    let hit = p.eval(v)?;
                    element = element.or(hit.element);
                }
                Some(Hit { element })
            }
            Predicate::Any(items) => items.iter().find_map(|p| p.eval(v)),
            Predicate::Not(inner) => match inner.eval(v) {
                Some(_) => None,
                None => whole,
            },
        }
    }
}

/// JSON equality where `1` equals `1.0`.
fn json_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => {
            if let (Some(x), Some(y)) = (x.as_i64(), y.as_i64()) {
                return x == y;
            }
            if let (Some(x), Some(y)) = (x.as_u64(), y.as_u64()) {
                return x == y;
            }
            match (x.as_f64(), y.as_f64()) {
                (Some(x), Some(y)) => x.partial_cmp(&y) == Some(std::cmp::Ordering::Equal),
                _ => false,
            }
        }
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(a, b)| json_eq(a, b))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, a)| y.get(k).is_some_and(|b| json_eq(a, b)))
        }
        _ => a == b,
    }
}

// ---------------------------------------------------------------------------
// The detector

/// `{ path, predicate }` as written in a rule.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PathSpec {
    path: String,
    predicate: PredicateSpec,
}

impl PathSpec {
    pub(crate) fn compile(self, format: Format) -> Result<StructuredDetector, String> {
        let key = match format {
            Format::Json => "json_path",
            Format::Yaml => "yaml_path",
            Format::Toml => "toml_path",
        };
        Ok(StructuredDetector {
            format,
            path: JsonPath::parse(&self.path).map_err(|e| format!("detect.{key}: {e}"))?,
            predicate: self
                .predicate
                .compile()
                .map_err(|e| format!("detect.{key}: {e}"))?,
        })
    }
}

/// A compiled structured detector.
#[derive(Debug)]
pub(crate) struct StructuredDetector {
    format: Format,
    path: JsonPath,
    predicate: Predicate,
}

impl StructuredDetector {
    pub(crate) fn detect(&self, input: &Input<'_>) -> Vec<Match> {
        let docs: Vec<(&Value, usize)> = match self.format {
            Format::Json => input.json().map(|v| vec![(v, 0)]).unwrap_or_default(),
            Format::Toml => input.toml().map(|v| vec![(v, 0)]).unwrap_or_default(),
            Format::Yaml => match input.yaml() {
                Ok(docs) => {
                    let starts = yaml_doc_starts(input.text, docs.len());
                    docs.iter().zip(starts).collect()
                }
                Err(_) => Vec::new(),
            },
        };
        let mut out = Vec::new();
        for (doc, start) in docs {
            for (steps, node) in self.path.evaluate(doc) {
                if out.len() >= MAX_MATCHES {
                    return out;
                }
                let Some(hit) = self.predicate.eval(node) else {
                    continue;
                };
                let (steps, leaf) = match hit.element {
                    Some(i) => match node.as_array().and_then(|a| a.get(i)) {
                        Some(el) => (with(&steps, Step::Index(i)), el),
                        None => (steps, node),
                    },
                    None => (steps, node),
                };
                let range = locate(input.text, start, doc, &steps);
                let value = escape_truncated(
                    &serde_json::to_string(leaf).unwrap_or_default(),
                    MAX_VALUE_CHARS,
                );
                let path = escape_truncated(&render_path(&steps), MAX_VALUE_CHARS);
                out.push(Match::with_detail(range, format!("{path} = {value}")));
            }
        }
        out
    }
}

/// Where each YAML document starts, if separators make that unambiguous;
/// otherwise every document is searched from the top.
pub(crate) fn yaml_doc_starts(text: &str, docs: usize) -> Vec<usize> {
    if docs <= 1 {
        return vec![0; docs];
    }
    let mut starts = Vec::new();
    let mut region = 0;
    let mut nonempty = false;
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let content = line.trim_end_matches(['\n', '\r']);
        let is_separator = content.starts_with("---")
            && content[3..].chars().next().is_none_or(char::is_whitespace);
        if is_separator {
            if nonempty {
                starts.push(region);
            }
            region = offset;
            let inline = content[3..].trim();
            nonempty = !inline.is_empty() && !inline.starts_with('#');
        } else {
            let t = content.trim();
            if !t.is_empty() && !t.starts_with('#') && !content.starts_with('%') {
                nonempty = true;
            }
        }
        offset += line.len();
    }
    if nonempty {
        starts.push(region);
    }
    if starts.len() == docs {
        starts
    } else {
        vec![0; docs]
    }
}

/// Locate the value at `steps` below `root` (a document starting at
/// `doc_start`) in the text; see the module docs. Array indices are honoured
/// by skipping the occurrences that belong to earlier elements: the next
/// key's occurrences inside them, or equal scalar elements.
pub(crate) fn locate(text: &str, doc_start: usize, root: &Value, steps: &[Step]) -> Range<usize> {
    let mut cursor = doc_start.min(text.len());
    let mut key_range: Option<Range<usize>> = None;
    let mut node = Some(root);
    let mut skip_keys = 0;
    let mut skip_scalars = 0;
    for (n, step) in steps.iter().enumerate() {
        match step {
            Step::Key(k) => {
                if let Some(r) = find_key(text, cursor, k, skip_keys) {
                    cursor = r.end;
                    key_range = Some(r);
                }
                skip_keys = 0;
                node = node.and_then(|v| v.as_object()).and_then(|m| m.get(k));
            }
            Step::Index(i) => {
                let items = node.and_then(Value::as_array);
                let earlier = items.and_then(|a| a.get(..*i)).unwrap_or(&[]);
                let element = items.and_then(|a| a.get(*i));
                match (steps.get(n + 1), element) {
                    (Some(Step::Key(next)), _) => {
                        skip_keys = earlier.iter().map(|e| count_key(e, next)).sum();
                    }
                    (None, Some(leaf)) => {
                        skip_scalars = earlier.iter().filter(|e| json_eq(e, leaf)).count();
                    }
                    _ => {}
                }
                node = element;
            }
        }
    }
    if let Some(r) = node.and_then(|leaf| find_scalar(text, cursor, leaf, skip_scalars)) {
        return r;
    }
    if let Some(r) = key_range {
        return r;
    }
    let first_line_end = text.find('\n').unwrap_or(text.len());
    let end = if text[..first_line_end].ends_with('\r') {
        first_line_end - 1
    } else {
        first_line_end
    };
    0..end
}

/// How many object members named `key` are in `value` (at any depth).
fn count_key(value: &Value, key: &str) -> usize {
    let mut count = 0;
    let mut stack = vec![value];
    while let Some(v) = stack.pop() {
        match v {
            Value::Object(map) => {
                count += usize::from(map.contains_key(key));
                stack.extend(map.values());
            }
            Value::Array(items) => stack.extend(items),
            _ => {}
        }
    }
    count
}

/// The `skip`+1-th occurrence of `key` as a key at or after `from`.
fn find_key(text: &str, from: usize, key: &str, skip: usize) -> Option<Range<usize>> {
    if key.is_empty() {
        return None;
    }
    let mut pos = from;
    let mut seen = 0;
    while let Some(i) = text.get(pos..)?.find(key) {
        let start = pos + i;
        let end = start + key.len();
        if is_key_at(text, start, end) {
            if seen == skip {
                return Some(start..end);
            }
            seen += 1;
        }
        pos = end;
    }
    None
}

fn is_key_at(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let quote = match before {
        Some(q @ ('"' | '\'')) => Some(q),
        None => None,
        Some(c) if c.is_whitespace() || matches!(c, '{' | ',' | '[' | '.' | '-' | '?') => None,
        Some(_) => return false,
    };
    let mut rest = text[end..].chars().peekable();
    if let Some(q) = quote {
        if rest.next() != Some(q) {
            return false;
        }
    }
    while rest.next_if(|c| *c == ' ' || *c == '\t').is_some() {}
    matches!(rest.next(), Some(':' | '=' | '.' | ']'))
}

fn find_scalar(text: &str, from: usize, leaf: &Value, skip: usize) -> Option<Range<usize>> {
    let (quoted, bare, fallback): (Vec<String>, Vec<String>, Vec<String>) = match leaf {
        Value::String(s) => {
            let mut quoted = vec![serde_json::to_string(s).unwrap_or_default()];
            if !s.contains('\'') {
                quoted.push(format!("'{s}'"));
            }
            let mut fallback = Vec::new();
            if let Some(first) = s.lines().map(str::trim).find(|l| !l.is_empty()) {
                if first.len() < s.len() {
                    fallback.push(first.to_owned());
                }
            }
            if !s.is_empty() {
                fallback.push(s.clone());
            }
            let bare = if s.is_empty() {
                vec![]
            } else {
                vec![s.clone()]
            };
            (quoted, bare, fallback)
        }
        Value::Bool(true) => (
            vec![],
            [
                "true", "True", "TRUE", "yes", "Yes", "YES", "on", "On", "ON",
            ]
            .map(String::from)
            .to_vec(),
            vec![],
        ),
        Value::Bool(false) => (
            vec![],
            [
                "false", "False", "FALSE", "no", "No", "NO", "off", "Off", "OFF",
            ]
            .map(String::from)
            .to_vec(),
            vec![],
        ),
        Value::Number(n) => (vec![], vec![n.to_string()], vec![]),
        Value::Null => (vec![], vec!["null".into(), "~".into()], vec![]),
        Value::Array(_) | Value::Object(_) => return None,
    };
    let window_end = crate::text::floor_char_boundary(text, from.saturating_add(SCALAR_WINDOW));
    let text = text.get(..window_end)?;
    let hay = text.get(from..)?;
    let mut best: Option<Range<usize>> = None;
    let mut consider = |r: Range<usize>| {
        if best.as_ref().is_none_or(|b| r.start < b.start) {
            best = Some(r);
        }
    };
    for q in quoted.iter().filter(|q| !q.is_empty()) {
        if let Some(i) = nth_find(hay, q, skip) {
            consider(from + i..from + i + q.len());
        }
    }
    for b in &bare {
        if let Some(r) = find_bare(text, from, b, skip) {
            consider(r);
        }
    }
    if best.is_some() {
        return best;
    }
    fallback
        .iter()
        .find_map(|f| nth_find(hay, f, skip).map(|i| from + i..from + i + f.len()))
}

/// Offset of the `skip`+1-th occurrence of `needle` in `hay`.
fn nth_find(hay: &str, needle: &str, skip: usize) -> Option<usize> {
    let mut pos = 0;
    for _ in 0..skip {
        pos += hay.get(pos..)?.find(needle)? + needle.len();
    }
    hay.get(pos..)?.find(needle).map(|i| pos + i)
}

/// A bare (unquoted) scalar: delimited like a YAML plain scalar or a TOML
/// value, not part of a longer word.
fn find_bare(text: &str, from: usize, needle: &str, skip: usize) -> Option<Range<usize>> {
    let mut pos = from;
    let mut seen = 0;
    while let Some(i) = text.get(pos..)?.find(needle) {
        let start = pos + i;
        let end = start + needle.len();
        let before_ok = text[..start]
            .chars()
            .next_back()
            .is_none_or(|c| c.is_whitespace() || matches!(c, ':' | '=' | ',' | '[' | '{' | '-'));
        let after_ok = text[end..]
            .chars()
            .next()
            .is_none_or(|c| c.is_whitespace() || matches!(c, ',' | ']' | '}' | '#'));
        if before_ok && after_ok {
            if seen == skip {
                return Some(start..end);
            }
            seen += 1;
        }
        pos = end;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn path(p: &str) -> JsonPath {
        JsonPath::parse(p).unwrap()
    }

    fn select(p: &str, v: &Value) -> Vec<Value> {
        path(p)
            .evaluate(v)
            .into_iter()
            .map(|(_, v)| v.clone())
            .collect()
    }

    fn detector(format: Format, yaml: &str) -> StructuredDetector {
        let spec: PathSpec = serde_saphyr::from_str(yaml).unwrap();
        spec.compile(format).unwrap()
    }

    fn found(format: Format, rule: &str, path: &str, text: &str) -> Vec<(String, String)> {
        let d = detector(format, rule);
        let input = Input::new(path, text);
        d.detect(&input)
            .into_iter()
            .map(|m| (text[m.range].to_string(), m.detail.unwrap_or_default()))
            .collect()
    }

    #[test]
    fn path_syntax() {
        assert_eq!(
            path("$.a[\"b c\"][*].*..d[2]['e\\'f']").segments,
            vec![
                Segment::Key("a".into()),
                Segment::Key("b c".into()),
                Segment::AnyElement,
                Segment::AnyValue,
                Segment::Descend("d".into()),
                Segment::Index(2),
                Segment::Key("e'f".into()),
            ]
        );
        assert_eq!(path("$").segments, vec![]);
        assert_eq!(
            path("$..[\"x y\"]").segments,
            vec![Segment::Descend("x y".into())]
        );
        for bad in [
            "a.b",
            "$.",
            "$[",
            "$[x]",
            "$..*",
            "$.a b",
            "$[\"x\"",
            "$[\"x\"y]",
            "$.a]",
        ] {
            assert!(JsonPath::parse(bad).is_err(), "{bad} should fail");
        }
    }

    #[test]
    fn path_evaluation() {
        let v = json!({
            "a": {"b": [1, {"c": 2}, {"c": 3, "d": {"c": 4}}]},
            "c": 0,
            "key with spaces": true
        });
        assert_eq!(select("$.a.b[1].c", &v), vec![json!(2)]);
        assert_eq!(select("$.a.b[*].c", &v), vec![json!(2), json!(3)]);
        // Pre-order: the root's own `c` comes before those below `a`.
        assert_eq!(
            select("$..c", &v),
            vec![json!(0), json!(2), json!(3), json!(4)]
        );
        assert_eq!(select("$[\"key with spaces\"]", &v), vec![json!(true)]);
        assert_eq!(select("$.*", &v).len(), 3);
        // `[*]` is for arrays, `.*` for objects.
        assert!(select("$.a[*]", &v).is_empty());
        assert!(select("$.a.b.*", &v).is_empty());
        assert!(select("$.missing.x", &v).is_empty());
        assert!(select("$.a.b[9]", &v).is_empty());
    }

    #[test]
    fn recursive_descent_deduplicates() {
        let v = json!({"a": {"a": {"a": 1}}});
        // `$..a..a` reaches the innermost `a` through two ancestors.
        let got = select("$..a..a", &v);
        assert_eq!(got.len(), 2);
    }

    fn pred(yaml: &str) -> Predicate {
        let spec: PredicateSpec = serde_saphyr::from_str(yaml).unwrap();
        spec.compile().unwrap()
    }

    #[test]
    fn predicates() {
        assert!(pred("equals: 1").eval(&json!(1.0)).is_some());
        assert!(pred("equals: null").eval(&Value::Null).is_some());
        assert!(pred("equals: null").eval(&json!(0)).is_none());
        assert!(pred("equals: {a: [1, x]}")
            .eval(&json!({"a": [1, "x"]}))
            .is_some());
        assert!(pred("matches: '^danger'")
            .eval(&json!("danger-full-access"))
            .is_some());
        assert!(pred("matches: '1'").eval(&json!(1)).is_none());
        assert!(pred("contains: Bash").eval(&json!("Bash(*)")).is_some());
        assert_eq!(
            pred("contains: Bash").eval(&json!(["Read", "Bash"])),
            Some(Hit { element: Some(1) })
        );
        assert!(pred("contains: Bash")
            .eval(&json!(["Bash(git:*)"]))
            .is_none());
        assert!(pred("exists: true").eval(&Value::Null).is_some());
        assert!(pred("is_true: true").eval(&json!(true)).is_some());
        assert!(pred("is_true: true").eval(&json!("true")).is_none());
        assert_eq!(
            pred("any_element_matches: '^/$'").eval(&json!(["-y", "/"])),
            Some(Hit { element: Some(1) })
        );
        assert!(pred("all: [{matches: a}, {matches: b}]")
            .eval(&json!("ab"))
            .is_some());
        assert!(pred("all: [{matches: a}, {matches: c}]")
            .eval(&json!("ab"))
            .is_none());
        assert!(pred("any: [{matches: x}, {matches: b}]")
            .eval(&json!("ab"))
            .is_some());
        assert!(pred("not: {matches: x}").eval(&json!("ab")).is_some());
        assert!(pred("not: {matches: a}").eval(&json!("ab")).is_none());
    }

    #[test]
    fn predicate_validation() {
        let compile = |yaml: &str| -> Result<Predicate, String> {
            let spec: PredicateSpec = serde_saphyr::from_str(yaml).map_err(|e| e.to_string())?;
            spec.compile()
        };
        assert!(compile("{}").unwrap_err().contains("found: none"));
        assert!(compile("equals: 1\nmatches: x")
            .unwrap_err()
            .contains("equals, matches"));
        assert!(compile("exists: false").is_err());
        assert!(compile("is_true: false").is_err());
        assert!(compile("all: []").is_err());
        assert!(compile("matches: '('").is_err());
        assert!(compile("not: {}").is_err());
        assert!(compile("bogus: 1").is_err());
    }

    #[test]
    fn json_detection_and_location() {
        let rule = "path: $.permissions.defaultMode\npredicate: {equals: bypassPermissions}";
        let text = "{\n  \"permissions\": {\n    \"allow\": [\"Read\"],\n    \"defaultMode\": \"bypassPermissions\"\n  }\n}\n";
        let got = found(Format::Json, rule, ".claude/settings.json", text);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "\"bypassPermissions\"");
        assert_eq!(
            got[0].1,
            "$.permissions.defaultMode = \"bypassPermissions\""
        );
    }

    #[test]
    fn contains_locates_the_element() {
        let rule = "path: $.permissions.allow\npredicate: {contains: Bash}";
        let text = r#"{"permissions": {"allow": ["Bash(git:*)", "Read", "Bash"]}}"#;
        let d = detector(Format::Json, rule);
        let m = d.detect(&Input::new("s.json", text));
        assert_eq!(m.len(), 1);
        // The exact element, not the `Bash(git:*)` prefix before it.
        assert_eq!(m[0].range.start, text.rfind("\"Bash\"").unwrap());
        assert_eq!(
            m[0].detail.as_deref(),
            Some("$.permissions.allow[2] = \"Bash\"")
        );
    }

    #[test]
    fn jsonc_comments_and_trailing_commas() {
        let text = "// See https://example.com/tasks\n{\n  /* block\n     comment */\n  \"tasks\": [\n    {\"label\": \"x // not a comment\", \"runOptions\": {\"runOn\": \"folderOpen\"},},\n  ],\n}\n";
        let v = parse_json(text).unwrap();
        assert_eq!(v["tasks"][0]["label"], json!("x // not a comment"));
        let got = found(
            Format::Json,
            "path: $.tasks[*].runOptions.runOn\npredicate: {equals: folderOpen}",
            ".vscode/tasks.json",
            text,
        );
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "\"folderOpen\"");
    }

    #[test]
    fn json_bom_and_errors() {
        assert_eq!(parse_json("\u{feff}{\"a\": 1}").unwrap(), json!({"a": 1}));
        let e = parse_json("{\"a\": }").unwrap_err();
        assert!(e.contains("line 1"), "{e}");
    }

    #[test]
    fn json_nested_ten_thousand_deep_is_an_error_not_a_crash() {
        let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
        let e = parse_json(&deep).unwrap_err();
        assert!(e.contains("recursion limit"), "{e}");
        let deep_obj = "{\"a\":".repeat(10_000) + "1" + &"}".repeat(10_000);
        assert!(parse_json(&deep_obj).is_err());
        // And the detector just yields nothing.
        let d = detector(Format::Json, "path: $..a\npredicate: {exists: true}");
        assert!(d.detect(&Input::new("x.json", &deep_obj)).is_empty());
    }

    #[test]
    fn yaml_nested_ten_thousand_deep_is_an_error_not_a_crash() {
        let flow = "[".repeat(10_000);
        assert!(parse_yaml(&flow).is_err());
        let flow_map = "{a: ".repeat(10_000);
        assert!(parse_yaml(&flow_map).is_err());
        // 1 000 levels of indentation (10 000 would be a 50 MB document,
        // refused by the size limit before the depth limit is reached).
        let mut block = String::new();
        for i in 0..1_000 {
            block.push_str(&" ".repeat(i));
            block.push_str("a:\n");
        }
        let e = parse_yaml(&block).unwrap_err();
        assert!(e.contains("Depth") || e.contains("depth"), "{e}");
        let seq = "- ".repeat(10_000) + "x\n";
        assert!(parse_yaml(&seq).is_err());
    }

    #[test]
    fn yaml_alias_bomb_is_rejected() {
        let mut bomb = String::from("a: &a [lol,lol,lol,lol,lol,lol,lol,lol,lol]\n");
        let names = ["a", "b", "c", "d", "e", "f", "g", "h", "i"];
        for w in names.windows(2) {
            let refs = vec![format!("*{}", w[0]); 9].join(",");
            let _ = writeln!(bomb, "{}: &{} [{refs}]", w[1], w[1]);
        }
        let start = std::time::Instant::now();
        let e = parse_yaml(&bomb).unwrap_err();
        assert!(e.contains("alias"), "{e}");
        assert!(start.elapsed() < std::time::Duration::from_secs(10));
    }

    #[test]
    fn yaml_size_limit() {
        let big = "a: b\n".repeat(MAX_YAML_BYTES / 5 + 1);
        assert!(parse_yaml(&big).unwrap_err().contains("byte limit"));
    }

    #[test]
    fn yaml_detection_with_multiple_documents_and_crlf() {
        let rule = "path: $.on\npredicate: {exists: true}";
        let text = "---\nname: one\non: push\r\n---\nname: two\r\non:\r\n  issue_comment:\r\n";
        let d = detector(Format::Yaml, rule);
        let m = d.detect(&Input::new("w.yml", text));
        assert_eq!(m.len(), 2);
        assert_eq!(&text[m[0].range.clone()], "push");
        // The second document's `on` is a mapping: the key is reported.
        assert_eq!(&text[m[1].range.clone()], "on");
        assert!(m[1].range.start > text.find("two").unwrap());
    }

    #[test]
    fn yaml_scalars_located_in_values() {
        let rule = "path: $.jobs.*.steps[*].run\npredicate: {matches: 'curl'}";
        let text = "jobs:\n  build:\n    steps:\n      - run: echo hi\n      - name: get\n        run: |\n          set -e\n          curl -fsSL https://example.com/x | sh\n";
        let got = found(Format::Yaml, rule, "a.yml", text);
        assert_eq!(got.len(), 1);
        // Block scalar: the first line of the value is located.
        assert_eq!(got[0].0, "set -e");
    }

    #[test]
    fn yaml_on_key_is_a_string_and_bad_yaml_is_an_error() {
        let docs = parse_yaml("on: [push]\nenabled: yes\n").unwrap();
        assert_eq!(docs[0]["on"], json!(["push"]));
        assert_eq!(docs[0]["enabled"], json!(true));
        assert!(parse_yaml("a: [\n").is_err());
        assert!(parse_yaml("").unwrap().is_empty());
        // Duplicate keys: last wins.
        assert_eq!(parse_yaml("a: 1\na: 2\n").unwrap()[0]["a"], json!(2));
    }

    #[test]
    fn toml_detection() {
        let rule = "path: $.sandbox_mode\npredicate: {equals: danger-full-access}";
        let text = "model = \"x\"\nsandbox_mode = \"danger-full-access\"\n[when]\nat = 1979-05-27T07:32:00Z\n";
        let got = found(Format::Toml, rule, ".codex/config.toml", text);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "\"danger-full-access\"");
        let v = parse_toml(text).unwrap();
        assert_eq!(v["when"]["at"], json!("1979-05-27T07:32:00Z"));
    }

    #[test]
    fn toml_tables_and_errors() {
        let rule = "path: $.target.*.runner\npredicate: {exists: true}";
        let text = "[target.x86_64-unknown-linux-gnu]\nrunner = \"./run.sh\"\n";
        let got = found(Format::Toml, rule, ".cargo/config.toml", text);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "\"./run.sh\"");
        let e = parse_toml("a = \n").unwrap_err();
        assert!(e.starts_with("line 1, column"), "{e}");
        let deep = "a = ".to_owned() + &"[".repeat(10_000);
        assert!(parse_toml(&deep).is_err());
    }

    #[test]
    fn location_falls_back_to_key_then_line_one() {
        let v = json!({"a": {"b": [1, 2]}});
        let text = "{\"a\": {\"b\": [1, 2]}}";
        let r = locate(text, 0, &v, &[Step::Key("a".into()), Step::Key("b".into())]);
        assert_eq!(&text[r], "b");
        let zz = json!({"zz": {}});
        let r = locate("first\r\nsecond", 0, &zz, &[Step::Key("zz".into())]);
        assert_eq!(r, 0..5);
    }

    #[test]
    fn keys_are_matched_as_keys_not_substrings() {
        let text = "{\"allowance\": 1, \"other_allow\": 2, \"allow\": \"x\"}";
        let r = find_key(text, 0, "allow", 0).unwrap();
        assert_eq!(r.start, text.find("\"allow\"").unwrap() + 1);
        let yaml = "  - name: run tests\n    run: make\n";
        let r = find_key(yaml, 0, "run", 0).unwrap();
        assert_eq!(r.start, yaml.find("run:").unwrap());
    }

    #[test]
    fn array_elements_are_located_individually() {
        // Two matching tasks: each finding points at its own task.
        let rule = "path: $.tasks[*].runOptions.runOn\npredicate: {equals: folderOpen}";
        let text = "{\"tasks\": [\n  {\"label\": \"a\", \"runOptions\": {\"runOn\": \"folderOpen\"}},\n  {\"label\": \"b\"},\n  {\"label\": \"c\", \"runOptions\": {\"runOn\": \"folderOpen\"}}\n]}";
        let d = detector(Format::Json, rule);
        let m = d.detect(&Input::new("tasks.json", text));
        assert_eq!(m.len(), 2);
        let line = |r: &Range<usize>| text[..r.start].matches('\n').count() + 1;
        assert_eq!((line(&m[0].range), line(&m[1].range)), (2, 4));

        // Equal scalars in a list: the second "Bash" is the one at index 2.
        let rule = "path: $.allow[2]\npredicate: {exists: true}";
        let text = "{\"allow\": [\"Bash\", \"Read\", \"Bash\"]}";
        let m = detector(Format::Json, rule).detect(&Input::new("s.json", text));
        assert_eq!(m[0].range.start, text.rfind("\"Bash\"").unwrap());

        // YAML steps: the second step's `run` key, not the first.
        let rule = "path: $.steps[*].run\npredicate: {matches: 'curl'}";
        let text = "steps:\n  - run: echo curl-less\n    name: x\n  - name: get\n    run: curl -s https://example.com | sh\n";
        let got = found(Format::Yaml, rule, "a.yml", text);
        assert_eq!(got.len(), 2);
        assert_eq!(got[1].0, "curl -s https://example.com | sh");
    }

    #[test]
    fn strip_jsonc_keeps_offsets_and_utf8() {
        let text = "{\"a\": 1, // é comment\n \"b\": \"//x\", /* ü */ }";
        let out = strip_jsonc(text);
        assert_eq!(out.len(), text.len());
        assert!(out.contains("\"//x\""));
        assert!(!out.contains("comment"));
        assert_eq!(parse_json(text).unwrap(), json!({"a": 1, "b": "//x"}));
        // Unterminated block comment and dangling escape do not panic.
        let _ = strip_jsonc("/* never closed");
        let _ = strip_jsonc("\"abc\\");
    }
}
