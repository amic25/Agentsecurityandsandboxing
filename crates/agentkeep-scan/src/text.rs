//! Byte offsets to line and column, and snippets that are safe to print.
//!
//! Detectors work on byte ranges. Humans and SARIF want 1-based lines and
//! columns; columns here count Unicode scalar values, so a line full of
//! emoji does not push a finding to the wrong place. Snippets come from a
//! hostile file and end up in terminals and on GitHub, so every invisible or
//! control character in them is rendered as `\u{XXXX}`.

use std::cell::Cell;
use std::fmt::Write as _;
use std::ops::Range;

use crate::report::Position;

/// Snippets never exceed this many characters (after escaping).
pub(crate) const SNIPPET_MAX_CHARS: usize = 200;

/// How many characters of context to keep before a match when a long line
/// has to be cut.
const SNIPPET_LEAD_CHARS: usize = 40;

/// Start offsets of every line in a text.
#[derive(Debug, Clone)]
pub(crate) struct LineIndex {
    starts: Vec<usize>,
    len: usize,
    /// A byte-order mark at offset 0 is not a visible character; editors and
    /// GitHub do not count it as a column, so neither do we.
    bom_len: usize,
    /// The last position computed: (offset, characters from its line start).
    /// Findings come sorted, so counting resumes from here instead of from
    /// the line start; a 1 MiB single-line file with many findings stays
    /// linear.
    memo: Cell<(usize, usize)>,
}

impl LineIndex {
    pub(crate) fn new(text: &str) -> Self {
        let mut starts = vec![0];
        starts.extend(
            text.bytes()
                .enumerate()
                .filter(|&(_, b)| b == b'\n')
                .map(|(i, _)| i + 1),
        );
        let bom_len = if text.starts_with('\u{feff}') { 3 } else { 0 };
        Self {
            starts,
            len: text.len(),
            bom_len,
            memo: Cell::new((0, 0)),
        }
    }

    /// 0-based index of the line containing `offset`.
    pub(crate) fn line_of(&self, offset: usize) -> usize {
        let offset = offset.min(self.len);
        match self.starts.binary_search(&offset) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        }
    }

    /// Byte offset where 0-based line `line` starts.
    pub(crate) fn line_start(&self, line: usize) -> usize {
        self.starts.get(line).copied().unwrap_or(self.len)
    }

    /// Byte offset where 0-based line `line` ends, excluding `\n` and a `\r`
    /// before it.
    pub(crate) fn line_end(&self, text: &str, line: usize) -> usize {
        let next = self
            .starts
            .get(line + 1)
            .map_or(self.len, |&s| s.saturating_sub(1));
        let start = self.line_start(line);
        if next > start && text.as_bytes().get(next - 1) == Some(&b'\r') {
            next - 1
        } else {
            next
        }
    }

    /// 1-based line and column of `offset`.
    pub(crate) fn position(&self, text: &str, offset: usize) -> Position {
        let offset = floor_char_boundary(text, offset);
        let line = self.line_of(offset);
        let mut start = self.line_start(line);
        if line == 0 {
            start = start.max(self.bom_len.min(offset));
        }
        let (memo_offset, memo_chars) = self.memo.get();
        let (base, base_chars) = if memo_offset >= start && memo_offset <= offset {
            (memo_offset, memo_chars)
        } else {
            (start, 0)
        };
        let chars = base_chars + text.get(base..offset).map_or(0, |s| s.chars().count());
        self.memo.set((offset, chars));
        Position {
            line: line + 1,
            column: chars + 1,
        }
    }

    /// Start and end positions of a range. The end is exclusive, as in
    /// SARIF; a trailing line terminator inside the range is not counted so a
    /// match on a whole line does not end on the next one.
    pub(crate) fn span(&self, text: &str, range: &Range<usize>) -> (Position, Position) {
        let start = range.start.min(text.len());
        let mut end = range.end.clamp(start, text.len());
        let bytes = text.as_bytes();
        if end > start && bytes.get(end - 1) == Some(&b'\n') {
            end -= 1;
            if end > start && bytes.get(end - 1) == Some(&b'\r') {
                end -= 1;
            }
        }
        (self.position(text, start), self.position(text, end))
    }
}

/// Largest char boundary not after `offset`.
pub(crate) fn floor_char_boundary(text: &str, offset: usize) -> usize {
    let mut offset = offset.min(text.len());
    while offset > 0 && !text.is_char_boundary(offset) {
        offset -= 1;
    }
    offset
}

/// Smallest char boundary not before `offset`.
pub(crate) fn ceil_char_boundary(text: &str, offset: usize) -> usize {
    let mut offset = offset.min(text.len());
    while offset < text.len() && !text.is_char_boundary(offset) {
        offset += 1;
    }
    offset
}

/// Should this character be shown as an escape rather than printed?
///
/// Tabs and newlines stay as they are; every other control character and
/// every character that renders as nothing (or as something other than what
/// it is) is escaped, so a snippet cannot move the cursor, recolour a
/// terminal or hide text from the reviewer reading it.
pub(crate) fn needs_escape(c: char) -> bool {
    if c == '\t' || c == '\n' {
        return false;
    }
    c.is_control()
        || crate::detect::unicode::is_hidden(c)
        || matches!(c, '\u{2028}' | '\u{2029}' | '\u{034F}')
}

/// Escape invisible and control characters as `\u{XXXX}`.
pub(crate) fn escape_for_display(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        push_escaped(&mut out, c);
    }
    out
}

fn push_escaped(out: &mut String, c: char) {
    if needs_escape(c) {
        // Writing to a String cannot fail.
        let _ = write!(out, "\\u{{{:04X}}}", u32::from(c));
    } else {
        out.push(c);
    }
}

fn escaped_width(c: char) -> usize {
    if needs_escape(c) {
        // `\u{` + at least four hex digits + `}`.
        let digits = format!("{:X}", u32::from(c)).len().max(4);
        digits + 4
    } else {
        1
    }
}

/// Escape and cut a string to at most `max` characters, marking the cut.
pub(crate) fn escape_truncated(s: &str, max: usize) -> String {
    let mut out = String::new();
    let mut width = 0;
    for c in s.chars() {
        let w = escaped_width(c);
        if width + w > max.saturating_sub(1) {
            out.push('…');
            return out;
        }
        push_escaped(&mut out, c);
        width += w;
    }
    out
}

/// The matched line(s), escaped, at most [`SNIPPET_MAX_CHARS`] characters.
/// Long lines are cut around the match so the interesting part is visible.
/// The work is bounded by the snippet size, not the line length.
pub(crate) fn snippet(text: &str, index: &LineIndex, range: &Range<usize>) -> String {
    let start = floor_char_boundary(text, range.start);
    let mut end = ceil_char_boundary(text, range.end.max(start));
    // A range that ends right after a newline belongs to the previous line.
    if end > start && text.as_bytes().get(end - 1) == Some(&b'\n') {
        end -= 1;
    }
    let first = index.line_of(start);
    let last = index.line_of(end).max(first);
    let mut from = index.line_start(first);
    let to = index.line_end(text, last).max(from);
    if from == 0 && text.starts_with('\u{feff}') {
        from = 3.min(to);
    }
    let Some(region) = text.get(from..to) else {
        return String::new();
    };
    let mut width = 0;
    let fits = region.chars().all(|c| {
        width += escaped_width(c);
        width <= SNIPPET_MAX_CHARS
    });
    if fits {
        return escape_for_display(region);
    }
    // Cut: start a little before the match so the reader sees context.
    let start = start.max(from);
    let window = text
        .get(from..start)
        .and_then(|s| s.char_indices().rev().nth(SNIPPET_LEAD_CHARS - 1))
        .map_or(from, |(i, _)| from + i);
    let mut out = String::new();
    let mut width = 0;
    if window > from {
        out.push('…');
        width += 1;
    }
    for c in text.get(window..to).unwrap_or("").chars() {
        let w = escaped_width(c);
        if width + w > SNIPPET_MAX_CHARS - 1 {
            out.push('…');
            break;
        }
        push_escaped(&mut out, c);
        width += w;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pos(line: usize, column: usize) -> Position {
        Position { line, column }
    }

    #[test]
    fn positions_count_scalar_values() {
        let text = "ab\nx😀y\n";
        let idx = LineIndex::new(text);
        assert_eq!(idx.position(text, 0), pos(1, 1));
        assert_eq!(idx.position(text, 3), pos(2, 1));
        // 'y' comes after a four-byte emoji: column 3, not 6.
        let y = text.find('y').unwrap();
        assert_eq!(idx.position(text, y), pos(2, 3));
    }

    #[test]
    fn bom_is_not_a_column() {
        let text = "\u{feff}abc\nd";
        let idx = LineIndex::new(text);
        assert_eq!(idx.position(text, 3), pos(1, 1));
        assert_eq!(idx.position(text, 4), pos(1, 2));
        assert_eq!(idx.position(text, 0), pos(1, 1));
        assert_eq!(snippet(text, &idx, &(3..4)), "abc");
    }

    #[test]
    fn crlf_lines() {
        let text = "one\r\ntwo\r\nthree";
        let idx = LineIndex::new(text);
        let two = text.find("two").unwrap();
        assert_eq!(idx.position(text, two), pos(2, 1));
        assert_eq!(idx.line_end(text, 1), two + 3);
        assert_eq!(snippet(text, &idx, &(two..two + 3)), "two");
        // A match that swallows the terminator ends on its own line.
        let (s, e) = idx.span(text, &(two..two + 5));
        assert_eq!((s, e), (pos(2, 1), pos(2, 4)));
    }

    #[test]
    fn offsets_inside_chars_are_clamped() {
        let text = "é";
        let idx = LineIndex::new(text);
        assert_eq!(idx.position(text, 1), pos(1, 1));
        assert_eq!(idx.position(text, 99), pos(1, 2));
    }

    #[test]
    fn snippets_escape_invisible_and_control_characters() {
        let text = "a\u{202e}b\u{1b}[31mc\u{e0041}\td\r";
        let idx = LineIndex::new(text);
        let s = snippet(text, &idx, &(0..1));
        assert_eq!(s, "a\\u{202E}b\\u{001B}[31mc\\u{E0041}\td");
        assert!(!s.chars().any(|c| c.is_control() && c != '\t'));
    }

    #[test]
    fn long_lines_are_cut_around_the_match() {
        let text = format!("{}NEEDLE{}", "x".repeat(1000), "y".repeat(1000));
        let idx = LineIndex::new(&text);
        let at = text.find("NEEDLE").unwrap();
        let s = snippet(&text, &idx, &(at..at + 6));
        assert!(s.chars().count() <= SNIPPET_MAX_CHARS);
        assert!(s.contains("NEEDLE"));
        assert!(s.starts_with('…') && s.ends_with('…'));
    }

    #[test]
    fn escaped_snippets_respect_the_limit() {
        let text = "\u{200b}".repeat(500);
        let idx = LineIndex::new(&text);
        let s = snippet(&text, &idx, &(0..3));
        assert!(s.chars().count() <= SNIPPET_MAX_CHARS, "{}", s.len());
        let t = escape_truncated(&text, 50);
        assert!(t.chars().count() <= 50);
    }

    #[test]
    fn positions_resume_from_the_last_one_and_stay_correct() {
        let text = format!("\u{feff}{}\nb\u{e9}b", "\u{e9}x".repeat(1000));
        let idx = LineIndex::new(&text);
        // Increasing offsets on one line, then a jump back, then line 2.
        for k in [0usize, 10, 500, 999] {
            let off = 3 + k * 3;
            assert_eq!(idx.position(&text, off).column, 2 * k + 1);
        }
        assert_eq!(idx.position(&text, 3 + 3).column, 3);
        assert_eq!(idx.position(&text, 0).column, 1);
        let b2 = text.rfind('b').unwrap();
        assert_eq!(idx.position(&text, b2), pos(2, 3));
    }

    #[test]
    fn multi_line_snippets_keep_newlines() {
        let text = "a\nbc\nd";
        let idx = LineIndex::new(text);
        assert_eq!(snippet(text, &idx, &(0..4)), "a\nbc");
    }

    #[test]
    fn empty_text() {
        let idx = LineIndex::new("");
        assert_eq!(idx.position("", 0), pos(1, 1));
        assert_eq!(snippet("", &idx, &(0..0)), "");
    }
}
