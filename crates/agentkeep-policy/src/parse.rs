//! TOML parsing with line and column information.

use thiserror::Error;

use crate::schema::PolicyFile;
use crate::SCHEMA_VERSION;

/// A parse or schema error, with a location when one is known.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The TOML was malformed or a key was unknown or mistyped.
    #[error("{origin}:{line}:{column}: {message}")]
    Syntax {
        /// Where the text came from (a path or `<cli>`).
        origin: String,
        /// 1-based line.
        line: usize,
        /// 1-based column.
        column: usize,
        /// The parser's message.
        message: String,
    },
    /// `schema` is missing.
    #[error("{origin}: missing `schema = {SCHEMA_VERSION}` at the top of the file")]
    MissingSchema {
        /// Where the text came from.
        origin: String,
    },
    /// `schema` has a version this build does not understand.
    #[error("{origin}: schema version {found} is not supported (this build understands {SCHEMA_VERSION})")]
    UnsupportedSchema {
        /// Where the text came from.
        origin: String,
        /// The version found.
        found: u32,
    },
}

/// Parse a policy file. `source` is used only in error messages.
///
/// The schema key is required so that a future version can change meaning
/// without old files silently being read under new rules.
pub fn parse_str(text: &str, source: &str) -> Result<PolicyFile, ParseError> {
    let file: PolicyFile = toml::from_str(text).map_err(|e| {
        let (line, column) = e.span().map_or((1, 1), |span| line_col(text, span.start));
        ParseError::Syntax {
            origin: source.to_string(),
            line,
            column,
            message: e.message().to_string(),
        }
    })?;
    match file.schema {
        None => Err(ParseError::MissingSchema {
            origin: source.to_string(),
        }),
        Some(v) if v != SCHEMA_VERSION => Err(ParseError::UnsupportedSchema {
            origin: source.to_string(),
            found: v,
        }),
        Some(_) => Ok(file),
    }
}

/// Convert a byte offset to a 1-based (line, column) pair. Columns count
/// characters, not bytes, so they match what an editor shows.
fn line_col(text: &str, offset: usize) -> (usize, usize) {
    let offset = offset.min(text.len());
    let before = &text[..offset];
    let line = before.matches('\n').count() + 1;
    let col = before
        .rfind('\n')
        .map_or(before.chars().count(), |i| before[i + 1..].chars().count());
    (line, col + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_schema() {
        assert_eq!(
            parse_str("[env]\nallow = []\n", "t"),
            Err(ParseError::MissingSchema { origin: "t".into() })
        );
        assert_eq!(
            parse_str("schema = 7\n", "t"),
            Err(ParseError::UnsupportedSchema {
                origin: "t".into(),
                found: 7
            })
        );
    }

    #[test]
    fn unknown_keys_are_errors_with_location() {
        let err = parse_str("schema = 1\n[filesystem]\nreadonly = []\n", "p.toml").unwrap_err();
        match err {
            ParseError::Syntax {
                line,
                column,
                message,
                ..
            } => {
                assert_eq!((line, column), (3, 1));
                assert!(message.contains("unknown field"), "{message}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn wrong_types_are_errors() {
        let err = parse_str("schema = 1\n[limits]\npids = \"many\"\n", "p").unwrap_err();
        assert!(matches!(err, ParseError::Syntax { line: 3, .. }), "{err}");
    }

    #[test]
    fn minimal_file_parses() {
        let f = parse_str("schema = 1\n", "p").unwrap();
        assert_eq!(f.schema, Some(1));
        assert!(f.filesystem.is_none());
    }

    #[test]
    fn line_col_handles_multibyte() {
        let t = "é\nab";
        assert_eq!(line_col(t, 0), (1, 1));
        assert_eq!(line_col(t, 3), (2, 1));
        assert_eq!(line_col(t, 4), (2, 2));
    }
}
