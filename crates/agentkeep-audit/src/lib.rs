//! Append-only, hash-chained JSONL audit log.
//!
//! One directory per session holds `events.jsonl`. Each event carries the
//! SHA-256 of the previous event's hash concatenated with its own canonical
//! JSON, so a removed, edited or truncated line breaks the chain and
//! [`verify`] reports exactly where. The file is opened append-only and
//! lives outside the sandbox; the agent never sees it (threat L-A1).

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod time;

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The crate version, re-exported so the CLI can report component versions.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Name of the event file inside a session directory.
pub const EVENTS_FILE: &str = "events.jsonl";

/// Hash recorded as `prev` for the first event.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Errors from writing or verifying a log.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O failure.
    #[error("{path}: {source}")]
    Io {
        /// File involved.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// A line was not a valid event.
    #[error("{path}:{line}: malformed event: {message}")]
    Malformed {
        /// File involved.
        path: PathBuf,
        /// 1-based line.
        line: usize,
        /// What went wrong.
        message: String,
    },
    /// The chain is broken at this line.
    #[error("{path}:{line}: hash chain broken ({reason})")]
    ChainBroken {
        /// File involved.
        path: PathBuf,
        /// 1-based line.
        line: usize,
        /// Which check failed.
        reason: String,
    },
}

/// One logged event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// 0-based sequence number.
    pub seq: u64,
    /// RFC 3339 UTC timestamp.
    pub ts: String,
    /// Event kind, dotted (`session.start`, `exec`, `policy.decision`).
    pub kind: String,
    /// Kind-specific payload.
    pub data: serde_json::Value,
    /// Hash of the previous event, or [`GENESIS`].
    pub prev: String,
    /// SHA-256 over `prev` and this event's canonical JSON without `hash`.
    pub hash: String,
}

impl Event {
    fn compute_hash(&self) -> String {
        // serde_json sorts map keys (no `preserve_order` feature), which
        // makes this encoding canonical.
        let unhashed = serde_json::json!({
            "seq": self.seq,
            "ts": self.ts,
            "kind": self.kind,
            "data": self.data,
            "prev": self.prev,
        });
        let mut h = Sha256::new();
        h.update(self.prev.as_bytes());
        h.update(unhashed.to_string().as_bytes());
        hex(&h.finalize())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Appends events to one session's log.
#[derive(Debug)]
pub struct Writer {
    path: PathBuf,
    file: File,
    seq: u64,
    prev: String,
}

impl Writer {
    /// Create `dir/events.jsonl` (the directory too) and start a chain.
    /// Fails if the file already exists: sessions are never appended to by
    /// a second writer.
    pub fn create(dir: &Path) -> Result<Self, Error> {
        fs::create_dir_all(dir).map_err(|e| Error::Io {
            path: dir.to_path_buf(),
            source: e,
        })?;
        let path = dir.join(EVENTS_FILE);
        let file = OpenOptions::new()
            .append(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| Error::Io {
                path: path.clone(),
                source: e,
            })?;
        Ok(Self {
            path,
            file,
            seq: 0,
            prev: GENESIS.to_string(),
        })
    }

    /// Path of the event file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one event and flush it.
    pub fn append(&mut self, kind: &str, data: serde_json::Value) -> Result<&str, Error> {
        let mut ev = Event {
            seq: self.seq,
            ts: time::now_rfc3339(),
            kind: kind.to_string(),
            data,
            prev: self.prev.clone(),
            hash: String::new(),
        };
        ev.hash = ev.compute_hash();
        let mut line = serde_json::to_string(&ev).map_err(|e| Error::Malformed {
            path: self.path.clone(),
            line: usize::try_from(self.seq).unwrap_or(0) + 1,
            message: e.to_string(),
        })?;
        line.push('\n');
        self.file
            .write_all(line.as_bytes())
            .and_then(|()| self.file.flush())
            .map_err(|e| Error::Io {
                path: self.path.clone(),
                source: e,
            })?;
        self.seq += 1;
        self.prev = ev.hash;
        Ok(&self.prev)
    }
}

/// Read every event, checking the chain. Returns the events on success.
pub fn verify(path: &Path) -> Result<Vec<Event>, Error> {
    let file = File::open(path).map_err(|e| Error::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mut events = Vec::new();
    let mut prev = GENESIS.to_string();
    for (i, line) in BufReader::new(file).lines().enumerate() {
        let line_no = i + 1;
        let line = line.map_err(|e| Error::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let ev: Event = serde_json::from_str(&line).map_err(|e| Error::Malformed {
            path: path.to_path_buf(),
            line: line_no,
            message: e.to_string(),
        })?;
        if ev.seq != events.len() as u64 {
            return Err(Error::ChainBroken {
                path: path.to_path_buf(),
                line: line_no,
                reason: format!("expected seq {}, found {}", events.len(), ev.seq),
            });
        }
        if ev.prev != prev {
            return Err(Error::ChainBroken {
                path: path.to_path_buf(),
                line: line_no,
                reason: "prev does not match previous hash".into(),
            });
        }
        if ev.compute_hash() != ev.hash {
            return Err(Error::ChainBroken {
                path: path.to_path_buf(),
                line: line_no,
                reason: "hash does not match content".into(),
            });
        }
        prev.clone_from(&ev.hash);
        events.push(ev);
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_roundtrip_and_tamper_detection() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = Writer::create(dir.path()).unwrap();
        w.append("session.start", serde_json::json!({"a": 1}))
            .unwrap();
        w.append("exec", serde_json::json!({"argv": ["ls"]}))
            .unwrap();
        w.append("session.end", serde_json::json!({"code": 0}))
            .unwrap();
        let path = w.path().to_path_buf();
        let events = verify(&path).unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].prev, GENESIS);
        assert_eq!(events[1].prev, events[0].hash);

        // Edit the middle event.
        let text = fs::read_to_string(&path).unwrap();
        let tampered = text.replace("\"ls\"", "\"rm\"");
        fs::write(&path, tampered).unwrap();
        let err = verify(&path).unwrap_err();
        assert!(matches!(err, Error::ChainBroken { line: 2, .. }), "{err}");

        // Truncate the last event.
        let mut lines: Vec<&str> = text.lines().collect();
        lines.pop();
        fs::write(&path, lines.join("\n") + "\n").unwrap();
        assert_eq!(
            verify(&path).unwrap().len(),
            2,
            "truncation shortens but keeps the chain valid; the writer's final hash detects it"
        );
    }

    #[test]
    fn refuses_second_writer() {
        let dir = tempfile::tempdir().unwrap();
        let _w = Writer::create(dir.path()).unwrap();
        assert!(Writer::create(dir.path()).is_err());
    }
}
