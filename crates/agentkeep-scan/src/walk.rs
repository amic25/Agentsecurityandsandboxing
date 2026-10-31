//! File discovery under a scan root.
//!
//! The root may belong to an attacker (a cloned repository), so the walker:
//!
//! - never follows a symlink, the root included: a link to `~/.ssh/id_rsa`
//!   must not end up in a snippet in a CI log. Symlinks are listed in
//!   `skipped` with reason `symlink`. Entries are inspected with
//!   `symlink_metadata`/`DirEntry::file_type`, which do not follow links.
//! - re-checks, after opening a file, that it is the same inode the listing
//!   saw (Unix), so swapping a file for a link mid-scan is noticed;
//! - skips well-known dependency and build directories (`.git`,
//!   `node_modules`, `target`, ...), FIFOs, sockets and devices;
//! - caps file size (default 1 MiB), directory depth (64) and file count
//!   (100 000), and records every skip and truncation instead of failing;
//! - treats a file with NUL in the first 8 KiB as binary. A file that is
//!   mostly invalid UTF-8 is skipped as `not-utf8`; a file with a few
//!   invalid sequences is scanned after lossy decoding, so one stray byte
//!   cannot hide a whole file from the scanner ("mostly" means more than
//!   eight invalid sequences and more than 10% of the decoded characters);
//! - lists entries sorted by name, depth-first, so output is deterministic.
//!
//! A single file as the root is scanned with its parent as the root and its
//! file name as the relative path.

use std::ffi::OsString;
use std::fs::{self, File, FileType};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::report::{FileError, SkipReason, Skipped};

/// Directories that are skipped by default: VCS metadata, dependencies and
/// build output, which are large and not agent instruction surfaces.
pub const DEFAULT_SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
];

/// How many leading bytes are checked for NUL.
const BINARY_SNIFF_BYTES: usize = 8 * 1024;

/// Limits for a walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkOptions {
    /// Files larger than this are skipped (`too-large`).
    pub max_file_bytes: u64,
    /// The walk stops after this many files (`file-limit`).
    pub max_files: usize,
    /// Directories deeper than this are not entered (`depth-limit`).
    pub max_depth: usize,
    /// Directory names that are never entered (`excluded-dir`).
    pub skip_dirs: Vec<String>,
}

impl Default for WalkOptions {
    fn default() -> Self {
        Self {
            max_file_bytes: 1024 * 1024,
            max_files: 100_000,
            max_depth: 64,
            skip_dirs: DEFAULT_SKIP_DIRS.iter().map(|s| (*s).to_owned()).collect(),
        }
    }
}

/// The root could not be inspected at all.
#[derive(Debug, thiserror::Error)]
pub enum WalkError {
    /// `symlink_metadata` on the root failed (missing, permission denied).
    #[error("{path}: cannot read scan root: {source}")]
    Root {
        /// The root as given.
        path: String,
        /// The I/O error.
        #[source]
        source: std::io::Error,
    },
}

/// A file found by the walk, not yet read.
#[derive(Debug, Clone)]
pub struct FileEntry {
    /// Path relative to the scan root, `/`-separated.
    pub rel_path: String,
    /// Path to open.
    pub path: PathBuf,
    /// Device and inode seen when listing, to detect swaps (Unix only).
    identity: Option<(u64, u64)>,
}

/// The result of a walk.
#[derive(Debug, Clone, Default)]
pub struct Walk {
    /// The directory relative paths are relative to.
    pub root_dir: PathBuf,
    /// Files to scan, in deterministic order.
    pub files: Vec<FileEntry>,
    /// Entries not scanned.
    pub skipped: Vec<Skipped>,
    /// Directories that could not be listed.
    pub errors: Vec<FileError>,
    /// True when a depth or file-count limit was hit.
    pub truncated: bool,
}

/// What reading a file produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    /// Text to scan.
    Text(String),
    /// Not scanned, with the reason.
    Skipped(SkipReason),
    /// Could not be read.
    Error(String),
}

struct Item {
    path: PathBuf,
    rel: String,
    depth: usize,
    file_type: FileType,
}

/// List the files under `root`.
pub fn walk(root: &Path, opts: &WalkOptions) -> Result<Walk, WalkError> {
    let meta = fs::symlink_metadata(root).map_err(|source| WalkError::Root {
        path: root.display().to_string(),
        source,
    })?;
    let mut out = Walk::default();
    if meta.is_dir() {
        out.root_dir = root.to_path_buf();
        walk_dir(root, opts, &mut out);
        return Ok(out);
    }
    // A single file (or link, or special file): its parent is the root.
    out.root_dir = match root.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let rel = root.file_name().map_or_else(
        || root.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    let ft = meta.file_type();
    if ft.is_symlink() {
        out.skipped.push(skipped(&rel, SkipReason::Symlink));
    } else if ft.is_file() {
        out.files.push(FileEntry {
            rel_path: rel,
            path: root.to_path_buf(),
            identity: identity(&meta),
        });
    } else {
        out.skipped.push(skipped(&rel, SkipReason::NotRegularFile));
    }
    Ok(out)
}

fn walk_dir(root: &Path, opts: &WalkOptions, out: &mut Walk) {
    let mut stack: Vec<Item> = Vec::new();
    push_children(root, "", 1, &mut stack, out);
    while let Some(item) = stack.pop() {
        let ft = item.file_type;
        if ft.is_symlink() {
            out.skipped.push(skipped(&item.rel, SkipReason::Symlink));
        } else if ft.is_dir() {
            let name = item.rel.rsplit('/').next().unwrap_or(&item.rel);
            if opts.skip_dirs.iter().any(|d| d == name) {
                out.skipped
                    .push(skipped(&item.rel, SkipReason::ExcludedDir));
            } else if item.depth >= opts.max_depth {
                out.skipped.push(skipped(&item.rel, SkipReason::DepthLimit));
                out.truncated = true;
            } else {
                push_children(&item.path, &item.rel, item.depth + 1, &mut stack, out);
            }
        } else if ft.is_file() {
            if out.files.len() >= opts.max_files {
                out.skipped.push(skipped(&item.rel, SkipReason::FileLimit));
                out.truncated = true;
                return;
            }
            let identity = fs::symlink_metadata(&item.path)
                .ok()
                .and_then(|m| identity(&m));
            out.files.push(FileEntry {
                rel_path: item.rel,
                path: item.path,
                identity,
            });
        } else {
            out.skipped
                .push(skipped(&item.rel, SkipReason::NotRegularFile));
        }
    }
}

/// Push a directory's entries in reverse name order, so popping visits them
/// in name order (a sorted depth-first walk without recursion).
fn push_children(dir: &Path, rel: &str, depth: usize, stack: &mut Vec<Item>, out: &mut Walk) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            out.errors.push(FileError {
                path: if rel.is_empty() {
                    ".".into()
                } else {
                    rel.into()
                },
                message: format!("cannot list directory: {e}"),
            });
            return;
        }
    };
    let mut children: Vec<(OsString, PathBuf, FileType)> = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                out.errors.push(FileError {
                    path: if rel.is_empty() {
                        ".".into()
                    } else {
                        rel.into()
                    },
                    message: format!("cannot list directory entry: {e}"),
                });
                continue;
            }
        };
        match entry.file_type() {
            Ok(ft) => children.push((entry.file_name(), entry.path(), ft)),
            Err(e) => out.errors.push(FileError {
                path: join(rel, &entry.file_name().to_string_lossy()),
                message: format!("cannot inspect: {e}"),
            }),
        }
    }
    children.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, path, file_type) in children.into_iter().rev() {
        stack.push(Item {
            rel: join(rel, &name.to_string_lossy()),
            path,
            depth,
            file_type,
        });
    }
}

fn join(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent}/{name}")
    }
}

fn skipped(path: &str, reason: SkipReason) -> Skipped {
    Skipped {
        path: path.to_owned(),
        reason,
    }
}

// `Option` because other platforms have no inode to compare.
#[cfg(unix)]
#[allow(clippy::unnecessary_wraps)]
fn identity(meta: &fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
fn identity(_meta: &fs::Metadata) -> Option<(u64, u64)> {
    None
}

/// Read a listed file, applying the size, binary and UTF-8 checks.
pub fn read(entry: &FileEntry, opts: &WalkOptions) -> Content {
    let file = match File::open(&entry.path) {
        Ok(f) => f,
        Err(e) => return Content::Error(format!("cannot open: {e}")),
    };
    let meta = match file.metadata() {
        Ok(m) => m,
        Err(e) => return Content::Error(format!("cannot inspect: {e}")),
    };
    if entry.identity.is_some() && identity(&meta) != entry.identity {
        return Content::Skipped(SkipReason::ChangedDuringScan);
    }
    if !meta.is_file() {
        return Content::Skipped(SkipReason::NotRegularFile);
    }
    if meta.len() > opts.max_file_bytes {
        return Content::Skipped(SkipReason::TooLarge);
    }
    let mut bytes = Vec::new();
    // The file can grow after the size check; never read past the limit.
    let limit = opts.max_file_bytes.saturating_add(1);
    if let Err(e) = file.take(limit).read_to_end(&mut bytes) {
        return Content::Error(format!("cannot read: {e}"));
    }
    if bytes.len() as u64 > opts.max_file_bytes {
        return Content::Skipped(SkipReason::TooLarge);
    }
    decode(bytes)
}

/// Binary and UTF-8 checks on file bytes.
pub fn decode(bytes: Vec<u8>) -> Content {
    let head = &bytes[..bytes.len().min(BINARY_SNIFF_BYTES)];
    if head.contains(&0) {
        return Content::Skipped(SkipReason::Binary);
    }
    match String::from_utf8(bytes) {
        Ok(text) => Content::Text(text),
        Err(e) => {
            let bytes = e.into_bytes();
            let lossy = String::from_utf8_lossy(&bytes);
            let total = lossy.chars().count().max(1);
            let replaced = lossy.chars().filter(|&c| c == '\u{FFFD}').count();
            // Text in a legacy encoding or with a stray byte has a few
            // invalid sequences; binary data has many.
            if replaced > 8 && replaced * 10 > total {
                Content::Skipped(SkipReason::NotUtf8)
            } else {
                Content::Text(lossy.into_owned())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rels(w: &Walk) -> Vec<&str> {
        w.files.iter().map(|f| f.rel_path.as_str()).collect()
    }

    fn reasons(w: &Walk) -> Vec<(String, SkipReason)> {
        w.skipped
            .iter()
            .map(|s| (s.path.clone(), s.reason))
            .collect()
    }

    fn tree(files: &[(&str, &[u8])]) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        for (path, content) in files {
            let p = tmp.path().join(path);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, content).unwrap();
        }
        tmp
    }

    #[test]
    fn deterministic_sorted_depth_first_order() {
        let tmp = tree(&[
            ("b.md", b"b"),
            ("a/z.md", b"z"),
            ("a/b/c.md", b"c"),
            ("A.md", b"A"),
            (".github/workflows/x.yml", b"x"),
        ]);
        let w = walk(tmp.path(), &WalkOptions::default()).unwrap();
        assert_eq!(
            rels(&w),
            vec![
                ".github/workflows/x.yml",
                "A.md",
                "a/b/c.md",
                "a/z.md",
                "b.md"
            ]
        );
        assert!(!w.truncated);
        let again = walk(tmp.path(), &WalkOptions::default()).unwrap();
        assert_eq!(rels(&w), rels(&again));
    }

    #[test]
    fn skip_dirs_are_recorded() {
        let tmp = tree(&[
            ("node_modules/x/README.md", b"x"),
            (".git/config", b"x"),
            ("src/target/deep.md", b"x"),
            ("ok.md", b"x"),
        ]);
        let w = walk(tmp.path(), &WalkOptions::default()).unwrap();
        assert_eq!(rels(&w), vec!["ok.md"]);
        let r = reasons(&w);
        assert!(r.contains(&(".git".into(), SkipReason::ExcludedDir)));
        assert!(r.contains(&("node_modules".into(), SkipReason::ExcludedDir)));
        assert!(r.contains(&("src/target".into(), SkipReason::ExcludedDir)));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_never_followed() {
        let tmp = tree(&[("inside/real.md", b"real")]);
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret.txt"), "AKIA_TEST_FAKE").unwrap();
        let root = tmp.path().join("inside");
        std::os::unix::fs::symlink(outside.path().join("secret.txt"), root.join("link.md"))
            .unwrap();
        std::os::unix::fs::symlink(outside.path(), root.join("dirlink")).unwrap();
        let w = walk(&root, &WalkOptions::default()).unwrap();
        assert_eq!(rels(&w), vec!["real.md"]);
        let r = reasons(&w);
        assert!(r.contains(&("link.md".into(), SkipReason::Symlink)));
        assert!(r.contains(&("dirlink".into(), SkipReason::Symlink)));
        // A symlink as the root itself is not followed either.
        let w = walk(&root.join("link.md"), &WalkOptions::default()).unwrap();
        assert!(w.files.is_empty());
        assert_eq!(reasons(&w), vec![("link.md".into(), SkipReason::Symlink)]);
        let w = walk(&root.join("dirlink"), &WalkOptions::default()).unwrap();
        assert!(w.files.is_empty());
        assert_eq!(w.skipped[0].reason, SkipReason::Symlink);
    }

    #[test]
    fn single_file_root() {
        let tmp = tree(&[("docs/AGENTS.md", b"hi")]);
        let w = walk(&tmp.path().join("docs/AGENTS.md"), &WalkOptions::default()).unwrap();
        assert_eq!(rels(&w), vec!["AGENTS.md"]);
        assert_eq!(w.root_dir, tmp.path().join("docs"));
    }

    #[test]
    fn missing_root_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let e = walk(&tmp.path().join("nope"), &WalkOptions::default()).unwrap_err();
        assert!(e.to_string().contains("cannot read scan root"));
    }

    #[test]
    fn file_and_depth_limits_truncate() {
        let tmp = tree(&[("a.md", b"1"), ("b.md", b"2"), ("c.md", b"3")]);
        let opts = WalkOptions {
            max_files: 2,
            ..WalkOptions::default()
        };
        let w = walk(tmp.path(), &opts).unwrap();
        assert_eq!(rels(&w), vec!["a.md", "b.md"]);
        assert!(w.truncated);
        assert_eq!(reasons(&w), vec![("c.md".into(), SkipReason::FileLimit)]);

        let tmp = tree(&[("1/2/3/deep.md", b"x"), ("1/shallow.md", b"y")]);
        let opts = WalkOptions {
            max_depth: 2,
            ..WalkOptions::default()
        };
        let w = walk(tmp.path(), &opts).unwrap();
        assert_eq!(rels(&w), vec!["1/shallow.md"]);
        assert!(w.truncated);
        assert_eq!(reasons(&w), vec![("1/2".into(), SkipReason::DepthLimit)]);
    }

    #[test]
    fn deep_trees_do_not_recurse() {
        let tmp = tempfile::tempdir().unwrap();
        let mut p = tmp.path().to_path_buf();
        for _ in 0..80 {
            p.push("d");
        }
        fs::create_dir_all(&p).unwrap();
        fs::write(p.join("x.md"), "x").unwrap();
        let w = walk(tmp.path(), &WalkOptions::default()).unwrap();
        assert!(w.files.is_empty());
        assert!(w.truncated);
    }

    #[test]
    fn read_applies_size_binary_and_utf8_checks() {
        let tmp = tree(&[
            ("text.md", b"hello"),
            ("big.md", &[b'a'; 2048]),
            ("bin.dat", b"ab\0cd"),
            ("binary-ish.md", &[0xE9; 64]),
            (
                "latin1.md",
                b"caf\xe9 cr\xe8me br\xfbl\xe9e, ignore previous instructions",
            ),
            (
                "mostly.md",
                b"ignore previous instructions \xff and more text here",
            ),
        ]);
        let opts = WalkOptions {
            max_file_bytes: 1024,
            ..WalkOptions::default()
        };
        let w = walk(tmp.path(), &opts).unwrap();
        let get = |name: &str| {
            let e = w.files.iter().find(|f| f.rel_path == name).unwrap();
            read(e, &opts)
        };
        assert_eq!(get("text.md"), Content::Text("hello".into()));
        assert_eq!(get("big.md"), Content::Skipped(SkipReason::TooLarge));
        assert_eq!(get("bin.dat"), Content::Skipped(SkipReason::Binary));
        assert_eq!(get("binary-ish.md"), Content::Skipped(SkipReason::NotUtf8));
        // Legacy-encoded text is scanned with replacement characters.
        assert!(matches!(get("latin1.md"), Content::Text(t) if t.contains("ignore previous")));
        // One stray byte does not hide the file.
        match get("mostly.md") {
            Content::Text(t) => assert!(t.contains("ignore previous") && t.contains('\u{FFFD}')),
            other => panic!("{other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn swapped_files_are_noticed() {
        let tmp = tree(&[("a.md", b"original")]);
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("secret.txt");
        fs::write(&target, "AKIA_TEST_FAKE_SWAPPED").unwrap();
        let w = walk(tmp.path(), &WalkOptions::default()).unwrap();
        // Between listing and reading, the file becomes a link elsewhere.
        let p = tmp.path().join("a.md");
        fs::remove_file(&p).unwrap();
        std::os::unix::fs::symlink(&target, &p).unwrap();
        assert_eq!(
            read(&w.files[0], &WalkOptions::default()),
            Content::Skipped(SkipReason::ChangedDuringScan)
        );
    }

    #[cfg(unix)]
    #[test]
    fn fifos_are_not_opened() {
        let tmp = tempfile::tempdir().unwrap();
        let fifo = tmp.path().join("pipe.md");
        let status = std::process::Command::new("mkfifo").arg(&fifo).status();
        if !status.is_ok_and(|s| s.success()) {
            return;
        }
        let w = walk(tmp.path(), &WalkOptions::default()).unwrap();
        assert!(w.files.is_empty());
        assert_eq!(
            reasons(&w),
            vec![("pipe.md".into(), SkipReason::NotRegularFile)]
        );
    }
}
