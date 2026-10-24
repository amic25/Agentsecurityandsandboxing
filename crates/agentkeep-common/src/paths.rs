//! Path expansion and lexical normalisation.
//!
//! Policies refer to paths with `~` and `$PROJECT`. These helpers resolve them
//! without touching the filesystem, so a policy can be validated for a path
//! that does not exist yet and so the result is deterministic in tests.

use std::path::{Component, Path, PathBuf};

/// Expand a leading `~` or `~/` to `home` and `$PROJECT` / `${PROJECT}` to
/// `project`, then normalise lexically (see [`normalize`]).
///
/// Only a leading tilde is expanded; `~user` forms are left untouched because
/// resolving other users' homes is never what a policy means.
pub fn expand(raw: &str, home: &Path, project: &Path) -> PathBuf {
    let with_project = raw
        .replace("${PROJECT}", &project.to_string_lossy())
        .replace("$PROJECT", &project.to_string_lossy());
    let expanded: PathBuf = if with_project == "~" {
        home.to_path_buf()
    } else if let Some(rest) = with_project.strip_prefix("~/") {
        home.join(rest)
    } else {
        PathBuf::from(with_project)
    };
    normalize(&expanded)
}

/// Remove `.` components and resolve `..` lexically, without following
/// symlinks. `..` at the root is dropped. Relative paths stay relative.
///
/// This is deliberately *not* `canonicalize`: the sandbox decides what a
/// symlink points to inside its own mount namespace, and a policy must mean
/// the same thing whether or not the path exists on the host.
pub fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                let popped = out.pop();
                if !popped && !path.has_root() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        if path.has_root() {
            out.push("/");
        } else {
            out.push(".");
        }
    }
    out
}

/// True when `path` is `base` or lies underneath it. Both are compared
/// lexically after normalisation; neither is required to exist.
pub fn is_within(path: &Path, base: &Path) -> bool {
    let path = normalize(path);
    let base = normalize(base);
    path.starts_with(&base)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_tilde_and_project() {
        let home = Path::new("/home/u");
        let project = Path::new("/home/u/proj");
        assert_eq!(
            expand("~/.ssh", home, project),
            PathBuf::from("/home/u/.ssh")
        );
        assert_eq!(expand("~", home, project), PathBuf::from("/home/u"));
        assert_eq!(
            expand("$PROJECT/.env", home, project),
            PathBuf::from("/home/u/proj/.env")
        );
        assert_eq!(
            expand("${PROJECT}/a", home, project),
            PathBuf::from("/home/u/proj/a")
        );
        assert_eq!(expand("~other/x", home, project), PathBuf::from("~other/x"));
    }

    #[test]
    fn normalises_dots() {
        assert_eq!(normalize(Path::new("/a/./b/../c")), PathBuf::from("/a/c"));
        assert_eq!(normalize(Path::new("/../..")), PathBuf::from("/"));
        assert_eq!(normalize(Path::new("a/../..")), PathBuf::from(".."));
        assert_eq!(normalize(Path::new(".")), PathBuf::from("."));
    }

    #[test]
    fn within_checks_boundaries() {
        assert!(is_within(Path::new("/p/x"), Path::new("/p")));
        assert!(is_within(Path::new("/p"), Path::new("/p")));
        assert!(!is_within(Path::new("/px"), Path::new("/p")));
        assert!(!is_within(Path::new("/p/../q"), Path::new("/p")));
    }
}
