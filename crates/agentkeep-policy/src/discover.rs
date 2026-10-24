//! Locating policy files on disk and assembling the layer list.

use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::defaults::DEFAULT_POLICY;
use crate::merge::{Layer, Source};
use crate::parse::{parse_str, ParseError};

/// Name of the per-project policy file.
pub const PROJECT_FILE_NAME: &str = "agentkeep.toml";

/// Errors while reading policy files.
#[derive(Debug, Error)]
pub enum LoadError {
    /// A file could not be read.
    #[error("cannot read {path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// A file did not parse.
    #[error(transparent)]
    Parse(#[from] ParseError),
}

/// Walk up from `start` looking for `agentkeep.toml`. Stops at the first
/// directory that contains either the file or a `.git` entry (the project
/// root), so a policy in a parent *unrelated* directory is never picked up.
pub fn find_project_file(start: &Path) -> Option<PathBuf> {
    for dir in start.ancestors() {
        let candidate = dir.join(PROJECT_FILE_NAME);
        if candidate.is_file() {
            return Some(candidate);
        }
        if dir.join(".git").exists() {
            return None;
        }
    }
    None
}

/// The project root: the nearest ancestor containing `.git`, or `start`.
pub fn project_root(start: &Path) -> PathBuf {
    start
        .ancestors()
        .find(|d| d.join(".git").exists())
        .map_or_else(|| start.to_path_buf(), Path::to_path_buf)
}

/// The global policy path: `$XDG_CONFIG_HOME/agentkeep/agentkeep.toml` or
/// `~/.config/agentkeep/agentkeep.toml`.
pub fn global_file(home: &Path, xdg_config_home: Option<&Path>) -> PathBuf {
    xdg_config_home
        .map_or_else(|| home.join(".config"), Path::to_path_buf)
        .join("agentkeep")
        .join(PROJECT_FILE_NAME)
}

/// Read and parse one file into a layer.
pub fn load_file(path: &Path, source: Source) -> Result<Layer, LoadError> {
    let text = std::fs::read_to_string(path).map_err(|e| LoadError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let file = parse_str(&text, &path.display().to_string())?;
    Ok(Layer {
        source,
        base_dir: path.parent().map(Path::to_path_buf),
        file,
    })
}

/// The built-in defaults as the first layer.
///
/// # Panics
///
/// If the compiled-in defaults do not parse, which is a build bug covered by
/// a unit test. Running with an empty lowest layer would be *less*
/// restrictive, so this refuses loudly instead.
pub fn defaults_layer() -> Layer {
    #[allow(clippy::expect_used)]
    let file = parse_str(DEFAULT_POLICY, "<defaults>").expect("built-in defaults must parse");
    Layer {
        source: Source::Defaults,
        base_dir: None,
        file,
    }
}

/// Assemble the standard layer list: defaults, optional global file,
/// optional project file. Presets and CLI overrides are appended by the
/// caller.
pub fn standard_layers(
    home: &Path,
    xdg_config_home: Option<&Path>,
    cwd: &Path,
    explicit_project_file: Option<&Path>,
) -> Result<Vec<Layer>, LoadError> {
    let mut layers = vec![defaults_layer()];
    let global = global_file(home, xdg_config_home);
    if global.is_file() {
        layers.push(load_file(&global, Source::Global(global.clone()))?);
    }
    let project_file = match explicit_project_file {
        Some(p) => Some(p.to_path_buf()),
        None => find_project_file(cwd),
    };
    if let Some(p) = project_file {
        layers.push(load_file(&p, Source::Project(p.clone()))?);
    }
    Ok(layers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_file_below_git_root_only() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join(PROJECT_FILE_NAME), "schema = 1\n").unwrap();
        let repo = root.join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::create_dir_all(repo.join("src/deep")).unwrap();
        // A file above the git root is not ours.
        assert_eq!(find_project_file(&repo.join("src/deep")), None);
        std::fs::write(repo.join(PROJECT_FILE_NAME), "schema = 1\n").unwrap();
        assert_eq!(
            find_project_file(&repo.join("src/deep")),
            Some(repo.join(PROJECT_FILE_NAME))
        );
        assert_eq!(project_root(&repo.join("src/deep")), repo);
    }

    #[test]
    fn global_path() {
        assert_eq!(
            global_file(Path::new("/h"), None),
            PathBuf::from("/h/.config/agentkeep/agentkeep.toml")
        );
        assert_eq!(
            global_file(Path::new("/h"), Some(Path::new("/xdg"))),
            PathBuf::from("/xdg/agentkeep/agentkeep.toml")
        );
    }

    #[test]
    fn standard_layers_without_files_is_defaults_only() {
        let tmp = tempfile::tempdir().unwrap();
        let layers = standard_layers(tmp.path(), None, tmp.path(), None).unwrap();
        assert_eq!(layers.len(), 1);
    }
}
