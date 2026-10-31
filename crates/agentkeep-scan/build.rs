//! Embed the rule set: walk `<workspace>/rules/**/*.yaml` and generate a
//! table of `include_str!` entries, so the binary carries its rules and
//! works with no rule directory on disk.

use std::env;
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let rules_dir = manifest.join("..").join("..").join("rules");
    println!("cargo:rerun-if-changed={}", rules_dir.display());

    let mut files = Vec::new();
    if rules_dir.is_dir() {
        collect(&rules_dir, &rules_dir, &mut files)?;
    }
    files.sort();

    let mut out = String::from(
        "/// Embedded rule files: (path relative to `rules/`, contents).\n\
         pub(crate) static EMBEDDED: &[(&str, &str)] = &[\n",
    );
    for (rel, abs) in &files {
        println!("cargo:rerun-if-changed={}", abs.display());
        let abs = abs
            .to_str()
            .ok_or_else(|| format!("rule path is not UTF-8: {}", abs.display()))?;
        // `{:?}` of a str is a valid Rust string literal.
        writeln!(out, "    ({rel:?}, include_str!({abs:?})),")?;
    }
    out.push_str("];\n");
    let dest = PathBuf::from(env::var("OUT_DIR")?).join("embedded_rules.rs");
    fs::write(dest, out)?;
    Ok(())
}

/// Every `*.yaml` under `dir`, with its `/`-separated path relative to
/// `root`. Symlinks are skipped: the embedded set must be exactly what is
/// in the tree.
fn collect(
    root: &Path,
    dir: &Path,
    out: &mut Vec<(String, PathBuf)>,
) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            println!("cargo:rerun-if-changed={}", path.display());
            collect(root, &path, out)?;
        } else if ft.is_file() && path.extension().is_some_and(|e| e == "yaml") {
            let rel = path
                .strip_prefix(root)?
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            out.push((rel, path.canonicalize()?));
        }
    }
    Ok(())
}
