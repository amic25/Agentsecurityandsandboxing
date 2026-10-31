//! `agentkeep scan`: load rules, scan, render, pick the exit code. The work
//! lives in `agentkeep-scan`; this module only wires arguments to it.
//!
//! Exit codes: 0 when no finding is at or above `--fail-on`, 1 when one is
//! (and when `--test-rules` finds a failing example), 2 for usage errors,
//! an unreadable root, a bad rule file or an unwritable output. Errors are
//! returned to `main`, which prints them and exits 2.

use std::fmt::Write as _;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use agentkeep_scan::output::{self, Format};
use agentkeep_scan::report::escape_for_display;
use agentkeep_scan::{engine, rule, Rule, Scanner, Severity, WalkOptions};
use anyhow::{bail, Context};

use crate::cli::{self, ScanArgs, ScanFormat};
use crate::ui;

/// Findings at or above `--fail-on`, or a failing rule example.
const EXIT_FINDINGS: u8 = 1;

/// Run `agentkeep scan`.
pub fn run(args: &ScanArgs) -> anyhow::Result<ExitCode> {
    if let Some(dirs) = &args.test_rules {
        return test_rules(args, dirs);
    }
    let scanner = load(&args.rule_dirs, &[])?;
    if args.list_rules {
        write_stdout(&list(scanner.rules()))?;
        return Ok(ExitCode::SUCCESS);
    }

    let opts = WalkOptions {
        max_file_bytes: args.max_file_size,
        ..WalkOptions::default()
    };
    let report = scanner.scan_with(&args.path, &opts).map_err(flat)?;
    let format = match args.format {
        ScanFormat::Text => Format::Text,
        ScanFormat::Json => Format::Json,
        ScanFormat::Sarif => Format::Sarif,
    };
    // A file is not a terminal, whatever stdout is.
    let colour = args.output.is_none() && output::text::colour_for_stdout();
    let rendered = output::render(&report, scanner.rules(), format, colour)?;
    match &args.output {
        Some(path) => {
            write_report(path, &rendered)
                .with_context(|| format!("cannot write the report to {}", path.display()))?;
            ui::info(&format!(
                "{} finding(s) written to {}",
                report.findings.len(),
                path.display()
            ));
        }
        None => write_stdout(&rendered)?,
    }
    if report.truncated {
        ui::warn("the scan stopped at a file-count or depth limit; some files were not scanned");
    }
    let threshold = severity(args.fail_on);
    Ok(if report.fails_at(threshold) {
        ExitCode::from(EXIT_FINDINGS)
    } else {
        ExitCode::SUCCESS
    })
}

fn severity(s: cli::Severity) -> Severity {
    match s {
        cli::Severity::Info => Severity::Info,
        cli::Severity::Low => Severity::Low,
        cli::Severity::Medium => Severity::Medium,
        cli::Severity::High => Severity::High,
        cli::Severity::Critical => Severity::Critical,
    }
}

/// The built-in rules plus every rule under `dirs` and `more`. Any rule
/// that fails to load, or a duplicate id, is an error: a rule set that is
/// silently missing a rule would scan as clean.
fn load(dirs: &[std::path::PathBuf], more: &[std::path::PathBuf]) -> anyhow::Result<Scanner> {
    let mut rules: Vec<Rule> = agentkeep_scan::builtin::rules()
        .map_err(flat)
        .context("the built-in rules failed to load")?;
    for dir in dirs.iter().chain(more) {
        let loaded = rule::load_dir(dir)
            .map_err(flat)
            .with_context(|| format!("cannot load rules from {}", dir.display()))?;
        rules.extend(loaded);
    }
    Scanner::new(rules).map_err(flat)
}

/// The scanner's errors already name their I/O cause in their message;
/// keep only that message so `main`'s `{:#}` does not print it twice.
fn flat(e: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("{e}")
}

/// `id  severity  title`, one rule per line, ids padded to line up.
fn list(rules: &[Rule]) -> String {
    let width = rules.iter().map(|r| r.id().len()).max().unwrap_or(0);
    let mut out = String::new();
    for r in rules {
        let _ = writeln!(
            out,
            "{:<width$}  {:<8}  {}",
            escape_for_display(r.id()),
            r.severity().as_str(),
            escape_for_display(r.title()),
        );
    }
    out
}

/// Run every loaded rule's inline examples; exit 1 on any failure.
fn test_rules(args: &ScanArgs, dirs: &[std::path::PathBuf]) -> anyhow::Result<ExitCode> {
    let scanner = load(&args.rule_dirs, dirs)?;
    let mut out = String::new();
    let mut examples = 0;
    let mut failed = 0;
    for r in scanner.rules() {
        examples += r.examples().matches.len() + r.examples().nomatch.len();
        let failures = engine::run_examples(r);
        if failures.is_empty() {
            let _ = writeln!(out, "ok    {}", escape_for_display(r.id()));
        } else {
            let _ = writeln!(out, "FAIL  {}", escape_for_display(r.id()));
            for f in &failures {
                let _ = writeln!(out, "      {f}");
            }
            failed += failures.len();
        }
    }
    let rules = scanner.rules().len();
    if failed == 0 {
        let _ = writeln!(out, "\n{rules} rules, {examples} examples: all passed.");
    } else {
        let _ = writeln!(
            out,
            "\n{rules} rules, {examples} examples: {failed} failed."
        );
    }
    write_stdout(&out)?;
    Ok(if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_FINDINGS)
    })
}

/// Write the report to `path` without following a symlink there. In CI the
/// output path usually sits inside a checkout that a pull request controls,
/// and a planted `scan.sarif -> ~/.bashrc` must not redirect the write. The
/// text goes to a temporary file in the same directory first and is renamed
/// into place, so nobody reads half a report and a link swapped in after
/// the check is replaced, not followed.
fn write_report(path: &Path, text: &str) -> anyhow::Result<()> {
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        bail!("it is a symbolic link; refusing to write through it");
    }
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let mut tmp = tempfile::Builder::new()
        .prefix(".agentkeep-scan-")
        .tempfile_in(dir)?;
    tmp.write_all(text.as_bytes())?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

/// Write to stdout. A closed pipe (`agentkeep scan | head`) is not an
/// error worth exit 2: the reader chose to stop, and the exit code must
/// still say whether there were findings.
fn write_stdout(text: &str) -> anyhow::Result<()> {
    let mut out = io::stdout().lock();
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Err(e) if e.kind() != io::ErrorKind::BrokenPipe => Err(e).context("cannot write to stdout"),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severities_map_one_to_one() {
        for (cli, scan) in [
            (cli::Severity::Info, Severity::Info),
            (cli::Severity::Low, Severity::Low),
            (cli::Severity::Medium, Severity::Medium),
            (cli::Severity::High, Severity::High),
            (cli::Severity::Critical, Severity::Critical),
        ] {
            assert_eq!(severity(cli), scan);
        }
    }

    #[test]
    fn the_rule_list_lines_up() {
        let scanner = load(&[], &[]).unwrap();
        let text = list(scanner.rules());
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), scanner.rules().len());
        let width = scanner.rules().iter().map(|r| r.id().len()).max().unwrap();
        for line in &lines {
            let rest = &line[width..];
            assert!(rest.starts_with("  "), "{line}");
            assert!(
                Severity::ALL
                    .iter()
                    .any(|s| rest[2..].starts_with(s.as_str())),
                "{line}"
            );
        }
        assert!(text.contains("risky-shell/curl-pipe-shell"));
    }
}
