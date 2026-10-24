# Working on agentkeep as an AI agent

This file is read by coding agents (Claude Code, Codex, Gemini CLI, Cursor and
others). It tells you how this repository works and what we expect.

## What this project is

A security sandbox and policy layer for AI agents, written in Rust. Trust is
the product. Read `PLAN.md` for the architecture and `docs/threat-model.md`
before touching `crates/agentkeep-sandbox`, `crates/agentkeep-proxy` or
`crates/agentkeep-policy`.

## Rules that are not negotiable

1. **Never claim a protection that is not implemented and tested.** If you
   add a rule, add an escape test in `tests/escape/` (or a corpus fixture in
   `tests/corpus/` for scanner rules) that fails closed. If you find a gap,
   write it in `docs/limitations.md` instead of papering over it.
2. **Attack fixtures are benign.** Fake secrets only (`AKIA_TEST_FAKE...`,
   `sk-test-fake-...`), exfiltration targets on localhost only, no working
   exploits against third parties.
3. **No telemetry, no network calls** by agentkeep itself except the explicit
   opt-in update check.
4. **No new dependency without a row in `docs/dependencies.md`** and a green
   `cargo deny check`.
5. **Unsafe code only in `agentkeep-sandbox`**, each block with a `// SAFETY:`
   comment. Every other crate has `#![forbid(unsafe_code)]`.
6. **Do not push, publish, tag or release** without explicit human approval.

## Before every commit

```sh
scripts/ci-local.sh
```

It runs fmt, clippy with `-D warnings`, doc build, tests, cargo-deny,
cargo-audit, the pinned-actions check and the escape suite. Commit only when
it passes. Sign off commits (`git commit -s`).

## Layout

- `crates/agentkeep` – CLI; keep it thin, logic lives in the library crates
- `crates/agentkeep-policy` – schema, parser, merge, `decide()`
- `crates/agentkeep-sandbox` – `Backend` trait and the backends
- `crates/agentkeep-proxy` – egress proxy and DLP
- `crates/agentkeep-mcp` – MCP gateway
- `crates/agentkeep-scan` – scanner and YAML rule engine
- `crates/agentkeep-audit` – hash-chained JSONL log, reports
- `crates/agentkeep-tui` – log viewer
- `rules/`, `presets/` – community YAML, see their READMEs
- `tests/escape`, `tests/corpus`, `fuzz/`, `benches/`

## Style

- Rust 2021, `rustfmt.toml` as given, clippy pedantic is on.
- Errors carry context; no `unwrap()` outside tests.
- Comments explain *why*, not *what*.
- Keep PRs small and single-purpose. Reference threat-model ids (`F1`, `N3`)
  in commit messages for protection changes.
