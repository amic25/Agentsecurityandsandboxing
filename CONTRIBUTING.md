# Contributing to agentkeep

Thank you. The two most valuable contributions right now are **presets** for
agents we do not support yet and **scanner rules** with fixtures. Both are
plain YAML and need no Rust. See `presets/README.md` and `rules/README.md`.

## Ground rules

- Be kind. The `CODE_OF_CONDUCT.md` applies everywhere in this project.
- Every commit is signed off under the Developer Certificate of Origin
  (`git commit -s`). There is no CLA. The DCO text is in `DCO`.
- Security bugs go through `SECURITY.md`, never a public issue.
- Attack fixtures and tests must be **benign**: fake secrets
  (`AKIA_TEST_FAKE...`), exfiltration only to a server on localhost, and never
  working exploits against third parties.

## Development setup

```sh
rustup show                 # picks up rust-toolchain.toml
cargo install cargo-deny cargo-audit   # optional but CI runs them
scripts/ci-local.sh         # fmt, clippy, doc, test, deny, audit, escape suite
```

Run `scripts/ci-local.sh` before every commit. CI runs the same checks on
Linux (x86_64 and arm64), macOS (Intel and Apple Silicon) and Windows.

## How we work

- **Small commits, one change each.** Use conventional commit prefixes
  (`feat:`, `fix:`, `docs:`, `test:`, `ci:`, `chore:`).
- **No new dependency without a note** in `docs/dependencies.md` saying why
  and what alternative was considered. `cargo deny` must stay green.
- **Never claim a protection that isn't tested.** A new sandbox rule comes
  with an escape test in `tests/escape/` that fails closed on every backend.
  A new scanner rule comes with positive and negative fixtures in
  `tests/corpus/`. Gaps go in `docs/limitations.md`.
- **No telemetry, ever.** agentkeep makes no network calls of its own except
  the explicit, opt-in update check.
- **Unsafe code** is only allowed in `agentkeep-sandbox` for syscalls, each
  block with a `// SAFETY:` comment.

## Pull requests

1. Open an issue first for anything bigger than a bug fix or a preset.
2. Fill in the PR template. Say what you tested and on which OS.
3. Add a line to `CHANGELOG.md` under *Unreleased*.
4. CI must be green, including the DCO check.

## Good first issues

Look for the `good first issue` label. Presets, scanner rules, corpus
fixtures and docs fixes are all well suited to a first contribution.

## Licence

By contributing you agree that your contributions are licensed under the
Apache License 2.0 (`LICENSE`).
