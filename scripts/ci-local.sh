#!/usr/bin/env bash
# Run the same checks CI runs. Use this before every commit.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> fmt";    cargo fmt --all --check
echo "==> clippy"; cargo clippy --workspace --all-targets --all-features -- -D warnings
echo "==> doc";    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items --quiet
echo "==> test";   cargo test --workspace --locked --quiet
if command -v cargo-deny >/dev/null;  then echo "==> deny";  cargo deny check; else echo "==> deny  (skipped: cargo-deny not installed)"; fi
if command -v cargo-audit >/dev/null; then echo "==> audit"; cargo audit;      else echo "==> audit (skipped: cargo-audit not installed)"; fi
echo "==> pinned actions"; scripts/check-pinned-actions.sh
if [ -x tests/escape/run.sh ]; then echo "==> escape suite"; tests/escape/run.sh; fi
echo "All local checks passed."
