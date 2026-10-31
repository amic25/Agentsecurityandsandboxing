# Fuzz targets

Requires nightly and `cargo install cargo-fuzz`.

```sh
cd fuzz
cargo +nightly fuzz run policy_parse -- -max_total_time=60
```

Targets:

- `policy_parse`: parse → merge → resolve → compile → decide.
- `proxy_inputs`: DLP scanning of arbitrary bytes, whole and streamed in
  chunks of every size (a secret blocked as one buffer must also be blocked
  when streamed), the redaction of logged samples, and destination parsing
  and matching (`split_host_port`, `pattern_matches`, `is_non_public`).
- `scan_inputs`: arbitrary bytes as a file under `x.md`,
  `.github/workflows/x.yml`, `.mcp.json`, `.codex/config.toml` and
  `agentkeep.toml` through the scanner with the built-in rules (finding
  ranges must stay inside the input, and the result must render as text,
  JSON and SARIF), and as a rule YAML file through the rule loader and its
  inline examples.

Planned: `proxy_http` (the HTTP/CONNECT request path), `mcp_frame`
(Phase 4).

Without nightly, `cargo check --manifest-path fuzz/Cargo.toml --bins`
type-checks the targets on stable. Coverage-guided runs also work on
stable without a sanitizer by passing the flags cargo-fuzz would set:

```sh
RUSTFLAGS="-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 \
  -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
  -Cllvm-args=-sanitizer-coverage-pc-table \
  -Cllvm-args=-sanitizer-coverage-trace-compares --cfg fuzzing -Cdebug-assertions" \
  cargo build --release --manifest-path fuzz/Cargo.toml --bin proxy_inputs \
  --target x86_64-unknown-linux-gnu
fuzz/target/x86_64-unknown-linux-gnu/release/proxy_inputs fuzz/corpus/proxy_inputs -max_total_time=60
```
