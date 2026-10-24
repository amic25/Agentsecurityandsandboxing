# Dependency policy and justifications

agentkeep is a security tool shipped as a static binary. Every dependency is
code we ask users to trust. Rules:

1. Prefer the standard library. Add a crate only when writing the code
   ourselves would be riskier (crypto, TLS, parsers, syscall bindings).
2. Permissive licences only (see `deny.toml`). No crates with telemetry, no
   crates that fetch at build time, no C dependencies unless unavoidable.
3. Every new crate gets a row below in the same PR that adds it, with the
   alternative considered.
4. `cargo deny check` and `cargo audit` run in CI; a failing advisory blocks
   merges until fixed or explicitly ignored with a dated reason in
   `deny.toml`.

## Runtime dependencies

| Crate | Used by | Why | Alternative considered |
|---|---|---|---|
| `clap` (derive, wrap_help) | `agentkeep` | De-facto standard argument parser; derive keeps the CLI surface declarative and testable; `debug_assert` validates it in tests | `argh`, `lexopt`: smaller but lose generated help quality and value validation we rely on for policy-sensitive flags |

## Development dependencies

None yet.

## Planned (will be justified when added)

`serde`, `serde_json`, `toml`, `tokio`, `hyper`, `hyper-util`, `rustls`,
`rcgen`, `webpki-roots`, `rustix`/`nix`, `landlock`, `seccompiler`, `regex`,
`aho-corasick`, `sha2`, `tracing`, `ratatui`, `crossterm`, `unicode-security`,
`globset`, `thiserror`, `anyhow`; dev: `criterion`, `proptest`, `insta`,
`cargo-fuzz` targets.
