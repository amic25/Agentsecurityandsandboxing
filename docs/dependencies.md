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
| `anyhow` | `agentkeep` (CLI only) | Error context chains for user-facing messages; libraries use typed errors instead | Hand-rolled error enum in the binary: more code, same output |
| `clap` (derive, wrap_help) | `agentkeep` | De-facto standard argument parser; derive keeps the CLI surface declarative and testable; `debug_assert` validates it in tests | `argh`, `lexopt`: smaller but lose generated help quality and value validation we rely on for policy-sensitive flags |
| `globset` | `agentkeep-policy` | Command patterns (`git push*`) need glob matching with well-defined semantics and a compiled set for speed; it is the matcher behind ripgrep | `regex` alone: users would have to write regexes in policy files; hand-written glob: easy to get wrong |
| `landlock` | `agentkeep-sandbox` (Linux) | Safe bindings to the Landlock syscalls with best-effort ABI negotiation, maintained by the Landlock kernel authors | Raw syscalls via `libc`: doable but the ABI compatibility logic is the hard part |
| `libc` | `agentkeep-sandbox` (Linux) | The few syscalls `rustix` does not wrap in the form we need (raw `clone`, `fexecve`, `mount` data strings, `capset`, `ioctl SIOCSIFFLAGS`, signal dispositions). Confined to `linux/sys.rs` | `nix`: a larger safe layer, but we already use `rustix` for the safe parts |
| `rustix` | `agentkeep-sandbox` (Linux) | Safe, `io-safety`-aware wrappers for `pipe`, `pidfd`, `setrlimit`, `prctl`, `sethostname`, `fcntl` | `nix`: comparable; `rustix` has no libc dependency on Linux and smaller surface |
| `seccompiler` | `agentkeep-sandbox` (Linux) | Pure-Rust BPF compiler for seccomp filters, from the Firecracker project; no libseccomp C dependency, so the binary stays static | `libseccomp` (C): widely used but breaks the single-static-binary goal |
| `serde` (derive) | policy, sandbox, audit | Schema definitions double as documentation; derive keeps them in one place | Hand-written parsers: far more code for the same guarantees |
| `serde_json` | sandbox (plan IPC), audit (JSONL), CLI (approval protocol) | Canonical key ordering (no `preserve_order`) makes the audit hash chain deterministic | Alternatives are smaller but less battle-tested |
| `sha2` | `agentkeep-audit` | SHA-256 for the audit hash chain; RustCrypto, pure Rust, widely audited | `ring`: brings a C/asm build; overkill for a hash |
| `tempfile` | sandbox (plan file), CLI (session scratch dir) | Secure temp files and directories with automatic cleanup and O_TMPFILE where available | `std` only: would need to reimplement safe unique naming |
| `thiserror` | all library crates | Typed error enums with derived `Display` and `source` | Manual `impl Error`: boilerplate without benefit |
| `toml` | policy, CLI | The policy file format; version 1.x reports spans for line/column errors | `toml_edit`: needed only if we rewrote files preserving comments (`policy init` writes from a template instead) |

## Development dependencies

| Crate | Why |
|---|---|
| `proptest` | Property tests for the policy engine and unit parsers |
| `tempfile` | Fixture directories for discovery, audit and escape tests |
| `libfuzzer-sys` (in `fuzz/`, separate workspace) | cargo-fuzz targets |

## Planned (will be justified when added)

Phase 2: `tokio`, `hyper`, `hyper-util`, `rustls`, `rcgen`, `webpki-roots`,
`aho-corasick`, `regex`. Phase 3: `unicode-security`. Phase 5: `ratatui`,
`crossterm`, `criterion` (dev).
