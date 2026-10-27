# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Phase 2 (experimental, UNVERIFIED until macOS CI passes): macOS backend
  (`macos`): a Seatbelt profile generated per session and applied with
  `sandbox-exec`; project and private `HOME`/`TMPDIR` read-write, system
  paths read-only, hidden paths denied even under allowed parents; network
  only through a supervisor-side loopback relay to the egress proxy; command
  shims on macOS; own process group with `RLIMIT_CORE=0` and an approximate
  per-user `RLIMIT_NPROC`. Escape suite made portable (absolute-path probes,
  host loopback, DNS, proxy positive control, fork cap, service managers)
  and required on the macOS CI runners. See `docs/limitations.md`.
- Phase 1: policy engine (`agentkeep-policy`) with layered merge,
  tightening-only semantics, `[override]` acknowledgement and a pure
  `decide()`; `agentkeep policy init|show|check`; `agentkeep doctor`.
- Phase 1: Linux sandbox backend: unprivileged user, mount, pid, net, ipc and
  uts namespaces; private root with the project read-write, system paths
  read-only, home replaced by an empty tmpfs and credential paths hidden;
  fresh `/proc` with `hidepid`; loopback-only network with no DNS; Landlock
  as a second layer; seccomp deny-list (ptrace, mounts, namespaces, bpf,
  io_uring, module loading, ...); no capabilities and `no_new_privs`;
  cgroup v2 limits when available, rlimits otherwise; wall-clock limit.
- Phase 1: command shims for `[commands]` rules with an approval channel
  (terminal prompt or `agentkeep approve <socket>`), deny on timeout.
- Phase 1: hash-chained JSONL audit log (`agentkeep-audit`) recording session
  start and end, scrubbed environment names, shimmed command decisions and
  approvals.
- Phase 1: escape suite (`crates/agentkeep/tests/escape.rs`, 21 tests named
  by threat id) that fails closed and never skips silently; startup
  benchmark (`benches/startup.sh`, ~10 ms overhead on the reference host).
- Phase 0: Cargo workspace with the nine planned crates, CLI command surface
  (`run`, `policy`, `mcp-gateway`, `scan`, `log`, `report`, `approve`,
  `version`), cross-platform CI, cargo-deny and cargo-audit, OpenSSF Scorecard,
  DCO check, pinned GitHub Actions, community files and the threat model.
  No sandboxing is implemented yet; every command except `version` exits with
  status 70.

[Unreleased]: https://github.com/amic25/Agentsecurityandsandboxing/commits/main
