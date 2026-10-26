# Known limitations

This file is the honest companion to `threat-model.md`. If a protection is
missing, partial or backend-specific, it is listed here. Please keep it
current: a limitation that is fixed is removed with the PR that fixes it, and
a new gap is added with the PR that discovers it.

Status: **Phase 2 in progress**. `agentkeep run` works on Linux with the
namespaces backend, and all sandbox traffic goes through the egress proxy
(`[network]` and `[dlp]` rules are enforced); `policy init|show|check`,
`doctor` and `approve` work everywhere the binary builds. `scan`,
`mcp-gateway`, `log` and `report` are not implemented yet and exit with
status 70.

## General

- agentkeep reduces blast radius. It does not make an agent trustworthy, and
  it does not stop the agent from sending data it can read to the model
  provider you allowed.
- Project-level persistence (git hooks, `.cargo/config.toml`, `.npmrc`,
  editor task files) is detected and reported, not blocked (threat F8).
- Command rules (`[commands]`) are enforced by a PATH shim, which a process can
  bypass by calling a binary through its absolute path. Treat them as a guard
  rail for well-behaved agents. Filesystem and network rules are the real
  boundary. Linux may gain enforced command rules through seccomp user
  notification in Phase 1.
- No disk quota. An agent can fill the disk inside the project directory.
- The sandbox has only a loopback interface and no DNS. The only way out is
  the egress proxy, reached through `127.0.0.1:3128` inside the sandbox.
  Tools that ignore `HTTP_PROXY`/`HTTPS_PROXY` have no network inside the
  sandbox. This is fail-closed by design. Presets list known offenders.
- Agent presets (`--preset`) land in Phase 5; `run` refuses the flag until
  then.
- The approval prompt reads from `/dev/tty`, the same terminal the agent's
  own UI reads from. While a prompt is open, a keystroke may go to either.
  `agentkeep approve <socket>` from a second terminal avoids this.
- The audit log records `exec` events only for shimmed commands (those named
  by `[commands]` rules), not every process. Full process accounting is a
  Phase 5 item.
- TLS inspection breaks clients that pin certificates. Those hosts go in
  `network.passthrough`, where they get allowlist control but no DLP.

## Egress proxy and DLP

- DLP is pattern matching on plaintext. A secret that is encoded (base64,
  hex, compression, including a `Content-Encoding: gzip` request body),
  split across requests, or in a format no detector knows leaves through an
  allowed host. It stops accidental and naive exfiltration, not a sender
  who is trying to evade it (threat N2).
- Bodies are streamed, not buffered: the request line and headers are
  checked before anything is sent, but body bytes are forwarded as they are
  scanned. When a secret in a body is blocked, the origin has already
  received the headers and every earlier chunk, and if the secret straddles
  two chunks, the part in the earlier chunk. The streaming scan never
  misses a whole secret that a one-buffer scan would block (property test
  in `dlp.rs`, fuzz target `proxy_inputs`).
- A `CONNECT` tunnel is classified by its first bytes: TLS is terminated and
  scanned, plaintext HTTP is scanned, anything else (SSH, database
  protocols, protocols where the server speaks first) is refused unless the
  host is in `network.passthrough`.
- `network.passthrough` hosts, every tunnel when `network.tls_inspect =
  false`, and WebSocket frames after the upgrade handshake are not scanned;
  the audit log marks them `inspected: false` (N7). The escape suite pins
  this so a change is deliberate.
- Inspection needs SNI: HTTPS to an IP literal through an inspected tunnel
  fails the handshake. Use a name or `passthrough`.
- The `CONNECT` host decides the destination; the inner `Host` header and
  SNI are not cross-checked against it. Domain fronting through an allowed
  CDN reaches whatever that CDN routes the `Host` header to.
- `network.allow_private = true` opens every private, loopback and
  link-local range to allowed names, including cloud metadata at
  `169.254.169.254` if it is allowed. There is no separate metadata block.
- A secret passed with `env.pass` is bound to its provider's API host only
  for well-known names (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GH_TOKEN`,
  ...). Any other name without a `dlp.allow_provider_keys_to` entry may be
  sent to any allowed host.
- The project's `agentkeep.toml` (untrusted when the repository is, threat
  S1) can set `network.tls_inspect = false`, `network.allow_private = true`,
  `network.trusted_cas`, `dlp.enabled = false`, `dlp.report_only` and
  `env.pass` (which passes a host variable into the sandbox) without an
  `[override]` acknowledgement or a warning. Review a cloned repository's
  policy file before running in it. Found while writing the network escape
  tests, which use exactly this to configure their local origins.
- The audit log records the sandboxed command line verbatim in
  `session.start`, so a secret passed as an argument is written to it.
  `audit.redact` is parsed but not implemented (L-A3).
- Every proxied request opens a new connection, and for HTTPS a new TLS
  handshake, to the origin; there is no connection pool. This is most of
  the added latency in `docs/benchmarks.md`.
- A tunnel whose client sends nothing for 10 seconds is closed and logged
  as denied.

## Linux backend

- Requires unprivileged user namespaces. Some distributions restrict them
  (`kernel.unprivileged_userns_clone=0`, or Ubuntu's AppArmor
  `kernel.apparmor_restrict_unprivileged_userns=1`). The probe prints the
  exact setting to change; otherwise the container backend is used.
- Landlock needs kernel 5.13+. TCP restriction (Landlock ABI 4) needs 6.7+.
  Older kernels get mount-namespace isolation only; the capability table
  shows which layers are active.
- cgroup limits need a writable cgroup v2 directory for the agentkeep
  process *and* permission to enable controllers for a child cgroup. Under a
  systemd user session the leaf scope usually contains other processes, so
  enabling controllers fails and agentkeep falls back to rlimits:
  `RLIMIT_AS` for memory (address space, not resident memory, so programs
  that reserve large virtual ranges may fail earlier than expected) and
  `RLIMIT_NPROC` for pids (per user namespace on Linux 5.14+). `cpu_percent`
  is not enforced without cgroups. `agentkeep doctor` reports which path is
  active. A `systemd-run --scope` integration is planned.
- Hidden *files* (as opposed to directories) under a visible tree are
  covered with an empty read-only file. A process can see that the path
  exists, just not its contents.
- The sandbox's `/etc` is the host's `/etc` read-only, with `passwd`, `group`,
  `shadow`, `gshadow`, `sudoers`, SSH host keys, Docker and Kubernetes
  configs replaced or hidden. Other host-specific files in `/etc` remain
  readable.

## macOS backend

- Built on `sandbox-exec` and Seatbelt profiles, which Apple has marked
  deprecated but still ships and uses internally. If Apple removes it, the
  container backend is the fallback.
- No mount namespace: the profile denies access to paths rather than making
  them disappear, so an agent can observe that `~/.ssh` exists even though it
  cannot read it.
- No pid namespace and no seccomp. Process visibility is limited by the
  profile, not by isolation.
- Hardlinks created inside the project to files outside it are not covered.
- Escape tests for this backend run only in CI on macOS runners. On other
  hosts the suite reports `UNTESTED ON THIS HOST` for it.

## Container backend

- Trusts the container runtime (Podman or Docker). A rootful Docker daemon
  makes the user effectively root on the host; prefer rootless Podman.
- Requires the runtime CLI on `PATH`. The daemon socket is never mounted into
  the sandbox.
- gVisor (`--runtime=runsc`) is used only when the policy asks and the runtime
  reports it; otherwise the runtime's default seccomp profile applies.
- Startup overhead is well above the 50 ms target; it is measured and
  published separately.

## Windows and WSL2

- agentkeep on Windows re-executes inside WSL2 and uses the Linux backend
  there. Native Windows sandboxing (AppContainer, Windows Sandbox) is not
  implemented.
- Policy paths are POSIX paths describing the sandbox tree. On Windows
  they refer to paths inside WSL2; drive-letter paths are not accepted.
- `/mnt/c` and other drive mounts are visible inside WSL2 by default and must
  be hidden by the policy; the Windows preset does this, but a custom policy
  that removes it exposes the Windows filesystem.
- Windows credentials stores (Credential Manager, browser profiles under
  `%APPDATA%`) are reachable through `/mnt/c` if that mount is exposed.
- Escape tests for this path run only in CI on Windows runners.

## Scanner

- Detection is pattern-based. Precision and recall are measured against the
  fixture corpus and published; both are below 1.0 by construction.
- Instruction-like text aimed at agents is inherently ambiguous. Expect false
  positives in documentation that *describes* prompt injection.

## MCP gateway

- stdio transport only in v0.1.0. HTTP and SSE servers are not proxied.
- Injection flagging on tool results is heuristic and detect-only by default.
- A standalone gateway (not started through `agentkeep run`) does not sandbox
  the server process; it only filters and logs.
