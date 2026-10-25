# Known limitations

This file is the honest companion to `threat-model.md`. If a protection is
missing, partial or backend-specific, it is listed here. Please keep it
current: a limitation that is fixed is removed with the PR that fixes it, and
a new gap is added with the PR that discovers it.

Status: **Phase 1**. `agentkeep run` works on Linux with the namespaces
backend; `policy init|show|check`, `doctor` and `approve` work everywhere
the binary builds. The proxy (`network` rules), `scan`, `mcp-gateway`, `log`
and `report` are not implemented yet and exit with status 70. There is no
network inside the sandbox at all until Phase 2 adds the proxy.

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
- **Phase 1: no network at all.** The sandbox has only a loopback interface
  and no DNS. The egress proxy that lets allowed domains through lands in
  Phase 2. Until then an agent cannot reach its model API from inside
  `agentkeep run`.
- Tools that ignore `HTTP_PROXY`/`HTTPS_PROXY` have no network inside the
  sandbox. This is fail-closed by design. Presets list known offenders.
- `[network]` rules are parsed and validated but not enforced until Phase 2.
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
