# Known limitations

This file is the honest companion to `threat-model.md`. If a protection is
missing, partial or backend-specific, it is listed here. Please keep it
current: a limitation that is fixed is removed with the PR that fixes it, and
a new gap is added with the PR that discovers it.

Status: **Phase 0**. No sandboxing is implemented yet. Every command except
`agentkeep version` exits with status 70 ("not implemented").

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
- Tools that ignore `HTTP_PROXY`/`HTTPS_PROXY` have no network inside the
  sandbox. This is fail-closed by design. Presets list known offenders.
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
- cgroup limits need cgroup v2 with delegation to the user's session (normal
  under systemd). Without it, `limits.memory` falls back to `RLIMIT_AS` and
  `limits.pids` cannot be enforced.

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
