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
- The sandboxed command shares the terminal it was started from. Terminal
  input injection with the `TIOCSTI` ioctl (pushing characters that the
  user's shell reads after the session ends) is not blocked by agentkeep on
  any backend. Linux 6.2+ can disable it host-wide with
  `sysctl dev.tty.legacy_tiocsti=0`.
- Degradations reported by the probe are printed and logged, but `run`
  does not yet refuse to start when `sandbox.allow_degraded = false`.

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
- When agentkeep itself runs as root, the kernel exempts the sandbox from
  `RLIMIT_NPROC` (the inner user maps to uid 0), so without a cgroup the
  `pids` limit is not enforced. The escape suite's fork-bomb test reports
  `NOT APPLICABLE` when run as root for this reason; CI runs it unprivileged.
- Hidden *files* (as opposed to directories) under a visible tree are
  covered with an empty read-only file. A process can see that the path
  exists, just not its contents.
- The sandbox's `/etc` is the host's `/etc` read-only, with `passwd`, `group`,
  `shadow`, `gshadow`, `sudoers`, SSH host keys, Docker and Kubernetes
  configs replaced or hidden. Other host-specific files in `/etc` remain
  readable.

## macOS backend

**Status: implemented, UNVERIFIED.** The backend (`crates/agentkeep-sandbox/src/macos/`)
was written without access to a Mac. Its profile generator, environment
rewriting and proxy relay are unit-tested on Linux; the code that runs
`sandbox-exec` has only been compiled for `aarch64-apple-darwin` and
`x86_64-apple-darwin`. Everything below about how macOS behaves is what the
profile is designed to do; it becomes a tested claim only when the escape
suite passes on the macOS CI runners (`AGENTKEEP_ESCAPE_BACKEND=macos`,
`AGENTKEEP_REQUIRE_SANDBOX=1`). Until then treat this backend as
experimental.

How it works: a Seatbelt (SBPL) profile is generated per session, written
with mode 0600 into the session's scratch directory, compiled once against
`/usr/bin/true` and then applied with `/usr/bin/sandbox-exec -f`. The policy
is inherited by every child process.

- **Deprecated mechanism.** `sandbox-exec` and SBPL are marked deprecated by
  Apple and undocumented, though Apple still ships and uses them. The
  profile relies on undocumented semantics (last matching rule wins, path
  filters on Unix sockets, `(target same-sandbox)`). A macOS update can
  change them; the escape suite is what would notice. If `sandbox-exec`
  disappears, the probe reports the backend unavailable.
- **Paths are denied, not absent.** There is no mount namespace. Paths
  outside the policy keep existing and are refused with `EPERM`
  ("Operation not permitted") instead of `ENOENT`. `stat` succeeds on the
  directories *above* every allowed path (so `realpath`, `git` and `cargo`
  work), which reveals that, for example, `/Users/you` exists, but not what
  is in it. A hidden path such as `~/.ssh` is denied for reading, writing
  and executing even when a parent is allowed, and the directories above a
  hidden path cannot be renamed or removed (otherwise moving the parent
  would carry the hidden path out from under its rule).
- **Private HOME and TMPDIR instead of an empty home.** The command gets
  `HOME` and `TMPDIR` pointing at fresh directories in the session scratch
  directory (removed at the end). The real home stays denied. Programs
  that ignore `HOME` and look up the home directory from the user database
  get the real path and are refused. `/tmp` and `/var/tmp` are the host's
  shared directories and are **not** writable: programs that hard-code
  `/tmp` instead of honouring `TMPDIR` fail. Per-user cache directories
  under `/var/folders/.../C` are not available either.
- **Hardlinks.** Seatbelt rules match paths, not files. The profile never
  allows creating hardlinks (`file-link` is left to `(deny default)`), so
  hardlink creation fails everywhere, including inside the project (tools
  that hardlink, such as `pnpm` or `git clone --local`, fall back to copying
  or fail). Whether that also covers every way of obtaining a second name
  for a file outside the policy is UNVERIFIED; the backend does not claim
  `hardlink_safe`.
- **No pid namespace.** Host processes exist alongside the sandbox. The
  profile limits signals and process inspection (`process-info*`) to
  processes in the same sandbox and does not allow reading process lists or
  arguments through `sysctl` (`kern.proc.*`, `kern.procargs*`), which on
  macOS would expose other processes' environments. There is no `/proc`.
  `ptrace(2)` itself is not filtered by the profile; the backend does not
  claim `ptrace_denied`.
- **Process group, not a container.** The command leads its own process
  group. The wall-clock limit and the end of the session kill that group. A
  process that calls `setsid` or `setpgid` leaves the group, survives the
  session and keeps the profile's access (to the project, for instance)
  until it exits.
- **No seccomp, no `no_new_privs`.** Seatbelt does not filter system calls.
  setuid programs still run (confined by the profile); `sudo` fails because
  the sudoers files are hidden, which the escape suite checks.
- **Resource limits.** `RLIMIT_CORE` is 0. `pids` becomes `RLIMIT_NPROC`,
  which on macOS counts **every process of the user**, so the backend sets
  it to the user's process count at launch plus `pids`: an approximate
  fork-bomb brake, not an exact count, and other processes of the user that
  start meanwhile use up the same budget. uid 0 is exempt. `memory` and
  `cpu_percent` are **not enforced** (`RLIMIT_AS` is not enforced by macOS
  and there are no cgroups); the probe reports both as degradations.
- **Network.** There is no network namespace and the loopback interface is
  shared with the host. The supervisor runs a TCP relay on
  `127.0.0.1:<random port>` that forwards to the egress proxy's Unix socket;
  the profile allows outbound connections to `localhost:<that port>` and to
  the decision socket, and refuses everything else, including the
  mDNSResponder socket and service (so there is no DNS inside) and other
  services on the host's loopback (threat N5). Caveats: any local process
  of the host can also connect to the relay port and use the proxy under
  the session's policy; a service listening on `[::1]` on the same port
  number would also be reachable (`localhost` covers both).
- **Mach services are a broad grant.** Every allowed Mach service is a
  daemon outside the sandbox acting on its behalf. The profile allows only
  `opendirectoryd` (user and group lookups), `notifyd`, the logging
  services and `cfprefsd` (whose preference reads the profile does not
  allow). It deliberately does **not** allow the keychain
  (`SecurityServer`, `securityd`), `trustd` (it fetches certificate URLs
  from the network on request, which would bypass the proxy),
  mDNSResponder, LaunchServices and Apple Events (which can start or script
  apps outside the sandbox), the pasteboard, `nsurlsessiond`, FSEvents and
  `configd`. Consequences: `security`, `git-credential-osxkeychain`, `open`
  and `osascript` fail; Go, Swift and other programs that verify TLS
  through Security.framework cannot verify certificates (inspected
  connections fail closed; such hosts can go in `network.passthrough`,
  which still needs `trustd` and so still fails); file watchers based on
  FSEvents receive nothing. Whether `opendirectoryd` would answer a host
  name lookup for the sandbox is UNVERIFIED; the escape suite's DNS probe
  checks for it.
- **System files.** `/usr`, `/bin`, `/sbin`, `/System`, `/Library` (not
  `~/Library`), `/private/etc`, `/private/var/db/timezone`,
  `/private/var/select`, the active Xcode or Command Line Tools developer
  directory and the policy's `read_only` paths are readable.
  `/Library/Keychains` is denied. Other host-specific files under `/Library`
  and `/private/etc` remain readable.
- **Terminals.** Only the terminal the session was started from can be
  reopened by name; there is no pseudo-terminal allocation inside the
  sandbox (`script`, `expect` and node-pty fail). The sandbox gets the
  terminal's foreground; the supervisor takes it back for an approval
  prompt and relays Ctrl-Z to the user's shell. All of this is UNVERIFIED:
  CI runners have no terminal, so no test exercises it. Whether the profile
  stops `TIOCSTI` input injection into the inherited terminal is UNVERIFIED
  (see General).
- **Socket path length.** macOS limits Unix socket paths to 104 bytes. A
  very long `TMPDIR` makes the session's sockets fail to bind (agentkeep
  refuses to start).
- **Not tested on macOS at all yet:** interactive agents, the approval
  prompt on the terminal, job control, Rosetta, Homebrew installations in
  unusual prefixes, macOS versions other than those on the CI runners.

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
