# Known limitations

This file is the honest companion to `threat-model.md`. If a protection is
missing, partial or backend-specific, it is listed here. Please keep it
current: a limitation that is fixed is removed with the PR that fixes it, and
a new gap is added with the PR that discovers it.

Status: **Phase 2 in progress**. `agentkeep run` works on Linux with the
namespaces backend and, on Linux hosts, with the container backend (Podman
or Docker). All sandbox traffic goes through the egress proxy, so
`[network]` and `[dlp]` rules are enforced. `policy init|show|check`,
`doctor` and `approve` work everywhere the binary builds. The macOS backend,
`scan`, `mcp-gateway`, `log` and `report` are not implemented yet; the last
four exit with status 70.

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
- The `CONNECT` host decides the destination, and the TLS server name and
  the `Host` header must both match it. This stops steering an allowed
  shared front end (a CDN or cloud load balancer) to another tenant by
  name, but not by other means a front end may offer (for example a path
  or header it routes on).
- `network.allow_private = true` opens private and loopback ranges to
  allowed names. Link-local and cloud metadata addresses (`169.254.0.0/16`,
  `100.100.100.200`, `fd00:ec2::254`, `fe80::/10`) stay refused; there is
  no setting that opens them.
- A secret passed with `env.pass` is bound to its provider's API host only
  for well-known names (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GH_TOKEN`,
  ...). Any other name without a `dlp.allow_provider_keys_to` entry may be
  sent to any allowed host.
- A project's `agentkeep.toml` applies in full only after `agentkeep
  policy trust` (or with `run --trust-project`, or when named with
  `--policy`). Trust is a decision about file content: `agentkeep policy
  trust` lists what the file loosens, but the user still has to read it.
  An untrusted file's tightening settings (hidden paths, deny and ask
  lists, block values, lower limits) always apply.
- The trust store and the audit directory are hidden in every sandbox,
  but a *trusted* policy can still expose other agentkeep-relevant paths
  (for example the agent's own configuration directory) read-write.
- Audit-log redaction (`audit.redact`, on by default) replaces what the
  DLP detectors recognise: known credential formats, `dlp.block_values`
  and secrets passed with `env.pass`. A secret in a format no detector
  knows (a random password, a private token scheme) is logged as written,
  for example on a command line. `dlp.block_values` themselves are never
  logged, only their count. With `audit.redact = false` nothing is redacted.
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

`--backend container` (or `auto` when the linux backend is unavailable) runs
the same launch plan in a Podman or Docker container, driven through the
runtime CLI. Podman is preferred when it works, then Docker;
`AGENTKEEP_CONTAINER_RUNTIME=podman|docker` picks one. Verified with the full
escape suite (all tests pass, none reported NOT APPLICABLE) on Linux 6.18
x86_64 with Docker 29.9 (rootful, run as root and as a `docker`-group user,
cgroup v1) and Podman 4.9.3 (rootful as root; rootless with `keep-id` as an
unprivileged user; both with runc). CI runs it with Docker on GitHub's
cgroup v2 runners; rootless Podman with crun on cgroup v2 runs there as a
non-blocking experiment and is otherwise untested.

- **Trusts the container runtime.** With rootful Docker or rootful Podman a
  root daemon or runtime builds the container, there is no user namespace,
  and the command runs with the invoking user's host uid (uid 0 without
  capabilities when agentkeep itself runs as root). A container escape
  through a runtime or kernel bug is root on the host. The probe reports
  this as a `container_runtime` degradation on every run. Prefer rootless
  Podman, where the invoking user is mapped to the plan's uid with `keep-id`
  like the linux backend's user namespace. Rootless Docker (container root is
  the invoking user) is implemented but untested.
- **Linux hosts only for now.** PID 1 in the container is the host's own
  agentkeep binary, bind-mounted read-only, so it must be a Linux binary for
  the container's kernel; and the proxy, approval and lifeline channels are
  Unix sockets bind-mounted from the host, which do not cross the VM
  boundary of Docker Desktop (or reach a remote `DOCKER_HOST`). The probe
  refuses Docker Desktop and any daemon whose kernel differs from the host's.
  macOS and Windows would need a Linux agentkeep inside the VM and a socket
  transport that crosses it.
- **gVisor is detected, not used.** When `runsc` is registered with Docker
  (or on `PATH` for Podman) the probe reports a `gvisor` degradation saying
  the stronger runtime is available but unused. There is no policy knob:
  gVisor refuses connections to host Unix sockets unless the runtime is
  configured with `--host-uds`, and has no Landlock, which container init
  refuses to run without when the host kernel has it. If `runsc` is the
  runtime's *default*, the backend reports itself unavailable. None of this
  is tested; the test host has no gVisor.
- **Startup overhead** is far above the 50 ms target: about 385 ms (Docker)
  and 660 ms (Podman) at p50 against 22 ms for the linux backend in the same
  session, see `docs/benchmarks.md`. `auto` therefore prefers the linux
  backend.
- **Limits.** When the runtime enforces `--memory` and `--pids-limit`
  (rootful runtimes; rootless Podman only with delegated `memory` and `pids`
  controllers) those are the limits, swap is disabled with `--memory-swap`,
  and the escape suite checks them in the container's cgroup and runs into
  the pid limit. Otherwise init falls back to rlimits like the linux backend,
  where `RLIMIT_NPROC` counts every process of the uid in its user namespace:
  for a rootful runtime that is all of the user's processes on the host, so
  a low `limits.pids` can make forks fail early. On cgroup v1 hosts the
  limits come from the v1 controllers; for this backend the `cgroup_v2`
  capability field means "the runtime's cgroup enforces the limits".
  `cpu_percent` becomes `--cpus`, omitted when it would not restrict
  anything; no test checks CPU throttling.
- **Bind mounts carry no `nosuid`/`nodev`.** Docker's `--mount` has no such
  options (the linux backend sets both). Setuid bits stay inert because of
  `no-new-privileges`, and device nodes on a bind mount cannot be opened
  because of the runtime's device cgroup.
- **Runtime-provided files.** The runtime adds `/etc/hosts`, `/etc/hostname`
  and `/etc/resolv.conf` (a copy of the host's resolver configuration; no
  resolver is reachable with `--network none`), and Podman adds
  `/run/.containerenv` (container and image name). `/proc` and `/sys` are the
  runtime's, with its masked paths, and `/proc` has no `hidepid`; host
  processes are invisible through the pid namespace alone.
- **The plan file stays readable.** `/run/agentkeep/plan.json` (mounts,
  limits, command and environment) is bind-mounted read-only for the whole
  session. It holds nothing the command does not already receive, but the
  host paths of the session files are visible (not their contents; the
  host-only approver socket is never mounted). The linux backend passes its
  plan through a file descriptor that is closed before the command starts.
- **No `--env-file`.** The environment reaches the command through the plan
  file, never the runtime: PID 1 is agentkeep and must start without
  `LD_PRELOAD` and friends (E2), the env-file format cannot carry a value
  with a newline (which would inject a variable), and the runtime would
  keep a copy. PID 1's own environment is the runtime's (`PATH`,
  `HOSTNAME`, `HOME`, Podman's `container`).
- **The runtime CLI** inherits the user's environment except `LD_*`
  variables (and, for Podman, `USER`, which can be stale and then breaks
  rootless id mapping). The daemon socket is never mounted into the
  sandbox, and `docker`/`podman` stay in the default `commands.ask` list.
- **The image** is `localhost/agentkeep/empty:1`: an empty layer imported
  locally on first use, never pulled (`--pull=never`). An image under that
  name with any other layer, an environment or volumes is refused.
- **Cleanup.** Normal exit, setup failure, Ctrl-C, SIGTERM, the wall-clock
  limit and SIGKILL of the supervisor after the container started all leave
  no container behind (the last through the lifeline socket: init kills
  everything when the supervisor's end closes). Signals, SIGKILL and the TTY
  path were checked by hand with Docker only, not by the automated suite
  (which covers exit codes, setup and the wall-clock limit). Residual: if
  the supervisor is SIGKILLed in the instant
  between the runtime creating and starting the container, a created,
  never-started container can remain (`docker ps -a --filter
  label=dev.agentkeep.session`).
- **Interactive use.** With a TTY, Docker's detach sequence is set to
  `ctrl-^ ctrl-@` because Docker cannot disable it; Podman's is disabled.
  Detaching ends the session (the lifeline closes).
- **Paths** containing `,`, `"` or a newline, and tmpfs targets containing
  `:`, are refused rather than passed to the runtime's mount syntax; use the
  linux backend for them.
- **SELinux hosts** (enforcing, e.g. Fedora): bind mounts are not relabelled,
  since relabelling would change the labels of the user's project on the
  host, so the runtime's SELinux policy may deny access. Untested.
- **Runtime selection probes `info`, not a container start.** A Podman whose
  `info` answers but whose OCI runtime cannot start containers (crun on a
  hybrid cgroup v1/v2 host, for example) is still preferred, and every
  session then fails at start with the runtime's error; set
  `AGENTKEEP_CONTAINER_RUNTIME=docker` or fix the runtime.
- **Podman versions.** `--userns keep-id:uid=,gid=` needs Podman 4.3+.
  Podman's tmpfs copies the covered directory into the new tmpfs by default,
  which would bring hidden files back; the backend passes `notmpcopyup`
  (found by `f1_hidden_paths_under_a_visible_tree_stay_hidden`). On the test
  host crun refuses the hybrid cgroup layout, so Podman was verified with
  runc only.

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
