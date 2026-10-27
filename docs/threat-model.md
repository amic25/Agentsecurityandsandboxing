# agentkeep threat model

This document is written before the code and is updated with it. Every
protection agentkeep claims must trace back to a row in this document, and
every row that is not yet enforced says so. If you find a gap between this
document and the behaviour of a release, that is a bug; report it through
`SECURITY.md`.

**Scope statement.** agentkeep reduces the blast radius of an AI agent that is
tricked, compromised or simply wrong. It is defense in depth. It is not a
guarantee, and nothing in our documentation claims one.

## 1. What we protect (assets)

| Id | Asset | Why it matters |
|---|---|---|
| A1 | Credentials on the host: SSH keys, cloud CLI credentials (`~/.aws`, `~/.config/gcloud`, `~/.azure`), Kubernetes and Docker configs, GPG keys, password stores, `.netrc`, package-registry tokens (`.npmrc`, `.pypirc`, `~/.cargo/credentials.toml`), browser cookies and profiles, OS keychains, `.env` files from other projects | Direct access to money, infrastructure, source code and identity |
| A2 | The user's other data: every directory outside the project | Confidentiality and integrity of unrelated work |
| A3 | The project the agent works on | Integrity of source, build scripts and git history |
| A4 | The agent's own provider credential (the API key or OAuth token that lets it talk to its model) | It is billable and, for some providers, grants account access |
| A5 | The host machine: processes, kernel, devices, persistence (shell rc files, cron, systemd units, launch agents) | Lateral movement and persistence |
| A6 | Reachable networks: the internal network, cloud metadata endpoints (`169.254.169.254`), localhost services | Pivot points and credential sources |
| A7 | The audit log | Without it the user cannot know what happened or prove it |
| A8 | The agentkeep policy and the agentkeep binary itself | If these are modified, every other protection is void |

## 2. Who we defend against (attackers)

All attackers below share one property: **they act through the agent's process
tree.** They have no other foothold on the host. This is the central
assumption that makes a sandbox meaningful.

| Id | Attacker | Vector | Capabilities |
|---|---|---|---|
| T1 | Malicious or compromised repository content | README, PR descriptions, issue text, code comments, `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `SKILL.md`, config files, documentation of dependencies, web pages the agent fetches | Prompt injection: makes the agent run commands, read files, make requests it was not asked to |
| T2 | A malicious or rug-pulled MCP server, skill or plugin | Tool descriptions (injection at install or after a silent update), tool results (injection at call time), tool side effects (the server itself exfiltrates what it is given) | Everything T1 can do, plus direct network access from the server process and the ability to read any argument the agent passes |
| T3 | A compromised package or binary the agent installs or runs | `npm install`, `pip install`, `cargo build` build scripts, a cloned repo's `Makefile`, pre-commit hooks, `postinstall` scripts | Arbitrary code execution inside the agent's process tree with the agent's privileges |
| T4 | The agent itself | A benign instruction interpreted creatively or wrongly; a model that "helpfully" fixes a failing test by deleting it, pushes to the wrong branch, or runs `rm -rf` on the wrong path | Any action within its privileges, with no malicious intent |

Out of scope attackers:

- an attacker with existing code execution on the host outside the sandbox;
- a malicious maintainer of agentkeep (mitigated, not prevented, by signed
  releases, reproducible builds, SLSA provenance and the small-dependency
  policy);
- a malicious kernel, hypervisor or container runtime;
- the human at the approval prompt approving something harmful.

## 3. Trust boundaries

```
                       trusted                         untrusted
 ┌──────────────────────────────────┐   ┌──────────────────────────────────┐
 │ policy files (built-in, global,  │   │ the agent binary and everything  │
 │ project), agentkeep binary,      │   │ it spawns: shells, tools, MCP    │
 │ supervisor process, proxy, audit │   │ servers, package managers,       │
 │ log, approval channel, the human │   │ build scripts                    │
 └──────────────┬───────────────────┘   └───────────────┬──────────────────┘
                │                                       │
                │  mounts (fs)    ←── B1 ──→            │
                │  proxy socket   ←── B2 ──→            │
                │  approval socket←── B3 ──→            │
                │  stdio / tty    ←── B4 ──→            │
                │  MCP JSON-RPC   ←── B5 ──→  (gateway) │
```

| Boundary | What crosses it | Control |
|---|---|---|
| B1 Filesystem | Reads and writes by the agent | Mount namespace: project rw, system ro, everything else absent; secrets paths covered by empty tmpfs; Landlock as a second layer; no `/proc` of host processes |
| B2 Network | HTTP(S) requests | No network interface in the sandbox except loopback; the only route out is a relay to the proxy's Unix socket; the proxy enforces the domain allowlist and DLP; DNS is resolved by the proxy outside the sandbox |
| B3 Approval | Ask requests and human answers | The sandbox can only *request*; answers come from `/dev/tty` of the supervisor or an authenticated local socket outside the sandbox |
| B4 Terminal | The agent's interactive I/O | Passed through unchanged; agentkeep does not read or filter it (see L7) |
| B5 MCP | Tool definitions, calls and results | Gateway filters tools, validates arguments, pins definitions, marks results untrusted, logs everything |

**The project directory is a shared, writable surface on both sides of B1.**
Anything the agent writes there (including hooks, rc files, `.cargo/config.toml`,
`.npmrc`, `.vscode/settings.json`) will be read by the user's tools later, outside
the sandbox. See L1 below.

## 4. Threats, controls and status

Status key: **enforced** (shipped with an escape test), **planned (phase N)**,
**detect-only** (logged, not blocked), **not addressed**.

### 4.1 Filesystem

| Id | Threat | Attacker | Control | Status |
|---|---|---|---|---|
| F1 | Read SSH keys, cloud credentials, tokens (A1) | T1–T4 | Home directory is not mounted; only the project and explicitly listed paths exist. Known secret locations are additionally covered with empty tmpfs so an agent that *expects* them sees nothing rather than an error, also when a policy makes their parent visible | enforced (`f1_*`) |
| F2 | Read or write other projects (A2) | T1–T4 | Same as F1 | enforced (`f2_*`) |
| F3 | Reach a hidden path through a symlink or hardlink inside the project | T1, T3 | Symlinks are resolved inside the mount namespace, where the target does not exist. Hardlinks cannot cross filesystems and the project is bind-mounted alone. Escape test creates both | enforced (`f3_*`) |
| F4 | Reach the host through `/proc/<pid>/root`, `/proc/<pid>/cwd`, `/proc/<pid>/fd` of a host process | T1–T4 | Fresh pid namespace and fresh `/proc` with `hidepid=2`; host pids are not visible | enforced (`f4_*`) |
| F5 | Read host process environment or memory via `/proc/<pid>/environ`, `/proc/<pid>/mem`, `process_vm_readv`, `ptrace` | T1–T4 | pid namespace; seccomp denies `ptrace` and `process_vm_*` | enforced (`f5_*`) |
| F6 | Mount, bind-mount or `pivot_root` to escape the private root | T3, T4 | No `CAP_SYS_ADMIN` in the user namespace after setup; seccomp denies `mount`, `umount2`, `pivot_root`, `open_by_handle_at`; nested `unshare`/`clone` with namespace flags denied | enforced (`f6_*`) |
| F7 | Persistence: write to shell rc files, cron, systemd user units, `~/.config/autostart`, launch agents | T1–T4 | These paths are not mounted (F1). Writes inside the project that have the same effect are covered by F8 | enforced (`f7_*`) |
| F8 | Project-level persistence: `.git/hooks`, `.cargo/config.toml` (runner, rustc wrapper), `.npmrc`, `Makefile`, `.vscode/tasks.json`, `.envrc`, `pre-commit` config | T1–T4 | **Cannot be blocked without blocking the agent's job.** Every write to a known-dangerous project path is logged as a `fs.write` event with severity high, surfaced in `agentkeep report`, and `agentkeep scan` flags them. `commands.ask` can cover `git commit` if the user wants a gate | detect-only (5) |
| F9 | Fill the disk or exhaust inodes | T3, T4 | Project is the host filesystem; no quota in v1. `limits` cover memory and pids, not disk | not addressed; documented in `limitations.md` |
| F10 | Read the audit log or policy from inside the sandbox | T1–T4 | Neither is mounted. The policy snapshot the agent can see is the one in the project, which is also what the user committed | enforced (`f10_*`) |

### 4.2 Environment

| Id | Threat | Attacker | Control | Status |
|---|---|---|---|---|
| E1 | Read secrets from environment variables inherited from the user's shell | T1–T4 | Deny-by-default allowlist (`env.allow`), explicit `env.pass` for the agent's own key, everything else dropped. Dropped names that look like secrets are logged (names only) | enforced (`e1_*`) |
| E2 | Abuse `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_*`, `PYTHONPATH`, `NODE_OPTIONS` to hijack the supervisor | T3 | The supervisor starts from the user's environment before the agent exists, and nothing inside the sandbox can change the supervisor's environment or binary. The variables are not in the default `env.allow`, so they are dropped before the command runs; the container runtime CLI, which runs outside the sandbox, gets the user's environment without `LD_*`. The binary is not static yet (today's builds link glibc dynamically; static musl releases are Phase 6), so loader variables set in the *user's* own shell do apply to agentkeep: that is the user's choice, outside T3 | enforced (`e2_loader_hijack_variables_are_scrubbed`) |
| E3 | Exfiltrate the agent's provider key (A4) to a non-provider domain | T1, T2 | DLP binds each `env.pass` secret to its provider's domains; a request carrying it elsewhere is blocked | enforced (`e3_provider_key_reaches_only_its_bound_host`); a passed name with no known provider and no `dlp.allow_provider_keys_to` entry may go to any allowed host (`limitations.md`) |

### 4.3 Network

| Id | Threat | Attacker | Control | Status |
|---|---|---|---|---|
| N1 | Send files or secrets to an attacker's server | T1–T4 | Domain allowlist in the proxy; deny by default; denied requests logged with host and rule | enforced (`n1_denied_hosts_get_403_and_are_never_contacted`; control `positive_control_allowed_host_works_through_the_proxy`) |
| N2 | Exfiltrate through an allowed domain (a GitHub gist, an npm publish, a pastebin on an allowed CDN) | T1–T4 | DLP scans the request line, headers and body of every request on plain HTTP and inside inspected `CONNECT` tunnels, whatever the port (a tunnel is classified by its first bytes; anything that is neither TLS nor HTTP is refused unless the host is `passthrough`); `ask` mode for sensitive endpoints in presets (for example `api.github.com` writes). **Data that is not a recognisable secret, or a secret encoded or split by a determined sender, can still leave through an allowed domain.** | partial: recognisable secrets enforced (`n2_secrets_are_blocked_over_plain_http_and_never_reach_the_origin`, `n2_secrets_are_blocked_inside_an_inspected_tls_tunnel`); passthrough hosts unscanned and logged so (`n2_passthrough_hosts_are_tunnelled_unscanned_and_logged_as_such`); preset `ask` rules not built; residual risk documented |
| N3 | DNS exfiltration (`<secret>.attacker.example`) | T1–T4 | No resolver reachable from the sandbox on Linux; names are resolved by the proxy and only for allowed hosts. macOS and container backends route DNS through the proxy's resolver as well; see per-backend limitations | enforced on the Linux and container backends (`n3_n4_no_network_and_no_dns`; `n3_dns_cannot_leave_and_denied_names_are_never_resolved`: no UDP route to any resolver, and under `strace` the supervisor makes no lookup or connection for a denied name); enforced on macOS by the same tests: no lookup works inside, a datagram to any resolver is refused with `EPERM`, and the proxy refuses a denied name without resolving it (the `strace` half is Linux-only) |
| N4 | Bypass the proxy with a raw socket, a different port, UDP, QUIC | T3, T4 | Linux: no network interface besides loopback, Landlock v4 restricts TCP connects to the proxy port. macOS: Seatbelt denies `network-outbound` except the supervisor's loopback relay port and the decision socket. Container: `--network none` plus a Unix-socket relay | enforced on the Linux and container backends (`n3_n4_no_network_and_no_dns`: loopback only; `positive_control_allowed_host_works_through_the_proxy`: a host origin reachable through the relay is unreachable directly); enforced on macOS by the same tests (no direct connection, UDP datagram or name lookup from inside) |
| N5 | Reach cloud metadata, the LAN, or localhost services of the host | T1–T4 | Private ranges and link-local are denied by the proxy regardless of the allowlist unless explicitly allowed with `network.allow_private = true`. Names are checked after resolution, so a public name that resolves to a private address is refused too. Host localhost is a different network namespace on Linux and the container backend; on macOS the profile refuses every loopback port but the relay's | enforced (`n5_private_ranges_and_cloud_metadata_are_refused`); link-local and cloud metadata addresses are refused even with `allow_private = true` (same test); host loopback services: `n5_host_loopback_services_are_unreachable` on every backend |
| N6 | TLS inspection leaks: the ephemeral CA private key, or minted certificates reused across sessions | — (weakness in our own control) | Key generated per run in supervisor memory, never written; the CA certificate given to the sandbox is public; passthrough mode exists for pinned clients; inspection can be disabled | enforced (`n6_session_ca_is_per_run_and_its_key_never_reaches_the_sandbox`: a new CA per session, no private key visible in the sandbox or the log); "never written to host disk" holds by construction, not by test |
| N7 | WebSocket or long-lived streams used to move data without inspection | T1–T4 | Allowlist still applies; the upgrade handshake is scanned like any request; the stream after it is tunneled and logged as *unscanned* | detect-only, tested (`n7_websocket_upgrade_is_tunnelled_and_logged_unscanned`) |
| N8 | Steer an allowed shared front end (CDN, cloud load balancer) to a different tenant with a different SNI or `Host` header | T1–T4 | Inside inspected tunnels the TLS server name must equal the `CONNECT` host; on every request the `Host` header must name the destination | enforced (proxy e2e `tls_server_name_must_match_the_connect_host`, `host_header_must_match_the_destination`) |

### 4.4 Commands and processes

| Id | Threat | Attacker | Control | Status |
|---|---|---|---|---|
| C1 | `git push` to a remote, force-push, branch deletion | T1, T4 | `commands.ask` default includes `git push*`; HTTPS pushes are also visible to the proxy as `git-receive-pack` requests and can be gated there, which is not bypassable from inside | shim enforced, advisory (`c1_c2_*`); proxy gate not implemented yet (`limitations.md`) |
| C2 | Destructive commands (`rm -rf`, `git reset --hard`, `git clean -fdx`) | T4 | `commands.ask` and `commands.deny` through the PATH shim (advisory) and, on Linux when it lands, seccomp user-notify on `execve` (enforced). The filesystem layer bounds the damage to the project either way | advisory, tested (`c1_c2_*`); enforced execve interception not yet built |
| C3 | Privilege escalation: `sudo`, `su`, setuid binaries, `pkexec` | T3, T4 | `no_new_privs` makes setuid bits inert; user namespace maps the user to an unprivileged uid; `sudo` is denied by the shim too | enforced (`c3_*`) |
| C4 | Fork bombs, memory exhaustion, CPU burn, runaway sessions | T3, T4 | cgroup v2 limits where delegated, rlimits otherwise, wall-clock kill of the whole pid namespace | enforced (`c4_*`, wall-time control); cpu_percent only with cgroups |
| C5 | Kernel attack surface: `io_uring`, `bpf`, `userfaultfd`, `keyctl`, module loading, `perf_event_open` | T3 | seccomp deny-list | enforced (`c5_*`) |
| C7 | Queue keystrokes into the user's terminal so the user's shell runs them after the session (the sandbox shares the terminal) | T1–T4 | seccomp refuses the `TIOCSTI` and `TIOCLINUX` ioctls | enforced on seccomp backends (`c5_terminal_input_injection_is_refused`) |
| C8 | Spoof an approval prompt with control characters in a command line or host name, so the human approves something other than what runs | T1–T4 | Every prompt and log line shown to a human escapes control and bidirectional-override characters | enforced (unit test `prompts_cannot_drive_the_terminal`) |
| C6 | Nested sandbox or container escape attempts (`docker run --privileged` from inside) | T3, T4 | No Docker socket mounted; nested namespaces denied by seccomp; `docker`/`podman` are in the default `commands.ask` list | enforced (`f6_*`) |

### 4.5 MCP

| Id | Threat | Attacker | Control | Status |
|---|---|---|---|---|
| M1 | A tool the user did not intend to expose (delete, admin, payment) is called | T1, T2, T4 | Gateway allowlist; denied tools are removed from `tools/list` so the model never sees them | planned (4) |
| M2 | A filesystem or shell tool is used with arguments outside the project | T1, T2, T4 | Per-argument rules (`within`, `matches`, `one_of`) evaluated before forwarding | planned (4) |
| M3 | Rug-pull: a server changes a tool description after install to inject instructions | T2 | `agentkeep.lock` pins a hash of each tool definition; `strict` refuses to start on change | planned (4) |
| M4 | Injection in tool results | T2, T1 via T2 | Results wrapped as untrusted data and scanned with the scanner's rules; optional block | detect-only by default (4) |
| M5 | The MCP server process itself exfiltrates | T2 | When started through `agentkeep run`, the server runs inside the same sandbox and proxy; standalone gateway use only gets logging | planned (4) |
| M6 | Secrets passed as tool arguments are logged | — (our own control) | Argument values pass through the DLP detectors before logging | planned (4) |

### 4.6 Scanner (detection, not enforcement)

The scanner has no enforcement role. It reduces T1 and T2 by surfacing
attack surfaces before an agent reads them. Its false-negative rate is a
documented metric, not a promise.

### 4.7 Audit log

| Id | Threat | Attacker | Control | Status |
|---|---|---|---|---|
| L-A1 | The agent edits or truncates its own log | T1–T4 | Not mounted into the sandbox; opened append-only by the supervisor; session directory `0700`, log `0600` so other local users cannot read it | enforced (`f10_*`, `l1_*`, unit test `log_is_owner_only`) |
| L-A2 | Log tampering after the fact by someone with host access | out of scope, but: | Hash chain per event; `agentkeep log verify` detects edits and truncation (not a replacement of the whole file by someone who recomputes the chain) | chain written and verified in tests (`l1_*`); `log verify` CLI planned (5) |
| L-A3 | Secrets written to the log | — | Redaction via the DLP detectors; `audit.redact = true` by default | enforced for recognisable secrets (`l3_secrets_on_command_lines_and_block_values_never_reach_the_log`, and `assert_log_free_of` in the `n2_*`, `e3_*`, `n7_*` tests): every string in every event passes through the DLP detectors, `dlp.block_values` are never logged; secrets in unknown formats are logged as written (`limitations.md`) |

### 4.8 agentkeep itself

| Id | Threat | Attacker | Control | Status |
|---|---|---|---|---|
| S1 | A malicious `agentkeep.toml` in a cloned repository loosens the policy (the repo is T1) | T1 | Until the user trusts the exact file content (`agentkeep policy trust`, SHA-256 per path), only its tightening settings apply and every ignored setting is named in a warning; editing the file revokes trust. Even a trusted file cannot remove `deny` or `hidden` rules without `[override]` and `acknowledge = true`, printed in red and logged. The trust store and audit logs are hidden in every sandbox, so the sandbox cannot trust its own policy | enforced (`s1_untrusted_project_policy_can_only_tighten`, `s1_trust_store_and_audit_logs_are_never_visible`, `s1_project_policy_cannot_silently_unhide`, unit tests in `trust.rs`); scanner rule planned (3) |
| S2 | A malicious preset or rule contributed to the community directories | T1 (via PR) | Code review, CODEOWNERS on `rules/` and `presets/`, corpus tests that must pass; presets cannot disable protections, only add domains and paths | planned (3, 5) |
| S3 | Supply-chain compromise of a dependency | — | `cargo deny`, `cargo audit`, lockfile, small dependency set with written justifications, no build scripts that fetch | enforced (0) |
| S4 | A tampered release binary | — | cosign keyless signatures, SLSA provenance, SBOM, reproducible builds, checksums printed by the installer | planned (6) |
| S5 | agentkeep phones home | — | No telemetry. No network calls except an explicit opt-in update check. `cargo deny` bans known telemetry crates | enforced by policy (0); tested on Linux and the container backend (`s5_supervisor_makes_no_outbound_connections`: under `strace -f`, every `connect()` of `agentkeep run -- true` is `AF_UNIX`; on the container backend only the supervisor and the runtime CLI are traced, because the runtime daemon starts the command, and a connect to an nscd or systemd-resolved socket that does not exist is not counted, because rootless Podman's user lookups try nscd first); not traced on macOS, which has no `strace` |

## 5. Backend capability matrix

What each backend can enforce. "Partial" entries are explained in
`limitations.md`. This table is regenerated by `agentkeep run --explain` once
backends exist, so it never drifts from the code.

The macOS column describes what `crates/agentkeep-sandbox/src/macos/`
implements and the escape suite verifies on GitHub's macOS 15.7 runners
(Apple Silicon and Intel) for the controls it claims (`agentkeep doctor`):
`fs_denied`, `net_isolation`, `no_core_dumps` and `nproc_per_user`. Tests
gated on other controls report NOT APPLICABLE there; the universal ones
run.

| Control | Linux | macOS (Seatbelt) | Container | WSL2 |
|---|---|---|---|---|
| Project rw, rest absent (F1, F2) | yes | partial: rest denied (`EPERM`), not absent; no mount namespace; private `HOME`/`TMPDIR`; `stat` works on parents of allowed paths | yes: the same mount plan bound into an empty image, read-only root | yes (Linux backend inside WSL); `/mnt/*` must be hidden explicitly |
| Hidden paths under an allowed parent (F1) | yes (empty tmpfs or file) | yes: denied for read, write and exec, last rule wins; parents cannot be renamed | yes (empty tmpfs or file, also against the runtime's tmpfs copy-up) | yes |
| Fresh `/proc`, pid isolation (F4, F5) | yes | no pid namespace; signals and process info limited to the sandbox; process listing via `sysctl` refused; `ptrace` not filtered | yes (the runtime's `/proc`, no `hidepid`) | yes |
| seccomp deny-list (C5) | yes | no (Seatbelt does not filter system calls) | yes: the runtime's default profile plus ours, applied by agentkeep's init | yes |
| No network except proxy (N4, N5) | yes | partial: profile allows only the supervisor's loopback relay port and the decision socket on the shared loopback; relies on `sandbox-exec` | yes: `--network none`, loopback relay to the proxy socket | yes |
| DNS isolation (N3) | yes | partial: mDNSResponder socket and service refused; whether `opendirectoryd` resolves names is checked by the suite | yes | yes |
| Approver socket unreachable (B3) | yes (never mounted) | yes: denied by name, and the profile refuses to build if an allowed tree contains it | yes (never mounted) | yes |
| Resource limits (C4) | cgroup v2 if delegated, else rlimits | `RLIMIT_CORE=0`; `RLIMIT_NPROC` per user (approximate); memory and CPU not enforced | yes when the runtime enforces `--memory`/`--pids-limit` (rootful; rootless Podman with delegated controllers), else rlimits | yes if delegated |
| Hardlink/symlink tricks (F3) | yes | partial: symlinks resolve to the real path the profile checks; hardlink creation never allowed, but not claimed as `hardlink_safe` | yes | yes |
| Landlock second layer | yes (kernel 5.13+ with Landlock enabled) | no | yes: init applies it and refuses to start if the runtime hides it | as Linux, if the WSL kernel has Landlock |
| Privilege escalation (C3) | yes (`no_new_privs`, no capabilities) | partial: setuid runs but stays confined; sudoers hidden | yes: `--cap-drop=ALL`, `no-new-privileges`, set again by init | as Linux |
| Trust in the runtime | kernel only | kernel and `sandbox-exec` | the container runtime too; rootful Docker or Podman means a root daemon (prefer rootless Podman) | kernel and WSL2 |

The Container column holds for Linux hosts only (`limitations.md` says why).
It is verified by the escape suite with Docker (rootful) and Podman (rootful
and rootless) on a cgroup v1 host; the `escape-container` CI job runs the
same suite with Docker and rootless Podman on cgroup v2 runners.

## 6. Residual risks we accept and document

1. **Data that is not a secret can leave through an allowed domain.** The
   model provider API is allowed by definition, and the agent sends your code
   to it. Anything the agent can read it can also paste into a prompt. The
   allowlist keeps the set of destinations small; it does not make them
   trustworthy.
2. **Project-level persistence (F8)** cannot be blocked without blocking the
   work. We detect and report it.
3. **Advisory command rules** on non-Linux backends and on Linux until
   seccomp user-notify lands. The filesystem and network layers are the real
   controls.
4. **Kernel and runtime escapes.** We reduce surface with seccomp and
   Landlock. We do not claim to stop a kernel exploit.
5. **The human.** An approval prompt can be approved carelessly. Prompts show
   the exact command, path or domain and the rule that triggered them, and
   `ask` has a timeout that denies.

## 7. Maintenance

- Every PR that touches `agentkeep-sandbox`, `agentkeep-proxy` or
  `agentkeep-policy` must reference the threat ids it affects.
- `crates/agentkeep/tests/escape.rs` is organised by threat id; the status
  column names the test that covers each enforced row.
- Review this document at every minor release.
