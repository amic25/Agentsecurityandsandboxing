# agentkeep — Plan

> Status: **draft for approval**. No code is written until this plan is approved.
>
> Working name decided: `agentkeep` (a keep is the strongest, innermost part of a
> castle). Verified free on crates.io, npm, PyPI and Homebrew core on 2026-10-23.
> GitHub org availability could not be checked from this environment; please
> confirm `github.com/agentkeep` before Phase 6.

Product promise: **Run any agent with one command. It can only touch what you
allow, and you can see everything it did.**

Scope boundary, stated once and repeated in every doc: agentkeep reduces blast
radius and is defense in depth. It is not a guarantee, and we never claim one.

---

## 1. Decisions taken on the open questions

| # | Question | Decision |
|---|---|---|
| 1 | Name | `agentkeep`. Binary `agentkeep`, crate `agentkeep`, policy file `agentkeep.toml`, lock file `agentkeep.lock`, global config `~/.config/agentkeep/`. |
| 2 | Platform priority | Linux is the reference backend and the only one whose escape suite runs on the development host. macOS and Windows/WSL backends are built and unit-tested here, and their escape suites run only in CI on native runners. The escape suite prints an explicit `UNTESTED ON THIS HOST` result for backends it cannot exercise; it never skips silently. |
| 3 | Container backend | Shell out to the `docker` or `podman` CLI. The user supplies the runtime. gVisor is enabled with `--runtime=runsc` when the policy asks for it and the runtime reports it available. No daemon-socket client in v1. |
| 4 | Ask mode transport | Both. Default: the wrapper's own terminal, using `/dev/tty` so prompts do not collide with the agent's stdin/stdout. Always available: a Unix socket (`$XDG_RUNTIME_DIR/agentkeep/<session>.sock`) speaking line-delimited JSON, which `agentkeep approve` and editor plugins attach to. If no approver is attached and no TTY exists, the action is **denied** (fail-closed) and logged. |
| 5 | Ownership and v0.1.0 scope | Repo stays under the owner's personal account for now; moving to a `agentkeep` org is a Phase 6 checklist item that only renames remotes. v0.1.0 ships all five commands. `run`, `scan` and `log` are the polished headline features. `mcp-gateway` ships with stdio servers, pinning and logging fully tested, and HTTP/SSE transport deferred to v0.2.0. |

---

## 2. Architecture

### 2.1 Repository layout

```
agentkeep/
├── Cargo.toml                 # workspace, single lockfile, resolver = "2"
├── crates/
│   ├── agentkeep/             # the CLI binary (clap). Thin: wires crates together.
│   ├── agentkeep-policy/      # policy schema, TOML parser, merge, evaluation engine
│   ├── agentkeep-sandbox/     # Backend trait + linux/, macos/, container/, wsl/
│   ├── agentkeep-proxy/       # egress proxy, allowlist, TLS inspection, DLP
│   ├── agentkeep-mcp/         # MCP gateway: JSON-RPC relay, pinning, output marking
│   ├── agentkeep-scan/        # static scanner, YAML rule engine, SARIF/JSON/text output
│   ├── agentkeep-audit/       # append-only hash-chained JSONL log, reader, report
│   ├── agentkeep-tui/         # ratatui viewer for `agentkeep log`
│   └── agentkeep-common/      # paths, secret patterns, unicode helpers, errors
├── rules/                     # community scanner rules (YAML)
├── presets/                   # community agent presets (YAML)
├── tests/
│   ├── escape/                # the escape test suite (runs against every backend)
│   ├── corpus/                # prompt-injection fixtures: positive/ negative/
│   └── fixtures/              # policies, MCP configs, workflows used by tests
├── fuzz/                      # cargo-fuzz targets: policy, proxy parser, scanner
├── benches/                   # criterion: startup, proxy latency, scan throughput
├── docs/                      # mdBook source
├── action/                    # GitHub Action (composite, pinned binary + checksum)
├── packaging/                 # brew formula, npm wrapper, pip wrapper, install.sh
├── .github/                   # workflows (pinned by SHA), templates, CODEOWNERS
└── SKILL.md, AGENTS.md, CLAUDE.md, SECURITY.md, CONTRIBUTING.md, ...
```

One static binary: `musl` targets on Linux, universal binary on macOS, MSVC on
Windows (the Windows binary only launches WSL2 or a container).

### 2.2 Process model for `agentkeep run`

```
 terminal ──┐
            │ /dev/tty prompts
            ▼
 ┌────────────────────────────────────────────────┐
 │ agentkeep (supervisor, outside the sandbox)    │
 │  • loads + merges policy                       │
 │  • opens audit log                             │
 │  • starts egress proxy on a Unix socket        │
 │  • starts approval socket                      │
 │  • picks backend, spawns sandbox              │
 │  • holds the ephemeral TLS CA private key      │
 └───────┬───────────────────────────┬────────────┘
         │ inherited fds             │ pidfd / wait
         ▼                           ▼
 ┌────────────────────────────────────────────────┐
 │ sandbox (new user+mount+pid+net namespaces)    │
 │  agentkeep --internal-init  (PID 1)            │
 │   • mounts: project rw, system ro, secrets     │
 │     hidden (tmpfs over them), /proc, /dev      │
 │   • loopback only; TCP 127.0.0.1:PROXY_PORT    │
 │     relayed to the inherited Unix socket       │
 │   • installs Landlock ruleset, seccomp filter  │
 │   • drops caps, no_new_privs                   │
 │   • exec agent (claude, codex, ...)            │
 │     with scrubbed env + HTTP(S)_PROXY set      │
 └────────────────────────────────────────────────┘
```

Key property: the sandbox has **no route to the internet and no DNS**. The only
way out is the proxy socket. DNS exfiltration is impossible by construction on
Linux because there is no resolver reachable; the proxy resolves names outside.
Programs that ignore `HTTP_PROXY` fail closed. This is documented as a
deliberate limitation, with a per-preset list of known tools that need it.

### 2.3 Backend abstraction

```rust
pub trait Backend {
    fn name(&self) -> &'static str;
    fn probe(&self) -> Probe;                 // Available | Degraded(reasons) | Unavailable(reason)
    fn capabilities(&self) -> Capabilities;   // fs_isolation, net_isolation, pid_limit, mem_limit, ...
    fn launch(&self, plan: &LaunchPlan) -> Result<SandboxHandle>;
}
```

`LaunchPlan` is backend-agnostic: resolved mounts (rw/ro/hidden), env map, proxy
socket fd, resource limits, command. Each backend compiles it into its own
mechanism. `capabilities()` is compared against what the policy requires; if a
backend cannot enforce a required rule, `run` refuses unless
`--allow-degraded` is given, and the degradation is written to the audit log and
printed in red. This is how we stay honest across backends.

Selection order (`backend = "auto"`):

| OS | Order |
|---|---|
| Linux | `linux` (userns + mount ns + net ns + Landlock + seccomp + cgroup v2 if delegated, rlimits otherwise) → `container` (podman, then docker) |
| macOS | `macos` (Seatbelt profile via `sandbox-exec`, generated per run) → `container` |
| Windows | `wsl` (re-exec inside WSL2 using the Linux backend; project path translated) → `container` (Docker Desktop) |

Backend-specific limitations go in `docs/limitations.md` from day one:
Seatbelt cannot do network namespaces, so macOS egress control relies on the
proxy plus a Seatbelt `network-outbound` deny rule for everything except the
proxy socket; `sandbox-exec` is deprecated by Apple but still present; the
container backend trusts the container runtime; WSL shares the Windows
filesystem via `/mnt/c` and that must be hidden explicitly.

### 2.4 Linux backend details

- **Namespaces:** user, mount, pid, net, ipc, uts. Unprivileged (no setuid, no
  root). If unprivileged user namespaces are disabled (some Debian/Ubuntu
  AppArmor configs), probe reports `Unavailable` with the exact sysctl to flip,
  and auto-selection moves to `container`.
- **Mounts:** build a private root under a tmpfs. Bind the host `/usr`, `/lib*`,
  `/bin`, `/etc` (filtered), `/opt` read-only. Bind the project directory
  read-write. Secrets paths become empty tmpfs mounts (`hidden`) so `ls ~/.ssh`
  shows nothing rather than failing, which avoids agents "fixing" the problem.
  `/proc` is a fresh procfs for the new pid namespace, with `hidepid=2`.
  `/dev` is a minimal devtmpfs-style set (`null`, `zero`, `random`,
  `urandom`, `tty`, `pts`).
- **Landlock:** applied in addition to mounts (defense in depth), restricting
  write access to the project and tmp, with the highest ABI the kernel offers
  (v1 through v5 detected at runtime; v4 adds TCP bind/connect restriction, used
  to pin connects to the proxy port only).
- **seccomp:** a deny-list generated with `seccompiler` (pure Rust, no libseccomp
  C dependency): block `ptrace`, `mount`, `umount2`, `pivot_root`, `kexec_*`,
  `init_module`, `finit_module`, `delete_module`, `bpf`, `perf_event_open`,
  `keyctl`, `add_key`, `request_key`, `userfaultfd`, `unshare` and `clone`
  with new namespace flags (prevents nested-namespace tricks), `setns`, `io_uring_*`
  (its sandbox-bypass history), `process_vm_readv/writev`, and `open_by_handle_at`.
  Architecture mismatch kills the process. Errors are `EPERM` not `KILL` for
  ergonomics except for the escape-class calls.
- **Command rules (ask / deny on commands):** Phase 1 ships a **PATH shim**:
  a directory of tiny wrappers placed first on `PATH` for sensitive binaries
  (`git`, `curl`, `wget`, `ssh`, `scp`, `rm`, `sudo`, `docker`, `kubectl`, ...)
  that consult the policy over the approval socket and then exec the real
  binary. This is bypassable by absolute path and is documented as *advisory*.
  Phase 1 stretch, Linux only: **seccomp user-notification on `execve`**, where
  the supervisor reads `argv` from the notifying process and decides. If it
  lands in Phase 1 it becomes the Linux mechanism and the shim stays for the
  other backends. Either way, real enforcement for the worst outcomes comes from
  the filesystem and network layers, not from command matching.
- **Resources:** cgroup v2 (`memory.max`, `pids.max`, `cpu.max`) when the user
  has a delegated cgroup (systemd user sessions normally do). Fallback:
  `RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_NOFILE`, plus a wall-clock timer in the
  supervisor that kills the whole pid namespace. The probe reports which one is
  active.

### 2.5 Egress proxy

- Runs in the supervisor process (tokio), listens on a Unix socket passed to
  the sandbox by fd; inside the sandbox a tiny relay exposes it as
  `127.0.0.1:PORT` and sets `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY=`
  (empty) and the CA environment variables (`SSL_CERT_FILE`,
  `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`,
  `DENO_CERT`, `CARGO_HTTP_CAINFO`).
- Protocols: HTTP/1.1 forward proxy and `CONNECT`. HTTP/2 to origins is
  negotiated by the client inside the tunnel; the proxy speaks HTTP/1.1 to
  clients and origins in v1.
- **Allowlist:** exact hosts and `*.suffix` globs, optional port lists. Decision
  is made on the `CONNECT` host (or `Host`/URL for plain HTTP), and
  cross-checked against TLS SNI when inspecting. Denied: `403` with a short
  body explaining which rule denied it, plus an audit event. In `ask` mode, a
  first-seen domain triggers an approval prompt with a 60 s timeout (deny on
  timeout).
- **TLS inspection for DLP (default on):** a per-run ephemeral CA (`rcgen`),
  private key held only in supervisor memory, the certificate exported into the
  sandbox. Per-host leaf certs are minted on demand and cached for the session.
  Inspected traffic is decrypted, parsed with `hyper`, scanned, then re-encrypted
  to the origin with `rustls` and the `webpki-roots` bundle (or the system store
  via `rustls-native-certs`). `network.tls_inspect = false` turns it off
  globally; `network.passthrough = ["..."]` turns it off per host (for pinned
  clients). Passthrough hosts get allowlist control but no DLP, and the audit
  log says so.
- **DLP:** streaming scan over request headers and bodies with a bounded
  window (keeps proxy latency flat). Detectors: AWS access keys, GCP service
  account keys, GitHub/GitLab tokens, Slack tokens, Anthropic/OpenAI/Google API
  keys, PEM private keys, JWTs, generic high-entropy `*_KEY=`/`*_TOKEN=`
  assignments, plus any literal values the user lists in `dlp.block_values`
  (hashed in memory, never logged). The agent's own provider key, passed through
  `env.pass`, is allowed **only** to the matching provider domain; sending it
  anywhere else is blocked. Match → connection is reset, event logged with the
  detector id and a redacted sample (first 4 chars), never the secret.
- Non-goals in v1: SOCKS, UDP, QUIC/HTTP3, WebSockets DLP (WebSocket upgrades
  are tunneled after allowlist check and logged as unscanned).

### 2.6 Policy engine

File discovery and merge order (later wins, except that `deny`/`hidden` rules
can only be **added** by lower-priority files and only removed by the project
file with an explicit `override = true` that is printed as a warning):

1. built-in defaults (compiled in, printed by `agentkeep policy show --defaults`)
2. preset selected by `--preset` or auto-detected from the agent command
3. global `~/.config/agentkeep/agentkeep.toml`
4. project `./agentkeep.toml` (walks up to the git root)
5. command-line flags

Schema sketch (`schema = 1`, validated with `serde` + a hand-written validator
that produces line/column errors):

```toml
schema = 1

[sandbox]
backend = "auto"              # auto | linux | macos | container | wsl
allow_degraded = false        # refuse to run if backend can't enforce the policy
preset = "claude-code"        # optional; auto-detected from the command otherwise

[filesystem]
project = "."                 # read-write root; resolved against the git root
read_only  = ["~/.gitconfig", "~/.cargo/registry"]
read_write = ["~/.cache/pip"]
hidden     = ["~/secrets"]    # added to the built-in secrets list
# built-ins (always hidden unless overridden): ~/.ssh ~/.aws ~/.config/gcloud
# ~/.kube ~/.docker ~/.gnupg ~/.password-store ~/.netrc ~/.npmrc(auth lines)
# browser profiles, keychains, and any .env* outside the project

[env]
allow = ["HOME", "PATH", "LANG", "TERM", "USER", "SHELL", "EDITOR"]   # pass through unchanged
pass  = ["ANTHROPIC_API_KEY"]   # secrets explicitly passed; bound to provider domains by DLP
set   = { CI = "1" }
# everything else is scrubbed; anything matching the secret-name pattern is logged as scrubbed

[network]
allow = ["api.anthropic.com", "*.npmjs.org", "crates.io", "static.crates.io", "pypi.org", "files.pythonhosted.org"]
ask   = ["*.github.com"]       # first contact prompts; approved domains are remembered for the session
deny  = ["*.pastebin.com"]     # deny beats ask beats allow
tls_inspect = true
passthrough = []               # allowlisted hosts exempt from inspection (no DLP)

[dlp]
enabled = true
block_values = []              # extra literal secrets to block (hashed in memory)
allow_provider_keys_to = { ANTHROPIC_API_KEY = ["api.anthropic.com"] }

[commands]
ask  = ["git push*", "rm -rf *", "docker *", "kubectl *"]
deny = ["sudo *", "curl * | sh", "ssh *"]

[mcp]
allow_tools = ["filesystem:*", "github:get_*", "github:list_*"]
deny_tools  = ["github:delete_*"]
[mcp.args.filesystem]
path = { within = "$PROJECT" }   # per-argument rule: must resolve inside the project
pin = "strict"                   # strict | warn | off — rug-pull handling

[limits]
cpu_percent = 200
memory = "4G"
pids = 512
wall_time = "2h"

[approval]
transport = ["tty", "socket"]
timeout = "60s"                   # deny on timeout

[audit]
dir = "~/.local/share/agentkeep/sessions"
redact = true
```

Evaluation is a pure function `decide(policy, Request) -> Decision` with
`Request` an enum (`Path`, `Domain`, `Command`, `McpTool`, `Env`) and
`Decision` one of `Allow`, `Deny { rule }`, `Ask { rule, prompt }`. Pure and
allocation-free on the hot path so it is cheap to fuzz and property-test.

**Plugin interface (documented, v1):** an external executable declared in
`[plugins] decide = "./my-plugin"` receives each `Ask` or `Allow` decision as
one JSON object on stdin and must answer `{"decision":"allow|deny|ask"}` on
stdout within the approval timeout. Plugins can only tighten a decision, never
loosen a `Deny`. WASM plugins are a post-v1 item.

### 2.7 MCP gateway

`agentkeep mcp-gateway --name github -- npx -y @modelcontextprotocol/server-github`

- Presents a stdio MCP server to the agent, spawns the real server as a child
  (inside the sandbox when invoked from `run`, standalone otherwise) and relays
  JSON-RPC 2.0 messages. Handles `initialize`, `tools/list`, `tools/call`,
  notifications; everything else is relayed verbatim.
- **Allowlist:** `tools/list` responses are filtered so the agent never sees a
  denied tool; `tools/call` on a denied or unknown tool returns a JSON-RPC error
  and logs it. Per-argument rules: `within`, `matches` (regex), `one_of`,
  `max_len`.
- **Pinning:** `agentkeep.lock` stores, per server name, the command, the
  package version when discoverable, and a SHA-256 over the canonicalised
  `tools/list` result (name + description + input schema). `pin = "strict"`
  refuses to start when the hash changes; `warn` logs and prompts.
- **Untrusted output marking:** every `tools/call` result's text content is
  wrapped: `<untrusted-tool-output source="github:get_issue" sha256=...>` ... `</untrusted-tool-output>`
  and scanned with the same rule engine as `scan`. Hits add an
  `agentkeep-warning` field and a log event; with `[mcp] block_injection = true`
  the result is replaced by an error. Delimiters are configurable since agents
  tokenize them differently.
- Full logging: request, response, latency, byte sizes, decisions, with
  argument values redacted through the DLP detectors.
- Transport: stdio in v1. Streamable HTTP in v0.2.0.

### 2.8 Scanner

- Inputs: `.mcp.json`, `claude_desktop_config.json`, `.claude/settings*.json`,
  `.codex/config.toml`, `.gemini/settings.json`, `.cursorrules`, `.cursor/rules/**`,
  `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `SKILL.md`, `.github/workflows/*.yml`,
  `.vscode/mcp.json`, `opencode.json`, plus any file passed explicitly.
- Rule engine: YAML rules in `rules/<category>/<id>.yaml` with `id`, `severity`,
  `title`, `description`, `applies_to` (globs), `detect` (one of: `regex`,
  `unicode` with class selectors, `yaml_path`/`json_path` with predicates,
  `markdown_image_url`, `shell_pattern`), `remediation`, `references`, and
  inline `examples: {match: [...], nomatch: [...]}` that are run as tests.
  Built-in detectors that cannot be expressed in YAML (bidi analysis,
  base64-decoded command detection, CI token-exposure analysis) are implemented
  in Rust and exposed as `detect.builtin: <name>`.
- Detections for v1 (all six categories from the brief): hidden/invisible
  Unicode and bidi overrides; imperative instructions aimed at an agent inside
  data files ("ignore previous instructions", "you are now", role-play
  framing, "do not tell the user"); exfiltration URLs and markdown image
  beacons with query strings; `curl | sh`, `base64 -d | bash`, `eval $(...)`;
  over-broad permissions (`"*"` tool allows, `allowedTools: Bash(*)`, mcp
  filesystem roots at `/` or `~`); CI workflows with `pull_request_target` or
  `issue_comment` triggers that pass `github.event.*.body` to an agent step with
  a `contents: write` or `pull-requests: write` token.
- Output: text (with snippets and colours), JSON (stable schema, versioned),
  SARIF 2.1.0 with rule metadata, fingerprints and `partialFingerprints` so GitHub
  code scanning de-duplicates across runs. Exit code 1 on findings at or above
  `--fail-on` (default `high`).
- Corpus: `tests/corpus/positive/<rule-id>/*.md|json|yml` and
  `tests/corpus/negative/**`. CI computes precision and recall per rule and
  overall, writes a markdown table to the job summary and fails if recall drops
  below the committed baseline in `tests/corpus/baseline.json`.
- GitHub Action: composite action downloading a release binary by exact
  version, verifying its SHA-256 (and cosign signature once Phase 6 lands),
  running `agentkeep scan --format sarif` and uploading with
  `github/codeql-action/upload-sarif` pinned by SHA.

### 2.9 Audit log and viewer

- One directory per session: `events.jsonl`, `meta.json` (policy snapshot,
  backend, capabilities, degradations), `approvals.jsonl`.
- Each event: `{ts, seq, kind, data, prev_hash, hash}` where `hash =
  sha256(prev_hash || canonical(event without hash))`. `agentkeep log verify`
  recomputes the chain. The file is opened `O_APPEND` and is not mounted into
  the sandbox at all, so the agent cannot read or edit its own log.
- Event kinds: `session.start/end`, `fs.mount`, `fs.write` (via fanotify on
  Linux when available, else a post-run diff of the project tree), `exec`
  (from shim or seccomp-notify), `net.request`, `net.deny`, `dlp.block`,
  `mcp.call`, `mcp.result`, `policy.decision`, `approval.request/response`,
  `backend.degraded`, `limit.hit`.
- `agentkeep log [session]`: ratatui TUI with a timeline, filters by kind and
  text, a detail pane, and "replay" that steps through events at wall-clock
  pace or instantly. Falls back to a plain `--format text|json` listing when
  stdout is not a TTY.
- `agentkeep report [session] --format md|html`: summary of what ran, what was
  touched, what was blocked, approvals given, with the HTML being a single
  self-contained file with no external assets.

### 2.10 Presets

`presets/<agent>.yaml` with `name`, `detect` (command basenames), `domains`,
`config_paths` (`rw`/`ro`), `needs_proxy_env`, `known_quirks` (free text
rendered in docs), `extra_env_allow`. First six: `claude-code`, `codex`,
`opencode`, `gemini-cli`, `cline`, `goose`; `openclaw` and `aider` follow once
their domain sets are verified. Presets must state honestly that mounting an
agent's own config directory read-write exposes that agent's credential file to
the agent itself; this is inherent and is the one secret the agent gets.

### 2.11 Performance budget

| Metric | Target | How measured |
|---|---|---|
| `agentkeep run -- true` overhead vs bare `true` | < 50 ms p50 on Linux | `benches/startup.rs` with hyperfine in CI, published in `docs/benchmarks.md` |
| Proxy added latency, plain `CONNECT` tunnel | < 5 ms p50 | criterion + a local origin server, 1 KiB and 1 MiB bodies |
| Proxy added latency with TLS inspection + DLP | < 5 ms p50 for 1 KiB bodies; reported separately for 1 MiB | same |
| `scan` throughput | > 50 MiB/s of text | criterion |

Design choices that protect the budget: no runtime config parsing on the hot
path (policy compiled to matchers once), `aho-corasick` for DLP literals with a
single regex set for structured keys, zero-copy relay for passthrough tunnels,
and lazy initialisation of the TUI and report crates behind feature flags so
`run` links only what it needs.

### 2.12 Dependency policy

Every dependency is justified in `docs/dependencies.md` with the reason and
the alternative considered. Initial set (all widely used, actively maintained,
permissively licensed): `clap`, `serde`, `serde_json`, `toml`, `tokio`, `hyper`,
`hyper-util`, `rustls`, `rcgen`, `webpki-roots`, `rustix`/`nix`, `landlock`,
`seccompiler`, `regex`, `aho-corasick`, `sha2`, `tracing`, `ratatui`,
`crossterm`, `unicode-security` (confusables and invisible classes), `globset`,
`anyhow`/`thiserror`, `criterion` (dev), `proptest` (dev), `insta` (dev).
`cargo-deny` bans duplicate major versions where practical, non-OSI licences,
and unmaintained advisories; `cargo-audit` runs on every push and nightly.

---

## 3. Milestones

Each phase ends with: tests green (unit, property, escape suite for available
backends, corpus metrics), `cargo clippy -D warnings`, `cargo fmt --check`,
`cargo deny check`, a phase report (built, test results, open risks, next steps),
and a stop for review.

| Phase | Deliverables | Exit criteria |
|---|---|---|
| **0** Skeleton | Workspace, CLI stub that prints `--help`, CI matrix (Linux x86_64 + arm64, macOS Intel + Apple Silicon, Windows), pinned actions, cargo-deny/audit, LICENSE (Apache-2.0), DCO check, SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, issue/PR templates, labels script, CHANGELOG.md, AGENTS.md, CLAUDE.md, SKILL.md, `docs/threat-model.md`, `docs/limitations.md` (empty sections per backend) | CI green on all runners; threat model reviewed |
| **1** Policy + Linux `run` | `agentkeep-policy` with parser, merge, validator, property tests and fuzz target; `agentkeep-sandbox` Linux backend with fs + env isolation, no-network netns, Landlock, seccomp, rlimits/cgroups, PATH shim; `agentkeep run`, `agentkeep policy init/show/check`; audit log writer (minimal); escape suite v1 (read `~/.ssh`, write outside project, symlink/hardlink into hidden paths, `/proc/1/environ`, `/proc/self/root` traversal, bind-mount attempts, `unshare` nesting, ptrace, raw socket, DNS, `LD_PRELOAD`, env secret visibility) | All escape tests fail-closed on Linux; startup overhead measured and reported |
| **2** Proxy + macOS + container | `agentkeep-proxy` with allowlist, ask, TLS inspection, DLP, fuzz target for the HTTP parser path; escape tests for denied domain, token leak over HTTP and HTTPS, provider-key misrouting, DNS exfil, WebSocket tunnel; macOS Seatbelt backend with generated profile; container backend (podman/docker, optional gVisor); escape suite running on macOS CI | Proxy latency measured; escape suite green on Linux, macOS, container; `UNTESTED` output verified on hosts without a backend |
| **3** Scanner | `agentkeep-scan`, YAML rule engine, initial rule pack (≥ 25 rules across the six categories), builtin detectors, text/JSON/SARIF outputs, fixture corpus (≥ 150 positive, ≥ 150 negative samples), precision/recall job, GitHub Action, fuzz target for the rule engine | Corpus recall ≥ 0.9 and precision ≥ 0.9 on the committed baseline; SARIF validated against the schema and uploaded in CI |
| **4** MCP gateway | `agentkeep-mcp` stdio relay, allowlist and argument rules, `agentkeep.lock` pinning with rug-pull detection, untrusted output marking and injection flagging, full logging, integration tests with a fake MCP server, fuzz target for the JSON-RPC framing | Rug-pull test passes; `run` + gateway work together on Claude Code's `.mcp.json` |
| **5** Audit TUI, presets, benchmarks | `agentkeep log` TUI, `log verify`, `agentkeep report` (md/html), six presets with per-agent quickstart tests, criterion benches and `docs/benchmarks.md`, `fs.write` events | Benchmarks meet targets or the gap is documented; each preset launches its agent's `--version` under `run` in CI |
| **6** Docs, README, release pipeline | mdBook site (concepts, policy reference, presets, threat model, CI/team/enterprise guides), README with demo script and GIF storyboard (recorded with `vhs`, recording done by the owner or in CI), comparison table, install paths (brew tap formula, `cargo install`, npm wrapper, pip wrapper, `install.sh` with printed checksum), release workflow: reproducible builds, cosign keyless signing, SLSA provenance via the official generator, SBOM (CycloneDX via `cargo-cyclonedx`), OpenSSF Scorecard workflow, v0.1.0 CHANGELOG | Dry-run release on a tag in a fork-like branch produces signed, verifiable artifacts; Scorecard ≥ 8 or each gap listed |
| **7** Launch kit | Show HN post, r/LocalLLaMA and r/selfhosted posts, X thread, blog post "We tried to make agents steal our SSH keys. Here's what stopped them." (built from real escape-suite output), all in `docs/launch/` for the owner to post | Owner review |

Phase 1 stretch (does not block the phase): seccomp user-notify `execve`
interception.

---

## 4. Threat model summary (full version in `docs/threat-model.md`, Phase 0)

**Assets:** credentials and keys on the host, the user's other projects and
data, the user's cloud and SaaS accounts reachable with those credentials, the
integrity of the project the agent works on, the user's machine itself, and the
audit log.

**Attackers:** (1) malicious or compromised repository content read by the
agent (READMEs, PR text, config files, dependencies' docs); (2) a malicious or
rug-pulled MCP server, skill or plugin; (3) a compromised package the agent
installs or runs; (4) the agent itself acting creatively or wrongly on a
benign instruction. All four share the same capability: they can only act
through the agent's process tree, which agentkeep confines.

**Trust boundaries:** the supervisor process and its policy files are trusted;
everything inside the sandbox is untrusted, including the agent binary; the
proxy is the only path out; approval decisions come from a human on the
terminal or the approval socket; the audit log is outside the sandbox.

**Out of scope:** a kernel or container-runtime escape (we reduce the surface
but do not prevent it), an attacker who already has host code execution, a
malicious agentkeep binary (mitigated by signed releases), attacks that work
entirely inside the allowed scope (an agent deleting project files is within
policy unless `commands.ask` covers it, which is why the audit log and git
exist), and social engineering of the human at the approval prompt.

---

## 5. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Unprivileged user namespaces disabled on some distros | Linux backend unavailable | Probe explains the fix; auto-fallback to container; documented |
| TLS inspection breaks pinned clients or Node/Python tools that ignore CA env vars | Agents fail to reach their API | Per-preset passthrough defaults verified in CI by running each agent's `--version` and a real request to a local fake API; clear error text naming the fix |
| Agents that do not honour `HTTP_PROXY` | Broken networking inside the sandbox | Fail-closed by design; presets list known tools; `docs/limitations.md` keeps the list |
| Secret paths list is never complete | A credential we did not think of leaks | Deny-by-default home directory: only the project and explicitly listed paths are visible; the secrets list is a second layer, not the first |
| False positives in DLP or injection detection annoy users into disabling it | Reduced protection | Corpus-driven precision targets; per-rule disable; detectors report confidence |
| macOS Seatbelt deprecation | Backend disappears in a future macOS | Container fallback; track Apple's `Endpoint Security`/`App Sandbox` alternatives in limitations |
| Startup budget blown by cgroup or mount setup | Adoption friction | Benchmarked from Phase 1; mount list kept minimal; cgroup setup optional |
| Scope: five commands for one engineer | Shallow features | Phase order puts `run`, `scan`, `log` first; gateway ships stdio-only |
| The existing `agentcell` crate is a Linux-only competitor | Confusion | Different name; comparison table credits it honestly |
| Supply chain of our own release | Trust | Pinned actions, cosign, SLSA, SBOM, reproducible builds, Scorecard |

---

## 6. What happens after approval

1. Phase 0 is built on branch `claude/busy-sagan-7drphr` in small commits, with
   `docs/threat-model.md` written before any Rust beyond the CLI stub.
2. Pushes go only to that branch. No package publishing, no releases, no tags
   without explicit approval.
3. At the end of Phase 0 a report is posted here with test results, open risks
   and the Phase 1 TODO list.
