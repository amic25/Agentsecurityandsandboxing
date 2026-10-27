# Policy reference

The policy is a TOML file named `agentkeep.toml`. agentkeep assembles the
effective policy from layers, lowest priority first:

1. built-in defaults (`agentkeep policy show --defaults`),
2. an agent preset (Phase 5),
3. the global file `~/.config/agentkeep/agentkeep.toml`
   (or `$XDG_CONFIG_HOME/agentkeep/agentkeep.toml`),
4. the project file `agentkeep.toml`, searched upward from the current
   directory and stopping at the git root,
5. command-line flags (`--project`, `--backend`, `--allow-domain`,
   `--allow-degraded`).

Scalars: the last layer that sets a value wins. Lists: the union of all
layers. `hidden`, `network.deny`, `commands.deny` and `mcp.deny_tools` only
grow; the one way to remove an entry is the `[override]` table in the
*project* file with `acknowledge = true`, and every removal is printed in red
at startup and written to the audit log.

Unknown keys are errors. `schema = 1` is required in every file.

Paths accept `~` (your home) and `$PROJECT` (the project root). They are
directory prefixes: `~/.config` covers everything beneath it.

## `[sandbox]`

| Key | Default | Meaning |
|---|---|---|
| `backend` | `"auto"` | `auto`, `linux`, `macos`, `container`, `wsl` |
| `allow_degraded` | `false` | Run even when the backend cannot enforce every rule |
| `preset` | unset | Agent preset name (Phase 5) |

`container` uses Podman when it works and Docker otherwise; the environment
variable `AGENTKEEP_CONTAINER_RUNTIME=podman|docker` picks one. It is not a
policy key because it describes the host, not what the agent may do.

## `[filesystem]`

| Key | Default | Meaning |
|---|---|---|
| `project` | `"."` | The read-write root. Relative paths resolve against the file that sets them; the default means the git root of the current directory |
| `read_only` | system paths | Host paths visible read-only. Missing paths are skipped |
| `read_write` | `[]` | Host paths visible read-write besides the project. `/` and `~` are refused |
| `hidden` | credential paths | Paths that must not exist inside the sandbox even under a visible tree |

The home directory itself is never mounted; it is replaced by a private,
empty tmpfs. `hidden` is a second layer for paths you expose on purpose
(for example `read_only = ["~/.config"]` keeps `~/.config/gcloud` hidden).

## `[env]`

| Key | Default | Meaning |
|---|---|---|
| `allow` | terminal and locale variables | Names, or `PREFIX_*` globs, passed through unchanged |
| `pass` | `[]` | Secrets passed through deliberately (the agent's own API key). The DLP layer binds each to its provider's domains (Phase 2) |
| `set` | `{ TMPDIR = "/tmp" }` | Fixed values |

Everything else is dropped. Names of dropped variables are written to the
audit log, split into "looked like a secret" and "other"; values never are.

## `[network]` (enforced from Phase 2)

| Key | Default | Meaning |
|---|---|---|
| `allow` | `[]` | Hosts the agent may reach. `*.example.com` matches subdomains, not the apex. `host:port` restricts the port |
| `ask` | `[]` | Hosts that prompt on first contact in a session |
| `deny` | `[]` | Always refused. Deny beats ask beats allow |
| `tls_inspect` | `true` | Inspect `CONNECT` tunnels on any port: TLS is decrypted and scanned, plaintext HTTP is scanned, any other protocol is refused. `false` tunnels everything unscanned |
| `passthrough` | `[]` | Allowed hosts exempt from inspection (pinned clients, non-HTTP protocols); no DLP there, logged `inspected: false` |
| `allow_private` | `false` | Permit private and loopback address ranges. Link-local and cloud metadata addresses are always refused |
| `trusted_cas` | `[]` | Extra PEM files the proxy trusts for origin certificates (internal CAs) |

`"*"` and single-label patterns such as `*.com` are rejected as too broad.

## `[dlp]` (Phase 2)

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Scan outbound requests for secrets |
| `block_values` | `[]` | Extra literal values to block (hashed in memory) |
| `allow_provider_keys_to` | `{}` | Map of secret name to the domains it may travel to |

## `[commands]`

Globs matched against the whole command line, with the program reduced to
its basename (`/usr/bin/git push` matches `git push*`). `*` matches anything
including spaces. Deny beats ask.

| Key | Default |
|---|---|
| `ask` | `git push*`, `rm -rf *`, `git reset --hard*`, `docker *`, cloud CLIs, `npm publish*`, ... |
| `deny` | `sudo *`, `su`, `*curl * \| *sh*`, `ssh *`, `mount *`, ... |

Enforced through shims placed first on `PATH` for the first word of each
pattern. A process can bypass a shim by calling the absolute path; treat
command rules as a guard rail, not a boundary.

## `[mcp]` (Phase 4)

`allow_tools`, `deny_tools` (`server:tool` globs), `pin` (`strict`, `warn`,
`off`), `block_injection`, and per-server `[mcp.args.<server>]` tables.

## `[limits]`

| Key | Default | Meaning |
|---|---|---|
| `cpu_percent` | `400` | CPU quota in percent of one core; cgroup backends only |
| `memory` | `"8G"` | Memory limit (`cgroup memory.max`, else `RLIMIT_AS`) |
| `pids` | `1024` | Maximum processes (`pids.max`, else `RLIMIT_NPROC`) |
| `wall_time` | `"8h"` | Kill the whole session after this long |

## `[approval]`

| Key | Default | Meaning |
|---|---|---|
| `transport` | `["tty", "socket"]` | Where prompts go, in order. `socket` means `agentkeep approve <path>` clients |
| `timeout` | `"60s"` | No answer within this time means deny |

`--no-ask` denies every prompt without asking.

## `[audit]`

| Key | Default | Meaning |
|---|---|---|
| `dir` | `~/.local/share/agentkeep/sessions` | One subdirectory per session with `events.jsonl` |
| `redact` | `true` | Replace anything the DLP detectors recognise (credential formats, `dlp.block_values`, `env.pass` secrets) in every logged string with `[REDACTED:<detector>]`. `dlp.block_values` are never logged either way |

## Trust for project files

A project's `agentkeep.toml` comes with the repository, so agentkeep does
not apply it in full until you trust it (threat model S1). Until then only
its *tightening* settings apply:

| Applies from an untrusted project file | Ignored until the file is trusted |
|---|---|
| `filesystem.hidden` | `filesystem.project`, `read_only`, `read_write` |
| `network.deny`; `tls_inspect = true`; `allow_private = false` | `network.allow`, `ask`, `passthrough`, `trusted_cas`; `tls_inspect = false`; `allow_private = true` |
| `dlp.block_values`; `dlp.enabled = true` | `dlp.enabled = false`, `report_only`, `allow_provider_keys_to` |
| `commands.ask`, `commands.deny` | everything in `[env]` |
| `mcp.deny_tools`; `pin = "strict"`; `block_injection = true` | `mcp.allow_tools`, `args`, weaker `pin`, `block_injection = false` |
| `limits` and `approval.timeout` that are lower than the current value | higher limits, `approval.transport`, `[audit]`, `[override]`, `sandbox.backend`, `allow_degraded = true` |

Every ignored setting is named in one warning at startup and recorded in
the session log (`project_trust`).

```sh
agentkeep policy trust [FILE]    # trust this exact content; prints what it loosens
agentkeep policy untrust [FILE]
agentkeep run --trust-project -- <cmd>   # trust for one run (CI)
```

Trust is stored per absolute path and SHA-256 in
`~/.config/agentkeep/trusted.toml` (mode `0600`). Editing the file revokes
it. `agentkeep policy init` trusts the file it writes. A file named
explicitly with `--policy` is treated as trusted. Your global file is
always trusted. The trust store and the audit directory are never
visible inside a sandbox.

## `[override]`

Project file only, and only when the file is trusted. Ignored, with a warning, anywhere else or without
`acknowledge = true`.

| Key | Meaning |
|---|---|
| `acknowledge` | Must be `true` |
| `unhide` | Hidden paths to expose again |
| `undeny_domains` | Domains to remove from `network.deny` |
| `undeny_commands` | Patterns to remove from `commands.deny` |

## Commands

```sh
agentkeep policy init              # interactive; --defaults writes the template
agentkeep policy show              # effective policy with sources and warnings
agentkeep policy show --defaults   # the compiled-in defaults
agentkeep policy check [FILE]      # validate; non-zero exit on error
agentkeep policy trust [FILE]      # apply a project file in full (see above)
agentkeep policy untrust [FILE]
agentkeep doctor                   # which backend works here and what it can enforce
```
