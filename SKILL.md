---
name: agentkeep
description: Configure and use agentkeep, the security layer for AI coding agents. Use when a user wants to sandbox an agent, write or fix an agentkeep.toml policy, allow a domain or path, set up the MCP gateway, scan a repository for prompt injection, or read an agentkeep audit log.
---

# agentkeep skill

agentkeep runs an agent in a sandbox where only the project is writable,
secrets are hidden, and all network traffic goes through an allowlisting
proxy with outbound secret detection. Everything is logged.

> This skill describes the v0.1.0 interface from `PLAN.md`. Until a command is
> implemented it exits with status 70 and says so. Check `CHANGELOG.md`.

## Quick commands

```sh
agentkeep run -- claude                 # sandbox Claude Code with the claude-code preset
agentkeep run --preset codex -- codex   # force a preset
agentkeep policy init                   # create agentkeep.toml interactively
agentkeep policy show                   # print the effective merged policy
agentkeep policy check                  # validate with line numbers
agentkeep scan . --format sarif         # scan for agent attack surfaces
agentkeep log                           # browse the latest session
agentkeep log --verify                  # check the hash chain
agentkeep report --format md            # summarise a session
```

## Policy file (`agentkeep.toml`)

Lives at the project root, merged over `~/.config/agentkeep/agentkeep.toml`
and the built-in defaults. Lower-priority files cannot remove `deny` or
`hidden` rules. A project file that came with the repository only tightens
until the user runs `agentkeep policy trust`; never run that on the user's
behalf, show them what the file loosens and let them decide.

```toml
schema = 1

[filesystem]
read_write = ["~/.cache/pip"]       # extra writable paths
hidden     = ["~/secrets"]          # added to the built-in secret paths

[env]
pass = ["ANTHROPIC_API_KEY"]        # the agent's own key; bound to its provider domain

[network]
allow = ["api.anthropic.com", "*.npmjs.org"]
ask   = ["*.github.com"]            # prompt on first contact
deny  = ["*.pastebin.com"]          # deny beats ask beats allow

[commands]
ask  = ["git push*", "rm -rf *"]
deny = ["sudo *", "curl * | sh"]

[limits]
memory = "4G"
pids = 512
wall_time = "2h"
```

## When the agent cannot reach something

1. Run `agentkeep log` and filter for `net.deny` or `policy.decision`.
2. Add the domain to `[network] allow` (or `ask`), or the path to
   `[filesystem] read_write`. Prefer the narrowest rule.
3. If a tool ignores `HTTP_PROXY`, it has no network by design. Check the
   preset's known quirks.

## Do not

- Do not set `allow = ["*"]` or `tls_inspect = false` globally to "fix" an
  error; add the specific host to `passthrough` instead.
- Do not mount `~` or `/` read-write.
- Do not disable `[dlp]`.
