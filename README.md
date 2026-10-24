# agentkeep

**Run any agent with one command. It can only touch what you allow, and you
can see everything it did.**

agentkeep is a drop-in security layer for AI coding and personal agents
(Claude Code, Codex CLI, OpenCode, Gemini CLI, Cline, Goose and others). One
static binary, one policy file, the same rules on every agent and every OS.

> **Status: pre-alpha, Phase 0.** The repository skeleton, CI and threat model
> exist. **No sandboxing is implemented yet.** Do not rely on it. Follow
> `PLAN.md` for what lands when, and `CHANGELOG.md` for what has landed.

<!-- demo GIF lands in Phase 6: an injected README tries to steal ~/.ssh and agentkeep blocks it -->

## Why

Agents run shell commands, read files and call tools with your full
permissions. Your SSH keys, cloud credentials, browser cookies and whole home
directory are one prompt injection away, and prompt injection hides in
READMEs, PR descriptions, MCP tool outputs, `SKILL.md`, `AGENTS.md`,
`.cursorrules` and config files. Built-in agent sandboxes differ per agent,
differ per OS, and have had escape CVEs. Malicious MCP servers and packages
are a growing supply-chain problem.

agentkeep gives you one policy, one audit log and one command, with
deny-by-default filesystem, environment, network and MCP controls.

## What it will do (v0.1.0)

| Command | What it does |
|---|---|
| `agentkeep run -- <agent>` | Sandbox: project read-write, system read-only, secrets hidden, env scrubbed, all traffic through an egress proxy with a domain allowlist and outbound secret detection, CPU/memory/pid/time limits. Linux namespaces + Landlock + seccomp, macOS Seatbelt, or a Podman/Docker container, picked automatically. |
| `agentkeep policy init` | Generate a commented `agentkeep.toml` for your project. "Ask" mode pauses for a human before `git push`, new domains and other sensitive actions. |
| `agentkeep mcp-gateway` | Proxy between the agent and its MCP servers: tool allowlists, per-argument rules, version and hash pinning with rug-pull detection, untrusted-output marking, full logging. |
| `agentkeep scan` | Static scanner for agent attack surfaces: hidden Unicode, instructions aimed at agents, exfiltration beacons, `curl \| sh`, over-broad permissions, unsafe CI workflows. Text, JSON and SARIF output, plus a GitHub Action. |
| `agentkeep log` / `report` | Append-only, hash-chained audit log of every command, write, request, MCP call and policy decision, with a terminal viewer and shareable reports. |

## Install

Not yet. Phase 6 adds `brew install`, `cargo install agentkeep`, `npm i -g`,
`pip install` and `curl | sh` with a printed checksum, all signed. Until then:

```sh
git clone https://github.com/amic25/Agentsecurityandsandboxing agentkeep
cd agentkeep && cargo build --release
./target/release/agentkeep --help
```

## Honest scope

agentkeep reduces blast radius. It is defense in depth, not a guarantee. The
threat model (`docs/threat-model.md`) lists what is covered, what is partial
per backend, and what is out of scope. `docs/limitations.md` tracks every
known gap. We never claim a protection that does not have a failing-closed
test behind it.

## Contributing

Presets for new agents and scanner rules are plain YAML and the best way to
help. See `CONTRIBUTING.md`, `presets/README.md` and `rules/README.md`.
Security issues go through `SECURITY.md`.

## Licence

Apache-2.0. Contributions are accepted under the Developer Certificate of
Origin (`DCO`); there is no CLA.
