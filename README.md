# agentkeep

**Run any agent with one command. It can only touch what you allow, and you
can see everything it did.**

agentkeep is a drop-in security layer for AI coding and personal agents
(Claude Code, Codex CLI, OpenCode, Gemini CLI, Cline, Goose and others). One
binary, one policy file, the same rules on every agent and every OS.

> **Status: pre-alpha, Phase 2.** `agentkeep run` sandboxes a command on
> Linux (namespaces, Landlock, seccomp), in a Podman/Docker container
> (`--backend container`), or on macOS with Seatbelt (weaker than Linux;
> see `docs/limitations.md`). Network traffic goes through an egress proxy
> with a domain allowlist, TLS inspection and outbound secret detection.
> The policy engine, approval prompts and the redacted, hash-chained audit
> log work, and 43 escape tests run against all three backends in CI. Not
> implemented yet: Windows, agent presets, the scanner, the MCP gateway,
> and the log viewer and reports. Check `PLAN.md`
> for when each lands and `CHANGELOG.md` for what has landed.

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

## Try it today (Linux or macOS)

```sh
cargo build --release
cd your-project
./target/release/agentkeep doctor                 # what this host can enforce
./target/release/agentkeep policy init --defaults # commented agentkeep.toml
./target/release/agentkeep run -- sh              # a shell that sees only the project
cat ~/.ssh/id_ed25519                             # inside: No such file or directory
curl -sI https://example.com                      # inside: 403 from the proxy, not allowed
exit
./target/release/agentkeep run --allow-domain example.com -- curl -sI https://example.com
```

Every session writes `~/.local/share/agentkeep/sessions/<id>/events.jsonl`.
A project's own `agentkeep.toml` can only tighten the policy until you run
`agentkeep policy trust`, because it comes with the repository.

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
