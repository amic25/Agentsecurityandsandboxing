# Agent presets

A preset tells `agentkeep run` what a particular agent needs: the domains it
must reach, the config paths it must write, and its known quirks. Presets can
only **add** domains and paths; they cannot disable a protection. The format
lands in Phase 5; the draft below is the target.

```yaml
name: claude-code
detect: ["claude"]                      # command basenames that select this preset
domains:
  - api.anthropic.com
  - statsig.anthropic.com               # feature flags; deny if you prefer
  - sentry.io                           # crash reports; deny if you prefer
config_paths:
  rw: ["~/.claude", "~/.claude.json"]   # contains the agent's own credential: inherent
  ro: ["~/.gitconfig"]
env_allow: ["CLAUDE_CONFIG_DIR"]
needs_proxy_env: true
tls_passthrough: []
known_quirks: |
  Honours HTTPS_PROXY and NODE_EXTRA_CA_CERTS. Needs /dev/tty for its UI.
```

Every preset must note honestly that mounting the agent's own config
directory read-write exposes that agent's credential to the agent itself.
That is inherent; it is the one secret the agent gets, and the DLP layer
pins it to the provider's domains.

Presets planned for v0.1.0: `claude-code`, `codex`, `opencode`, `gemini-cli`,
`cline`, `goose`. Open a *preset request* issue for others.
