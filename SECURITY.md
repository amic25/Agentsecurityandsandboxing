# Security Policy

agentkeep is a security tool. Bugs in it can expose exactly the things it
exists to protect, so we treat every report seriously and respond fast.

## Reporting a vulnerability

**Please do not open a public issue for security bugs.**

Use one of these private channels:

1. **GitHub private vulnerability reporting** (preferred):
   open the repository's *Security* tab and click *Report a vulnerability*.
   This creates a private advisory that only maintainers can see.
2. **Email:** `security@agentkeep.dev` *(mailbox pending; until it is live,
   use channel 1)*.

Include, where you can:

- the agentkeep version (`agentkeep version`) and the backend in use
  (`linux`, `macos`, `container`, `wsl`),
- the operating system and kernel version,
- a minimal reproduction, ideally as a new case in `tests/escape/`,
- the impact you believe it has (what the sandboxed agent could read, write,
  reach or exfiltrate).

You will get an acknowledgement within **3 days** and a triage decision within
**7 days**. We aim to ship a fix for confirmed sandbox escapes, policy
bypasses and data-loss-protection bypasses within **30 days**, and we will
credit you in the advisory and the CHANGELOG unless you ask us not to.

## What counts as a vulnerability

In scope:

- any way for a sandboxed agent to read, write or delete outside the policy,
  reach a domain that is not allowed, or send a secret the DLP layer should
  have blocked;
- any way to make the audit log miss or misrepresent an action;
- policy parsing or merging that silently loosens a rule;
- the MCP gateway letting a denied tool through or failing to detect a
  changed tool definition when pinning is strict;
- a scanner bypass for a rule category we claim to detect, when it is
  realistic rather than contrived;
- supply-chain issues in our release pipeline.

Out of scope (see `docs/threat-model.md`):

- kernel, hypervisor and container-runtime escapes that are not specific to
  agentkeep;
- attacks that stay entirely inside what the policy allows;
- findings that require an attacker to already control the host or the
  policy file;
- social engineering of the human at the approval prompt.

## Supported versions

Until 1.0, only the latest minor release receives fixes.

## Disclosure

We follow coordinated disclosure. We publish a GitHub security advisory with a
CVE when a fix is released, and we will never ask you to delay disclosure for
more than 90 days from your report.
