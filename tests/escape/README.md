# Escape suite

`crates/agentkeep/tests/escape.rs` tries, from inside a sandbox, to do what
`docs/threat-model.md` says must fail: read `~/.ssh`, write outside the
project, follow symlinks and hardlinks to hidden paths, see host processes,
ptrace, mount, create namespaces, reach the network or DNS, keep secret
environment variables, gain capabilities, exceed limits, or run a denied
command. Each test is named after its threat id and must fail closed.

Run it with `tests/escape/run.sh`. It never skips silently: on a host without
a usable backend every test prints `UNTESTED ON THIS HOST`, and with
`AGENTKEEP_REQUIRE_SANDBOX=1` that is a failure. CI sets it on the Linux and
macOS runners and pins the backend with `AGENTKEEP_ESCAPE_BACKEND`.

Tests gated on a control the backend does not claim print `NOT APPLICABLE`;
universal ones (no secret leaks, the host is never modified, the proxy is
the only way out, the approver socket is unreachable) run on every backend.
Host paths are probed through `~` and through their absolute location,
because on macOS `HOME` inside the sandbox is a private directory and only
the absolute probes exercise the Seatbelt profile.

The network tests start their own origins on host `127.0.0.1` (plain HTTP,
and TLS with a throwaway self-signed certificate trusted through
`network.trusted_cas`). Each origin records every byte it receives, so a test
can assert that a blocked secret never arrived. They cover the allowlist
(N1), DLP over HTTP and inside inspected TLS (N2), provider-key binding (E3),
private and metadata addresses (N5), passthrough, DNS (N3), WebSocket
upgrades (N7), the session CA (N6), and, under `strace`, that the
supervisor itself opens no network connection (S5). `curl`, `python3` and
`strace` are needed on the host; a missing tool is reported as UNTESTED.

All fixtures are fake (`FAKE_TEST_KEY`, `AKIATESTFAKE...`, `ghp_TESTFAKE...`,
`sk-ant-test-fake-...`) and the only network destinations are host
loopback, a TEST-NET address that must be unreachable, and
`169.254.169.254`, which the proxy must refuse before connecting.
