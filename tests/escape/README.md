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

All fixtures are fake (`FAKE_TEST_KEY`, `AKIA_TEST_FAKE...`) and the only
network destination is loopback or a TEST-NET address that must be
unreachable.
