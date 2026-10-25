# Escape suite

`crates/agentkeep/tests/escape.rs` tries, from inside a sandbox, to do what
`docs/threat-model.md` says must fail: read `~/.ssh`, write outside the
project, follow symlinks and hardlinks to hidden paths, see host processes,
ptrace, mount, create namespaces, reach the network or DNS, keep secret
environment variables, gain capabilities, exceed limits, or run a denied
command. Each test is named after its threat id and must fail closed.

Run it with `tests/escape/run.sh`. It never skips silently: on a host without
a usable backend every test prints `UNTESTED ON THIS HOST`, and with
`AGENTKEEP_REQUIRE_SANDBOX=1` that is a failure.

All fixtures are fake (`FAKE_TEST_KEY`, `AKIA_TEST_FAKE...`) and the only
network destination is loopback or a TEST-NET address that must be
unreachable.
