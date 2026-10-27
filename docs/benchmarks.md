# Benchmarks

Numbers are measured, not promised. Re-run with `benches/startup.sh` (needs a
release build) and update this file in the same PR as any change that could
move them.

## Startup overhead (`agentkeep run -- true` vs bare `true`)

Target: under 50 ms at p50 on Linux.

| Host | Backend | bare `true` p50 | `agentkeep run -- true` p50 | Overhead |
|---|---|---|---|---|
| Linux 6.18 x86_64, 4 vCPU Firecracker VM, cgroup v1 (rlimit fallback), Landlock ABI 7 | linux | 1.98 ms | 12.33 ms | **~10.4 ms** |

Measured 2026-10-25 with 40 runs after 3 warm-ups, wall clock around
`subprocess.run`, default policy (24 mounts, seccomp, Landlock). The cost is
dominated by namespace creation, the bind mounts and two `execve`s (init and
the command).

### Container backend

| Host | Backend | bare `true` p50 | `agentkeep run -- true` p50 | Overhead |
|---|---|---|---|---|
| same VM, Docker 29.9 rootful, cgroup v1 | container (docker) | 1.9 ms | 385.4 ms | **~384 ms** |
| same VM, Podman 4.9.3 rootful, runc | container (podman) | 1.9 ms | 661.4 ms | **~660 ms** |
| same VM, same session, for comparison | linux | 1.9 ms | 21.7 ms | ~20 ms |

Measured 2026-10-26 with `N=30 BACKEND=container benches/startup.sh`
(`AGENTKEEP_CONTAINER_RUNTIME` selecting the runtime), release build, while
other jobs shared the 4 vCPUs, which is also why the linux row is higher than
the 2026-10-25 measurement above. Where the Docker time goes (p50 of 10 runs
each): `docker info` for the probe 74 ms, `docker image inspect` 40 ms, a
bare `docker run --rm` of `/bin/true` with the same mounts 232 ms. The
container backend is an order of magnitude above the 50 ms target, which is
why `auto` picks it only when the linux backend is unavailable.

Not yet measured: GitHub Actions runners (cgroup v2 path), arm64, rootless
Podman, macOS.

## Proxy latency

Targets (PLAN 2.11): under 5 ms added at p50 for a plain `CONNECT` tunnel,
and for TLS inspection with DLP on 1 KiB bodies; 1 MiB is reported
separately.

Re-run with `benches/proxy.sh [samples_1KiB] [samples_1MiB]` (release
build of `crates/agentkeep-proxy/examples/latency.rs`, no dependencies
beyond the proxy's own).

Method: one process starts a plain HTTP origin, a TLS origin (self-signed
for `localhost`) and the proxy on its own two-worker runtime, exactly as
`agentkeep run` starts it, with DLP on, TLS inspection on and every event
written to a real hash-chained audit log. Each sample is one `POST` with an
N-byte body answered by an N-byte body, on a fresh connection (TCP, plus a
TLS handshake for HTTPS), and the client reads the full response. The
client talks to the proxy's Unix socket directly, so the in-sandbox
loopback relay (one extra local copy) is not included. Direct and proxied
samples are interleaved; "added" is the p50/p95 of the per-pair
difference. Origins are on host loopback; nothing leaves the machine.

| Host | Run |
|---|---|
| Linux 6.18 x86_64, 4 vCPU (Intel Xeon @ 2.80 GHz, KVM/Firecracker VM, shared with other jobs, load average ~1) | 2026-10-26, 500 samples at 1 KiB, 100 at 1 MiB, two runs |

Milliseconds, first run / second run:

| Path | Body | direct p50 | proxied p50 | **added p50** | added p95 |
|---|---|---|---|---|---|
| plain HTTP, forward proxy, DLP | 1 KiB | 0.24 / 0.21 | 0.42 / 0.35 | **0.17 / 0.14** | 0.39 / 0.26 |
| HTTPS, `CONNECT` inspected (TLS + DLP) | 1 KiB | 0.74 / 0.72 | 1.85 / 1.74 | **1.08 / 1.02** | 1.94 / 1.54 |
| HTTPS, `CONNECT` passthrough | 1 KiB | 0.67 / 0.67 | 1.02 / 1.04 | **0.33 / 0.36** | 0.68 / 0.69 |
| plain HTTP, forward proxy, DLP | 1 MiB | 3.47 / 3.59 | 6.56 / 6.17 | **2.95 / 2.65** | 5.86 / 3.86 |
| HTTPS, `CONNECT` inspected (TLS + DLP) | 1 MiB | 4.89 / 4.43 | 10.24 / 9.09 | **5.17 / 4.76** | 7.07 / 5.99 |
| HTTPS, `CONNECT` passthrough | 1 MiB | 4.38 / 4.18 | 6.11 / 5.00 | **1.75 / 0.94** | 9.76 / 2.87 |

A third run on the committed code (load average ~2.4) gave added p50 of
0.14, 0.99 and 0.30 ms at 1 KiB and 2.68, 4.67 and 1.01 ms at 1 MiB, in
table order.

Re-run 2026-10-27 after the Phase 2 hardening (metadata block, SNI and
`Host` checks), with the benchmark now also redacting every event before
logging it, as `agentkeep run` does. Same host, load average ~0.7 to 1.0,
500/100 samples, two runs, added p50 in table order:

| Run | 1 KiB plain | 1 KiB inspected | 1 KiB passthrough | 1 MiB plain | 1 MiB inspected | 1 MiB passthrough |
|---|---|---|---|---|---|---|
| 1 | 0.18 | 1.12 | 0.40 | 2.99 | 5.67 | 0.92 |
| 2 | 0.20 | 1.34 | 0.43 | 3.05 | 6.32 | 1.07 |

Reading: every 1 KiB path and the plain tunnel at both sizes are well
inside the 5 ms p50 budget. Inspection of a 1 MiB body costs 5 to 6.5 ms at
p50 on this host, above the 5 ms line that applies to 1 KiB bodies: the
body is decrypted, scanned in chunks with the carry-over window, and
re-encrypted. The 10-27 runs are about 1 ms slower on that row than the
10-26 runs. Direct 1 MiB HTTPS times were up to 1 ms higher too in one of
the two runs, so host variance may explain part of it; nothing in the
hardening runs per byte. Not investigated further yet. Most of the 1 KiB
inspected cost is the second TLS handshake, because the proxy opens a new
origin connection for every request (no pool; see `limitations.md`). p95
on the passthrough 1 MiB row varies between runs on this shared host.

Not yet measured: keep-alive reuse from the client, HTTP/2 inside the
tunnel (not negotiated in v1), GitHub Actions runners, arm64, macOS.

## Scanner throughput

Phase 3.
