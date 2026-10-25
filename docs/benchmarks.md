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

Not yet measured: GitHub Actions runners (cgroup v2 path), arm64, the
container backend (expected to be far above 50 ms; will be reported
separately), macOS.

## Proxy latency

Phase 2.

## Scanner throughput

Phase 3.
