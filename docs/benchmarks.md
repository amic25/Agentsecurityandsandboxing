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

Phase 2.

## Scanner throughput

Phase 3.
