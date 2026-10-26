#!/usr/bin/env bash
# Measure the latency the egress proxy adds, against the 5 ms p50 budget.
# Starts local origins and the proxy in one process; nothing leaves the host.
# Usage: benches/proxy.sh [samples_1KiB] [samples_1MiB]
set -euo pipefail
cd "$(dirname "$0")/.."
echo "host: $(uname -srm), $(getconf _NPROCESSORS_ONLN 2>/dev/null || echo '?') CPUs"
if [ -r /proc/cpuinfo ]; then
  echo "cpu:  $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')"
fi
echo "date: $(date -u +%Y-%m-%dT%H:%MZ)"
echo
cargo run --release --locked --quiet -p agentkeep-proxy --example latency -- "$@"
