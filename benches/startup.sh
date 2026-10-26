#!/usr/bin/env bash
# Measure the overhead of `agentkeep run -- true` against a bare `true`.
# Prints p50 and mean in milliseconds. Uses hyperfine when available.
# BACKEND=container (or linux) forces a backend; default is auto.
set -euo pipefail
cd "$(dirname "$0")/.."
AK=$(realpath "${AK:-target/release/agentkeep}")
[ -x "$AK" ] || { echo "build first: cargo build --release" >&2; exit 1; }
N=${N:-30}
RUN=("$AK" --no-ask run)
if [ -n "${BACKEND:-}" ]; then RUN+=(--backend "$BACKEND"); fi
tmp=$(mktemp -d)
mkdir -p "$tmp/home" "$tmp/proj"
export HOME="$tmp/home"
cd "$tmp/proj"
if command -v hyperfine >/dev/null; then
  hyperfine -N --warmup 3 --runs "$N" "true" "${RUN[*]} -- true"
  exit 0
fi
measure() {
  local times=()
  for _ in $(seq 1 "$N"); do
    local s e
    s=$(date +%s%N); "$@" >/dev/null 2>&1 || { echo "command failed: $*" >&2; exit 1; }; e=$(date +%s%N)
    times+=($(( (e - s) / 1000 )))
  done
  printf '%s\n' "${times[@]}" | sort -n | awk -v n="$N" '{a[NR]=$1; s+=$1} END {printf "p50=%.1fms mean=%.1fms min=%.1fms max=%.1fms\n", a[int((n+1)/2)]/1000, s/n/1000, a[1]/1000, a[n]/1000}'
}
echo "bare true:        $(measure true)"
echo "agentkeep run:    $(measure "${RUN[@]}" -- true)  (backend ${BACKEND:-auto})"
