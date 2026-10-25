#!/usr/bin/env bash
# Run the escape suite with full output so every UNTESTED line is visible.
# On Linux CI, AGENTKEEP_REQUIRE_SANDBOX=1 turns UNTESTED into a failure.
set -euo pipefail
cd "$(dirname "$0")/../.."
echo "escape suite: host $(uname -s) $(uname -m)"
cargo test -p agentkeep --test escape -- --nocapture --test-threads=2 "$@" 2>&1 | tee /tmp/agentkeep-escape.log
if grep -q "UNTESTED ON THIS HOST" /tmp/agentkeep-escape.log; then
  echo
  echo "============================================================"
  echo " UNTESTED ON THIS HOST: the sandbox could not be exercised."
  echo " These tests did not pass; they did not run."
  echo "============================================================"
  if [ "${AGENTKEEP_REQUIRE_SANDBOX:-}" = "1" ]; then exit 1; fi
fi
