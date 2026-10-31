#!/usr/bin/env bash
# Regenerate tests/corpus/baseline.json from the current rules and corpus.
#
# The corpus test fails when overall precision or recall, or any rule's
# recall, drops below this file. Rewriting it accepts the current numbers as
# the new floor, so a human must review the diff before committing: a lower
# number is a regression being accepted, and a removed rule disappears from
# the floor.
set -euo pipefail
cd "$(dirname "$0")/.."

AGENTKEEP_CORPUS_WRITE_BASELINE=1 \
  cargo test -p agentkeep-scan --test corpus --locked -- --nocapture

echo
echo "Review before committing:"
git --no-pager diff --stat -- tests/corpus/baseline.json
git --no-pager diff -- tests/corpus/baseline.json
