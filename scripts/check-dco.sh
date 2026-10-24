#!/usr/bin/env bash
# Fail if any commit in BASE..HEAD lacks a "Signed-off-by:" trailer.
# Usage: scripts/check-dco.sh <base-sha> <head-sha>
set -euo pipefail

base="${1:?base sha}"
head="${2:?head sha}"

missing=0
while IFS= read -r sha; do
  [ -z "$sha" ] && continue
  if ! git log -1 --format='%(trailers:key=Signed-off-by,valueonly)' "$sha" | grep -q .; then
    echo "::error::commit $sha has no Signed-off-by trailer (use: git commit -s)"
    missing=1
  fi
done < <(git rev-list "$base".."$head")

if [ "$missing" -ne 0 ]; then
  echo "See DCO and CONTRIBUTING.md: every commit must carry a Developer Certificate of Origin sign-off."
  exit 1
fi
echo "All commits are signed off."
