#!/usr/bin/env bash
# Every `uses:` in .github/workflows and action/ must reference a full 40-hex
# commit SHA (with a trailing version comment), never a tag or branch.
# Local actions (./path) are exempt.
set -euo pipefail

status=0
while IFS= read -r file; do
  while IFS= read -r line; do
    ref=$(printf '%s' "$line" | sed -E 's/.*uses:[[:space:]]*"?([^"[:space:]#]+)"?.*/\1/')
    case "$ref" in
      ./*|docker://*) continue ;;
    esac
    if ! printf '%s' "$ref" | grep -Eq '@[0-9a-f]{40}$'; then
      echo "::error file=$file::unpinned action: $ref"
      status=1
    fi
  done < <(grep -En '^[[:space:]]*-?[[:space:]]*uses:' "$file" || true)
done < <(find .github/workflows action -name '*.yml' -o -name '*.yaml' 2>/dev/null)

[ "$status" -eq 0 ] && echo "All actions are pinned by commit SHA."
exit "$status"
