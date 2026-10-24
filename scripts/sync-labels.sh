#!/usr/bin/env bash
# Create or update the repository labels from .github/labels.yml.
# Requires: gh (authenticated), python3.
set -euo pipefail
repo="${1:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
python3 - "$repo" <<'PY'
import subprocess, sys, re
repo = sys.argv[1]
labels, cur = [], {}
for line in open(".github/labels.yml"):
    m = re.match(r"\s*-\s*name:\s*(.+)", line)
    if m:
        cur = {"name": m.group(1).strip()}; labels.append(cur); continue
    m = re.match(r"\s*(color|description):\s*(.+)", line)
    if m and cur:
        cur[m.group(1)] = m.group(2).strip()
for l in labels:
    args = ["gh", "label", "create", l["name"], "--repo", repo, "--force",
            "--color", l.get("color", "ededed"), "--description", l.get("description", "")]
    print(" ".join(args[2:4]))
    subprocess.run(args, check=True)
PY
