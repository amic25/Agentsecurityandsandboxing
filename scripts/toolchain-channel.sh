#!/usr/bin/env bash
# Print the pinned toolchain from rust-toolchain.toml as `channel=<version>`,
# so CI installs exactly the version developers use. Single source of truth.
set -euo pipefail
cd "$(dirname "$0")/.."
channel=$(sed -nE 's/^channel *= *"([^"]+)".*/\1/p' rust-toolchain.toml)
[ -n "$channel" ] || { echo "no channel in rust-toolchain.toml" >&2; exit 1; }
echo "channel=$channel"
