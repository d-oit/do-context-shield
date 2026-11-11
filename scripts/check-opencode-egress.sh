#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cargo build --manifest-path "$root/Cargo.toml" -p do-context-shield
cd "$root/adapters/opencode-egress"
bun install --frozen-lockfile
bun run check
