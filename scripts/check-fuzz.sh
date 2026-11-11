#!/usr/bin/env bash
set -euo pipefail

# The fuzz workspace is detached from the root workspace and must be checked
# through its own manifest, matching the dedicated CI job.
if [[ -n "$(bash scripts/fuzz-duration.sh self-test 2>/dev/null)" ]]; then
  echo "::error::the resolver self-test wrote to stdout"
  exit 1
fi
bash scripts/fuzz-duration.sh self-test
cargo fmt --manifest-path fuzz/Cargo.toml -- --check
cargo clippy --manifest-path fuzz/Cargo.toml --locked --all-targets -- -D warnings
cargo check --manifest-path fuzz/Cargo.toml --locked --all-targets
cargo test --manifest-path fuzz/Cargo.toml --locked --test seed_corpus
