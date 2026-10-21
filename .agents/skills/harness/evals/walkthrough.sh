#!/usr/bin/env bash
# harness walkthrough: proves the structure gate accepts this skill and that the
# documented config -> list -> verify path works — hermetically inside the eval
# sandbox.
#
# The eval sandbox contains only this skill directory (plus skill-creator's
# scripts), so this walkthrough writes its own minimal config and never depends
# on mirrored repository files. Repo-path claims in the sensor map are checked
# by scripts/check-skills.sh, which runs against the real workspace.
set -euo pipefail
root="${DO_HARNESS_ROOT:?DO_HARNESS_ROOT required}"
bin="${DO_HARNESS_BIN:-do-harness}"
receipt="$root/harness_receipt.txt"

python3 "$root/.agents/skills/skill-creator/scripts/quick_validate.py" \
  "$root/.agents/skills/harness" > "$root/harness_validate.txt"

cat > "$root/do-harness.toml" << 'TOML'
language = "generic"

[signal-sets]
verification = ["probe"]

[[sensors]]
name = "probe"
argv = ["true"]
TOML

"$bin" --root "$root" list > "$root/harness_sensors.txt"
grep -qx probe "$root/harness_sensors.txt"
"$bin" --root "$root" verify --set verification > "$root/harness_verify.txt"
grep -q 'All sensors passed' "$root/harness_verify.txt"

# Member manifest selection and invalid manifest failure fixture
git_fixture="$root/fixture"
mkdir -p "$git_fixture/crates/member-crate"
(
  cd "$git_fixture"
  git init -q
  git config user.email "test@example.com"
  git config user.name "Test"
  cat > do-harness.toml << 'EOF'
language = "rust"

[signal-sets]
verification = ["fmt", "check", "clippy", "test"]

[[sensors]]
name = "fmt"
argv = ["cargo", "fmt", "--all", "--", "--check"]
when-changed = ["**/*.rs", "**/Cargo.toml", "Cargo.lock", "rust-toolchain.toml"]

[[sensors]]
name = "check"
argv = ["cargo", "check", "--workspace"]
when-changed = ["**/*.rs", "**/Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".cargo/config.toml"]

[[sensors]]
name = "clippy"
argv = ["cargo", "clippy", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"]
when-changed = ["**/*.rs", "**/Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".cargo/config.toml"]

[[sensors]]
name = "test"
argv = ["cargo", "test", "--workspace"]
when-changed = ["**/*.rs", "**/Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".cargo/config.toml"]
EOF
  cat > Cargo.toml << 'EOF'
[workspace]
members = ["crates/member-crate"]
resolver = "2"
EOF
  cat > crates/member-crate/Cargo.toml << 'EOF'
[package]
name = "member-crate"
version = "0.1.0"
edition = "2024"
EOF
  mkdir -p crates/member-crate/src
  cat > crates/member-crate/src/lib.rs << 'EOF'
pub fn hello() {}
EOF
  git add .
  git commit -m "initial" -q

  # 1. Selection test on member manifest edit
  echo "# edit" >> crates/member-crate/Cargo.toml
  "$bin" --root . explain --set verification --changed --format json > explain_out.json
  grep -q '"name": "check"' explain_out.json
  grep -q '"name": "clippy"' explain_out.json
  grep -q '"name": "test"' explain_out.json

  # 2. Non-zero exit on broken member manifest
  cat > crates/member-crate/Cargo.toml << 'EOF'
[package
invalid = toml
EOF
  set +e
  "$bin" --root . verify --changed --set verification > verify_out.txt 2>&1
  verify_rc=$?
  set -e
  if (( verify_rc == 0 )); then
    echo "Expected verify on broken member manifest to fail, but exited 0"
    exit 1
  fi
)

printf 'sensor contract: gate passes and CLI config->list->verify works\n' > "$receipt"

cat > "$root/harness_negative.txt" << 'TXT'
negative: general-knowledge question — no workspace touched, no sensors run
TXT
