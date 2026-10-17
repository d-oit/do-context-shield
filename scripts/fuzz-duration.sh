#!/usr/bin/env bash
# fuzz-duration.sh — resolve the fuzz duration for `.github/workflows/fuzz.yml`.
#
# Usage:
#   scripts/fuzz-duration.sh [<seconds>]   # print the clamped duration
#   scripts/fuzz-duration.sh --self-test   # run the boundary table
#
# A request is digits only, leading zeros are ignored, and an absent or empty
# request means the default. The printed value is between 1 and the cap
# (`FUZZ_MAX_SECONDS`, default 3600).
#
# Why the digit-string dance: `$((10#…))` wraps around the shell's signed
# 64-bit arithmetic, so `18446744073709551615` became `-1` — neither zero nor
# greater than the cap, so it passed both checks and reached libFuzzer as
# `-max_total_time=-1`, a flag documented as limiting the run only when it is
# positive (an unbounded fuzz run). Comparing digit counts and then digit
# strings keeps every parsed value small and every oversized request clamped.
#
# Sensor: none of its own; `--self-test` runs in the CI `fuzz-check` job, and
# the fuzz step carries its own `timeout-minutes` so the bound does not depend
# on this arithmetic.
set -euo pipefail

DEFAULT_SECONDS=300
MAX_SECONDS="${FUZZ_MAX_SECONDS:-3600}"

is_digits() {
    [[ "$1" =~ ^[0-9]+$ ]]
}

# Strip leading zeros; an all-zero value prints nothing.
strip_leading_zeros() {
    local value="$1"
    printf '%s' "${value#"${value%%[!0]*}"}"
}

# Print the smaller of two digit strings, without shell arithmetic.
cap_digits() {
    local requested="$1"
    local maximum="$2"
    if (( ${#requested} > ${#maximum} )); then
        printf '%s' "$maximum"
        return 0
    fi
    if (( ${#requested} < ${#maximum} )); then
        printf '%s' "$requested"
        return 0
    fi
    # Equal digit counts: lexicographic order is numeric order.
    if [[ "$requested" > "$maximum" ]]; then
        printf '%s' "$maximum"
    else
        printf '%s' "$requested"
    fi
}

# Print the resolved duration, or explain on stderr and exit 2.
resolve() {
    local requested="${1:-}"
    local maximum="$MAX_SECONDS"
    if [[ -z "$requested" ]]; then
        requested="$DEFAULT_SECONDS"
    fi
    if ! is_digits "$maximum"; then
        printf 'FUZZ_MAX_SECONDS must be digits only, got %q\n' "$maximum" >&2
        return 2
    fi
    maximum="$(strip_leading_zeros "$maximum")"
    if [[ -z "$maximum" ]]; then
        printf 'FUZZ_MAX_SECONDS must be at least 1, got 0\n' >&2
        return 2
    fi
    # Bound the cap itself so the final `10#` parse cannot wrap either.
    if (( ${#maximum} > 9 )); then
        printf 'FUZZ_MAX_SECONDS must be at most 9 digits, got %q\n' "$maximum" >&2
        return 2
    fi
    if ! is_digits "$requested"; then
        printf 'fuzz duration must be digits only, got %q\n' "$requested" >&2
        return 2
    fi
    requested="$(strip_leading_zeros "$requested")"
    if [[ -z "$requested" ]]; then
        printf 'fuzz duration must be at least 1 second\n' >&2
        return 2
    fi
    local capped
    capped="$(cap_digits "$requested" "$maximum")"
    printf '%s\n' "$((10#$capped))"
}

self_test() {
    local failures=0
    local input expected got
    while IFS='|' read -r input expected; do
        if [[ -z "$input" && -z "$expected" ]]; then
            continue
        fi
        if ! got="$(resolve "$input" 2>/dev/null)"; then
            got='<error>'
        fi
        if [[ "$got" != "$expected" ]]; then
            printf 'FAIL %-24s -> %-10s expected %s\n' "${input:-<empty>}" "$got" "$expected" >&2
            failures=$((failures + 1))
        fi
    done <<'CASES'
|300
300|300
1|1
3600|3600
3601|3600
9999999999|3600
18446744073709551615|3600
9223372036854775808|3600
99999999999999999999999|3600
000300|300
0000000000300|300
03600|3600
0|<error>
000|<error>
abc|<error>
-5|<error>
+300|<error>
0x10|<error>
 300|<error>
1; rm -rf /|<error>
CASES
    if (( failures > 0 )); then
        printf 'fuzz-duration self-test FAILED (%d cases)\n' "$failures" >&2
        return 1
    fi
    printf 'fuzz-duration self-test OK\n'
}

case "${1:-}" in
--self-test)
    self_test
    ;;
--help | -h)
    printf 'usage: %s [<seconds>|--self-test]\n' "$(basename "$0")"
    ;;
*)
    resolve "${1:-}"
    ;;
esac
