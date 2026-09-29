#!/usr/bin/env bash
# honeyfleet test helpers — sourced by every tests/test_*.sh.
#
# A test file sources this, runs assertions, and ends with `t_done <name>`:
# exit 0 only if every assertion passed. tests/run-tests.sh aggregates.
#
# Deliberately not a framework: the suite has no runtime dependencies and must
# run on a bare Ubuntu/Debian box (and under Git Bash) with nothing installed —
# the thing under test is an installer that assumes nothing.

HF_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_FAILURES=0

t_pass() { printf '  ok   %s\n' "$1"; }
t_fail() { printf '  FAIL %s\n' "$1"; TEST_FAILURES=$((TEST_FAILURES + 1)); }

t_eq() {  # t_eq <desc> <expected> <actual>
    if [ "$2" = "$3" ]; then t_pass "$1"; else t_fail "$1 (expected '$2', got '$3')"; fi
}

t_ne() {  # t_ne <desc> <unexpected> <actual>
    if [ "$2" != "$3" ]; then t_pass "$1"; else t_fail "$1 (both '$2')"; fi
}

t_contains() {  # t_contains <desc> <haystack> <needle>
    case "$2" in
        *"$3"*) t_pass "$1" ;;
        *) t_fail "$1 (missing '$3' in '$2')" ;;
    esac
}

t_not_contains() {  # t_not_contains <desc> <haystack> <needle>
    case "$2" in
        *"$3"*) t_fail "$1 (unexpected '$3' in '$2')" ;;
        *) t_pass "$1" ;;
    esac
}

t_ok() {  # t_ok <desc> <command...> — pass when the command exits 0
    local desc=$1
    shift
    if "$@" >/dev/null 2>&1; then t_pass "$desc"; else t_fail "$desc"; fi
}

t_done() {  # t_done <suite-name>
    if [ "$TEST_FAILURES" -eq 0 ]; then
        printf '%s: PASS\n' "$1"
        return 0
    fi
    printf '%s: FAIL (%s assertion(s))\n' "$1" "$TEST_FAILURES"
    return 1
}
