#!/usr/bin/env bash
# honeyfleet test runner — runs every tests/test_*.sh and aggregates.
#
# Usage: bash tests/run-tests.sh
#
# Dependency-free on purpose: no bats, no pytest, nothing to install. The thing
# under test is an installer that assumes nothing about the box, so its own test
# suite must not assume anything either — it has to run bare on Ubuntu/Debian and
# under Git Bash on Windows.
#
# These suites cover what is verifiable WITHOUT a deployed host: the config
# accessor, the backup/retention policy, dependency resolution, the registry
# parse behind the consistency gate, and the module contract. Behaviour that
# needs a live systemd host is covered by the install/verify CI job instead.

set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

suites=0
failed=0
failed_names=""

for t in "$HERE"/test_*.sh; do
    [ -f "$t" ] || continue
    name=$(basename "$t" .sh)
    suites=$((suites + 1))
    printf '\n== %s\n' "$name"
    if ! bash "$t"; then
        failed=$((failed + 1))
        failed_names="$failed_names $name"
    fi
done

printf '\n%s\n' "----------------------------------------"
# Non-vacuity: an unexpanded glob leaves `suites` at 0 and everything below
# would report a cheerful PASS. A runner that passes when it ran nothing is
# worse than no runner.
if [ "$suites" -eq 0 ]; then
    printf 'tests: FAIL (no suites found — tests/test_*.sh matched nothing)\n'
    exit 1
fi
if [ "$failed" -eq 0 ]; then
    printf 'tests: PASS (%s suite(s))\n' "$suites"
    exit 0
fi
printf 'tests: FAIL (%s of %s suite(s):%s)\n' "$failed" "$suites" "$failed_names"
exit 1
