#!/usr/bin/env bash
# Idempotence consumers: a module that compares "the content I am about to
# deploy" against the deployed file must use the SAME printf form as the writer.
# Write with `printf '%s\n'` and compare with `printf '%s'` and the two differ by
# exactly one byte, so the comparison can never be equal.
#
# Real bug, v1.0.0 through 1.0.2, found by the install-verify CI job on its first
# real run: modules/waterline-alerts.sh wrote with `printf '%s\n'` and compared
# with `printf '%s'`, so hf_install_if_changed always returned "changed",
# waterline-alerts re-deployed on every install, and its
# "already consistent - NO-OP" branch was unreachable code. Every sibling had it
# right (fail2ban-stack x2, honeypot-ssh x2), which is exactly why this wants to
# be a lint rather than a review item: the odd one out is one character.
#
# The CI install-verify job catches this class end to end (it asserts the
# re-install NO-OP and the deployed fingerprint). This suite is the fast local
# signal, and it names the offending line.

set -uo pipefail
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# `[|]` rather than `\|`: a literal pipe inside an ERE bracket expression.
# `[$]?` covers both `"$content"` (a variable) and a literal name; without it the
# pattern matched nothing at all and every assertion below passed vacuously —
# which the self-test at the bottom of this file caught.
PATTERN="^[^#]*printf '%s' \"[$]?[A-Za-z_]+\" [|] *(sudo )?cmp"

ALL=$(sed -n 's/^ALL_MODULES="\(.*\)"$/\1/p' "$HF_ROOT/install.sh")
t_ok "ALL_MODULES is declared" test -n "$ALL"

checked=0
for mod in $ALL; do
    f="$HF_ROOT/modules/$mod.sh"
    [ -f "$f" ] || continue
    checked=$((checked + 1))
    offenders=$(grep -nE "$PATTERN" "$f" | tr '\n' ';')
    t_eq "$mod: compares with the same printf form it writes" "" "$offenders"
done

# Non-vacuity: an unexpanded ALL_MODULES would make the loop body never run and
# every assertion above would vanish without failing.
expected=$(printf '%s' "$ALL" | wc -w | tr -d ' ')
t_ok "every module was checked" test "$checked" -gt 0
t_eq "every module ALL_MODULES names was checked" "$expected" "$checked"

# The pattern must actually match the shape it guards: a lint that matches
# nothing is indistinguishable from a passing one. These two literals differ by
# the single character that caused the bug.
good=$(cat <<'GOOD'
    if [ -f "$t" ] && printf '%s\n' "$content" | sudo cmp -s - "$t"; then
GOOD
)
bad=$(cat <<'BAD'
    if [ -f "$t" ] && printf '%s' "$content" | sudo cmp -s - "$t"; then
BAD
)
t_eq "the pattern ignores the correct form" "" "$(printf '%s\n' "$good" | grep -nE "$PATTERN")"
t_ok "the pattern matches the broken form" test -n "$(printf '%s\n' "$bad" | grep -nE "$PATTERN")"

t_done "module_idempotence"
