#!/usr/bin/env bash
# Module contract, checked mechanically.
#
# docs/MODULE-CONTRACT.md states the naming and dispatch rules in prose, and
# rule 2 claims "(verify gates in CI enforce this)". This file is what actually
# enforces the naming half — without it the contract is documentation that drifts.
#
# Concrete drift this catches: modules/file-integrity.sh exported hf_fi_* rather
# than hf_file_integrity_*, a leftover from the 1.0.1 fix that renamed MOD but not
# the functions. Nothing noticed for a release, because nothing checked. The same
# class of check catches `MOD="fi"`, which made the consistency gate look for a
# module file that did not exist.

set -uo pipefail
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# ALL_MODULES in install.sh is the single source of the module set.
ALL=$(sed -n 's/^ALL_MODULES="\(.*\)"$/\1/p' "$HF_ROOT/install.sh")
t_ok "ALL_MODULES is declared in install.sh" test -n "$ALL"

checked=0
for mod in $ALL; do
    checked=$((checked + 1))
    f="$HF_ROOT/modules/$mod.sh"
    fn=${mod//-/_}
    if [ ! -f "$f" ]; then
        t_fail "modules/$mod.sh exists"
        continue
    fi
    t_pass "modules/$mod.sh exists"

    # MOD must equal the filename: the registry, hf_requires and the consistency
    # gate all key on it.
    modvar=$(sed -n 's/^MOD="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$f" | head -1)
    t_eq "$mod: MOD matches the filename" "$mod" "$modvar"

    # The four contract functions, named per docs/MODULE-CONTRACT.md
    # (module name with dashes as underscores).
    for op in install verify status remove; do
        t_ok "$mod: defines hf_${fn}_${op}()" grep -q "^hf_${fn}_${op}()" "$f"
    done

    # No contract function may carry a foreign prefix — the hf_fi_* drift class.
    foreign=$(grep -oE "^hf_[a-z0-9_]+_(install|verify|status|remove)\(\)" "$f" \
              | grep -v "^hf_${fn}_" | tr '\n' ' ')
    t_eq "$mod: no foreign-prefixed contract function" "" "$foreign"

    # The dispatcher must route all four operations, or the installer's
    # `set -- "$op"; . module.sh` contract silently does nothing.
    for op in install verify status remove; do
        t_ok "$mod: dispatches '$op'" grep -qE "^ *${op}[)|]" "$f"
    done
done

# Non-vacuity: the loop above passes trivially if ALL_MODULES is empty or the
# modules directory is missing, which is the failure mode that hides everything.
# The expected count is derived, never pinned — a pinned number would have to be
# edited whenever a module is added, which is exactly when it stops being read.
expected=$(printf '%s' "$ALL" | wc -w | tr -d ' ')
t_ok "the contract test covered at least one module" test "$checked" -gt 0
t_eq "the contract test covered every module ALL_MODULES names" "$expected" "$checked"

t_done "module_contract"
