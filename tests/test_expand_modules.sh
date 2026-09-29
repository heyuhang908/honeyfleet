#!/usr/bin/env bash
# install.sh dependency resolution — `deps()` + `expand_modules()`.
#
# MODULE-CONTRACT rule 6 ("Dependencies declared ... the installer resolves
# order via deps()") and install.sh's own rule 2 both rest on this resolving
# correctly: waterline-alerts and federation call hf_notify, so notifiers must be
# installed first, and honeypot-ssh needs the fail2ban jail in place before it
# takes over port 22.
#
# `plan` prints the resolved order WITHOUT touching the system, so this — the one
# part of the installer that needs no root — can be verified in CI. The ordering
# assertions below are the edges declared in install.sh's deps().

set -uo pipefail
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

CONF="$HF_ROOT/config/honeyfleet.conf.example"
t_ok "the example config exists" test -f "$CONF"

plan=$(bash "$HF_ROOT/install.sh" plan --config "$CONF" 2>/dev/null)
t_contains "plan announces the module order" "$plan" "modules (dependency order):"
order=${plan#*modules (dependency order): }

pos() {  # 1-based position of $1 within $order, or 0 when absent
    local i=0 m
    for m in $order; do
        i=$((i + 1))
        if [ "$m" = "$1" ]; then printf '%s' "$i"; return; fi
    done
    printf '0'
}

# Every module ALL_MODULES names must appear — a silently dropped module is a
# hardening step that never runs.
ALL=$(sed -n 's/^ALL_MODULES="\(.*\)"$/\1/p' "$HF_ROOT/install.sh")
t_ok "ALL_MODULES is declared" test -n "$ALL"
for m in $ALL; do
    t_ok "the plan includes $m" test "$(pos "$m")" -gt 0
done

before() {  # before <dependency> <dependent>
    local pa pb
    pa=$(pos "$1")
    pb=$(pos "$2")
    if [ "$pa" -gt 0 ] && [ "$pb" -gt 0 ] && [ "$pa" -lt "$pb" ]; then
        t_pass "$1 is ordered before $2"
    else
        t_fail "$1 must precede $2 (positions $pa, $pb)"
    fi
}

# Edges declared in install.sh deps() — one assertion per declared edge.
before fail2ban-stack honeypot-ssh
before ssh-hardening file-integrity
before notifiers waterline-alerts
before notifiers federation

# `--only` must yield exactly that module and nothing else: partial installs are
# how a single module is re-run, and an unexpected expansion would deploy more
# than the operator asked for.
only=$(bash "$HF_ROOT/install.sh" plan --only notifiers --config "$CONF" 2>/dev/null)
only=${only#*modules (dependency order): }
only=$(printf '%s' "$only" | tr -s ' ' | sed 's/^ *//; s/ *$//')
t_eq "--only returns exactly one module" "notifiers" "$only"

# An unknown --only keeps the plan empty rather than defaulting to everything.
unknown=$(bash "$HF_ROOT/install.sh" plan --only no-such-module --config "$CONF" 2>/dev/null)
unknown=${unknown#*modules (dependency order): }
unknown=$(printf '%s' "$unknown" | tr -s ' ' | sed 's/^ *//; s/ *$//')
t_eq "--only with an unknown module plans nothing" "" "$unknown"

t_done "expand_modules"
