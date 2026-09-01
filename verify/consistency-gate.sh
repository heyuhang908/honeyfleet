#!/usr/bin/env bash
# honeyfleet consistency gate — runs every installed module's verify function,
# then fleet-level cross-checks. Exits non-zero if ANY module fails.
# This is the project's core differentiator: the deployment must be verifiable
# against its own configuration, not merely present. (See docs/design-rationale.md)

set -uo pipefail
HFROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CONF=/etc/honeyfleet/honeyfleet.conf
[ -f "$CONF" ] || { echo "consistency-gate: config missing ($CONF)"; exit 1; }
# shellcheck disable=SC1090
. "$CONF"
# shellcheck disable=SC1091
. "$HFROOT/lib/common.sh"

pass=0; fail=0; failed=""

# ── per-module verify (only modules the registry marks installed) ────────────
if [ -f /var/lib/honeyfleet/registry ]; then
    for mod in $(sed -E 's/^hf_mod_(.+)_installed=1$/\1/' /var/lib/honeyfleet/registry | grep 'hf_mod_\|^[a-z-]*$' | sed -E 's/^hf_mod_//; s/_installed=1$//' | tr '_' '-'); do
        f="$HFROOT/modules/$mod.sh"
        if [ ! -f "$f" ]; then
            echo "FAIL $mod (module file missing on this checkout)"
            fail=$((fail+1)); failed="$failed $mod"; continue
        fi
        # Source the module with $1=verify so its own case dispatch runs the
        # module's verify function exactly once (same contract as install.sh).
        # shellcheck disable=SC1090,SC1091
        if ( set -- verify; . "$f" ); then
            pass=$((pass+1))
        else
            fail=$((fail+1)); failed="$failed $mod"
        fi
    done
fi

# ── fleet-level cross-checks (consumer enumeration, see design-rationale) ────
gate_fail() { echo "FAIL $1"; fail=$((fail+1)); failed="$failed $1"; }
gate_pass() { echo "PASS $1"; pass=$((pass+1)); }

# 1. registry must exist after install
if [ -f /var/lib/honeyfleet/registry ]; then gate_pass "registry"; else gate_fail "registry"; fi

# 2. notifier: if any module requires notifications, the library must be deployed
if grep -q 'hf_mod_notifiers_installed=1' /var/lib/honeyfleet/registry 2>/dev/null; then
    [ -f "$HF_LIB/notifiers/dispatch.sh" ] && [ -f "$HF_LIB/notify.sh" ] \
        && gate_pass "notifier-library" || gate_fail "notifier-library"
fi

# 3. honeypot/real-ssh separation (when honeypot module installed)
if grep -q 'hf_mod_honeypot-ssh_installed=1' /var/lib/honeyfleet/registry 2>/dev/null; then
    port=$(ss -tln 2>/dev/null | awk '/:22 /{print "22"}')
    [ -n "$port" ] && gate_pass "honeypot-listener" || gate_fail "honeypot-listener"
fi

echo "consistency-gate: PASS=$pass FAIL=$fail${failed:+ (failed:$failed)}"
[ "$fail" -eq 0 ]
