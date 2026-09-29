#!/usr/bin/env bash
# hf_registry_installed_modules — which registry lines actually name a module.
#
# Regression test for a consistency-gate failure that followed ANY uninstall.
# Every module's remove path writes `hf_registry 0 "$MOD"`, so the registry keeps
# a `=0` record of what was once installed. The gate's old four-stage pipeline
# stripped only `_installed=1`, so a `=0` line was read as a literal module name:
#   FAIL fail2ban-stack-installed=0 (module file missing on this checkout)
# and the gate — the project's headline feature — stayed red until someone
# hand-edited the registry. Reinstalling a *different* module does not clear the
# stale line, so the failure never self-heals.
#
# The assertions below are exactly the shapes that broke.

set -uo pipefail
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=../lib/common.sh
. "$HF_ROOT/lib/common.sh"

reg=$(mktemp)
trap 'rm -f "$reg"' EXIT

cat > "$reg" <<'REG'
hf_mod_ssh-hardening_installed=1
hf_mod_firewall-baseline_installed=1
hf_mod_fail2ban-stack_installed=0
hf_mod_notifiers_installed=1
hf_mod_waterline-alerts_installed=0
REG

got=$(hf_registry_installed_modules "$reg" | tr '\n' ' ')

t_eq "only =1 marks are listed" "ssh-hardening firewall-baseline notifiers " "$got"
t_not_contains "no '=0' record leaks into the module list" "$got" "installed="
t_not_contains "no '=' survives into a module name" "$got" "="
t_contains "an installed module is listed" "$got" "notifiers"
t_not_contains "an uninstalled module is not listed" "$got" "waterline-alerts"

# Every listed name must resolve to a module file: that lookup is precisely what
# produced the bogus "module file missing on this checkout" failure.
missing=""
for m in $(hf_registry_installed_modules "$reg"); do
    [ -f "$HF_ROOT/modules/$m.sh" ] || missing="$missing $m"
done
t_eq "every listed name resolves to a real module" "" "$missing"

# A name containing dashes must survive intact (dashes are the separator the
# gate re-expands, so a mangled name silently verifies the wrong file).
t_contains "dashed module names survive" "$got" "firewall-baseline"

# Empty and absent registries: nothing listed, and not an error. The gate runs
# on a host where a partial install may have left no registry at all.
: > "$reg"
t_eq "an empty registry lists nothing" "" "$(hf_registry_installed_modules "$reg" | tr '\n' ' ')"
t_ok "a missing registry is not an error" hf_registry_installed_modules "$reg.does-not-exist"

# Comments and blank lines must not become module names.
cat > "$reg" <<'REG'

# a comment an operator left behind
hf_mod_notifiers_installed=1

REG
t_eq "comments and blanks are ignored" "notifiers " "$(hf_registry_installed_modules "$reg" | tr '\n' ' ')"

t_done "registry_parse"
