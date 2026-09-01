#!/usr/bin/env bash
# honeyfleet installer / dispatcher.
#   install.sh install  --role central|agent [--only MODULE] [--config FILE]
#   install.sh verify   [--only MODULE]      # consistency gates + e2e checks
#   install.sh status   [--only MODULE]      # one-line health per module
#   install.sh uninstall [--only MODULE]
#   install.sh plan                          # print planned module order (no changes)
#
# Design rules (violations = bugs):
#   1. Every parameter comes from ONE config file (never hardcoded in modules).
#   2. Modules are idempotent: re-running install must be a NO-OP.
#   3. Every module ships a verify gate (template↔deployed + e2e).
#   4. Dependencies are declared via hf_requires, executed in declared order.
#   5. This script is a DISPATCHER — it never duplicates module logic.

set -uo pipefail
HFROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CONF=/etc/honeyfleet/honeyfleet.conf
MODE=install
ROLE=""          # from config unless --role given
ONLY=""          # run a single module
CONF_OVERRIDE=""

usage() { sed -n '2,10p' "$HFROOT/install.sh"; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
    case "$1" in
        install|verify|status|uninstall|plan) MODE=$1 ;;
        --role)    ROLE=$2;            shift ;;
        --only)    ONLY=$2;            shift ;;
        --config)  CONF_OVERRIDE=$2;   shift ;;
        -h|--help) usage 0 ;;
        *) echo "unknown argument: $1" >&2; usage 1 ;;
    esac
    shift
done

[ -n "$CONF_OVERRIDE" ] && CONF=$CONF_OVERRIDE

# modules in dependency order
ALL_MODULES="ssh-hardening firewall-baseline fail2ban-stack honeypot-ssh file-integrity waterline-alerts notifiers federation"
# declared dependencies (module: requires)
deps() {
    case $1 in
        honeypot-ssh)    echo "fail2ban-stack" ;;
        file-integrity)  echo "ssh-hardening" ;;
        waterline-alerts) echo "notifiers" ;;
        federation)      echo "notifiers" ;;
        *) : ;;
    esac
}

load_env() {
    [ -f "$CONF" ] || { echo "config missing: $CONF — copy config/honeyfleet.conf.example, edit, retry" >&2; exit 1; }
    # shellcheck disable=SC1090
    . "$CONF"
    # shellcheck disable=SC1091
    . "$HFROOT/lib/common.sh"
    case "${HF_ROLE:-}" in
        central|agent) : ;;
        *) echo "config error: HF_ROLE must be 'central' or 'agent'" >&2; exit 1 ;;
    esac
    [ -n "$ROLE" ] && [ "$ROLE" != "$HF_ROLE" ] && \
        { echo "config error: --role $ROLE conflicts with HF_ROLE=$HF_ROLE in $CONF" >&2; exit 1; }
    export HFROLE=$HF_ROLE
}

run_module() {
    local mod=$1 op=$2
    [ -f "$HFROOT/modules/$mod.sh" ] || { echo "SKIP $mod (module file missing)"; return 0; }
    # Source the module in a subshell with $1 = the operation, so the module's
    # own case dispatch runs exactly once (functions must not be re-invoked).
    # (2026-08-31: sourcing without setting $1 made every module hit its usage
    # branch — the installer's main path was broken; fixed here.)
    # shellcheck disable=SC1090,SC1091
    ( set -- "$op"; . "$HFROOT/modules/$mod.sh" )
    hf_log "── module $mod: $op"
}

expand_modules() {
    # resolve dependency closure for $1 (or ALL_MODULES), dependency-first:
    # a module is appended only once its managed deps are already ordered;
    # deps outside the managed set count as satisfied.
    local want=$1 out="" m d ok
    for m in $ALL_MODULES; do
        if [ -z "$want" ] || [ "$m" = "$want" ]; then out="$out $m"; fi
    done
    local ordered="" added=1
    while [ "$added" = 1 ]; do
        added=0
        for m in $out; do
            case " $ordered " in *" $m "*) continue ;; esac
            ok=1
            for d in $(deps "$m"); do
                case " $out " in *" $d "*) ;; *) continue ;; esac
                case " $ordered " in *" $d "*) ;; *) ok=0 ;; esac
            done
            if [ "$ok" = 1 ]; then ordered="$ordered$m "; added=1; fi
        done
    done
    # safety net: anything left (dependency cycle) is appended with a warning
    for m in $out; do
        case " $ordered " in *" $m "*) continue ;; esac
        hf_warn "dependency cycle involving '$m' — appended last"
        ordered="$ordered$m "
    done
    printf '%s\n' "$ordered"
}

load_env
[ "$MODE" = "plan" ] && { echo "modules (dependency order): $(expand_modules "$ONLY")"; exit 0; }

for m in $(expand_modules "$ONLY"); do
    run_module "$m" "$MODE"
done

if [ "$MODE" = "install" ] && [ -x "$HFROOT/verify/consistency-gate.sh" ]; then
    hf_log "── fleet verify (all modules)"
    "$HFROOT/verify/consistency-gate.sh" || { hf_warn "verify gate FAILED — see output above"; exit 1; }
fi
hf_log "done: mode=$MODE role=$HFROLE modules=$(expand_modules "$ONLY")"
