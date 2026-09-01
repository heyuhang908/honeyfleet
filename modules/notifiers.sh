#!/usr/bin/env bash
# honeyfleet module: notifiers — pluggable alert channels (hf_notify entrypoint).
# Deploys the notifier library to $HF_LIB so every other module and runtime
# script can call hf_notify via $HF_LIB/notify.sh (= /usr/local/lib/honeyfleet/notify.sh).

set -uo pipefail
MOD=notifiers
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"

DEPLOY_NOTIFIER_DIR=/usr/local/lib/honeyfleet/notifiers
DEPLOY_LIB_DIR=/usr/local/lib/honeyfleet/lib

hf_notifiers_install() {
    sudo mkdir -p "$DEPLOY_NOTIFIER_DIR" "$DEPLOY_LIB_DIR"
    local f src dst
    for f in dispatch.sh telegram.sh wecom.sh dingtalk.sh smtp.sh; do
        src="$SCRIPT_DIR/../notifiers/$f"; dst="$DEPLOY_NOTIFIER_DIR/$f"
        [ -f "$src" ] || hf_die "notifiers: missing repo file notifiers/$f"
        bash -n "$src" || hf_die "notifiers: $f fails bash -n"
        hf_backup "$dst"
        sudo install -o root -g root -m 0644 "$src" "$dst"
    done
    src="$SCRIPT_DIR/../lib/common.sh"; dst="$DEPLOY_LIB_DIR/common.sh"
    [ -f "$src" ] || hf_die "notifiers: dependency missing: repo lib/common.sh"
    bash -n "$src" || hf_die "notifiers: lib/common.sh fails bash -n"
    hf_backup "$dst"
    sudo install -o root -g root -m 0644 "$src" "$dst"
    # shim: part of the module contract — consumers (waterline-alerts,
    # consistency-gate) call hf_notify via $HF_LIB/notify.sh (path is stable,
    # do not move).
    printf '%s\n' '#!/usr/bin/env bash' \
        '# honeyfleet notify shim — sources the notifier dispatcher (hf_notify entrypoint)' \
        ". \"$DEPLOY_NOTIFIER_DIR/dispatch.sh\"" | sudo -n tee "$HF_LIB/notify.sh" > /dev/null
    sudo -n chmod 0644 "$HF_LIB/notify.sh"
    bash -n "$HF_LIB/notify.sh" || hf_die "notifiers: notify.sh shim fails bash -n"
    hf_registry 1 "$MOD"
    hf_log "notifiers: deployed to $DEPLOY_NOTIFIER_DIR (+ $HF_LIB/notify.sh shim)"
}

hf_notifiers_verify() {
    local rc=0 f
    for f in dispatch.sh telegram.sh wecom.sh dingtalk.sh smtp.sh; do
        [ -f "$DEPLOY_NOTIFIER_DIR/$f" ] || { echo "FAIL notifiers ($f missing)"; rc=1; }
    done
    [ -f "$HF_LIB/notify.sh" ] || { echo "FAIL notifiers (notify.sh shim missing)"; rc=1; }
    bash -n "$HF_LIB/notify.sh" 2>/dev/null || { echo "FAIL notifiers (shim syntax)"; rc=1; }
    [ "$rc" -eq 0 ] && echo "PASS notifiers"
    return $rc
}

hf_notifiers_status() {
    printf 'notifiers: channel=%s deployed=%s\n' \
        "$(hf_conf NOTIFIER unknown)" \
        "$([ -f "$HF_LIB/notify.sh" ] && echo yes || echo no)"
}

hf_notifiers_remove() {
    sudo rm -rf "$DEPLOY_NOTIFIER_DIR"
    sudo rm -f "$HF_LIB/notify.sh"
    hf_registry 0 "$MOD"
    hf_log "notifiers: removed"
}

case "${1:-}" in
    install) hf_notifiers_install ;;
    verify)  hf_notifiers_verify ;;
    status)  hf_notifiers_status ;;
    remove)  hf_notifiers_remove ;;
    *) hf_die "usage: notifiers.sh install|verify|status|remove" ;;
esac
