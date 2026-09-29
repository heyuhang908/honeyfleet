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
    # Every write goes through the compare-first helpers, so a re-run on a
    # consistent node writes nothing and says so (MODULE-CONTRACT rule 2).
    local f src dst changed=0 shim
    for f in dispatch.sh telegram.sh wecom.sh dingtalk.sh smtp.sh; do
        src="$SCRIPT_DIR/../notifiers/$f"; dst="$DEPLOY_NOTIFIER_DIR/$f"
        [ -f "$src" ] || hf_die "notifiers: missing repo file notifiers/$f"
        bash -n "$src" || hf_die "notifiers: $f fails bash -n"
        hf_copy_if_changed "$src" "$dst" 0644 && changed=1
    done
    src="$SCRIPT_DIR/../lib/common.sh"; dst="$DEPLOY_LIB_DIR/common.sh"
    [ -f "$src" ] || hf_die "notifiers: dependency missing: repo lib/common.sh"
    bash -n "$src" || hf_die "notifiers: lib/common.sh fails bash -n"
    hf_copy_if_changed "$src" "$dst" 0644 && changed=1
    # shim: part of the module contract — consumers (waterline-alerts,
    # consistency-gate) call hf_notify via $HF_LIB/notify.sh (path is stable,
    # do not move).
    shim=$(printf '%s\n' '#!/usr/bin/env bash' \
        '# honeyfleet notify shim — sources the notifier dispatcher (hf_notify entrypoint)' \
        ". \"$DEPLOY_NOTIFIER_DIR/dispatch.sh\"")
    # hf_install_if_changed appends the trailing newline, so this lands
    # byte-identical to what the previous `printf ... | tee` wrote.
    hf_install_if_changed "$shim" "$HF_LIB/notify.sh" 0644 && changed=1
    bash -n "$HF_LIB/notify.sh" || hf_die "notifiers: notify.sh shim fails bash -n"
    hf_registry 1 "$MOD"
    if [ "$changed" -eq 0 ]; then
        hf_log "notifiers: already consistent — NO-OP (5 channels + common.sh + notify.sh shim)"
    else
        hf_log "notifiers: deployed to $DEPLOY_NOTIFIER_DIR (+ $HF_LIB/notify.sh shim)"
    fi
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
