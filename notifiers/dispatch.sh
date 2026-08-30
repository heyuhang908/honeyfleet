#!/usr/bin/env bash
# honeyfleet notifier dispatcher — pluggable alert channels.
#
# Usage (from any module or runtime script):
#   . "$SCRIPT_DIR/../notifiers/dispatch.sh"              # repo tree
#   . /usr/local/lib/honeyfleet/notifiers/dispatch.sh     # deployed tree
#   hf_notify "title" "body"
#
# Channel selection: HF_NOTIFIER (read via hf_conf): telegram | wecom |
# dingtalk | smtp. Credentials (all via hf_conf, never hardcoded):
#   telegram: HF_TG_BOT_TOKEN + HF_TG_CHAT_ID
#   wecom:    HF_WECOM_WEBHOOK
#   dingtalk: HF_DINGTALK_WEBHOOK (+ optional HF_DINGTALK_SECRET for 加签)
#   smtp:     HF_SMTP_TO + HF_SMTP_RELAY
#
# Failure semantics (contract: an alert failure must never break the caller's
# main flow):
#   - channel unconfigured (empty credentials) -> hf_warn + return 0
#     (未配置≠故障)
#   - channel send failure                     -> hf_warn + return non-zero
#   - hf_notify never calls exit/hf_die; callers decide whether to tolerate
#
# This file is a LIBRARY, not a module: no install/verify/status/remove here.
# Consuming modules deploy the whole directory to
# /usr/local/lib/honeyfleet/notifiers (reference deployment:
# hf_federation_ensure_notifiers in modules/federation.sh) and source the
# deployed dispatch.sh from runtime scripts.

# self-bootstrap: hf_notify depends on hf_conf from lib/common.sh
if ! type hf_conf >/dev/null 2>&1; then
    _HF_NOTIFIER_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
    if [ -f "$_HF_NOTIFIER_DIR/../lib/common.sh" ]; then
        # shellcheck source=../lib/common.sh
        . "$_HF_NOTIFIER_DIR/../lib/common.sh"
    elif [ -f /usr/local/lib/honeyfleet/lib/common.sh ]; then
        . /usr/local/lib/honeyfleet/lib/common.sh
    else
        printf '[honeyfleet][ERROR] notifiers/dispatch.sh: lib/common.sh not found\n' >&2
        return 1 2>/dev/null || exit 1
    fi
fi

hf_notify() {
    # hf_notify TITLE [BODY] — route to the configured channel; returns the
    # channel's exit code (0 = sent or unconfigured; non-zero = send failure).
    local title=${1:-honeyfleet alert} body=${2:-} ch dir
    ch=$(hf_conf NOTIFIER telegram)
    ch=$(printf '%s' "$ch" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
    if [ -z "$ch" ]; then
        hf_warn "notify skipped: HF_NOTIFIER is empty (telegram|wecom|dingtalk|smtp)"
        return 0
    fi
    dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
    case "$ch" in
        telegram) type hf_notify_telegram >/dev/null 2>&1 || . "$dir/telegram.sh"; hf_notify_telegram "$title" "$body" ;;
        wecom)    type hf_notify_wecom    >/dev/null 2>&1 || . "$dir/wecom.sh";    hf_notify_wecom    "$title" "$body" ;;
        dingtalk) type hf_notify_dingtalk >/dev/null 2>&1 || . "$dir/dingtalk.sh"; hf_notify_dingtalk "$title" "$body" ;;
        smtp)     type hf_notify_smtp     >/dev/null 2>&1 || . "$dir/smtp.sh";     hf_notify_smtp     "$title" "$body" ;;
        *)
            hf_warn "notify failed: unknown HF_NOTIFIER '$ch' (expected telegram|wecom|dingtalk|smtp)"
            return 1 ;;
    esac
}

# direct CLI: notifiers/dispatch.sh "title" "body"
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    hf_notify "${1:-}" "${2:-}"
fi
