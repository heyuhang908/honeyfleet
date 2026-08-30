#!/usr/bin/env bash
# honeyfleet notifier channel: WeCom (企业微信) group robot webhook.
# Config (via hf_conf only): HF_WECOM_WEBHOOK, e.g.
#   https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=<YOUR_WEBHOOK_KEY>
# rc: 0 = sent or unconfigured (warn); non-zero = transport/API failure.
# Never exits, never raises into the caller.
# Requires: curl, python3.

hf_notify_wecom() {
    local title=${1:-honeyfleet alert} body=${2:-}
    local webhook payload resp rc
    webhook=$(hf_conf WECOM_WEBHOOK "")
    if [ -z "$webhook" ]; then
        hf_warn "wecom notifier not configured (HF_WECOM_WEBHOOK empty) — skipped"
        return 0
    fi
    command -v curl >/dev/null 2>&1 || { hf_warn "wecom: curl not found"; return 1; }
    payload=$(python3 - "$title" "$body" <<'PY'
import json, sys
title, body = sys.argv[1], sys.argv[2][:3800]   # wecom markdown content limit: 4096 bytes
content = f"**{title}**\n{body}"
print(json.dumps({"msgtype": "markdown", "markdown": {"content": content}}))
PY
) || { hf_warn "wecom: payload build failed"; return 1; }
    resp=$(curl -sS --max-time 10 -H 'Content-Type: application/json' \
        --data-binary "$payload" "$webhook")
    rc=$?
    [ "$rc" -ne 0 ] && { hf_warn "wecom: curl failed (rc=$rc)"; return 1; }
    case "$resp" in
        *'"errcode":0'*) return 0 ;;
        *) hf_warn "wecom: API error: ${resp:-<empty response>}"; return 1 ;;
    esac
}

# direct CLI: notifiers/wecom.sh "title" "body"
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    type hf_conf >/dev/null 2>&1 || . "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dispatch.sh"
    hf_notify_wecom "${1:-}" "${2:-}"
fi
