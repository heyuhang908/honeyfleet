#!/usr/bin/env bash
# honeyfleet notifier channel: DingTalk (钉钉) group robot webhook.
# Config (via hf_conf only): HF_DINGTALK_WEBHOOK; optional HF_DINGTALK_SECRET
# (add the key to /etc/honeyfleet/honeyfleet.conf to enable 加签 signing —
# when set, timestamp + HMAC-SHA256 signature are appended to the webhook URL
# per the DingTalk custom-robot security protocol).
# rc: 0 = sent or unconfigured (warn); non-zero = transport/API failure.
# Never exits, never raises into the caller.
# Requires: curl, python3.

hf_notify_dingtalk() {
    local title=${1:-honeyfleet alert} body=${2:-}
    local webhook secret qs payload resp rc
    webhook=$(hf_conf DINGTALK_WEBHOOK "")
    secret=$(hf_conf DINGTALK_SECRET "")
    if [ -z "$webhook" ]; then
        hf_warn "dingtalk notifier not configured (HF_DINGTALK_WEBHOOK empty) — skipped"
        return 0
    fi
    command -v curl >/dev/null 2>&1 || { hf_warn "dingtalk: curl not found"; return 1; }
    if [ -n "$secret" ]; then
        qs=$(python3 - "$secret" <<'PY'
import base64, hashlib, hmac, sys, time, urllib.parse
secret = sys.argv[1]
ts = str(round(time.time() * 1000))
digest = hmac.new(secret.encode(), f"{ts}\n{secret}".encode(), hashlib.sha256).digest()
print(f"&timestamp={ts}&sign={urllib.parse.quote_plus(base64.b64encode(digest))}")
PY
) || { hf_warn "dingtalk: signature computation failed"; return 1; }
        webhook="${webhook}${qs}"
    fi
    payload=$(python3 - "$title" "$body" <<'PY'
import json, sys
title, body = sys.argv[1], sys.argv[2][:18000]   # dingtalk markdown text limit ~20000 bytes
text = f"**{title}**\n\n{body}"
print(json.dumps({"msgtype": "markdown", "markdown": {"title": title, "text": text}}))
PY
) || { hf_warn "dingtalk: payload build failed"; return 1; }
    resp=$(curl -sS --max-time 10 -H 'Content-Type: application/json' \
        --data-binary "$payload" "$webhook")
    rc=$?
    [ "$rc" -ne 0 ] && { hf_warn "dingtalk: curl failed (rc=$rc)"; return 1; }
    case "$resp" in
        *'"errcode":0'*) return 0 ;;
        *) hf_warn "dingtalk: API error: ${resp:-<empty response>}"; return 1 ;;
    esac
}

# direct CLI: notifiers/dingtalk.sh "title" "body"
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    type hf_conf >/dev/null 2>&1 || . "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dispatch.sh"
    hf_notify_dingtalk "${1:-}" "${2:-}"
fi
