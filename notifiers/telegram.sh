#!/usr/bin/env bash
# honeyfleet notifier channel: Telegram Bot API sendMessage (MarkdownV2).
# Config (via hf_conf only): HF_TG_BOT_TOKEN + HF_TG_CHAT_ID.
# Placeholder discipline: the config example stores "<YOUR_BOT_TOKEN>" — real
# tokens never appear in this repository (docs/MODULE-CONTRACT.md rule 7).
# rc: 0 = sent or unconfigured (warn); non-zero = transport/API failure.
# Never exits, never raises into the caller.
# Requires: curl, python3.

hf_notify_telegram() {
    local title=${1:-honeyfleet alert} body=${2:-}
    local token chat payload resp rc
    token=$(hf_conf TG_BOT_TOKEN "")
    chat=$(hf_conf TG_CHAT_ID "")
    if [ -z "$token" ] || [ -z "$chat" ]; then
        hf_warn "telegram notifier not configured (HF_TG_BOT_TOKEN / HF_TG_CHAT_ID empty) — skipped"
        return 0
    fi
    command -v curl >/dev/null 2>&1 || { hf_warn "telegram: curl not found"; return 1; }
    # Payload built by python3: html.escape as the HTML safety layer (& < >),
    # then MarkdownV2 special-character escaping on top; body truncated below
    # the Telegram 4096-character message limit.
    payload=$(python3 - "$title" "$body" "$chat" <<'PY'
import html, json, re, sys
def mdv2(s: str) -> str:
    s = html.escape(s, quote=False)                          # HTML layer: & < >
    return re.sub(r"([_*\[\]()~`>#+\-=|{}.!])", r"\\\1", s)  # MarkdownV2 layer
title, body, chat = sys.argv[1], sys.argv[2][:3500], sys.argv[3]
text = "*" + mdv2(title) + "*\n\n" + mdv2(body)
print(json.dumps({"chat_id": chat, "parse_mode": "MarkdownV2", "text": text}))
PY
) || { hf_warn "telegram: payload build failed"; return 1; }
    resp=$(curl -sS --max-time 10 -H 'Content-Type: application/json' \
        --data-binary "$payload" \
        "https://api.telegram.org/bot${token}/sendMessage")
    rc=$?
    [ "$rc" -ne 0 ] && { hf_warn "telegram: curl failed (rc=$rc)"; return 1; }
    case "$resp" in
        *'"ok":true'*) return 0 ;;
        *) hf_warn "telegram: API error: ${resp:-<empty response>}"; return 1 ;;
    esac
}

# direct CLI: notifiers/telegram.sh "title" "body"
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    type hf_conf >/dev/null 2>&1 || . "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dispatch.sh"
    hf_notify_telegram "${1:-}" "${2:-}"
fi
