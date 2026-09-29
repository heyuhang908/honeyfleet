#!/usr/bin/env bash
# honeyfleet notifier channel: SMTP single-shot mail via python3 smtplib.
# Config (via hf_conf only): HF_SMTP_TO (recipient), HF_SMTP_RELAY (relay,
# "relay.example.com" or "relay.example.com:25"; the relay is mandatory —
# this channel never delivers directly to MX).
# rc semantics:
#   0        sent; or HF_SMTP_TO empty = unconfigured (warn + 0, 未配置≠故障)
#   2        HF_SMTP_TO set but HF_SMTP_RELAY empty (misconfigured) — callers
#            may treat 2 specially; hf_notify just forwards the code
#   other≠0  send failure. Never exits, never raises into the caller.
# Requires: python3.

hf_notify_smtp() {
    local title=${1:-honeyfleet alert} body=${2:-}
    local to relay rc
    to=$(hf_conf SMTP_TO "")
    relay=$(hf_conf SMTP_RELAY "")
    if [ -z "$to" ]; then
        hf_warn "smtp notifier not configured (HF_SMTP_TO empty) — skipped"
        return 0
    fi
    if [ -z "$relay" ]; then
        hf_warn "smtp: HF_SMTP_TO is set but HF_SMTP_RELAY is empty — set the relay (e.g. relay.example.com:25) in the config"
        return 2
    fi
    command -v python3 >/dev/null 2>&1 || { hf_warn "smtp: python3 not found"; return 1; }
    python3 - "$relay" "$to" "$title" "$body" <<'PY' || { rc=$?; hf_warn "smtp: send failed (rc=$rc) — check HF_SMTP_RELAY reachability"; return "$rc"; }
import smtplib, socket, sys
from email.message import EmailMessage
relay, to, title, body = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4][:3500]
# relay may be "host" or "host:port" — split before handing to smtplib
host, _, port = relay.rpartition(":")
if not port.isdigit():
    host, port = relay, "25"
msg = EmailMessage()
msg["Subject"] = title
msg["From"] = f"honeyfleet@{socket.gethostname()}"
msg["To"] = to
msg.set_content(body)
with smtplib.SMTP(host, int(port), timeout=15) as s:
    s.send_message(msg)
PY
}

# direct CLI: notifiers/smtp.sh "title" "body"
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    type hf_conf >/dev/null 2>&1 || . "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dispatch.sh"
    hf_notify_smtp "${1:-}" "${2:-}"
fi
