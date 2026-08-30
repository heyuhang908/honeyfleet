#!/usr/bin/env bash
# honeyfleet module: federation — dual-role fleet status push/receive.
# Follows docs/MODULE-CONTRACT.md exactly (exemplar: modules/file-integrity.sh).
#
# Roles (HF_ROLE in the single config, read ONLY via hf_conf):
#
#   agent — pushes a local snapshot JSON every HF_PUSH_INTERVAL seconds to
#     HF_CENTRAL_USER@HF_CENTRAL_HOST:HF_CENTRAL_PORT over SSH, where the
#     central receiver (/usr/local/lib/honeyfleet/receive-fleet.py) validates
#     and stores it. Snapshot contents reuse module state (honest counters):
#       * fail2ban per-jail counters — queried live from fail2ban-client
#       * file-integrity state — the state JSON behind hf_fi_status
#       * waterline — disk/mem/swap %, thresholds via hf_conf (computed inline
#         until the waterline-alerts module exposes its own state file)
#       * hostname + timestamp
#
#   central — receive-fleet.py (python3, stdlib only): reads ONE snapshot on
#     stdin (typically via an SSH forced command), validates schema and
#     timestamps (anti-replay: rejects a timestamp older than the one already
#     stored for the agent, and far-future skew), stores
#     /var/lib/honeyfleet/fleet/<agent>.json atomically, replies
#     "OK <agent> age=0 entries=N", then sends a one-line-per-agent fleet
#     summary through hf_notify (shared notifier library, honors HF_NOTIFIER).
#     A scan timer flags agents silent for > 10 * HF_PUSH_INTERVAL (600 s at
#     the 60 s default) as stale and alerts "fleet agent stale" — staleness is
#     NEVER silent, and recovery is announced when pushes resume.
#
# SSH push-key setup guidance (agent -> central):
#   1. agent:   ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519_fleetpush
#   2. central: create the push user (HF_CENTRAL_USER, default "honeyfleet"),
#      append the agent PUBLIC key to ~<user>/.ssh/authorized_keys, locked to
#      the receiver with a forced command and no forwarding (one line):
#        command="/usr/local/lib/honeyfleet/receive-fleet.py",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ssh-ed25519 AAAA... agent@192.0.2.10
#   3. agent config: set HF_CENTRAL_HOST / HF_CENTRAL_PORT / HF_CENTRAL_USER,
#      then run: install.sh install --only federation
#   A plain (non-forced) authorized key also works — the receiver is invoked
#   directly by the push script; use the forced command for least privilege.
#
# Dependency: notifiers (declared in install.sh deps(); runtime scripts source
# the deployed /usr/local/lib/honeyfleet/notifiers/dispatch.sh; see
# hf_federation_ensure_notifiers below for how the dependency is satisfied).

set -uo pipefail
MOD=federation
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"

PUSH_SCRIPT=/usr/local/lib/honeyfleet/fleet-push.sh
RECV_SCRIPT=/usr/local/lib/honeyfleet/receive-fleet.py
DEPLOY_LIB_DIR=/usr/local/lib/honeyfleet/lib
DEPLOY_NOTIFIER_DIR=/usr/local/lib/honeyfleet/notifiers
UNIT_PUSH_SERVICE=honeyfleet-push.service
UNIT_PUSH_TIMER=honeyfleet-push.timer
UNIT_SCAN_SERVICE=honeyfleet-fleet-scan.service
UNIT_SCAN_TIMER=honeyfleet-fleet-scan.timer
FLEET_DIR=/var/lib/honeyfleet/fleet
PUSH_STATE=/var/lib/honeyfleet/fleet-push-state.json
VERIFY_LOG=/var/log/honeyfleet/federation-verify.log

fed_role() { hf_conf ROLE agent; }

# ── shared dependency: notifier library ──────────────────────────────────────
hf_federation_ensure_notifiers() {
    # Declared dependency: federation -> notifiers (install.sh deps()). In the
    # full checkout modules/notifiers.sh registers it; in minimal checkouts
    # the installer's SKIP path leaves the shared library undeployed, so
    # federation deploys the library it needs (dispatch + channels +
    # common.sh), verifies every file with bash -n, and only then records the
    # dependency as satisfied. Runtime consumers source
    # $DEPLOY_NOTIFIER_DIR/dispatch.sh (self-bootstraps common.sh).
    if grep -q 'hf_mod_notifiers_installed=1' "$HF_STATE/registry" 2>/dev/null; then
        return 0
    fi
    local f src dst
    sudo mkdir -p "$DEPLOY_NOTIFIER_DIR" "$DEPLOY_LIB_DIR"
    for f in dispatch.sh telegram.sh wecom.sh dingtalk.sh smtp.sh; do
        src="$SCRIPT_DIR/../notifiers/$f"; dst="$DEPLOY_NOTIFIER_DIR/$f"
        [ -f "$src" ] || hf_die "federation: dependency missing: repo notifiers/$f"
        bash -n "$src" || hf_die "federation: notifiers/$f fails bash -n"
        hf_backup "$dst"
        sudo install -o root -g root -m 0644 "$src" "$dst"
    done
    src="$SCRIPT_DIR/../lib/common.sh"; dst="$DEPLOY_LIB_DIR/common.sh"
    [ -f "$src" ] || hf_die "federation: dependency missing: repo lib/common.sh"
    bash -n "$src" || hf_die "federation: lib/common.sh fails bash -n"
    hf_backup "$dst"
    sudo install -o root -g root -m 0644 "$src" "$dst"
    # shim: runtime consumers (waterline-alerts etc.) call hf_notify via
    # $HF_LIB/notify.sh — keep this path stable, it is part of the contract.
    printf '%s\n' '#!/usr/bin/env bash' \
        '# honeyfleet notify shim — sources the notifier dispatcher (hf_notify entrypoint)' \
        ". \"$DEPLOY_NOTIFIER_DIR/dispatch.sh\"" | sudo -n tee "$DEPLOY_LIB_DIR/notify.sh" > /dev/null
    sudo -n chmod 0644 "$DEPLOY_LIB_DIR/notify.sh"
    bash -n "$DEPLOY_LIB_DIR/notify.sh" || hf_die "federation: notify.sh shim fails bash -n"
    hf_registry 1 notifiers
    hf_log "federation: notifier library deployed to $DEPLOY_NOTIFIER_DIR (dependency 'notifiers' satisfied)"
}

# ── install: agent role ──────────────────────────────────────────────────────
hf_federation_install_agent() {
    local host port user interval
    host=$(hf_conf CENTRAL_HOST "")
    port=$(hf_conf CENTRAL_PORT 22)
    user=$(hf_conf CENTRAL_USER honeyfleet)
    interval=$(hf_conf PUSH_INTERVAL 60)
    [ -n "$host" ] || hf_die "federation agent: HF_CENTRAL_HOST is empty — set it in $HF_ETC/honeyfleet.conf (SSH key setup: see module header)"

    # snapshot pusher — deployed script reads config ONLY via hf_conf at
    # runtime (no hardcoded host/port/interval), so one artifact serves nodes
    # with different configs; edits belong in this module, not in the copy.
    hf_backup "$PUSH_SCRIPT"
    sudo tee "$PUSH_SCRIPT" > /dev/null <<'PUSH'
#!/usr/bin/env bash
# honeyfleet fleet push (agent role) — deployed by modules/federation.sh.
# Reads configuration ONLY via hf_conf from /etc/honeyfleet/honeyfleet.conf
# (central host/port/user, push interval, waterline thresholds). Requires an
# SSH push key authorized on the central node — setup guidance lives in the
# federation module header. Exit 0 = central accepted the snapshot.
set -uo pipefail

CONF=/etc/honeyfleet/honeyfleet.conf
[ -f "$CONF" ] || { printf '[honeyfleet][ERROR] config missing: %s\n' "$CONF" >&2; exit 1; }
set -a; . "$CONF"; set +a   # export config so python3 children see HF_* keys
# shellcheck source=../../lib/common.sh
. /usr/local/lib/honeyfleet/lib/common.sh

state_file=/var/lib/honeyfleet/fleet-push-state.json
host=$(hf_conf CENTRAL_HOST "")
port=$(hf_conf CENTRAL_PORT 22)
user=$(hf_conf CENTRAL_USER honeyfleet)
interval=$(hf_conf PUSH_INTERVAL 60)
[ -n "$host" ] || { hf_warn "fleet-push: HF_CENTRAL_HOST empty"; exit 1; }

tmp=$(mktemp /tmp/hf-fleet-snap.XXXXXX.json) || exit 1
errf=$(mktemp /tmp/hf-fleet-err.XXXXXX) || exit 1
trap 'rm -f "$tmp" "$errf"' EXIT

# ---- snapshot build (honest counters: live queries and real state files) ----
python3 - "$tmp" "$interval" <<'PY'
import json, os, socket, subprocess, sys, time
out, interval = sys.argv[1], int(sys.argv[2])
now = int(time.time())
snap = {
    "schema": 1,
    "hostname": socket.gethostname(),
    "timestamp": now,
    "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
    "push_interval": interval,
    "fail2ban": {},
    "file_integrity": None,
    "waterline": {},
}

# fail2ban per-jail counters, queried live; absent daemon -> empty (honest)
try:
    outj = subprocess.run(["fail2ban-client", "status"], capture_output=True,
                          text=True, timeout=10).stdout
    for line in outj.splitlines():
        if not line.strip().lower().startswith("jail list"):
            continue
        for jail in line.split(":", 1)[1].split(","):
            jail = jail.strip()
            if not jail:
                continue
            cur = tot = 0
            st = subprocess.run(["fail2ban-client", "status", jail],
                                capture_output=True, text=True, timeout=10).stdout
            for ln in st.splitlines():
                parts = ln.split("\t")
                if len(parts) == 2:
                    k, v = parts[0].strip(), parts[1].strip()
                    if k == "Currently banned":
                        cur = int(v) if v.isdigit() else 0
                    elif k == "Total banned":
                        tot = int(v) if v.isdigit() else 0
            snap["fail2ban"][jail] = {"currently_banned": cur, "total_banned": tot}
except Exception:
    pass

# file-integrity state: the same JSON that hf_fi_status reads
try:
    with open("/var/lib/honeyfleet/file-integrity-state.json") as fh:
        s = json.load(fh)
    snap["file_integrity"] = {
        "files_tracked": s.get("files_tracked"),
        "drift_count": s.get("drift_count"),
        "last_result": s.get("last_result"),
    }
except Exception:
    pass

# waterline: thresholds come from the config (HF_WATERLINE_* exported above);
# same caliber the waterline-alerts module enforces
def pct(a, b):
    return round(100.0 * a / b, 1) if b else 0.0

try:
    mi = {}
    for ln in open("/proc/meminfo"):
        k, _, v = ln.partition(":")
        v = v.split()
        mi[k.strip()] = int(v[0]) if v else 0
    used = 0; avail = 0
    st = os.statvfs("/")
    used = st.f_blocks - st.f_bfree
    avail = st.f_bavail
    disk_used = pct(used, used + avail) if (used + avail) else 0.0  # df caliber
    mem_avail = pct(mi.get("MemAvailable", 0), mi.get("MemTotal", 0))
    swap_used = pct(mi.get("SwapTotal", 0) - mi.get("SwapFree", 0), mi.get("SwapTotal", 0))
    snap["waterline"] = {
        "disk_used_pct": disk_used,
        "mem_avail_pct": mem_avail,
        "swap_used_pct": swap_used,
        "alert_disk": disk_used >= float(os.environ.get("HF_WATERLINE_DISK", "80")),
        "alert_mem": mem_avail <= float(os.environ.get("HF_WATERLINE_MEM", "20")),
        "alert_swap": swap_used >= float(os.environ.get("HF_WATERLINE_SWAP", "50")),
    }
except Exception:
    pass

with open(out, "w") as fh:
    json.dump(snap, fh)
PY

# ---- push: snapshot on stdin to the central receiver (SSH; the forced-
# command authorized key and a direct-path key both work) ----
resp=$(ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new \
        -p "$port" "$user@$host" /usr/local/lib/honeyfleet/receive-fleet.py \
        < "$tmp" 2>"$errf")
rc=$?
ssh_err=$(tr -d '\r' < "$errf" | head -n 1)

# push state (for status + verify freshness caliber), always valid JSON
python3 - "$state_file" "$rc" "$resp" "$ssh_err" <<'PY'
import json, sys, time
state, rc, resp, err = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
ok = rc == 0 and resp.startswith("OK ")
json.dump({
    "schema": 1,
    "last_push_rc": rc,
    "last_push_ok": ok,
    "last_push_at": int(time.time()),
    "last_push_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "central_reply": resp[:200],
    "error": (err or ("" if ok else "rejected: " + resp))[:200],
}, open(state, "w"), indent=2)
PY

if [ "$rc" -eq 0 ] && [ "${resp#OK }" != "$resp" ]; then
    hf_log "fleet-push: accepted by central ($resp)"
    exit 0
fi
hf_warn "fleet-push: push to $user@$host:$port failed (rc=$rc)${ssh_err:+ — $ssh_err}${resp:+ — $resp}"
exit 1
PUSH
    sudo install -o root -g root -m 0755 "$PUSH_SCRIPT" "$PUSH_SCRIPT"

    # systemd service + timer (self-healing schedule, contract rule 9: the
    # timer keeps firing after failures; central flags the agent stale when
    # pushes stop, so a failed push is never silent)
    hf_unit_write "$UNIT_PUSH_SERVICE" <<UNIT
[Unit]
Description=honeyfleet fleet status push (agent -> central)
Wants=network-online.target
After=network-online.target
[Service]
Type=oneshot
ExecStart=$PUSH_SCRIPT
UNIT
    hf_unit_write "$UNIT_PUSH_TIMER" <<UNIT
[Unit]
Description=Push fleet snapshot every ${interval}s
[Timer]
OnBootSec=1min
OnUnitActiveSec=${interval}s
AccuracySec=10s
[Install]
WantedBy=timers.target
UNIT
    sudo systemctl enable --now "$UNIT_PUSH_TIMER"

    hf_log "federation agent: push to $user@$host:$port every ${interval}s ($UNIT_PUSH_SERVICE + $UNIT_PUSH_TIMER)"
    hf_log "federation agent: make sure the push key is authorized on the central (see module header)"
}

# ── install: central role ────────────────────────────────────────────────────
hf_federation_install_central() {
    local user window scan_interval
    user=$(hf_conf CENTRAL_USER honeyfleet)

    # fleet storage (kept on remove for forensics)
    sudo mkdir -p "$FLEET_DIR"
    sudo chmod 0755 "$FLEET_DIR"
    if id "$user" >/dev/null 2>&1; then
        sudo chown "$user" "$FLEET_DIR"
    else
        hf_warn "federation central: push user '$user' (HF_CENTRAL_USER) does not exist yet — create it, then rerun install so $FLEET_DIR is writable by pushes"
    fi

    # receiver (python3, stdlib only; modes: stdin | --scan | --selftest)
    hf_backup "$RECV_SCRIPT"
    sudo tee "$RECV_SCRIPT" > /dev/null <<'RECV'
#!/usr/bin/env python3
"""honeyfleet fleet receiver (central role) — deployed by modules/federation.sh;
edit the module, not this file. python3, stdlib only.

Modes:
  (stdin)  read one agent snapshot JSON, validate schema + timestamps
           (anti-replay), store atomically as <FLEET_DIR>/<agent>.json, reply
           "OK <agent> age=0 entries=N" on stdout, then send a one-line-per-
           agent fleet summary via hf_notify (shared notifier library,
           honors HF_NOTIFIER; notification failure is never fatal).
  --scan   mark agents silent for > 10 * HF_PUSH_INTERVAL as stale and alert
           "fleet agent stale" (never silent); clear + announce recovery.
  --selftest  validate the validator (used by the verify gate).

Replay protection: a snapshot whose timestamp is OLDER than the one already
stored for the same agent is rejected; timestamps >120 s in the future are
rejected (clock-skew abuse). Stale window: 10 * HF_PUSH_INTERVAL (600 s at
the 60 s default). Summary notification is deduped (identical content within
1 h is suppressed unless a heartbeat is due) — state transitions always alert
immediately via scan().
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import time

FLEET_DIR = os.environ.get("HF_FLEET_DIR", "/var/lib/honeyfleet/fleet")
CONFIG = "/etc/honeyfleet/honeyfleet.conf"
DEFAULT_INTERVAL = 60
MAX_FUTURE_SKEW = 120
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def push_interval():
    """HF_PUSH_INTERVAL from the single config file (never hardcoded)."""
    try:
        with open(CONFIG) as fh:
            for line in fh:
                m = re.match(r'\s*(?:export\s+)?HF_PUSH_INTERVAL\s*=\s*"?(\d+)', line)
                if m:
                    return max(1, int(m.group(1)))
    except OSError:
        pass
    return DEFAULT_INTERVAL


def stale_window():
    return 10 * push_interval()


def notify(title, body):
    """Route through notifiers/dispatch.sh (hf_notify). Never raises, never
    fails the receive: alerting is best-effort, the snapshot is already safe."""
    shim = (
        ". /etc/honeyfleet/honeyfleet.conf 2>/dev/null || true; "
        ". /usr/local/lib/honeyfleet/lib/common.sh 2>/dev/null || true; "
        ". /usr/local/lib/honeyfleet/notifiers/dispatch.sh 2>/dev/null || true; "
        'hf_notify "$1" "$2"'
    )
    try:
        proc = subprocess.run(
            ["bash", "-c", shim, "hf-notify", str(title), str(body)],
            capture_output=True, text=True, timeout=60,
        )
        if proc.returncode != 0:
            lines = [l for l in (proc.stderr or "").strip().splitlines() if l]
            print("notify: channel returned %d%s" % (
                proc.returncode, " (%s)" % lines[-1][:120] if lines else ""),
                file=sys.stderr)
    except Exception as exc:
        print(f"notify failed: {exc}", file=sys.stderr)


def validate(snap, now):
    """Raise ValueError on any schema/timestamp violation; return (host, ts)."""
    if not isinstance(snap, dict):
        raise ValueError("payload is not a JSON object")
    if snap.get("schema") != 1:
        raise ValueError("unsupported schema (want 1)")
    host = snap.get("hostname")
    if not isinstance(host, str) or not HOST_RE.match(host):
        raise ValueError("bad hostname")
    ts = snap.get("timestamp")
    if isinstance(ts, bool) or not isinstance(ts, int) or ts <= 0:
        raise ValueError("bad timestamp")
    if ts > now + MAX_FUTURE_SKEW:
        raise ValueError("timestamp too far in the future (clock skew/replay)")
    for key in ("fail2ban", "waterline"):
        if not isinstance(snap.get(key), dict):
            raise ValueError("missing/bad section: " + key)
    fi = snap.get("file_integrity")
    if fi is not None and not isinstance(fi, dict):
        raise ValueError("bad file_integrity section")
    return host, ts


def load_snapshot(path):
    with open(path) as fh:
        return json.load(fh)


def store(host, snap, ts):
    path = os.path.join(FLEET_DIR, host + ".json")
    prev = 0
    if os.path.exists(path):
        try:
            prev = int(load_snapshot(path).get("timestamp") or 0)
        except Exception:
            prev = 0
    if ts < prev:
        raise ValueError("replay rejected: ts %d older than stored %d" % (ts, prev))
    tmp = path + ".tmp.%d" % os.getpid()
    with open(tmp, "w") as fh:
        json.dump(snap, fh)
    os.replace(tmp, path)
    return path


def summary_line(host, snap, now, window):
    try:
        age = now - int(snap.get("timestamp") or 0)
    except Exception:
        return host + ": unreadable state"
    f2b = snap.get("fail2ban") or {}
    bans = sum(int(v.get("currently_banned") or 0) for v in f2b.values()
               if isinstance(v, dict))
    fi = snap.get("file_integrity") or {}
    wl = snap.get("waterline") or {}
    state = "STALE" if age > window else "fresh"
    return ("%s: %s age=%ds bans=%d integrity=%s/drift=%s disk=%s%% mem_avail=%s%%"
            % (host, state, age, bans,
               fi.get("last_result", "n/a"), fi.get("drift_count", "n/a"),
               wl.get("disk_used_pct", "n/a"), wl.get("mem_avail_pct", "n/a")))


def scan(now=None):
    """Stale sweep + honest alerting. Returns (fresh, stale) name lists."""
    now = int(time.time()) if now is None else now
    window = stale_window()
    fresh, stale = [], []
    if not os.path.isdir(FLEET_DIR):
        return fresh, stale
    for name in sorted(os.listdir(FLEET_DIR)):
        if name.startswith(".") or not name.endswith(".json"):
            continue
        host = name[:-len(".json")]
        try:
            ts = int(load_snapshot(os.path.join(FLEET_DIR, name)).get("timestamp") or 0)
        except Exception:
            continue
        marker = os.path.join(FLEET_DIR, "." + host + ".stale")
        if ts and now - ts > window:
            stale.append(host)
            if not os.path.exists(marker):
                with open(marker, "w") as fh:
                    fh.write(str(now))
                notify("fleet agent stale",
                       "agent %s has not pushed for %ds (stale window %ds) "
                       "- check the push timer/SSH on the agent"
                       % (host, now - ts, window))
        else:
            fresh.append(host)
            if os.path.exists(marker):
                os.remove(marker)
                notify("fleet agent recovered",
                       "agent %s is pushing again (age %ds)" % (host, max(0, now - ts)))
    return fresh, stale


def maybe_notify_summary(lines, now):
    """Fleet summary on receipt (one line per agent). Deduped: identical
    content within 1 h is suppressed unless the heartbeat is due; disable via
    HF_FLEET_SUMMARY_DEDUPE=0 for strict notify-on-every-receipt. The digest
    ignores the volatile age=N figure (fresh/STALE state is kept), otherwise
    every receive would look 'changed'."""
    if os.environ.get("HF_FLEET_SUMMARY_DEDUPE", "1").lower() in ("0", "false", "no"):
        notify("honeyfleet fleet summary", "\n".join(lines))
        return "sent(dedupe-off)"
    canon = [re.sub(r"age=\d+s", "age=Xs", l) for l in lines]
    digest = hashlib.sha256("\n".join(canon).encode()).hexdigest()
    sp = os.path.join(FLEET_DIR, ".summary-state.json")
    try:
        with open(sp) as fh:
            prev = json.load(fh)
    except Exception:
        prev = {}
    changed = prev.get("hash") != digest
    heartbeat = now - int(prev.get("ts") or 0) >= 3600
    if not changed and not heartbeat:
        return "suppressed"
    notify("honeyfleet fleet summary", "\n".join(lines))
    tmp = sp + ".tmp.%d" % os.getpid()
    with open(tmp, "w") as fh:
        json.dump({"hash": digest, "ts": now}, fh)
    os.replace(tmp, sp)
    return "sent" if changed else "sent(heartbeat)"


def main(argv):
    if "--selftest" in argv:
        now = int(time.time())
        good = {"schema": 1, "hostname": "agent.example.com", "timestamp": now,
                "fail2ban": {"sshd": {"currently_banned": 0, "total_banned": 0}},
                "waterline": {"disk_used_pct": 1.0}}
        host, ts = validate(good, now)
        assert host == "agent.example.com" and ts == now
        for bad, why in (
            (dict(good, schema=2), "schema"),
            (dict(good, hostname="bad host!"), "hostname"),
            (dict(good, timestamp="x"), "timestamp"),
            (dict(good, fail2ban=None), "fail2ban"),
        ):
            try:
                validate(bad, now)
            except ValueError:
                continue
            raise AssertionError("selftest: %s should have been rejected" % why)
        print("selftest OK (stale window %ds)" % stale_window())
        return 0

    if "--scan" in argv:
        fresh, stale = scan()
        msg = "fleet scan: fresh=%d stale=%d" % (len(fresh), len(stale))
        if stale:
            msg += " stale_agents=" + ",".join(stale)
        print(msg)
        return 0

    raw = sys.stdin.read()
    now = int(time.time())
    try:
        snap = json.loads(raw)
        host, ts = validate(snap, now)
    except ValueError as exc:
        print("REJECTED %s" % exc, file=sys.stderr)
        return 2
    os.makedirs(FLEET_DIR, exist_ok=True)
    try:
        store(host, snap, ts)
    except ValueError as exc:
        print("REJECTED %s" % exc, file=sys.stderr)
        return 2
    # acknowledge immediately (the snapshot is safe), then best-effort alerting
    window = stale_window()
    lines = []
    for name in sorted(os.listdir(FLEET_DIR)):
        if name.startswith(".") or not name.endswith(".json"):
            continue
        try:
            lines.append(summary_line(name[:-len(".json")],
                                      load_snapshot(os.path.join(FLEET_DIR, name)),
                                      now, window))
        except Exception:
            lines.append(name[:-len(".json")] + ": unreadable state")
    how = maybe_notify_summary(lines, now)
    print("OK %s age=0 entries=%d summary=%s" % (host, len(lines), how), flush=True)
    scan(now)   # transition alerts (stale/recovery) fire here too, never fatal
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
RECV
    sudo install -o root -g root -m 0755 "$RECV_SCRIPT" "$RECV_SCRIPT"

    # stale-scan units: window = 10 * push interval; sweep at half-window pace
    window=$(( $(hf_conf PUSH_INTERVAL 60) * 10 ))
    scan_interval=$(( window / 2 ))
    if [ "$scan_interval" -lt 60 ]; then scan_interval=60; fi
    hf_unit_write "$UNIT_SCAN_SERVICE" <<UNIT
[Unit]
Description=honeyfleet fleet stale scan (central)
[Service]
Type=oneshot
ExecStart=$RECV_SCRIPT --scan
UNIT
    hf_unit_write "$UNIT_SCAN_TIMER" <<UNIT
[Unit]
Description=Scan fleet for stale agents every $((scan_interval))s
[Timer]
OnBootSec=2min
OnUnitActiveSec=${scan_interval}s
[Install]
WantedBy=timers.target
UNIT
    sudo systemctl enable --now "$UNIT_SCAN_TIMER"

    hf_log "federation central: receiver $RECV_SCRIPT, fleet dir $FLEET_DIR, stale window ${window}s"
    hf_log "federation central: authorize each agent push key (forced command, one line):"
    hf_log "  echo 'command=\"$RECV_SCRIPT\",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty <agent-public-key>' >> ~$user/.ssh/authorized_keys"
}

# ── install ──────────────────────────────────────────────────────────────────
hf_federation_install() {
    local role; role=$(fed_role)
    hf_log "federation: install (role=$role)"
    sudo mkdir -p "$HF_LIB" "$HF_STATE" /var/log/honeyfleet
    hf_federation_ensure_notifiers
    case "$role" in
        agent)   hf_federation_install_agent ;;
        central) hf_federation_install_central ;;
        *) hf_die "federation: unknown role '$role' (HF_ROLE must be central|agent)" ;;
    esac
    hf_registry 1 "$MOD"
    hf_log "federation: installed (role=$role)"
}

# ── verify gate ──────────────────────────────────────────────────────────────
hf_federation_verify_agent() {
    local rc=0 host interval
    host=$(hf_conf CENTRAL_HOST "")
    interval=$(hf_conf PUSH_INTERVAL 60)
    [ -n "$host" ] || { hf_warn "federation verify: HF_CENTRAL_HOST empty"; return 1; }
    [ -x "$PUSH_SCRIPT" ] || { hf_warn "federation verify: $PUSH_SCRIPT missing"; return 1; }
    bash -n "$PUSH_SCRIPT" 2>/dev/null || { hf_warn "federation verify: $PUSH_SCRIPT fails bash -n"; return 1; }
    systemctl is-enabled --quiet "$UNIT_PUSH_TIMER" 2>/dev/null \
        || { hf_warn "federation verify: $UNIT_PUSH_TIMER not enabled"; rc=1; }
    systemctl is-active --quiet "$UNIT_PUSH_TIMER" 2>/dev/null \
        || { hf_warn "federation verify: $UNIT_PUSH_TIMER not active"; rc=1; }
    # e2e gate — one real push. Success proves BOTH spec conditions at once:
    #   * the push itself succeeded, and
    #   * the central-side entry is fresh (< 2 * HF_PUSH_INTERVAL): the
    #     receiver only answers "OK ... age=0" after it stored the snapshot,
    #     so acceptance timestamp age is 0 by construction.
    mkdir -p /var/log/honeyfleet 2>/dev/null
    if [ -f "$VERIFY_LOG" ] && [ "$(wc -c <"$VERIFY_LOG" 2>/dev/null || echo 0)" -gt 1048576 ]; then
        sudo truncate -s 0 "$VERIFY_LOG"
    fi
    if ! sudo -n "$PUSH_SCRIPT" >>"$VERIFY_LOG" 2>&1; then
        hf_warn "federation verify: e2e push to $host failed (last log line: $(sudo tail -n 1 "$VERIFY_LOG" 2>/dev/null | head -c 200))"
        return 1
    fi
    return "$rc"
}

hf_federation_verify_central() {
    local rc=0 window
    window=$(( $(hf_conf PUSH_INTERVAL 60) * 10 ))
    [ -f "$RECV_SCRIPT" ] || { hf_warn "federation verify: $RECV_SCRIPT missing"; return 1; }
    # py_compile gate (temp .pyc so the gate works for any invoking user)
    if ! python3 - "$RECV_SCRIPT" <<'PY'
import os, py_compile, sys, tempfile
fd, tmp = tempfile.mkstemp(suffix=".pyc"); os.close(fd)
try:
    py_compile.compile(sys.argv[1], cfile=tmp, doraise=True)
finally:
    os.remove(tmp)
PY
    then
        hf_warn "federation verify: receive-fleet.py py_compile FAILED"
        return 1
    fi
    [ -d "$FLEET_DIR" ] || { hf_warn "federation verify: $FLEET_DIR missing"; return 1; }
    "$RECV_SCRIPT" --selftest >/dev/null 2>&1 \
        || { hf_warn "federation verify: receiver selftest failed"; rc=1; }
    systemctl is-enabled --quiet "$UNIT_SCAN_TIMER" 2>/dev/null \
        || { hf_warn "federation verify: $UNIT_SCAN_TIMER not enabled"; rc=1; }
    systemctl is-active --quiet "$UNIT_SCAN_TIMER" 2>/dev/null \
        || { hf_warn "federation verify: $UNIT_SCAN_TIMER not active"; rc=1; }
    hf_log "federation central: stale window ${window}s"
    return "$rc"
}

hf_federation_verify() {
    local role; role=$(fed_role)
    local rc=0
    case "$role" in
        agent)   hf_federation_verify_agent   || rc=1 ;;
        central) hf_federation_verify_central || rc=1 ;;
        *) hf_warn "federation verify: unknown role '$role'"; return 1 ;;
    esac
    if [ "$rc" -eq 0 ]; then
        hf_log "federation: verify PASS (role=$role)"
    else
        hf_warn "federation: verify FAIL (role=$role) — see warnings above"
    fi
    return "$rc"
}

# ── status (one line, no side effects) ───────────────────────────────────────
hf_federation_status() {
    local role; role=$(fed_role)
    if [ "$role" = "agent" ]; then
        python3 - "$PUSH_STATE" "$(hf_conf CENTRAL_HOST '')" "$(hf_conf CENTRAL_PORT 22)" "$(hf_conf PUSH_INTERVAL 60)" <<'PY'
import json, sys, time
state, host, port, interval = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
try:
    s = json.load(open(state))
    age = int(time.time()) - int(s.get("last_push_at") or 0)
    last = "%s rc=%s" % (s.get("last_push_utc"), s.get("last_push_rc"))
except Exception:
    age = -1; last = "never"
if age < 0:
    verdict = "no-push-yet"
elif age <= 2 * interval:
    verdict = "ok"
else:
    verdict = "STALE"
print("federation: role=agent central=%s:%s interval=%ds last_push=%s age=%ss -> %s"
      % (host, port, interval, last, age, verdict))
PY
    else
        python3 - "$FLEET_DIR" "$(( $(hf_conf PUSH_INTERVAL 60) * 10 ))" <<'PY'
import json, os, sys, time
fleet, window = sys.argv[1], int(sys.argv[2])
now = int(time.time())
fresh = 0; stale = 0; names = []
try:
    for n in sorted(os.listdir(fleet)):
        if n.startswith(".") or not n.endswith(".json"):
            continue
        try:
            ts = int(json.load(open(os.path.join(fleet, n))).get("timestamp") or 0)
        except Exception:
            ts = 0
        if ts and now - ts <= window:
            fresh += 1
        else:
            stale += 1; names.append(n[:-5])
except OSError:
    pass
extra = (" stale_agents=" + ",".join(names)) if names else ""
print("federation: role=central agents=%d fresh=%d stale=%d%s" % (fresh + stale, fresh, stale, extra))
PY
    fi
}

# ── remove (clean removal; state kept for forensics) ─────────────────────────
hf_federation_remove() {
    local u
    for u in "$UNIT_PUSH_TIMER" "$UNIT_SCAN_TIMER"; do
        sudo systemctl disable --now "$u" 2>/dev/null || true
    done
    for u in "$UNIT_PUSH_SERVICE" "$UNIT_PUSH_TIMER" "$UNIT_SCAN_SERVICE" "$UNIT_SCAN_TIMER"; do
        hf_backup "/etc/systemd/system/$u" 2>/dev/null
        sudo rm -f "/etc/systemd/system/$u"
    done
    sudo systemctl daemon-reload
    hf_backup "$PUSH_SCRIPT"; sudo rm -f "$PUSH_SCRIPT"
    hf_backup "$RECV_SCRIPT"; sudo rm -f "$RECV_SCRIPT"
    # notifiers library stays: waterline-alerts (and others) may still use it
    # fleet dir + push state are kept for forensics (contract rule on removal)
    hf_registry 0 "$MOD"
    hf_log "federation: removed (fleet state kept in $FLEET_DIR, push state in $PUSH_STATE)"
}

case "${1:-}" in
    install) hf_federation_install ;;
    verify)  hf_federation_verify ;;
    status)  hf_federation_status ;;
    remove)  hf_federation_remove ;;
    *) hf_die "usage: federation.sh install|verify|status|remove" ;;
esac
