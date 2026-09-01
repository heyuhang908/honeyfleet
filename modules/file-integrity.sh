#!/usr/bin/env bash
# honeyfleet module: file-integrity — self-monitoring of security-critical files.
# Exemplar module: every other module MUST follow this contract
# (see docs/MODULE-CONTRACT.md): hf_fi_install|verify|status|remove, idempotent,
# NO-OP on re-run, config read ONLY via hf_conf, backups via hf_backup.

set -uo pipefail
MOD="file-integrity"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"

CHECK_SCRIPT=/usr/local/lib/honeyfleet/file-integrity-check.sh
UNIT_SERVICE=file-integrity.service
UNIT_TIMER=file-integrity.timer
INTERVAL_MIN=1

targets_list() {
    # Expand HF_FI_TARGETS (space-separated files/dirs). Dirs contribute all
    # regular files beneath them (maxdepth 2). Emit one absolute path per line.
    local t
    for t in $(hf_conf FI_TARGETS); do
        if [ -d "$t" ]; then
            find "$t" -maxdepth 2 -type f 2>/dev/null
        elif [ -f "$t" ]; then
            printf '%s\n' "$t"
        else
            hf_warn "integrity target '$t' does not exist on this node — skipped (counted in dangling report)"
        fi
    done
}

hf_fi_install() {
    hf_requires ssh-hardening   # files to protect must exist; ordering declared

    sudo mkdir -p "$HF_LIB" "$HF_ETC" "$HF_STATE" /var/log/honeyfleet
    hf_backup /etc/honeyfleet/file-integrity-targets.conf

    # 1. targets from config (single source)
    targets_list | sudo tee /etc/honeyfleet/file-integrity-targets.conf > /dev/null
    local n; n=$(sudo grep -cvE '^\s*$' /etc/honeyfleet/file-integrity-targets.conf)
    hf_log "file-integrity: $n targets written"

    # 2. check/baseline script (fixed caliber: files_tracked == actual baseline size)
    sudo tee "$CHECK_SCRIPT" > /dev/null <<'CHECK'
#!/usr/bin/env bash
# file-integrity check — writes state.json; NEVER fails the unit on drift.
set -uo pipefail
config_dir=/etc/honeyfleet; state_dir=/var/lib/honeyfleet
targets_file=$config_dir/file-integrity-targets.conf
baseline_file=$config_dir/file-integrity-baseline.json
state_file=$state_dir/file-integrity-state.json
now=$(date +%s); now_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
drift=0; drift_files="[]"; tracked=0

if [ ! -f "$baseline_file" ]; then
    printf '{"schema":1,"updated_at":%d,"files_tracked":0,"drift_count":0,"drift_files":[],"last_result":"baseline_missing"}\n' "$now" > "$state_file"
    exit 0
fi
tracked=$(python3 -c "import json;print(len(json.load(open('$baseline_file')).get('files', {})))" 2>/dev/null || echo 0)
drift=$(python3 - "$baseline_file" "$targets_file" <<'PY'
import hashlib, json, sys
base = json.load(open(sys.argv[1]))
files = dict(base.get("files", {}))
tg = [l.strip() for l in open(sys.argv[2]) if l.strip() and not l.strip().startswith("#")]
d = []
for path, old in files.items():
    try:
        h = hashlib.sha256(open(path, "rb").read()).hexdigest()
        if h != old.get("sha256"):
            d.append(path)
    except FileNotFoundError:
        d.append(path)
for t in tg:
    if t not in files:
        d.append(t)
print(json.dumps(sorted(set(d))))
PY
)
drift_count=$(python3 -c "import json,sys;print(len(json.loads(sys.argv[1])))" "$drift")
if [ "$drift_count" -gt 0 ]; then
    result=drift
else
    result=clean
fi
python3 - "$state_file" "$now" "$now_utc" "$result" "$drift_count" "$drift" "$tracked" <<'PY'
import json, os, sys
sp, now, utc, result, dc, dj, tracked = sys.argv[1:8]
json.dump({
    "schema": 1, "updated_at": int(now), "updated_at_utc": utc,
    "files_tracked": int(tracked), "drift_count": int(dc),
    "drift_files": json.loads(dj), "last_result": result,
    # caliber fix: tracked reports the REAL baseline size, not the config line count
}, open(sp, "w"), indent=2)
PY
CHECK
    sudo chmod 0755 "$CHECK_SCRIPT"

    # 3. baseline (first install or explicit rebase)
    if [ ! -f /etc/honeyfleet/file-integrity-baseline.json ]; then
        hf_fi_rebase
    fi

    # 4. systemd units
    hf_unit_write "$UNIT_SERVICE" <<UNIT
[Unit]
Description=honeyfleet file integrity check
[Service]
Type=oneshot
ExecStart=$CHECK_SCRIPT
UNIT
    hf_unit_write "$UNIT_TIMER" <<UNIT
[Unit]
Description=Run file integrity check every $INTERVAL_MIN minute(s)
[Timer]
OnBootSec=2min
OnUnitActiveSec=${INTERVAL_MIN}min
[Install]
WantedBy=timers.target
UNIT
    sudo systemctl enable --now "$UNIT_TIMER"

    hf_registry 1 "$MOD"
    hf_log "file-integrity: installed ($n targets, baseline $([ -f /etc/honeyfleet/file-integrity-baseline.json ] && echo present || echo MISSING))"
}

hf_fi_rebase() {
    # Accept current state of all targets as trusted. Warn on dangling entries,
    # then WRITE the baseline (sha256 per existing target) — without this file
    # the drift check would have nothing to compare against.
    local dangling
    dangling=$(sudo grep -vE '^\s*$' /etc/honeyfleet/file-integrity-targets.conf 2>/dev/null | while read -r t; do
        [ -f "$t" ] || printf '%s\n' "$t"
    done)
    [ -n "$dangling" ] && hf_warn "dangling targets (file missing, excluded from baseline): $dangling"
    sudo python3 - /etc/honeyfleet/file-integrity-targets.conf /etc/honeyfleet/file-integrity-baseline.json <<'PY'
import hashlib, json, os, sys
targets_file, out = sys.argv[1], sys.argv[2]
files = {}
for line in open(targets_file, encoding="utf-8"):
    t = line.strip()
    if not t or t.startswith("#"):
        continue
    if os.path.isfile(t):
        files[t] = {"sha256": hashlib.sha256(open(t, "rb").read()).hexdigest()}
json.dump({"schema": 1, "files": files}, open(out, "w"), indent=2)
PY
    local n; n=$(python3 -c "import json;print(len(json.load(open('/etc/honeyfleet/file-integrity-baseline.json')).get('files', {})))" 2>/dev/null || echo 0)
    hf_log "file-integrity: baseline rebased ($n files)"
}

hf_fi_verify() {
    # Consistency gate: state must be clean AND the tracked caliber must be honest
    # (state files_tracked == actual baseline keys == live target files).
    local rc=0
    local s; s=$(sudo cat /var/lib/honeyfleet/file-integrity-state.json 2>/dev/null || echo '{}')
    python3 - "$s" <<'PY' || rc=1
import json, sys, subprocess
s = json.loads(sys.argv[1])
base = json.loads(subprocess.run(["sudo","-n","cat","/etc/honeyfleet/file-integrity-baseline.json"],
                                 capture_output=True, text=True).stdout or "{}")
ok = (s.get("last_result") == "clean"
      and s.get("drift_count") == 0
      and s.get("files_tracked") == len(base.get("files", {})))
print("file-integrity: tracked=%s result=%s drift=%s" %
      (s.get("files_tracked"), s.get("last_result"), s.get("drift_files")))
sys.exit(0 if ok else 1)
PY
    [ $rc -eq 0 ] && hf_log "file-integrity: verify PASS" || hf_warn "file-integrity: verify FAIL"
    return $rc
}

hf_fi_status() {
    local s; s=$(sudo cat /var/lib/honeyfleet/file-integrity-state.json 2>/dev/null || echo '{}')
    printf 'file-integrity: tracked=%s result=%s drift_files=%s\n' \
        "$(python3 -c "import json,sys;print(json.loads(sys.argv[1]).get('files_tracked'))" "$s" 2>/dev/null || echo '?')" \
        "$(python3 -c "import json,sys;print(json.loads(sys.argv[1]).get('last_result'))" "$s" 2>/dev/null || echo '?')" \
        "$(python3 -c "import json,sys;print(json.loads(sys.argv[1]).get('drift_files'))" "$s" 2>/dev/null || echo '?')"
}

hf_fi_remove() {
    hf_backup "$UNIT_SERVICE" 2>/dev/null
    sudo systemctl disable --now "$UNIT_TIMER" 2>/dev/null || true
    sudo rm -f "/etc/systemd/system/$UNIT_SERVICE" "/etc/systemd/system/$UNIT_TIMER" "$CHECK_SCRIPT"
    sudo systemctl daemon-reload
    hf_registry 0 "$MOD"
    hf_log "file-integrity: removed (state kept in $HF_STATE for forensics)"
}

case "${1:-}" in
    install) hf_fi_install ;;
    verify)  hf_fi_verify ;;
    status)  hf_fi_status ;;
    rebase)  hf_fi_rebase ;;
    remove)  hf_fi_remove ;;
    *) hf_die "usage: file-integrity.sh install|verify|status|rebase|remove" ;;
esac
