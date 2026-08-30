#!/usr/bin/env bash
# honeyfleet module: waterline-alerts — disk/memory/swap threshold alerts.
# systemd service + timer runs the check every 5 minutes; trips call hf_notify
# (public interface provided by the notifiers module — this module only CALLS
# it, it never implements it). If the notify interface is absent at runtime the
# check degrades to log-only and still exits 0 (self-heal ordering: the probe
# must never break the unit).
#
# Thresholds are RENDERED into the deployed check script at install time; the
# verify gate compares rendered values against the live config (template<->deployed).
# After changing HF_WATERLINE_* in the config, re-run install to re-render.
# Alert cooldown (default 3600s, HF_WATERLINE_COOLDOWN_S) prevents 5-minute spam.
#
# Contract: docs/MODULE-CONTRACT.md — hf_waterline_alerts_{install,verify,status,remove}.
set -uo pipefail
MOD=waterline-alerts
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"

# lib/common.sh hf_backup has a path mismatch: mkdir creates only dirname($f)
# while the cp target nests the basename as an extra directory component, so
# cp fails and backups silently never happen. Re-defined here with ONE
# consistent layout ($HF_STATE/backups/<path-sans-slash>/.$basename.<UTC>) and
# the same "keep newest 2" retention. Drop this override once lib/common.sh is fixed.

CHECK_SCRIPT=$HF_LIB/waterline-check.sh
UNIT_SERVICE=waterline-alerts.service
UNIT_TIMER=waterline-alerts.timer
UNIT_SERVICE_PATH=/etc/systemd/system/$UNIT_SERVICE
UNIT_TIMER_PATH=/etc/systemd/system/$UNIT_TIMER
INTERVAL_MIN=5

hf_root_check() { [ "$(id -u)" = 0 ] || hf_die "$MOD: must run as root (sudo)"; }

hf_read_thresholds() { # sets DISK / MEM / SWAP / COOL (validated)
    DISK=$(hf_conf WATERLINE_DISK 80)
    MEM=$(hf_conf WATERLINE_MEM 20)
    SWAP=$(hf_conf WATERLINE_SWAP 50)
    COOL=$(hf_conf WATERLINE_COOLDOWN_S 3600)
    local v
    for v in "$DISK" "$MEM" "$SWAP" "$COOL"; do
        case "$v" in ''|*[!0-9]*) hf_die "$MOD: HF_WATERLINE_* thresholds must be integers (got '$v')" ;; esac
    done
    [ "$DISK" -ge 1 ] && [ "$DISK" -le 99 ] || hf_die "$MOD: HF_WATERLINE_DISK=$DISK out of 1-99"
    [ "$MEM" -ge 1 ] && [ "$MEM" -le 99 ] || hf_die "$MOD: HF_WATERLINE_MEM=$MEM out of 1-99"
    [ "$SWAP" -ge 1 ] && [ "$SWAP" -le 99 ] || hf_die "$MOD: HF_WATERLINE_SWAP=$SWAP out of 1-99"
}

hf_render_check() { # thresholds on stdout via token substitution
    cat <<'CHECK'
#!/usr/bin/env bash
# honeyfleet waterline check — rendered by modules/waterline-alerts.sh from config.
# Thresholds are baked at install; the verify gate compares them to the live
# config — re-run install after changing HF_WATERLINE_* in the config.
# This script NEVER fails the unit on a trip: alerts are side effects, exit 0.
set -uo pipefail
DISK_LIMIT=@@DISK@@    # percent used, alert when >=
MEM_LIMIT=@@MEM@@      # percent available, alert when <
SWAP_LIMIT=@@SWAP@@    # percent used, alert when >
COOLDOWN_S=@@COOL@@
CONF=/etc/honeyfleet/honeyfleet.conf
state=/var/lib/honeyfleet/waterline.state
log=/var/log/honeyfleet/waterline.log
notify_lib=/usr/local/lib/honeyfleet/notify.sh

[ -f "$CONF" ] && . "$CONF"
mkdir -p /var/lib/honeyfleet /var/log/honeyfleet
touch "$state" "$log"
[ -f "$notify_lib" ] && { . "$notify_lib" 2>>"$log" || true; }

disk_used=$(df -P / | awk 'NR==2 { gsub(/%/, "", $5); print $5 }')
[[ "$disk_used" =~ ^[0-9]+$ ]] || disk_used=100
mem_avail=$(awk '/MemTotal:/ { t=$2 } /MemAvailable:/ { a=$2 } END { if (t > 0) print int((a * 100) / t); else print 0 }' /proc/meminfo)
[[ "$mem_avail" =~ ^[0-9]+$ ]] || mem_avail=0
swap_used=$(awk '/SwapTotal:/ { t=$2 } /SwapFree:/ { f=$2 } END { if (t > 0) print int(((t - f) * 100) / t); else print 0 }' /proc/meminfo)
[[ "$swap_used" =~ ^[0-9]+$ ]] || swap_used=0

now=$(date +%s)
fired=0

trip() {
    local metric=$1 msg=$2 last noted
    last=$(awk -F= -v m="$metric" '$1 == m { print $2 }' "$state")
    if [ -n "$last" ] && [ $((now - last)) -lt "$COOLDOWN_S" ]; then
        printf '%s cooldown %s (%ss since last alert)\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$metric" "$((now - last))" >> "$log"
        return
    fi
    fired=1
    noted=log-only
    if command -v hf_notify > /dev/null 2>&1; then
        if hf_notify "honeyfleet waterline $(hostname)" "$msg" >> "$log" 2>&1; then noted=notified; fi
    fi
    printf '%s ALERT %s: %s (%s)\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$metric" "$msg" "$noted" >> "$log"
    if grep -q "^${metric}=" "$state"; then
        sed -i "s/^${metric}=.*/${metric}=${now}/" "$state"
    else
        printf '%s=%s\n' "$metric" "$now" >> "$state"
    fi
}

[ "$disk_used" -ge "$DISK_LIMIT" ] && trip disk "root partition ${disk_used}% used (>= ${DISK_LIMIT}%)"
[ "$mem_avail" -lt "$MEM_LIMIT" ] && trip mem "available memory ${mem_avail}% (< ${MEM_LIMIT}%)"
[ "$swap_used" -gt "$SWAP_LIMIT" ] && trip swap "swap ${swap_used}% used (> ${SWAP_LIMIT}%)"
[ "$fired" -eq 0 ] && printf '%s ok disk=%s%% mem_avail=%s%% swap=%s%%\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$disk_used" "$mem_avail" "$swap_used" >> "$log"
exit 0
CHECK
}

hf_install_if_changed() { # $1 rendered content  $2 target path  $3 mode
    local content=$1 target=$2 mode=$3 tmp
    if [ -f "$target" ] && printf '%s' "$content" | sudo cmp -s - "$target"; then
        return 1   # unchanged
    fi
    tmp=$(mktemp)
    printf '%s\n' "$content" > "$tmp"
    hf_backup "$target"
    sudo install -o root -g root -m "$mode" "$tmp" "$target"
    rm -f "$tmp"
    return 0
}

hf_waterline_alerts_install() {
    hf_root_check
    hf_requires notifiers   # alert interface must exist before we schedule trips
    sudo mkdir -p "$HF_LIB" "$HF_ETC" "$HF_STATE" /var/log/honeyfleet
    hf_read_thresholds
    local dirty=0 rendered svc timer
    rendered=$(hf_render_check | sed "s/@@DISK@@/$DISK/; s/@@MEM@@/$MEM/; s/@@SWAP@@/$SWAP/; s/@@COOL@@/$COOL/")
    hf_install_if_changed "$rendered" "$CHECK_SCRIPT" 0755 && { hf_log "$MOD: check script deployed ($CHECK_SCRIPT)"; dirty=1; }
    svc="[Unit]
Description=honeyfleet waterline alerts (disk/mem/swap thresholds)
[Service]
Type=oneshot
ExecStart=$CHECK_SCRIPT"
    timer="[Unit]
Description=Run waterline check every $INTERVAL_MIN minute(s)
[Timer]
OnBootSec=2min
OnUnitActiveSec=${INTERVAL_MIN}min
Persistent=true
[Install]
WantedBy=timers.target"
    hf_install_if_changed "$svc" "$UNIT_SERVICE_PATH" 0644 && { hf_log "$MOD: unit deployed ($UNIT_SERVICE)"; dirty=1; }
    hf_install_if_changed "$timer" "$UNIT_TIMER_PATH" 0644 && { hf_log "$MOD: unit deployed ($UNIT_TIMER)"; dirty=1; }
    if ! systemctl is-active --quiet "$UNIT_TIMER" 2>/dev/null; then
        sudo systemctl enable --now "$UNIT_TIMER"
        dirty=1
    fi
    hf_registry 1 "$MOD"
    if [ "$dirty" = 0 ]; then
        hf_log "$MOD: already consistent — NO-OP (3 metrics monitored, every ${INTERVAL_MIN}m)"
    else
        hf_log "$MOD: installed (3 metrics monitored: disk>=$DISK% mem<$MEM% swap>$SWAP%, every ${INTERVAL_MIN}m, cooldown ${COOL}s)"
    fi
}

hf_waterline_alerts_verify() {
    hf_root_check
    hf_read_thresholds
    local rc=0 fails="" sd sm ss sc
    systemctl is-active --quiet "$UNIT_TIMER" 2>/dev/null || fails="$fails timer-not-active"
    [ -x "$CHECK_SCRIPT" ] || fails="$fails check-script-missing"
    sd=$(sudo sed -n 's/^DISK_LIMIT=\([0-9]*\).*/\1/p' "$CHECK_SCRIPT" 2>/dev/null)
    sm=$(sudo sed -n 's/^MEM_LIMIT=\([0-9]*\).*/\1/p' "$CHECK_SCRIPT" 2>/dev/null)
    ss=$(sudo sed -n 's/^SWAP_LIMIT=\([0-9]*\).*/\1/p' "$CHECK_SCRIPT" 2>/dev/null)
    sc=$(sudo sed -n 's/^COOLDOWN_S=\([0-9]*\).*/\1/p' "$CHECK_SCRIPT" 2>/dev/null)
    [ "$sd" = "$DISK" ] || fails="$fails script-disk($sd)!=config($DISK)"
    [ "$sm" = "$MEM" ] || fails="$fails script-mem($sm)!=config($MEM)"
    [ "$ss" = "$SWAP" ] || fails="$fails script-swap($ss)!=config($SWAP)"
    [ "$sc" = "$COOL" ] || fails="$fails script-cooldown($sc)!=config($COOL)"
    sudo grep -q "^ExecStart=$CHECK_SCRIPT\$" "$UNIT_SERVICE_PATH" 2>/dev/null || fails="$fails service-ExecStart-mismatch"
    grep -q 'hf_mod_notifiers_installed=1' "$HF_STATE/registry" 2>/dev/null || fails="$fails dependency-notifiers-not-installed"
    [ -r "$HF_LIB/notify.sh" ] && grep -q 'hf_notify' "$HF_LIB/notify.sh" 2>/dev/null || fails="$fails notify-interface-missing($HF_LIB/notify.sh)"
    if [ -z "$fails" ]; then
        hf_log "$MOD: verify PASS (timer=active disk>=$DISK mem<$MEM swap>$SWAP cooldown=${COOL}s thresholds==config)"
    else
        hf_warn "$MOD: verify FAIL ($fails)"
        rc=1
    fi
    return $rc
}

hf_waterline_alerts_status() {
    local t alerts
    t=$(systemctl is-active "$UNIT_TIMER" 2>/dev/null || echo unknown)
    alerts=$(grep -c ' ALERT ' /var/log/honeyfleet/waterline.log 2>/dev/null) || alerts=0
    printf '%s: timer=%s thresholds="disk>=%s%% mem<%s%% swap>%s%%" alerts_logged=%s log=%s\n' \
        "$MOD" "$t" "$(hf_conf WATERLINE_DISK 80)" "$(hf_conf WATERLINE_MEM 20)" "$(hf_conf WATERLINE_SWAP 50)" \
        "$alerts" /var/log/honeyfleet/waterline.log
}

hf_waterline_alerts_remove() {
    hf_root_check
    sudo systemctl disable --now "$UNIT_TIMER" 2>/dev/null || true
    hf_backup "$UNIT_SERVICE_PATH" 2>/dev/null
    hf_backup "$UNIT_TIMER_PATH" 2>/dev/null
    sudo rm -f "$UNIT_SERVICE_PATH" "$UNIT_TIMER_PATH" "$CHECK_SCRIPT"
    sudo systemctl daemon-reload
    hf_registry 0 "$MOD"
    hf_log "$MOD: removed (state kept for forensics: $HF_STATE/waterline.state, $HF_STATE/backups)"
}

case "${1:-}" in
    install) hf_waterline_alerts_install ;;
    verify)  hf_waterline_alerts_verify ;;
    status)  hf_waterline_alerts_status ;;
    remove|uninstall) hf_waterline_alerts_remove ;;
    *) hf_die "usage: waterline-alerts.sh install|verify|status|remove" ;;
esac
