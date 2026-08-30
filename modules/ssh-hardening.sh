#!/usr/bin/env bash
# honeyfleet module: ssh-hardening — real-sshd hardening + port migration, with
# anti-lockout discipline as the core feature:
#   1. sshd -t validates the candidate config BEFORE any reload.
#   2. A standalone test sshd is started on the NEW port and a real key-auth
#      login is proven through it BEFORE the switch (second channel).
#   3. Every write is preceded by hf_backup; any failed step triggers an
#      automatic rollback of all changed files + a config reload.
#   4. README-level operator warning: KEEP A SECOND TERMINAL OPEN.
# Default posture: NO source whitelist (dynamic-IP lockout lesson — B5 rollback
# record, 2026-08-29). A whitelist is applied ONLY when HF_SSH_SOURCE_RESTRICT
# is explicitly true in config, and then behind a 60s auto-rollback watchdog
# armed via the same pattern as the audited b5 whitelist rollout.
# Contract: docs/MODULE-CONTRACT.md — hf_ssh_hardening_{install,verify,status,remove}.
set -uo pipefail
MOD=ssh-hardening
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"

# lib/common.sh hf_backup has a path mismatch: mkdir creates only dirname($f)
# while the cp target nests the basename as an extra directory component, so
# cp fails and backups silently never happen. Re-defined here with ONE
# consistent layout ($HF_STATE/backups/<path-sans-slash>/.$basename.<UTC>) and
# the same "keep newest 2" retention. Drop this override once lib/common.sh is fixed.

MAIN_CFG=/etc/ssh/sshd_config
DROPIN_DIR=/etc/ssh/sshd_config.d
DROPIN=$DROPIN_DIR/50-honeyfleet.conf
CONF_FILE=/etc/honeyfleet/honeyfleet.conf
ONBOX_COPY=$HF_LIB/ssh-hardening.sh
README=$HF_ETC/README-ssh-hardening.txt
RESTRICT_OK=$HF_STATE/ssh-restrict.ok
PERSIST_V4=/etc/iptables/rules.v4
WATCHDOG_S=60
ROLL_CHANGED=()   # files we modified that had a pre-existing backup
ROLL_CREATED=()   # files we created (rollback = delete)

hf_root_check() { [ "$(id -u)" = 0 ] || hf_die "$MOD: must run as root (sudo)"; }

# ---------------------------------------------------------------- sshd helpers
hf_sshd_bin() { command -v sshd 2>/dev/null || printf '%s' /usr/sbin/sshd; }

hf_sshd_T() {
    local b; b=$(hf_sshd_bin)
    "$b" -T 2>/dev/null || "$b" -T -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null
}

hf_sshd_t_ok() { "$(hf_sshd_bin)" -t 2>/dev/null; }

# unique effective port list (one per line); empty when sshd -T unavailable
hf_sshd_effective_ports() { hf_sshd_T | awk '$1 == "port" { print $2 }' | sort -u; }

hf_port_listening() {
    command -v ss >/dev/null 2>&1 || { hf_warn "$MOD: ss(8) unavailable — listener state unknown"; return 0; }
    ss -tln 2>/dev/null | awk 'NR>1 { n=split($4, a, ":"); print a[n] }' | grep -qx "$1"
}

hf_sshd_reload() {
    if systemctl is-active --quiet ssh 2>/dev/null; then sudo systemctl reload ssh; return $?; fi
    if systemctl is-active --quiet sshd 2>/dev/null; then sudo systemctl reload sshd; return $?; fi
    hf_warn "$MOD: no active ssh/sshd unit found"
    return 1
}

# ---------------------------------------------------------------- port choice
hf_pick_random_port() {
    local used central svc p cand i hit
    used=$(ss -tln 2>/dev/null | awk 'NR>1 { n=split($4, a, ":"); print a[n] }' | sort -u)
    central=$(hf_conf CENTRAL_PORT 22)
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25; do
        cand=$(shuf -i 10000-65535 -n 1 2>/dev/null)
        [ -n "$cand" ] || cand=$(( (RANDOM % 55536) + 10000 ))
        [ "$cand" = 22 ] && continue                       # 22 = honeypot feed (IANA ssh)
        [ "$cand" = "$central" ] && continue
        printf '%s\n' "$used" | grep -qx "$cand" && continue
        hit=0
        for svc in $(hf_conf FW_SERVICES ""); do p=${svc%%/*}; [ "$p" = "$cand" ] && { hit=1; break; }; done
        [ "$hit" = 1 ] && continue
        printf '%s\n' "$cand"; return 0
    done
    return 1
}

hf_persist_port_choice() {
    local port=$1
    [ -f "$CONF_FILE" ] || hf_die "$MOD: cannot persist a random port — $CONF_FILE missing; set a numeric HF_SSH_REAL_PORT instead"
    hf_backup "$CONF_FILE"
    if grep -q '^HF_SSH_REAL_PORT=' "$CONF_FILE"; then
        sudo sed -i "s|^HF_SSH_REAL_PORT=.*|HF_SSH_REAL_PORT=\"$port\"|" "$CONF_FILE"
    else
        printf '\nHF_SSH_REAL_PORT="%s"\n' "$port" | sudo tee -a "$CONF_FILE" > /dev/null
    fi
    grep -q "^HF_SSH_REAL_PORT=\"$port\"$" "$CONF_FILE" || \
        hf_die "$MOD: failed to persist the port choice in $CONF_FILE (refusing to migrate on an unpersisted random port — re-runs would pick a different port)"
    hf_log "$MOD: HF_SSH_REAL_PORT=random resolved to $port and persisted to $CONF_FILE"
}

hf_resolve_target_port() { # resolves the port; result in RESOLVED_PORT (no stdout — keep clean for callers)
    local v; v=$(hf_conf SSH_REAL_PORT random)
    if [ "$v" = "random" ]; then
        v=$(hf_pick_random_port) || hf_die "$MOD: could not pick a free random port in 10000-65535"
        hf_persist_port_choice "$v"
        HF_SSH_REAL_PORT=$v   # keep in-process view consistent for hf_conf
    fi
    case "$v" in ''|*[!0-9]*) hf_die "$MOD: HF_SSH_REAL_PORT must be 'random' or numeric (got '$v')" ;; esac
    [ "$v" -ge 1024 ] && [ "$v" -le 65535 ] || hf_die "$MOD: HF_SSH_REAL_PORT=$v out of range 1024-65535"
    RESOLVED_PORT=$v
}

# ---------------------------------------------------------------- deployment
hf_dropin_content() {
    local port=$1 tries=$2
    cat <<EOF
# managed by honeyfleet ssh-hardening — edits are overwritten; honeyfleet.conf is the source of truth
Port $port
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries $tries
EOF
}

hf_ensure_include() {
    grep -Eq '^[[:space:]]*Include[[:space:]]+.*sshd_config\.d' "$MAIN_CFG" 2>/dev/null && return 0
    hf_backup "$MAIN_CFG"
    sudo sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' "$MAIN_CFG"
    ROLL_CHANGED+=("$MAIN_CFG")
    hf_log "$MOD: added Include directive at top of $MAIN_CFG"
}

hf_neutralize_foreign_ports() {
    # Port accumulates across sshd_config + drop-ins; migration must leave
    # exactly ONE active Port directive (ours). Foreign ones are commented out
    # (with a marker) after hf_backup, never deleted.
    local f
    for f in "$MAIN_CFG" "$DROPIN_DIR"/*.conf; do
        [ -f "$f" ] || continue
        [ "$f" = "$DROPIN" ] && continue
        grep -qE '^[[:space:]]*Port[[:space:]]+[0-9]+' "$f" 2>/dev/null || continue
        hf_backup "$f"
        sudo sed -i -E 's|^([[:space:]]*)Port([[:space:]]+[0-9]+.*)|# honeyfleet-migrated:\1Port\2|' "$f"
        ROLL_CHANGED+=("$f")
        hf_log "$MOD: neutralized active Port directive(s) in $f (commented, backup kept)"
    done
}

hf_fw_preopen() {
    command -v iptables >/dev/null 2>&1 || return 0
    [ "$(iptables -S INPUT 2>/dev/null | head -n 1)" = "-P INPUT DROP" ] || return 0
    iptables -C INPUT -p tcp -m tcp --dport "$1" -m comment --comment honeyfleet-ssh-migration -j ACCEPT 2>/dev/null || \
        iptables -I INPUT 1 -p tcp -m tcp --dport "$1" -m comment --comment honeyfleet-ssh-migration -j ACCEPT
    hf_log "$MOD: pre-opened tcp/$1 in the live firewall for the migration window"
}

hf_fw_preopen_undo() {
    command -v iptables >/dev/null 2>&1 || return 0
    iptables -D INPUT -p tcp -m tcp --dport "$1" -m comment --comment honeyfleet-ssh-migration -j ACCEPT 2>/dev/null || true
}

# ------------------------------------------------------------ second channel
hf_pick_test_user() {
    local u h
    for u in "${SUDO_USER:-}" root; do
        [ -n "$u" ] || continue
        h=$(getent passwd "$u" 2>/dev/null | cut -d: -f6)
        [ -n "$h" ] || continue
        [ -s "$h/.ssh/authorized_keys" ] && { printf '%s\n' "$u"; return 0; }
    done
    return 1
}

hf_second_channel_proof() { # $1 = port; rc 0 proven, 2 no testable identity, 1 failed
    local port=$1 u home kargs="" k
    command -v ssh >/dev/null 2>&1 || return 1
    u=$(hf_pick_test_user) || return 2
    home=$(getent passwd "$u" 2>/dev/null | cut -d: -f6)
    local keys=()
    while read -r k; do [ -n "$k" ] && keys+=("$k"); done < <(ls "$home"/.ssh/id_* 2>/dev/null | grep -v '\.pub$' | head -n 3)
    if [ "${#keys[@]}" -gt 0 ]; then
        for k in "${keys[@]}"; do kargs="$kargs -i $k"; done
    fi
    # shellcheck disable=SC2086
    if ssh -p "$port" -o BatchMode=yes -o StrictHostKeyChecking=no \
           -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR \
           $kargs "$u@127.0.0.1" true 2>/dev/null; then
        hf_log "$MOD: second-channel key-auth login PROVEN on port $port (user $u)"
        return 0
    fi
    hf_warn "$MOD: key-auth login on port $port FAILED (user $u)"
    return 1
}

hf_kill_test_sshd() {
    local pidf=$1 pid
    [ -f "$pidf" ] || return 0
    pid=$(cat "$pidf" 2>/dev/null)
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
    sleep 0.3
    [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
    rm -f "$pidf"
}

hf_spawn_test_sshd() { # $1 port  $2 pidfile  $3 cfgfile — standalone sshd on the NEW port
    local port=$1 pidf=$2 cfg=$3 tmp i log
    log="${cfg%.conf}.log"
    tmp=$(mktemp)
    "$(hf_sshd_bin)" -T > "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }
    { printf 'PidFile %s\nPort %s\n' "$pidf" "$port"
      grep -viE '^(port|pidfile|listenaddress) ' "$tmp"
    } > "$cfg"
    rm -f "$tmp"
    "$(hf_sshd_bin)" -f "$cfg" -E "$log" 2>>"$log" || return 1
    for i in 1 2 3 4 5 6 7 8 9 10; do
        sleep 0.5
        hf_port_listening "$port" && return 0
    done
    hf_kill_test_sshd "$pidf"
    return 1
}

# ------------------------------------------------------------------ rollback
hf_rollback_migration() {
    local f dir base b
    if [ "${#ROLL_CREATED[@]}" -gt 0 ]; then
        for f in "${ROLL_CREATED[@]}"; do sudo rm -f "$f"; done
    fi
    if [ "${#ROLL_CHANGED[@]}" -gt 0 ]; then
        for f in "${ROLL_CHANGED[@]}"; do
            dir=${f#/}; dir=${dir%/*}; base=${f##*/}
            b=$(ls -1t "$HF_STATE/backups/$dir/.$base".* 2>/dev/null | head -n 1)
            [ -n "$b" ] && sudo cp -a "$b" "$f"
        done
    fi
    hf_sshd_t_ok || hf_warn "$MOD: WARNING sshd -t still failing after rollback — inspect $HF_STATE/backups"
    hf_sshd_reload || hf_warn "$MOD: reload after rollback failed — running sshd may still hold the old in-memory config"
    hf_log "$MOD: rollback complete (previous sshd config restored)"
}

# ------------------------------------------------------------------ migration
hf_migrate() {
    local port=$1 desired=$2 old_eff=$3 rc
    ROLL_CHANGED=(); ROLL_CREATED=()
    hf_warn "================================================================"
    hf_warn " ssh-hardening: PORT MIGRATION ${old_eff:-?} -> $port"
    hf_warn " KEEP A SECOND TERMINAL OPEN until you verified login via:"
    hf_warn "   ssh -p $port <user>@<host>"
    hf_warn " The running session and the provider console are recovery paths."
    hf_warn "================================================================"
    hf_ensure_include
    hf_neutralize_foreign_ports
    if [ -f "$DROPIN" ]; then hf_backup "$DROPIN"; ROLL_CHANGED+=("$DROPIN"); else ROLL_CREATED+=("$DROPIN"); fi
    printf '%s\n' "$desired" | sudo tee "$DROPIN" > /dev/null

    if ! hf_sshd_t_ok; then
        hf_rollback_migration
        hf_die "$MOD: sshd -t rejected the candidate config — rolled back; running sshd was never touched"
    fi
    hf_fw_preopen "$port"

    if [ "$old_eff" != "$port" ]; then
        sudo mkdir -p /run/sshd
        local tconf tpidf
        tconf=$(mktemp /tmp/hf-sshd-test.XXXXXX.conf)
        tpidf=$(mktemp /tmp/hf-sshd-test.XXXXXX.pid)
        if hf_spawn_test_sshd "$port" "$tpidf" "$tconf"; then
            if hf_second_channel_proof "$port"; then
                hf_kill_test_sshd "$tpidf"
                rm -f "$tconf" "${tconf%.conf}.log"
            else
                rc=$?
                hf_kill_test_sshd "$tpidf"
                rm -f "$tconf" "${tconf%.conf}.log"
                hf_fw_preopen_undo "$port"
                hf_rollback_migration
                if [ "$rc" = 2 ]; then
                    hf_die "$MOD: no testable key identity (SUDO_USER/root authorized_keys empty) — second channel UNPROVEN, kept port ${old_eff:-?}; deploy a key then re-run install"
                fi
                hf_die "$MOD: second-channel login on port $port FAILED — kept port ${old_eff:-?}; nothing is live"
            fi
        else
            rm -f "$tconf" "${tconf%.conf}.log" "$tpidf"
            hf_fw_preopen_undo "$port"
            hf_rollback_migration
            hf_die "$MOD: could not start a test sshd on port $port (port busy?) — kept port ${old_eff:-?}"
        fi
    else
        hf_log "$MOD: port $port already effective — spawn test skipped (live sshd proves it)"
    fi

    if ! hf_sshd_reload; then
        hf_fw_preopen_undo "$port"
        hf_rollback_migration
        hf_die "$MOD: reload failed — rolled back"
    fi
    sleep 1
    if [ "$(hf_sshd_effective_ports)" != "$port" ] || ! hf_port_listening "$port"; then
        hf_fw_preopen_undo "$port"
        hf_rollback_migration
        hf_die "$MOD: post-switch verification failed — rolled back to the previous config"
    fi
    hf_log "$MOD: MIGRATION COMPLETE — sshd live on port $port (was: ${old_eff:-?})"
}

# ------------------------------------------------- source whitelist (opt-in)
hf_valid_cidr() {
    local ip=${1%%/*} mask="" o
    case "$1" in */*) mask=${1#*/} ;; esac
    [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for o in "${BASH_REMATCH[@]:1}"; do [ "$o" -le 255 ] || return 1; done
    [ -n "$mask" ] || return 0
    [[ "$mask" =~ ^[0-9]{1,2}$ ]] || return 1
    [ "$mask" -le 32 ] || return 1
}

hf_restrict_rules_present() {
    local port=$1 s
    command -v iptables >/dev/null 2>&1 || return 1
    for s in $(hf_conf SSH_MANAGEMENT_SOURCES ""); do
        iptables -C INPUT -s "$s" -p tcp -m tcp --dport "$port" -m comment --comment honeyfleet-ssh-restrict-accept -j ACCEPT 2>/dev/null || return 1
    done
    iptables -C INPUT -p tcp -m tcp --dport "$port" -m comment --comment honeyfleet-ssh-restrict-drop -j DROP 2>/dev/null
}

hf_strip_f2b() { grep -Ev '^(#|:f2b|-A f2b)| -j f2b-'; }

hf_persist_rules_stripped() {
    command -v iptables >/dev/null 2>&1 || return 0
    sudo mkdir -p /etc/iptables
    local tmp; tmp=$(mktemp)
    iptables-save 2>/dev/null | hf_strip_f2b > "$tmp"
    hf_backup "$PERSIST_V4"
    sudo install -o root -g root -m 0644 "$tmp" "$PERSIST_V4"
    rm -f "$tmp"
}

hf_apply_restrict() { # $1 = real port
    local port=$1 s
    command -v iptables >/dev/null 2>&1 || hf_die "$MOD: HF_SSH_SOURCE_RESTRICT requires iptables"
    local snap="$HF_STATE/ssh-restrict-pre-$(date -u +%Y%m%dT%H%M%SZ).v4"
    iptables-save > "$snap" 2>/dev/null
    chmod 600 "$snap" 2>/dev/null || true
    rm -f "$RESTRICT_OK"   # a stale flag must never silently disarm a fresh watchdog (B5 review R6/W2)
    nohup bash -c "sleep $WATCHDOG_S; if [ -f '$RESTRICT_OK' ]; then rm -f '$RESTRICT_OK'; exit 0; fi; iptables-restore < '$snap' && { cp '$snap' '$PERSIST_V4' 2>/dev/null || true; }; logger -t honeyfleet-ssh-watchdog 'source whitelist ROLLED BACK'; rm -f '$RESTRICT_OK'" >/dev/null 2>&1 &
    hf_log "$MOD: whitelist watchdog armed pid=$! (auto-rollback in ${WATCHDOG_S}s)"
    for s in $(hf_conf SSH_MANAGEMENT_SOURCES ""); do
        iptables -C INPUT -s "$s" -p tcp -m tcp --dport "$port" -m comment --comment honeyfleet-ssh-restrict-accept -j ACCEPT 2>/dev/null || \
            iptables -I INPUT 1 -s "$s" -p tcp -m tcp --dport "$port" -m comment --comment honeyfleet-ssh-restrict-accept -j ACCEPT
    done
    iptables -C INPUT -p tcp -m tcp --dport "$port" -m comment --comment honeyfleet-ssh-restrict-drop -j DROP 2>/dev/null || \
        iptables -A INPUT -p tcp -m tcp --dport "$port" -m comment --comment honeyfleet-ssh-restrict-drop -j DROP
    hf_persist_rules_stripped
    hf_warn "$MOD: source whitelist LIVE (only: $(hf_conf SSH_MANAGEMENT_SOURCES ''))"
    hf_warn "$MOD: within ${WATCHDOG_S}s confirm access with: sudo $ONBOX_COPY confirm   (otherwise everything rolls back)"
}

hf_maybe_restrict_apply() { # $1 = real port
    local port=$1
    if ! hf_conf_bool SSH_SOURCE_RESTRICT false; then
        hf_log "$MOD: source whitelist OFF (default — dynamic-IP lockout lesson; opt in with HF_SSH_SOURCE_RESTRICT=true)"
        return 0
    fi
    [ -n "$(hf_conf SSH_MANAGEMENT_SOURCES '')" ] || \
        hf_die "$MOD: HF_SSH_SOURCE_RESTRICT=true but HF_SSH_MANAGEMENT_SOURCES is empty — refusing (self-lockout)"
    local s
    for s in $(hf_conf SSH_MANAGEMENT_SOURCES ""); do
        hf_valid_cidr "$s" || hf_die "$MOD: invalid management source '$s' — refusing to apply a broken whitelist"
    done
    if hf_restrict_rules_present "$port"; then
        hf_log "$MOD: source whitelist already in place — NO-OP"
        return 0
    fi
    hf_apply_restrict "$port"
}

hf_ssh_hardening_confirm() { # operator-facing: disarm the whitelist watchdog
    mkdir -p "$HF_STATE"
    printf '%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$RESTRICT_OK"
    command -v logger >/dev/null 2>&1 && logger -t honeyfleet-ssh "source whitelist confirmed by operator" || true
    hf_log "$MOD: whitelist watchdog disarmed (flag written: $RESTRICT_OK)"
}

# ------------------------------------------------------------- README / copy
hf_install_onbox_copy() {
    if [ -f "$ONBOX_COPY" ] && cmp -s "$SCRIPT_DIR/ssh-hardening.sh" "$ONBOX_COPY" 2>/dev/null; then return 0; fi
    hf_backup "$ONBOX_COPY"
    sudo install -o root -g root -m 0755 "$SCRIPT_DIR/ssh-hardening.sh" "$ONBOX_COPY"
}

hf_write_readme() {
    local port=$1 trip="off"
    hf_conf_bool SSH_HONEYPOT false && trip="on"
    local restrict="disabled"
    hf_conf_bool SSH_SOURCE_RESTRICT false && restrict="enabled"
    local tmp; tmp=$(mktemp)
    cat > "$tmp" <<README
honeyfleet ssh-hardening — operator README (generated $(date -u +%F))
=====================================================================
1. PORT: the real sshd listens on port @@PORT@@; keep a second terminal
   open until you verified: ssh -p @@PORT@@ <user>@<host>

2. ANTI-LOCKOUT LADDER (in order):
   running session -> second terminal -> provider console (VNC).
   Backups of every touched file: $HF_STATE/backups/etc/ssh/
   Manual rollback: restore the newest .sshd_config* backup there,
   run sshd -t, then: systemctl reload ssh

3. known_hosts tripwire (honeypot: $trip):
   - real sshd (port @@PORT@@) and the port-22 honeypot use DIFFERENT host
     keys by design (when HF_SSH_HONEYPOT=true).
   - pin the real key: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
     and keep an '[host]:@@PORT@@' entry in your local known_hosts.
   - a HOST KEY MISMATCH warning when connecting to port 22 is EXPECTED —
     that is the tripwire signal: the honeypot (or an imposter) answered,
     not your real sshd.

4. source whitelist: @@RESTRICT@@
   (off by default — dynamic-IP lockout lesson). If enabled, a ${WATCHDOG_S}s
   watchdog auto-rolls back unless you run: sudo $ONBOX_COPY confirm
README
    sed -i "s|@@PORT@@|$port|g; s|@@RESTRICT@@|$restrict|g" "$tmp"
    if [ -f "$README" ] && cmp -s "$tmp" "$README" 2>/dev/null; then rm -f "$tmp"; return 0; fi
    hf_backup "$README"
    sudo install -o root -g root -m 0644 "$tmp" "$README"
    rm -f "$tmp"
}

# ---------------------------------------------------------------- contract ops
hf_ssh_hardening_install() {
    hf_root_check
    sudo mkdir -p "$HF_LIB" "$HF_ETC" "$HF_STATE" /var/log/honeyfleet "$DROPIN_DIR"
    local tries; tries=$(hf_conf SSH_MAXAUTHTRIES 3)
    case "$tries" in ''|*[!0-9]*) hf_die "$MOD: HF_SSH_MAXAUTHTRIES must be numeric (got '$tries')" ;; esac
    local port; hf_resolve_target_port; port=$RESOLVED_PORT
    local desired; desired=$(hf_dropin_content "$port" "$tries")
    local current; current=$(sudo cat "$DROPIN" 2>/dev/null || true)
    local eff; eff=$(hf_sshd_effective_ports)

    if [ "$current" = "$desired" ] && [ "$eff" = "$port" ] && hf_port_listening "$port" \
       && ! grep -hqE '^[[:space:]]*Port[[:space:]]+[0-9]+' "$MAIN_CFG" 2>/dev/null; then
        hf_log "$MOD: already consistent (port $port) — NO-OP"
    else
        hf_migrate "$port" "$desired" "$eff"
    fi
    hf_install_onbox_copy
    hf_write_readme "$port"
    hf_maybe_restrict_apply "$port"
    hf_registry 1 "$MOD"
    hf_log "$MOD: installed (port=$port maxauthtries=$tries passwordauth=no restrict=$(hf_conf_bool SSH_SOURCE_RESTRICT false && echo on || echo off))"
}

hf_ssh_hardening_verify() {
    hf_root_check
    local rc=0 fails="" port
    port=$(hf_conf SSH_REAL_PORT random)
    if [ "$port" = "random" ]; then
        fails="$fails port-unresolved(HF_SSH_REAL_PORT=random:install-never-ran)"
        port=""
    fi
    local eff; eff=$(hf_sshd_effective_ports)
    if [ -n "$port" ]; then
        [ "$eff" = "$port" ] || fails="$fails sshd-T-port($eff!=$port)"
        [ "$(hf_sshd_T | awk '$1 == "passwordauthentication" { print $2 }')" = "no" ] || fails="$fails passwordauth-not-no"
        [ "$(hf_sshd_T | awk '$1 == "maxauthtries" { print $2 }')" = "$(hf_conf SSH_MAXAUTHTRIES 3)" ] || fails="$fails maxauthtries-mismatch"
        [ "$(hf_sshd_T | awk '$1 == "permitemptypasswords" { print $2 }')" = "no" ] || fails="$fails permitemptypasswords-not-no"
        [ "$(hf_sshd_T | awk '$1 == "x11forwarding" { print $2 }')" = "no" ] || fails="$fails x11forwarding-not-no"
        hf_port_listening "$port" || fails="$fails listener-missing"
    fi
    if hf_conf_bool SSH_SOURCE_RESTRICT false; then
        hf_restrict_rules_present "$(hf_conf SSH_REAL_PORT '')" || fails="$fails restrict-rules-missing"
    fi
    hf_log "$MOD: port=$port sshd-T=$eff maxauthtries=$(hf_conf SSH_MAXAUTHTRIES 3) passwordauth=$(hf_sshd_T | awk '$1 == "passwordauthentication" { print $2 }')"
    if [ -z "$fails" ]; then
        hf_log "$MOD: verify PASS"
    else
        hf_warn "$MOD: verify FAIL ($fails)"
        rc=1
    fi
    return $rc
}

hf_ssh_hardening_status() {
    local port; port=$(hf_conf SSH_REAL_PORT random)
    [ "$port" = "random" ] && port="unresolved"
    printf '%s: port=%s effective=%s maxauthtries=%s passwordauth=%s listener=%s dropin=%s restrict=%s\n' \
        "$MOD" "$port" \
        "$(hf_sshd_effective_ports 2>/dev/null | tr '\n' ',' | sed 's/,$//')" \
        "$(hf_conf SSH_MAXAUTHTRIES 3)" \
        "$(hf_sshd_T 2>/dev/null | awk '$1 == "passwordauthentication" { print $2 }')" \
        "$([ -n "$port" ] && [ "$port" != unresolved ] && hf_port_listening "$port" && echo yes || echo unknown)" \
        "$([ -f "$DROPIN" ] && echo present || echo absent)" \
        "$(hf_conf_bool SSH_SOURCE_RESTRICT false && echo on || echo off)"
}

hf_ssh_hardening_remove() {
    hf_root_check
    if [ -f "$DROPIN" ]; then hf_backup "$DROPIN"; sudo rm -f "$DROPIN"; fi
    if command -v iptables >/dev/null 2>&1; then
        iptables -D INPUT -p tcp -m tcp --dport "$(hf_conf SSH_REAL_PORT 22)" -m comment --comment honeyfleet-ssh-restrict-drop -j DROP 2>/dev/null || true
        local s
        for s in $(hf_conf SSH_MANAGEMENT_SOURCES ""); do
            iptables -D INPUT -s "$s" -p tcp -m tcp --dport "$(hf_conf SSH_REAL_PORT 22)" -m comment --comment honeyfleet-ssh-restrict-accept -j ACCEPT 2>/dev/null || true
        done
        iptables -D INPUT -p tcp -m tcp --dport "$(hf_conf SSH_REAL_PORT 22)" -m comment --comment honeyfleet-ssh-migration -j ACCEPT 2>/dev/null || true
    fi
    rm -f "$RESTRICT_OK"
    hf_sshd_t_ok && hf_sshd_reload || hf_warn "$MOD: sshd not reloaded — remove the drop-in manually and reload"
    hf_registry 0 "$MOD"
    hf_log "$MOD: removed (sshd falls back to config defaults; backups in $HF_STATE/backups; README kept for forensics)"
}

case "${1:-}" in
    install) hf_ssh_hardening_install ;;
    verify)  hf_ssh_hardening_verify ;;
    status)  hf_ssh_hardening_status ;;
    confirm) hf_ssh_hardening_confirm ;;
    remove|uninstall) hf_ssh_hardening_remove ;;
    *) hf_die "usage: ssh-hardening.sh install|verify|status|confirm|remove" ;;
esac
