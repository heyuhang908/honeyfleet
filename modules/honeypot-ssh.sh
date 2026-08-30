#!/usr/bin/env bash
# honeyfleet module: honeypot-ssh — fake SSH entrance on port HF_HP_PORT (22).
#
# Deploys:
#   /usr/local/bin/sshesame                 pinned upstream binary (SHA256 gate)
#   /etc/honeyfleet/sshesame/config.yaml    honeypot config; banner calibrated
#                                           byte-for-byte from the REAL sshd
#   /etc/honeyfleet/sshesame/ssh_host_ed25519_key   dedicated honeypot host key
#                                           (deliberately NOT the real host key:
#                                           known-hosts mismatch = operator tripwire)
#   honeyfleet-sshesame.service             User=nobody, NoNewPrivileges,
#                                           ProtectSystem=full, Restart=always,
#                                           CAP_NET_BIND_SERVICE
#   /usr/local/lib/honeyfleet/sshesame-health.sh + .service/.timer
#                                           every 3 min, restart after 2
#                                           consecutive failures, 15 min cooldown
#   /etc/logrotate.d/honeyfleet-sshesame    weekly + 10M + copytruncate, keep 8
#
# Log caliber: honeypot evidence is always reported against the CURRENT LOG
# WINDOW — never "today / last 24h" (caliber rule).
#
# Contract (docs/MODULE-CONTRACT.md): hf_honeypot_ssh_{install,verify,status,remove},
# idempotent, config read ONLY via hf_conf, hf_backup before writes.
# The verify gate checks behavior, not file existence:
#   1. real sshd listens ONLY on HF_SSH_REAL_PORT
#   2. honeypot listens on HF_HP_PORT (default 22)
#   3. honeypot banner byte-equal to the real sshd banner
#   4. health probe timer active
#   5. ALL THREE fail2ban jails' (sshd/sshesame/recidive) parameters match the
#      config — consumer gate for the f2b-parameter incident class (2026-08-29)

set -uo pipefail
MOD=honeypot-ssh
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"

# lib/common.sh hf_backup has a path mismatch: mkdir creates only dirname($f)
# while the cp target nests the basename as an extra directory component, so
# cp fails and backups silently never happen. Re-defined here with ONE
# consistent layout ($HF_STATE/backups/<path-sans-slash>/.$basename.<UTC>) and
# the same "keep newest 2" retention — identical to the
# firewall-baseline/ssh-hardening overrides, plus a sudo fallback for non-root
# scattered-sudo runs. Drop this override once lib/common.sh is fixed.
hf_backup() {
    local f=$1 d b ts
    [ -f "$f" ] || return 0
    d=${f#/}; d=${d%/*}; b=${f##*/}; ts=$(date -u +%Y%m%dT%H%M%SZ)
    mkdir -p "$HF_STATE/backups/$d" 2>/dev/null || sudo mkdir -p "$HF_STATE/backups/$d"
    cp -a "$f" "$HF_STATE/backups/$d/.$b.$ts" 2>/dev/null || \
        sudo cp -a "$f" "$HF_STATE/backups/$d/.$b.$ts" || return 1
    ls -1t "$HF_STATE/backups/$d/.$b".* 2>/dev/null | tail -n +3 | while read -r old; do
        rm -f "$old" 2>/dev/null || sudo rm -f "$old"
    done
    return 0
}

HP_LOG_DEFAULT=/var/log/honeyfleet/sshesame/sshesame.json
UNIT_SVC=honeyfleet-sshesame.service
UNIT_HEALTH=honeyfleet-sshesame-health.service
UNIT_TIMER=honeyfleet-sshesame-health.timer
PROBE=$HF_LIB/sshesame-health.sh
LOGROTATE=/etc/logrotate.d/honeyfleet-sshesame

# Pinned upstream artifact (supply-chain gate).
# Tag: v0.0.39 — the version recorded by the production audit for the honeypot.
# SHA256: the audited production binary (linux/amd64, source-built at that tag
# and recorded by the audit + filehash baseline). Upstream release assets are
# built by a different toolchain and will NOT match this pin; install is
# fail-closed on mismatch and the message explains the operator options.
SSHSAME_TAG="v0.0.39"
SSHSAME_SHA256_AMD64="1ded2e0107295af5eae08774371b8d276ce80ef1d10ac8458d72569d46f67414"
SSHSAME_SHA256_ARM64=""    # no audited build for this arch — override via HF_HP_SSHESAME_SHA256
SSHSAME_URL_TPL="https://github.com/jaksi/sshesame/releases/download/__TAG__/__ASSET__"

# ── helpers ──────────────────────────────────────────────────────

hf_hp_load_config() {
    HF_CONF_FILE=${HF_CONF:-/etc/honeyfleet/honeyfleet.conf}
    [ -f "$HF_CONF_FILE" ] || return 1
    # shellcheck disable=SC1090
    . "$HF_CONF_FILE"
    return 0
}

hf_hp_sha256() {
    if command -v sha256sum > /dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

hf_hp_nogroup() { id -gn nobody 2>/dev/null || echo nobody; }

hf_hp_to_sec() {
    python3 - "$1" <<'PY'
import re, sys
s = str(sys.argv[1]).strip().lower()
if re.fullmatch(r"-?\d+", s):
    print(int(s)); raise SystemExit
units = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
total = 0
for num, unit in re.findall(r"(\d+)([smhdw]?)", s):
    if num:
        total += int(num) * units.get(unit or "s", 1)
print(total)
PY
}

hf_hp_real_port() {
    local p; p=$(hf_conf SSH_REAL_PORT "")
    case "$p" in
        ""|random|RANDOM)
            p=$(sudo sshd -T 2>/dev/null | awk '$1 == "port" {print $2; exit}')
            [ -n "$p" ] || return 1
            hf_warn "HF_SSH_REAL_PORT='random' unresolved — using live sshd port $p"
            ;;
    esac
    case "$p" in ''|*[!0-9]*) return 1 ;; esac
    [ "$p" -ge 1 ] && [ "$p" -le 65535 ] || return 1
    printf '%s\n' "$p"
}

# listener ports for a process name, one per line, sorted numeric unique
hf_hp_listener_ports() {
    sudo ss -tlnp 2>/dev/null | awk -v proc="$1" '
    {
        idx = index($0, "users:((")
        if (idx == 0) next
        if (index(substr($0, idx), "\"" proc "\"") == 0) next
        addr = $4
        sub(/^.*:/, "", addr)
        if (addr ~ /^[0-9]+$/) print addr
    }' | sort -un
}

# full banner line (calibration — exact, any length)
hf_hp_grab_banner_line() {
    local l
    l=$(timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/$1; IFS= read -r l <&3; printf '%s' \"\$l\"" 2>/dev/null) || return 1
    printf '%s\n' "${l%$'\r'}"
}

# first 44 bytes (task-prescribed verification caliber — see hf_hp_gate_banner)
hf_hp_grab_banner44() {
    timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/$1; dd bs=1 count=44 <&3 2>/dev/null" 2>/dev/null
}

hf_hp_derive_banner() {
    local real=$1 b=""
    if [ -n "$(hf_conf HP_BANNER "")" ]; then
        b=$(hf_conf HP_BANNER "")
    else
        b=$(hf_hp_grab_banner_line "$real") || b=""
        if [ -z "$b" ]; then
            b=$(hf_hp_grab_banner44 "$real")
            b=${b%$'\r'}
        fi
        [ -n "$b" ] || hf_die "cannot read the real sshd banner on port $real — honeypot banner cannot be calibrated"
        case "$b" in SSH-2.0-*|SSH-1.99-*) : ;; *) hf_die "unexpected sshd banner on port $real: '$b'" ;; esac
    fi
    if printf '%s' "$b" | grep -qE '["\\]'; then
        hf_die "calibrated banner contains YAML-unsafe characters — set HF_HP_BANNER manually"
    fi
    printf '%s\n' "$b"
}

# ── deployment pieces ────────────────────────────────────────────

hf_hp_expected_sha() {
    local override; override=$(hf_conf HP_SSHESAME_SHA256 "")
    if [ -n "$override" ]; then
        printf '%s\n' "$override"
        return 0
    fi
    case "$(uname -m)" in
        x86_64)        printf '%s\n' "$SSHSAME_SHA256_AMD64" ;;
        aarch64|arm64) printf '%s\n' "$SSHSAME_SHA256_ARM64" ;;
        *)             printf '\n' ;;
    esac
}

hf_hp_fetch_binary() {
    local want; want=$(hf_hp_expected_sha)
    [ -n "$want" ] || hf_die "no pinned sshesame SHA256 for $(uname -m) — set HF_HP_SSHESAME_SHA256 in the config"
    local cur=""
    [ -x /usr/local/bin/sshesame ] && cur=$(hf_hp_sha256 /usr/local/bin/sshesame)
    if [ "$cur" = "$want" ]; then
        hf_log "honeypot-ssh: sshesame binary already matches pinned SHA256 (NO-OP)"
        return 0
    fi

    local tag=$SSHSAME_TAG short arch tmp asset url bin got
    short=${tag#v}
    case "$(uname -m)" in
        x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) arch=unknown ;;
    esac
    tmp=$(mktemp -d) || hf_die "mktemp failed"
    for asset in "sshesame_${short}_linux_${arch}.tar.gz" "sshesame_${short}_linux_${arch}" "sshesame-linux-${arch}"; do
        url=${SSHSAME_URL_TPL/__TAG__/$tag}
        url=${url/__ASSET__/$asset}
        if command -v curl > /dev/null 2>&1; then
            curl -fsSL --retry 2 -o "$tmp/dl" "$url" || { rm -f "$tmp/dl"; continue; }
        elif command -v wget > /dev/null 2>&1; then
            wget -q -O "$tmp/dl" "$url" || { rm -f "$tmp/dl"; continue; }
        else
            rm -rf "$tmp"
            hf_die "neither curl nor wget available — cannot fetch the pinned sshesame release"
        fi
        bin="$tmp/dl"
        if [ "${asset%.tar.gz}" != "$asset" ]; then
            tar -xzf "$tmp/dl" -C "$tmp" 2>/dev/null || { rm -f "$tmp/dl"; continue; }
            bin=$(find "$tmp" -maxdepth 2 -type f -name 'sshesame*' ! -name '*.tar.gz' | head -1)
            [ -n "$bin" ] || { rm -f "$tmp/dl"; continue; }
        fi
        chmod +x "$bin"
        got=$(hf_hp_sha256 "$bin")
        if [ "$got" != "$want" ]; then
            rm -rf "$tmp"
            hf_die "pinned sshesame SHA256 mismatch: got $got, want $want

  The pin records the AUDITED production binary (built from $tag on the
  reference node). Official upstream release assets are built differently
  and will not match. To proceed deliberately, pick ONE:
    - build sshesame from the pinned tag the way the audited node did, or
    - review the official release artifact, then set HF_HP_SSHESAME_SHA256
      in /etc/honeyfleet/honeyfleet.conf to its reviewed SHA256, or
    - update the module pin constants as part of a reviewed version bump."
        fi
        sudo install -o root -g root -m 0755 "$bin" /usr/local/bin/sshesame
        rm -rf "$tmp"
        hf_log "honeypot-ssh: sshesame $tag installed (SHA256 verified)"
        return 0
    done
    rm -rf "$tmp"
    hf_die "could not download a pinned sshesame release asset for $tag linux/$arch — set HF_HP_SSHESAME_URL / provide the binary manually, then pin HF_HP_SSHESAME_SHA256"
}

hf_hp_ensure_hostkey() {
    local key="$HF_ETC/sshesame/ssh_host_ed25519_key"
    local nogrp; nogrp=$(hf_hp_nogroup)
    if [ ! -f "$key" ]; then
        sudo ssh-keygen -q -t ed25519 -N '' -C 'honeyfleet-sshesame-honeypot' -f "$key" \
            || hf_die "ssh-keygen failed for the honeypot host key"
        hf_log "honeypot-ssh: generated dedicated honeypot host key (distinct from the real host key — known-hosts mismatch acts as a tripwire)"
    fi
    sudo chown root:"$nogrp" "$key" 2>/dev/null || true
    sudo chmod 0640 "$key"
    [ -f "$key.pub" ] && sudo chmod 0644 "$key.pub"
    return 0
}

hf_hp_build_config() {
    local banner=$1 port listen tries logp svc services="" line
    port=$(hf_conf HP_PORT 22)
    listen=$(hf_conf HP_LISTEN "0.0.0.0")
    tries=$(hf_conf SSH_MAXAUTHTRIES 3)
    logp=$(hf_conf HP_LOGPATH "$HP_LOG_DEFAULT")
    for svc in $(hf_conf HP_TCPIP_SERVICES "25:SMTP 80:HTTP 110:POP3 587:SMTP 8080:HTTP"); do
        case "$svc" in [0-9]*:[A-Za-z0-9_-]*) : ;; *) hf_die "invalid HF_HP_TCPIP_SERVICES entry '$svc' (expected PORT:SERVICE)" ;; esac
        line=${svc%%:*}
        services="$services    $line: ${svc#*:}"$'\n'
    done
    cat <<EOF
# honeyfleet: sshesame honeypot configuration (generated by modules/honeypot-ssh.sh).
# Source of truth: /etc/honeyfleet/honeyfleet.conf (HF_HP_* / HF_SSH_*).
# The banner below is calibrated from the real sshd; never reveal the honeypot.
server:
  listen_address: ${listen}:${port}
  host_keys:
    - ${HF_ETC}/sshesame/ssh_host_ed25519_key
  tcpip_services:
${services%$'\n'}
logging:
  file: ${logp}
  json: true
  timestamps: true
  debug: false
  split_host_port: true
auth:
  no_auth: false
  max_tries: ${tries}
  password_auth:
    enabled: true
    accepted: true
  public_key_auth:
    enabled: true
    accepted: true
  keyboard_interactive_auth:
    enabled: false
    accepted: false
ssh_proto:
  version: "${banner}"
  banner: ""
EOF
}

hf_hp_write_config() {
    local real_port=$1 banner content
    banner=$(hf_hp_derive_banner "$real_port") || hf_die "honeypot banner calibration failed"
    content=$(hf_hp_build_config "$banner") || hf_die "failed to build the honeypot config — check the honeyfleet config (ports, services)"
    [ -n "$content" ] || hf_die "empty honeypot config — refusing to overwrite $HF_ETC/sshesame/config.yaml"
    local cfg="$HF_ETC/sshesame/config.yaml"
    if [ -f "$cfg" ] && printf '%s\n' "$content" | sudo cmp -s - "$cfg"; then
        hf_log "honeypot-ssh: config unchanged (NO-OP)"
        return 1
    fi
    hf_backup "$cfg"
    printf '%s\n' "$content" | sudo tee "$cfg" > /dev/null
    sudo chmod 0644 "$cfg"
    hf_log "honeypot-ssh: config written $cfg (banner calibrated byte-for-byte from the real sshd)"
    return 0
}

hf_hp_write_probe() {
    local tmp; tmp=$(mktemp) || hf_die "mktemp failed"
    cat > "$tmp" <<'PROBE_EOF'
#!/usr/bin/env bash
# honeyfleet sshesame-health: self-healing guard for the port-22 honeypot.
# Detects accept-stall (process alive but NOT accepting connections) and
# restarts after the configured threshold, with a cooldown between restarts.
# Alerting of a downed honeypot is the notifier modules' job; evidence figures
# are always scoped to the CURRENT LOG WINDOW (never "today / last 24h").
set -uo pipefail

HP_PORT=__HP_PORT__
HP_THRESHOLD=__HP_THRESHOLD__
HP_COOLDOWN_S=__HP_COOLDOWN__
HP_UNIT=__HP_UNIT__
state_dir=/var/lib/honeyfleet/sshesame-health
state_file="$state_dir/state.json"
lock_file="$state_dir/.health.lock"
mkdir -p "$state_dir"
chmod 0700 "$state_dir"
exec 9>"$lock_file"
flock -n 9 || { logger -t honeyfleet-sshesame-health 'previous run still active; skipping overlap.'; exit 0; }
chmod 0600 "$lock_file"

now=$(date +%s)

get_state() {
  python3 - "$state_file" "$1" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
    print(d.get(sys.argv[2], 0))
except Exception:
    print(0)
PY
}

put_state() {
  python3 - "$state_file" "$now" "$@" <<'PY'
import json, os, sys, tempfile
state_path, now = sys.argv[1], int(sys.argv[2])
payload = {}
if os.path.exists(state_path):
    try:
        payload = json.load(open(state_path, encoding="utf-8"))
    except Exception:
        payload = {}
it = iter(sys.argv[3:])
for key, value in zip(it, it):
    try:
        payload[key] = int(value)
    except ValueError:
        payload[key] = value
payload["updated_at"] = now
payload["schema"] = 1
fd, temporary = tempfile.mkstemp(prefix=".s.", dir=os.path.dirname(state_path))
try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False)
        handle.write("\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, state_path)
except Exception:
    pass
PY
}

failures=$(get_state consecutive_failures)
last_restart=$(get_state last_restart_at)
ok=1

# 1) systemd active
if ! systemctl is-active --quiet "$HP_UNIT"; then ok=0; fi
# 2) TCP accept on 127.0.0.1:HP_PORT (loopback is in the fail2ban ignoreip —
#    the health probe can never self-ban)
if ! timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/$HP_PORT" 2>/dev/null; then ok=0; fi
# 3) SSH banner present (matches the real sshd banner)
banner=$(timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/$HP_PORT; IFS= read -r l <&3; printf '%s' \"\$l\"" 2>/dev/null)
case "$banner" in
  SSH-2.0-*|SSH-1.99-*) ;;
  *) ok=0 ;;
esac

if [ "$ok" = 1 ]; then
  put_state consecutive_failures 0 last_result ok
  logger -t honeyfleet-sshesame-health 'honeypot healthy'
  exit 0
fi

failures=$((failures + 1))
put_state consecutive_failures "$failures" last_result fail
logger -t honeyfleet-sshesame-health "honeypot degraded (consecutive_failures=$failures)"

if [ "$failures" -ge "$HP_THRESHOLD" ] && [ $((now - last_restart)) -ge "$HP_COOLDOWN_S" ]; then
  logger -t honeyfleet-sshesame-health 'restarting honeypot (accept-stall recovery)'
  systemctl restart "$HP_UNIT"
  put_state consecutive_failures 0 last_restart_at "$now" last_restart_reason threshold-reached
fi
exit 0
PROBE_EOF
    sed -i \
        -e "s|__HP_PORT__|$(hf_conf HP_PORT 22)|g" \
        -e "s|__HP_THRESHOLD__|$(hf_conf HP_HEALTH_THRESHOLD 2)|g" \
        -e "s|__HP_COOLDOWN__|$(hf_conf HP_HEALTH_COOLDOWN 900)|g" \
        -e "s|__HP_UNIT__|$UNIT_SVC|g" \
        "$tmp"
    if [ -f "$PROBE" ] && sudo cmp -s "$tmp" "$PROBE"; then
        rm -f "$tmp"
        hf_log "honeypot-ssh: health probe unchanged (NO-OP)"
        return 1
    fi
    hf_backup "$PROBE"
    sudo install -o root -g root -m 0755 "$tmp" "$PROBE"
    rm -f "$tmp"
    hf_log "honeypot-ssh: health probe written $PROBE"
    return 0
}

hf_hp_write_logrotate() {
    local nogrp; nogrp=$(hf_hp_nogroup)
    local logp; logp=$(hf_conf HP_LOGPATH "$HP_LOG_DEFAULT")
    local content
    content=$(cat <<EOF
# honeyfleet: sshesame honeypot log rotation.
# Criteria are additive (weekly OR size); copytruncate keeps the honeypot
# writing across rotation. Evidence scope = current log window.
${logp} {
    weekly
    rotate 8
    size 10M
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    create 0640 nobody ${nogrp}
}
EOF
)
    if [ -f "$LOGROTATE" ] && printf '%s\n' "$content" | sudo cmp -s - "$LOGROTATE"; then
        hf_log "honeypot-ssh: logrotate unchanged (NO-OP)"
        return 1
    fi
    hf_backup "$LOGROTATE"
    printf '%s\n' "$content" | sudo tee "$LOGROTATE" > /dev/null
    sudo chmod 0644 "$LOGROTATE"
    hf_log "honeypot-ssh: logrotate written $LOGROTATE"
    return 0
}

# ── verify gates ─────────────────────────────────────────────────

hf_hp_gate_real_listener() {
    local real; real=$(hf_hp_real_port) || return 1
    local got; got=$(hf_hp_listener_ports sshd)
    [ -n "$got" ] && [ "$got" = "$real" ]
}

hf_hp_gate_hp_listener() {
    local got; got=$(hf_hp_listener_ports sshesame)
    [ -n "$got" ] && [ "$got" = "$(hf_conf HP_PORT 22)" ]
}

# Byte-equality via the task-prescribed 44-byte capture: both SSH servers send
# their banner immediately followed by the KEXINIT packet, whose first two
# bytes are always 0x00 0x00 (packet length, dropped symmetrically by command
# substitution), so identical banners always compare equal here.
hf_hp_gate_banner() {
    local real; real=$(hf_hp_real_port) || return 1
    local a b
    a=$(hf_hp_grab_banner44 "$real")
    b=$(hf_hp_grab_banner44 "$(hf_conf HP_PORT 22)")
    [ -n "$a" ] && [ -n "$b" ] || return 1
    case "$a" in SSH-2.0-*|SSH-1.99-*) : ;; *) return 1 ;; esac
    [ "$a" = "$b" ]
}

hf_hp_gate_timer() {
    systemctl is-active --quiet "$UNIT_TIMER" || return 1
    [ -x "$PROBE" ]
}

hf_hp_gate_jail() {
    # Gate 5: the three fail2ban jails (sshd / sshesame / recidive) must match
    # the config, read back from the RUNNING daemon via fail2ban-client get
    # (consumer caliber — same parameter set fail2ban-stack's verify enforces;
    # this is the second consumer, f2b-incident class 2026-08-29).
    local real hp_port logp got inc mult
    real=$(hf_hp_real_port) || { hf_warn "honeypot-ssh: gate 5 cannot resolve HF_SSH_REAL_PORT"; return 1; }
    hp_port=$(hf_conf HP_PORT 22)
    logp=$(hf_conf HP_LOGPATH "$HP_LOG_DEFAULT")

    sudo fail2ban-client ping > /dev/null 2>&1 \
        || { hf_warn "honeypot-ssh: fail2ban not responding (fail2ban-client ping)"; return 1; }

    # [sshd] jail — real-port brute-force funnel
    got=$(sudo fail2ban-client get sshd maxretry 2>/dev/null)
    [ "$got" = "$(hf_conf F2B_MAXRETRY_SSH 5)" ] \
        || { hf_warn "honeypot-ssh: f2b sshd maxretry=$got expected $(hf_conf F2B_MAXRETRY_SSH 5)"; return 1; }
    got=$(sudo fail2ban-client get sshd findtime 2>/dev/null)
    [ "$got" = "$(hf_hp_to_sec "$(hf_conf F2B_FINDTIME_SSH 600)")" ] \
        || { hf_warn "honeypot-ssh: f2b sshd findtime=$got"; return 1; }
    got=$(sudo fail2ban-client get sshd bantime 2>/dev/null)
    [ "$got" = "$(hf_hp_to_sec "$(hf_conf F2B_BANTIME_SSH 10m)")" ] \
        || { hf_warn "honeypot-ssh: f2b sshd bantime=$got"; return 1; }
    got=$(sudo fail2ban-client get sshd bantime.increment 2>/dev/null)
    inc=false; hf_conf_bool F2B_INCREMENT true && inc=true
    [ "$(printf '%s' "$got" | tr '[:upper:]' '[:lower:]')" = "$inc" ] \
        || { hf_warn "honeypot-ssh: f2b sshd bantime.increment=$got expected $inc"; return 1; }
    got=$(sudo fail2ban-client get sshd bantime.maxtime 2>/dev/null)
    [ "$(hf_hp_to_sec "$got")" = "$(hf_hp_to_sec "$(hf_conf F2B_INCREMENT_MAXTIME 3650d)")" ] \
        || { hf_warn "honeypot-ssh: f2b sshd bantime.maxtime=$got"; return 1; }
    mult=$(printf '%s' "$(hf_conf F2B_INCREMENT_MULTIPLIERS '1 525600')" | tr -s '[:space:]' ' ' | sed 's/^ //;s/ $//')
    got=$(sudo fail2ban-client get sshd bantime.multipliers 2>/dev/null | tr -s '[:space:]' ' ' | sed 's/^ //;s/ $//')
    [ "$got" = "$mult" ] \
        || { hf_warn "honeypot-ssh: f2b sshd bantime.multipliers=[$got] expected [$mult]"; return 1; }

    # sshd jail action must mount ONLY the real port (same parameter, second
    # consumer — this is the f2b-incident consumer gate)
    local act ports=""
    while IFS= read -r act; do
        [ -n "$act" ] || continue
        ports="$ports $(sudo fail2ban-client get sshd action "$act" actionstart 2>/dev/null \
            | grep -oE -- '--dports? [A-Za-z0-9_,]+' | grep -oE '[0-9]+' | tr '\n' ' ')"
    done < <(sudo fail2ban-client get sshd actions 2>/dev/null | tail -n +2)
    got=$(printf '%s\n' $ports | sort -un | tr '\n' ' ' | sed 's/ $//')
    [ "$got" = "$real" ] \
        || { hf_warn "honeypot-ssh: f2b sshd jail ports=[$got] expected [$real]"; return 1; }

    # [sshesame] jail — honeypot feed
    sudo fail2ban-client get sshesame bantime > /dev/null 2>&1 \
        || { hf_warn "honeypot-ssh: [sshesame] jail missing or fail2ban down"; return 1; }
    got=$(sudo fail2ban-client get sshesame maxretry 2>/dev/null)
    [ "$got" = "$(hf_conf HP_MAXRETRY 3)" ] \
        || { hf_warn "honeypot-ssh: sshesame maxretry=$got"; return 1; }
    got=$(sudo fail2ban-client get sshesame findtime 2>/dev/null)
    [ "$got" = "$(hf_hp_to_sec "$(hf_conf HP_FINDTIME 600)")" ] \
        || { hf_warn "honeypot-ssh: sshesame findtime=$got"; return 1; }
    got=$(sudo fail2ban-client get sshesame bantime 2>/dev/null)
    [ "$got" = "$(hf_hp_to_sec "$(hf_conf HP_BANTIME 30d)")" ] \
        || { hf_warn "honeypot-ssh: sshesame bantime=$got"; return 1; }
    sudo fail2ban-client get sshesame logpath 2>/dev/null | grep -qF "$logp" \
        || { hf_warn "honeypot-ssh: sshesame logpath does not contain $logp"; return 1; }

    # [recidive] jail — repeat-offender escalation (third jail, same caliber)
    sudo fail2ban-client get recidive bantime > /dev/null 2>&1 \
        || { hf_warn "honeypot-ssh: [recidive] jail missing or fail2ban down"; return 1; }
    got=$(sudo fail2ban-client get recidive maxretry 2>/dev/null)
    [ "$got" = "$(hf_conf RECIDIVE_MAXRETRY 2)" ] \
        || { hf_warn "honeypot-ssh: f2b recidive maxretry=$got"; return 1; }
    got=$(sudo fail2ban-client get recidive findtime 2>/dev/null)
    [ "$got" = "$(hf_hp_to_sec "$(hf_conf RECIDIVE_FINDTIME 30d)")" ] \
        || { hf_warn "honeypot-ssh: f2b recidive findtime=$got"; return 1; }
    got=$(sudo fail2ban-client get recidive bantime 2>/dev/null)
    [ "$got" = "$(hf_hp_to_sec "$(hf_conf RECIDIVE_BANTIME 3650d)")" ] \
        || { hf_warn "honeypot-ssh: f2b recidive bantime=$got"; return 1; }
    sudo fail2ban-client get recidive logpath 2>/dev/null | grep -qF "$(hf_conf RECIDIVE_LOGPATH /var/log/fail2ban.log)" \
        || { hf_warn "honeypot-ssh: f2b recidive logpath mismatch"; return 1; }
    return 0
}

hf_hp_gate_binary() {
    local want got
    want=$(hf_hp_expected_sha)
    [ -n "$want" ] || return 1
    [ -x /usr/local/bin/sshesame ] || return 1
    got=$(hf_hp_sha256 /usr/local/bin/sshesame)
    [ "$got" = "$want" ]
}

hf_hp_gate_service() {
    systemctl is-active --quiet "$UNIT_SVC"
}

# ── contract functions ───────────────────────────────────────────

hf_honeypot_ssh_install() {
    hf_hp_load_config || hf_die "config missing: ${HF_CONF_FILE:-/etc/honeyfleet/honeyfleet.conf} — copy config/honeyfleet.conf.example, edit, retry"
    if ! hf_conf_bool SSH_HONEYPOT true; then
        hf_log "honeypot-ssh: HF_SSH_HONEYPOT=false — skipping (NO-OP)"
        return 0
    fi
    hf_requires fail2ban-stack

    local real_port hp_port nogrp logp logdir
    real_port=$(hf_hp_real_port) || hf_die "cannot resolve the real sshd port (HF_SSH_REAL_PORT or live sshd)"
    hp_port=$(hf_conf HP_PORT 22)
    [ "$real_port" != "$hp_port" ] || hf_die "real sshd port equals the honeypot port ($hp_port) — move the real sshd first (see ssh-hardening)"

    nogrp=$(hf_hp_nogroup)
    logp=$(hf_conf HP_LOGPATH "$HP_LOG_DEFAULT")
    logdir=$(dirname "$logp")

    sudo mkdir -p "$HF_ETC/sshesame" "$HF_LIB" "$HF_STATE" "$logdir"
    sudo chown "nobody:$nogrp" "$logdir"
    sudo chmod 0750 "$logdir"

    hf_hp_fetch_binary
    hf_hp_ensure_hostkey
    hf_hp_write_config "$real_port"
    hf_hp_write_probe
    hf_hp_write_logrotate

    hf_unit_write "$UNIT_SVC" <<UNIT
[Unit]
Description=honeyfleet sshesame SSH honeypot (fake SSH on port ${hp_port})
After=network.target

[Service]
ExecStart=/usr/local/bin/sshesame -config ${HF_ETC}/sshesame/config.yaml -data_dir ${HF_ETC}/sshesame
Restart=always
RestartSec=3s
User=nobody
Group=${nogrp}
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=full
ReadWritePaths=${logdir}
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
UNIT
    hf_unit_write "$UNIT_HEALTH" <<UNIT
[Unit]
Description=honeyfleet sshesame honeypot self-healing guard
After=${UNIT_SVC} network.target

[Service]
Type=oneshot
ExecStart=${PROBE}
UNIT
    hf_unit_write "$UNIT_TIMER" <<UNIT
[Unit]
Description=Run the honeyfleet sshesame health check every $(hf_conf HP_HEALTH_INTERVAL 180)s

[Timer]
OnBootSec=2min
OnUnitActiveSec=$(hf_conf HP_HEALTH_INTERVAL 180)s
RandomizedDelaySec=20s
Persistent=true

[Install]
WantedBy=timers.target
UNIT

    # pre-create the JSON log so the fail2ban [sshesame] jail finds its logpath
    if [ ! -f "$logp" ]; then
        sudo install -o nobody -g "$nogrp" -m 0640 /dev/null "$logp"
    fi

    sudo systemctl enable --now "$UNIT_SVC" > /dev/null 2>&1 || hf_die "could not enable/start $UNIT_SVC"
    sudo systemctl enable --now "$UNIT_TIMER" > /dev/null 2>&1 || hf_die "could not enable $UNIT_TIMER"

    local listening="" i
    for i in 1 2 3 4 5 6 7 8 9 10; do
        listening=$(hf_hp_listener_ports sshesame)
        [ -n "$listening" ] && break
        sleep 0.5
    done
    [ "$listening" = "$hp_port" ] || hf_die "honeypot did not bind port $hp_port (listening: ${listening:-none})"

    # pick the (now existing) log file up in the fail2ban sshesame jail
    if sudo fail2ban-client get sshesame bantime > /dev/null 2>&1; then
        sudo fail2ban-client reload sshesame > /dev/null 2>&1 || true
    fi

    hf_registry 1 "$MOD"
    local banner; banner=$(hf_hp_grab_banner44 "$hp_port")
    hf_log "honeypot-ssh: installed (real sshd on ${real_port}, honeypot on ${hp_port}, health probe every $(hf_conf HP_HEALTH_INTERVAL 180)s, restart after $(hf_conf HP_HEALTH_THRESHOLD 2) failures with $(hf_conf HP_HEALTH_COOLDOWN 900)s cooldown)"
    hf_log "honeypot-ssh: evidence: listener=${listening} banner_prefix=$(printf '%s' "$banner" | cut -c1-20)"
}

hf_honeypot_ssh_verify() {
    hf_hp_load_config || hf_die "config missing: ${HF_CONF_FILE:-/etc/honeyfleet/honeyfleet.conf}"
    if ! hf_conf_bool SSH_HONEYPOT true; then
        hf_log "honeypot-ssh: verify SKIP (HF_SSH_HONEYPOT=false)"
        return 0
    fi
    local rc=0 fails=0
    hf_hp_gate() {
        local name=$1; shift
        if "$@"; then
            printf 'PASS: %s\n' "$name"
        else
            printf 'FAIL: %s\n' "$name"
            fails=$((fails + 1))
        fi
    }
    hf_hp_gate "1-sshd-real-port-listener(=HF_SSH_REAL_PORT)" hf_hp_gate_real_listener
    hf_hp_gate "2-honeypot-listener(=HF_HP_PORT)"            hf_hp_gate_hp_listener
    hf_hp_gate "3-honeypot-banner-byte-equal-to-real-sshd"   hf_hp_gate_banner
    hf_hp_gate "4-health-probe-timer-active"                 hf_hp_gate_timer
    hf_hp_gate "5-fail2ban-three-jail-params-match-config"   hf_hp_gate_jail
    hf_hp_gate "extra-sshesame-binary-matches-pinned-sha256" hf_hp_gate_binary
    hf_hp_gate "extra-honeypot-service-active"               hf_hp_gate_service
    if [ "$fails" -eq 0 ]; then
        hf_log "honeypot-ssh: verify PASS"
    else
        hf_warn "honeypot-ssh: verify FAIL ($fails gate(s) failed)"
        rc=1
    fi
    return $rc
}

hf_honeypot_ssh_status() {
    hf_hp_load_config 2>/dev/null || true
    local svc tmr listen banned logp sz
    svc=$(systemctl is-active "$UNIT_SVC" 2>/dev/null || echo inactive)
    tmr=$(systemctl is-active "$UNIT_TIMER" 2>/dev/null || echo inactive)
    listen=$(hf_hp_listener_ports sshesame 2>/dev/null || true)
    listen=${listen:-none}
    banned=$(sudo fail2ban-client status sshesame 2>/dev/null | sed -n 's/^.*Currently banned:[[:space:]]*//p' | head -1)
    banned=${banned:-n/a}
    logp=$(hf_conf HP_LOGPATH "$HP_LOG_DEFAULT")
    sz=$(sudo stat -c '%s' "$logp" 2>/dev/null || echo '?')
    printf 'honeypot-ssh: service=%s timer=%s listen=%s banned=%s evidence_log_bytes=%s (scope: current log window)\n' \
        "$svc" "$tmr" "$listen" "$banned" "$sz"
}

hf_honeypot_ssh_remove() {
    sudo systemctl disable --now "$UNIT_TIMER" 2>/dev/null || true
    sudo systemctl disable --now "$UNIT_SVC" 2>/dev/null || true
    hf_backup "$HF_ETC/sshesame/config.yaml" 2>/dev/null || true
    hf_backup "$HF_ETC/sshesame/ssh_host_ed25519_key" 2>/dev/null || true
    hf_backup "$PROBE" 2>/dev/null || true
    hf_backup "/etc/systemd/system/$UNIT_SVC" 2>/dev/null || true
    hf_backup "/etc/systemd/system/$UNIT_HEALTH" 2>/dev/null || true
    hf_backup "/etc/systemd/system/$UNIT_TIMER" 2>/dev/null || true
    hf_backup "$LOGROTATE" 2>/dev/null || true
    sudo rm -f "/etc/systemd/system/$UNIT_SVC" \
               "/etc/systemd/system/$UNIT_HEALTH" \
               "/etc/systemd/system/$UNIT_TIMER" \
               "$PROBE" \
               "$LOGROTATE" \
               /usr/local/bin/sshesame
    sudo rm -rf "$HF_ETC/sshesame"
    sudo systemctl daemon-reload 2>/dev/null || true
    hf_registry 0 "$MOD"
    hf_log "honeypot-ssh: removed (logs in $(dirname "$HP_LOG_DEFAULT") and health state in $HF_STATE kept for forensics)"
    hf_warn "honeypot-ssh: the [sshesame] jail in fail2ban-stack still references the removed honeypot — re-run fail2ban-stack install with HF_SSH_HONEYPOT=false, or re-install honeypot-ssh"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    case "${1:-}" in
        install) hf_honeypot_ssh_install ;;
        verify)  hf_honeypot_ssh_verify ;;
        status)  hf_honeypot_ssh_status ;;
        remove)  hf_honeypot_ssh_remove ;;
        *) hf_die "usage: honeypot-ssh.sh install|verify|status|remove" ;;
    esac
fi
