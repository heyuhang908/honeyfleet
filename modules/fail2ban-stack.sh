#!/usr/bin/env bash
# honeyfleet module: fail2ban-stack — enforcement funnel for the SSH honeypot.
#
# Deploys three jails in ONE managed file (/etc/fail2ban/jail.d/honeyfleet.local):
#   sshd      — bans brute-force against the REAL sshd port (HF_SSH_REAL_PORT)
#   sshesame  — bans honeypot hits (port HF_HP_PORT, default 22), JSON log filter
#   recidive  — repeat-offender escalation (all-ports ban; parameters from config)
# Policy is generalized from the audited production deployment:
# backend=systemd (journald) for sshd, bantime.increment with multipliers,
# recidive via %(banaction_allports)s, dbpurgeage >= recidive horizon,
# ignoreip always covers loopback + HF_SSH_MANAGEMENT_SOURCES (operator
# mis-typings must never cause a self-lockout).
#
# Contract (docs/MODULE-CONTRACT.md): hf_fail2ban_stack_{install,verify,status,remove},
# idempotent (re-run = NO-OP), config read ONLY via hf_conf, hf_backup before writes.
# The verify gate is the CONSUMER GATE for the f2b-parameter incident class
# (2026-08-29): every deployed jail parameter is read back with
# `fail2ban-client get` and must match the config exactly, AND the whole repo
# is grepped for stale pre-generalization f2b parameter literals (contract
# rule 4: every consumer must be updated in the same change).

set -uo pipefail
MOD=fail2ban-stack
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"

# lib/common.sh hf_backup has a path mismatch: mkdir creates only dirname($f)
# while the cp target nests the basename as an extra directory component, so
# cp fails and backups silently never happen (which would also leave `remove`
# without a policy to restore). Re-defined here with ONE consistent layout
# ($HF_STATE/backups/<path-sans-slash>/.$basename.<UTC>) and the same
# "keep newest 2" retention — identical to the firewall-baseline/ssh-hardening
# overrides, plus a sudo fallback for non-root scattered-sudo runs. Drop this
# override once lib/common.sh is fixed.
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

JAIL_FILE=/etc/fail2ban/jail.d/honeyfleet.local
FILTER_FILE=/etc/fail2ban/filter.d/honeyfleet-sshesame.conf
F2B_CONF=/etc/fail2ban/fail2ban.conf
HP_LOG_DEFAULT=/var/log/honeyfleet/sshesame/sshesame.json

# ── helpers ──────────────────────────────────────────────────────

hf_f2b_load_config() {
    HF_CONF_FILE=${HF_CONF:-/etc/honeyfleet/honeyfleet.conf}
    [ -f "$HF_CONF_FILE" ] || return 1
    # shellcheck disable=SC1090
    . "$HF_CONF_FILE"
    return 0
}

# hf_f2b_to_sec "10m" -> 600 ; accepts composites ("1d12h") and plain integers
hf_f2b_to_sec() {
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

# Resolve the REAL sshd port: numeric config wins; "random" falls back to the
# live sshd configuration (resolved by ssh-hardening at install time).
hf_f2b_real_port() {
    local p; p=$(hf_conf SSH_REAL_PORT "")
    case "$p" in
        ""|random|RANDOM)
            p=$(sudo sshd -T 2>/dev/null | awk '$1 == "port" {print $2; exit}')
            [ -n "$p" ] || hf_die "HF_SSH_REAL_PORT is '${p:-random}' and no live sshd port found — install ssh-hardening first or set a concrete port"
            hf_warn "HF_SSH_REAL_PORT='random' unresolved — using live sshd port $p (install ssh-hardening to persist it)"
            ;;
    esac
    case "$p" in
        ''|*[!0-9]*) hf_die "invalid HF_SSH_REAL_PORT: '$p' (must be an integer or 'random')" ;;
    esac
    [ "$p" -ge 1 ] && [ "$p" -le 65535 ] || hf_die "HF_SSH_REAL_PORT out of range: $p"
    if hf_conf_bool SSH_HONEYPOT true && [ "$p" = "$(hf_conf HP_PORT 22)" ]; then
        hf_die "HF_SSH_REAL_PORT=$p collides with the honeypot port — the real sshd must move off port $(hf_conf HP_PORT 22) first (see ssh-hardening)"
    fi
    printf '%s\n' "$p"
}

hf_f2b_hp_enabled() { hf_conf_bool SSH_HONEYPOT true; }

# ignoreip = loopback + management sources (fail-closed on malformed tokens)
hf_f2b_ignoreip() {
    local out="127.0.0.0/8 ::1" t
    for t in $(hf_conf SSH_MANAGEMENT_SOURCES ""); do
        python3 -c "import ipaddress,sys; ipaddress.ip_network(sys.argv[1] if '/' in sys.argv[1] else sys.argv[1], strict=False)" "$t" 2>/dev/null \
            || hf_die "HF_SSH_MANAGEMENT_SOURCES contains an invalid address: '$t'"
        out="$out $t"
    done
    printf '%s\n' "$out"
}

hf_f2b_backend() {
    # Mirrors the production validator: backend=systemd => NO logpath (journald);
    # backend=auto => /var/log/auth.log.
    local b; b=$(hf_conf F2B_SSHD_BACKEND "systemd")
    case "$b" in
        systemd) printf 'systemd\n' ;;
        auto)    printf 'auto\n' ;;
        *) hf_die "invalid HF_F2B_SSHD_BACKEND '$b' (systemd|auto)" ;;
    esac
}

hf_f2b_write_filter() {
    local filter='[Definition]
failregex = ^\{.*"source":\{"host":"<HOST>","port":\d+\}.*"event_type":"[a-z_]+".*$
ignoreregex =
'
    if [ -f "$FILTER_FILE" ] && printf '%s\n' "$filter" | sudo cmp -s - "$FILTER_FILE"; then
        return 0
    fi
    hf_backup "$FILTER_FILE"
    printf '%s\n' "$filter" | sudo tee "$FILTER_FILE" > /dev/null
    sudo chmod 0644 "$FILTER_FILE"
    hf_log "fail2ban-stack: filter written $FILTER_FILE"
}

hf_f2b_build_jail() {
    local real_port=$1
    local backend; backend=$(hf_f2b_backend)
    local inc; if hf_conf_bool F2B_INCREMENT true; then inc=true; else inc=false; fi
    local mult; mult=$(hf_conf F2B_INCREMENT_MULTIPLIERS "1 525600")
    local hp_port; hp_port=$(hf_conf HP_PORT 22)
    local hp_log; hp_log=$(hf_conf HP_LOGPATH "$HP_LOG_DEFAULT")
    local ignoreip; ignoreip=$(hf_f2b_ignoreip)
    local rec_logpath; rec_logpath=$(hf_conf RECIDIVE_LOGPATH /var/log/fail2ban.log)
    local rec_maxretry; rec_maxretry=$(hf_conf RECIDIVE_MAXRETRY 2)

    local sshd_logpath_line=""
    [ "$backend" = "auto" ] && sshd_logpath_line="logpath = /var/log/auth.log"$'\n'

    local block
    block=$(cat <<EOF
# honeyfleet: managed fail2ban policy (generated by modules/fail2ban-stack.sh).
# Source of truth: /etc/honeyfleet/honeyfleet.conf (HF_F2B_* / HF_HP_* / HF_RECIDIVE_*).
# Hand edits are overwritten on the next install — change the config instead.

[sshd]
enabled = true
port = ${real_port}
backend = ${backend}
${sshd_logpath_line}bantime = $(hf_conf F2B_BANTIME_SSH 10m)
findtime = $(hf_conf F2B_FINDTIME_SSH 600)
maxretry = $(hf_conf F2B_MAXRETRY_SSH 5)
bantime.increment = ${inc}
bantime.multipliers = ${mult}
bantime.maxtime = $(hf_conf F2B_INCREMENT_MAXTIME 3650d)
ignoreip = ${ignoreip}

[recidive]
enabled = true
filter = recidive
logpath = ${rec_logpath}
backend = auto
bantime = $(hf_conf RECIDIVE_BANTIME 3650d)
findtime = $(hf_conf RECIDIVE_FINDTIME 30d)
maxretry = ${rec_maxretry}
banaction = %(banaction_allports)s
ignoreip = ${ignoreip}
EOF
)

    if hf_f2b_hp_enabled; then
        block="$block"$'\n'$(cat <<EOF

[sshesame]
enabled = true
filter = honeyfleet-sshesame
logpath = ${hp_log}
backend = auto
protocol = tcp
port = ${hp_port}
findtime = $(hf_conf HP_FINDTIME 600)
maxretry = $(hf_conf HP_MAXRETRY 3)
bantime = $(hf_conf HP_BANTIME 30d)
ignoreip = ${ignoreip}
EOF
)
    fi
    printf '%s\n' "$block"
}

hf_f2b_write_jail() {
    local content
    content=$(hf_f2b_build_jail "$1") || hf_die "failed to build the jail policy — check the honeyfleet config (ports, addresses, time units)"
    [ -n "$content" ] || hf_die "empty jail policy — refusing to overwrite $JAIL_FILE"
    if [ -f "$JAIL_FILE" ] && printf '%s\n' "$content" | sudo cmp -s - "$JAIL_FILE"; then
        hf_log "fail2ban-stack: jail policy unchanged (NO-OP)"
        return 1   # 1 = nothing changed
    fi
    hf_backup "$JAIL_FILE"
    printf '%s\n' "$content" | sudo tee "$JAIL_FILE" > /dev/null
    sudo chmod 0644 "$JAIL_FILE"
    hf_log "fail2ban-stack: jail policy written $JAIL_FILE"
    return 0    # 0 = changed
}

hf_f2b_ensure_dbpurgeage() {
    # recidive bans for the full horizon, so the ban database must retain at
    # least as long (production caliber: 3650d).
    local want; want=$(hf_conf F2B_DBPURGEAGE 3650d)
    local cur; cur=$(sudo grep -E '^\s*dbpurgeage\s*=' "$F2B_CONF" 2>/dev/null | tail -1 | sed 's/^\s*dbpurgeage\s*=\s*//')
    if [ "$cur" = "$want" ]; then
        return 1
    fi
    hf_backup "$F2B_CONF"
    sudo python3 - "$F2B_CONF" "$want" <<'PY'
import re, sys
path, want = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8").read()
updated, n = re.subn(r"(?m)^(\s*dbpurgeage\s*=\s*).*$", r"\g<1>" + want, text)
if n != 1:
    raise SystemExit("unexpected dbpurgeage layout in %s (%d matches)" % (path, n))
open(path, "w", encoding="utf-8").write(updated)
PY
    hf_log "fail2ban-stack: dbpurgeage set to $want in $F2B_CONF"
    return 0
}

hf_f2b_ensure_pkg() {
    command -v fail2ban-client > /dev/null 2>&1 && return 0
    hf_log "fail2ban-stack: installing fail2ban package"
    if command -v apt-get > /dev/null 2>&1; then
        sudo apt-get update -qq || true
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban
    elif command -v dnf > /dev/null 2>&1; then
        sudo dnf install -y epel-release 2>/dev/null || true
        sudo dnf install -y fail2ban
    elif command -v yum > /dev/null 2>&1; then
        sudo yum install -y epel-release 2>/dev/null || true
        sudo yum install -y fail2ban
    else
        hf_die "fail2ban is missing and no supported package manager found (apt/dnf/yum)"
    fi
    command -v fail2ban-client > /dev/null 2>&1 || hf_die "fail2ban install did not produce fail2ban-client"
}

# Evidence: read the DEPLOYED values back via fail2ban-client get (consumer
# caliber — what fail2ban actually runs, not what we wrote to disk).
hf_f2b_evidence() {
    local j p v line
    for j in "$@"; do
        line="fail2ban-stack: evidence [$j]"
        for p in bantime findtime maxretry bantime.increment bantime.maxtime; do
            if v=$(sudo fail2ban-client get "$j" "$p" 2>/dev/null | head -1); then
                [ -n "$v" ] && line="$line $p=$v"
            fi
        done
        hf_log "$line"
    done
}

# Contract rule 4 (f2b incident 2026-08-29): every consumer of the f2b policy
# must read HF_F2B_* / HF_HP_* / HF_RECIDIVE_* via config — embedded literals
# drift (the incident was exactly that: two scripts deploying/validating
# different hardcoded recidive findtimes). Grep the whole repo for stale
# jail-parameter literals outside this module. Repo root = the tree this
# module file ships in. Scans shell/python code; the stale-literal list covers
# the pre-generalization policy constants (jail-style `param = value`
# assignments, the fixed increment flag, and the epoch forms of the old
# recidive horizon: 3650d/30d as seconds).
hf_f2b_repo_consumer_gate() {
    local root self bname hits
    root=$(cd "$SCRIPT_DIR/.." && pwd) || return 0
    bname=$(basename "${BASH_SOURCE[0]}")
    self=$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")
    # self-exclusion must survive platform path-separator differences (grep -R
    # may print / or \ separators depending on host): filter on the
    # modules/<this-module>.sh: path suffix in both forms.
    hits=$(grep -RnE \
        --include='*.sh' --include='*.bash' --include='*.py' \
        -e '(^|[^A-Za-z0-9_.-])(bantime|findtime|maxretry|dbpurgeage|bantime\.increment|bantime\.multipliers|bantime\.maxtime)[[:space:]]*=[[:space:]]*[0-9"]' \
        -e '(^|[^A-Za-z0-9_.-])bantime\.increment[[:space:]]*=[[:space:]]*(true|false)[[:space:]]*$' \
        -e '^[[:space:]]*port[[:space:]]*=[[:space:]]*[0-9]' \
        -e '315360000' \
        -e '2592000' \
        "$root" 2>/dev/null \
        | grep -vF -- "$self" \
        | grep -vE "modules[/\\\\]$bname:" || true)
    if [ -n "$hits" ]; then
        hf_warn "fail2ban-stack: repo consumer gate FAIL — stale f2b parameter literals outside $self (every consumer must read the config):"
        printf '%s\n' "$hits" >&2
        return 1
    fi
    hf_log "fail2ban-stack: repo consumer gate PASS (no stale f2b parameter literals outside this module)"
    return 0
}

# ── contract functions ───────────────────────────────────────────

hf_fail2ban_stack_install() {
    hf_f2b_load_config || hf_die "config missing: ${HF_CONF_FILE:-/etc/honeyfleet/honeyfleet.conf} — copy config/honeyfleet.conf.example, edit, retry"
    local real_port; real_port=$(hf_f2b_real_port)

    sudo mkdir -p /etc/fail2ban/jail.d /etc/fail2ban/filter.d "$HF_ETC" "$HF_LIB" "$HF_STATE" /var/log/honeyfleet

    hf_f2b_ensure_pkg
    hf_f2b_write_filter

    local was_running; was_running=$(systemctl is-active fail2ban 2>/dev/null || echo inactive)

    hf_f2b_write_jail "$real_port"; local jail_changed=$?
    hf_f2b_ensure_dbpurgeage; local db_changed=$?

    sudo systemctl enable fail2ban > /dev/null 2>&1 || true

    # validate BEFORE any (re)start: a mis-rendered jail must fail fast without
    # bouncing the daemon (production lesson: config test moved before reload)
    sudo fail2ban-client -t > /dev/null 2>&1 || hf_die "fail2ban config test failed (fail2ban-client -t) — fix the configuration and retry"
    if [ "$was_running" != "active" ]; then
        sudo systemctl start fail2ban || hf_die "fail2ban failed to start"
    fi
    if [ "$jail_changed" = 0 ] || [ "$db_changed" = 0 ]; then
        if [ "$was_running" = "active" ]; then
            sudo fail2ban-client reload > /dev/null || hf_die "fail2ban-client reload failed"
            hf_log "fail2ban-stack: reload applied (note: reload resets in-flight failure counters)"
        fi
    fi

    if hf_f2b_hp_enabled; then hf_f2b_evidence sshd sshesame recidive; else hf_f2b_evidence sshd recidive; fi

    hf_registry 1 "$MOD"
    hf_log "fail2ban-stack: installed (sshd port=$real_port, recidive maxretry=$(hf_conf RECIDIVE_MAXRETRY 2), honeypot jail $(hf_f2b_hp_enabled && echo enabled || echo disabled))"
}

hf_fail2ban_stack_verify() {
    # Consumer gate: EVERY deployed parameter must match the config when read
    # back from the running fail2ban (not from the file we wrote), plus the
    # repo-wide stale-literal sweep (contract rule 4, f2b incident 2026-08-29).
    hf_f2b_load_config || hf_die "config missing: ${HF_CONF_FILE:-/etc/honeyfleet/honeyfleet.conf}"
    local rc=0
    sudo python3 - "$HF_CONF_FILE" <<'PY' || rc=1
import ipaddress, re, shutil, socket, subprocess, sys

fails = []

def check(name, cond, detail=""):
    print("%s: %s %s" % ("PASS" if cond else "FAIL", name, detail))
    if not cond:
        fails.append(name)

def out(*args):
    r = subprocess.run(["fail2ban-client", *args], capture_output=True, text=True, timeout=10)
    return r.stdout if r.returncode == 0 else ""

def to_sec(s):
    s = str(s).strip().lower()
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    total = 0
    for num, unit in re.findall(r"(\d+)([smhdw]?)", s):
        if num:
            total += int(num) * units.get(unit or "s", 1)
    return total

def conf(k, default=""):
    # config file keys carry the HF_ prefix (same convention as hf_conf in
    # lib/common.sh, which reads the HF_<KEY> variable)
    v = cfg.get("HF_" + k, "")
    return v if v != "" else default

def conf_bool(k, default="false"):
    return conf(k, default).strip().lower() in ("true", "yes", "on", "1")

# single config source (same file the installer used — passed in as argv[1])
cfg = {}
try:
    for line in open(sys.argv[1], encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        cfg[k.strip()] = v.strip().strip('"').strip("'")
except OSError:
    pass
if not cfg:
    fails.append("config-readable")

def real_port():
    p = conf("SSH_REAL_PORT")
    if p in ("", "random", "RANDOM"):
        r = subprocess.run([shutil.which("sshd") or "/usr/sbin/sshd", "-T"],
                           capture_output=True, text=True, timeout=10)
        m = re.search(r"(?m)^port\s+(\d+)$", r.stdout)
        return int(m.group(1)) if m else None
    return int(p) if p.isdigit() else None

def norm_ips(text):
    s = set()
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(("|-", "`-")):
            line = line[2:].strip()
        for tok in line.split():
            tok = tok.strip("[](),|").lstrip("+-")
            try:
                s.add(str(ipaddress.ip_network(tok, strict=False)) if "/" in tok
                      else str(ipaddress.ip_address(tok)))
            except ValueError:
                continue
    return s

def ports_from_action(text):
    ports = set()
    for m in re.finditer(r"--dports?\s+([A-Za-z0-9_,-]+)\b", text or ""):
        for raw in m.group(1).split(","):
            tok = raw.strip().lower()
            if tok.isdigit():
                p = int(tok)
            elif re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", tok):
                try:
                    p = socket.getservbyname(tok, "tcp")
                except OSError:
                    continue
            else:
                continue
            if 1 <= p <= 65535:
                ports.add(p)
    for m in re.finditer(r"\b(?:tcp|udp)\s+dports?\s+\{?\s*([0-9,\s]+?)\s*\}?", text or ""):
        for raw in re.split(r"[,\s]+", m.group(1)):
            if raw.isdigit() and 1 <= int(raw) <= 65535:
                ports.add(int(raw))
    return ports

def jail_ports(jail):
    txt = out("get", jail, "actions")
    names = [l.strip() for l in txt.splitlines()[1:]
             if re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", l.strip())]
    ports = set()
    for n in names:
        ports |= ports_from_action(out("get", jail, "action", n, "actionstart"))
    return ports

def expected_ignoreip():
    # loopback literals in the exact form fail2ban normalizes `get ignoreip`
    # to (verified against the audited deployment: "127.0.0.0/8" and "::1" —
    # NOT "::1/128", which would never match and fail every correct deploy)
    s = {"127.0.0.0/8", "::1"}
    for tok in conf("SSH_MANAGEMENT_SOURCES").split():
        try:
            s.add(str(ipaddress.ip_network(tok, strict=False)) if "/" in tok
                  else str(ipaddress.ip_address(tok)))
        except ValueError:
            pass
    return s

rp = real_port()
check("sshd-real-port-resolvable", rp is not None)
hp_enabled = conf_bool("SSH_HONEYPOT", "true")
try:
    hp_port = int(conf("HP_PORT", "22"))
except ValueError:
    hp_port = None
    check("hp-port-valid", False, "HF_HP_PORT must be an integer, got %r" % conf("HP_PORT", "22"))

# service health
check("service-active", subprocess.run(
    ["systemctl", "is-active", "--quiet", "fail2ban"],
    capture_output=True, timeout=10).returncode == 0)
check("client-ping", "pong" in out("ping").lower() or subprocess.run(
    ["fail2ban-client", "ping"], capture_output=True, timeout=10).returncode == 0)

def numeric_jail_checks(jail, bantime, findtime, maxretry):
    got = {}
    for p in ("bantime", "findtime", "maxretry"):
        raw = out("get", jail, p).strip()
        got[p] = int(re.search(r"\d+", raw).group(0)) if re.search(r"\d+", raw) else None
    check("%s.bantime" % jail, got["bantime"] == to_sec(bantime),
          "deployed=%s expected=%ss" % (got["bantime"], to_sec(bantime)))
    check("%s.findtime" % jail, got["findtime"] == to_sec(findtime),
          "deployed=%s expected=%ss" % (got["findtime"], to_sec(findtime)))
    check("%s.maxretry" % jail, got["maxretry"] == int(maxretry),
          "deployed=%s expected=%s" % (got["maxretry"], maxretry))

def increment_checks(jail, inc, maxtime, multipliers):
    raw = out("get", jail, "bantime.increment").strip()
    check("%s.bantime.increment" % jail, raw.lower() == str(inc).lower(),
          "deployed=%s expected=%s" % (raw, inc))
    if inc:
        raw = out("get", jail, "bantime.maxtime").strip()
        check("%s.bantime.maxtime" % jail,
              re.search(r"\d+", raw) is not None and int(re.search(r"\d+", raw).group(0)) == to_sec(maxtime),
              "deployed=%s expected=%ss" % (raw, to_sec(maxtime)))
        raw = out("get", jail, "bantime.multipliers").strip()
        check("%s.bantime.multipliers" % jail,
              " ".join(raw.split()) == " ".join(str(multipliers).split()),
              "deployed=%r expected=%r" % (raw, multipliers))

def ignoreip_check(jail):
    got, want = norm_ips(out("get", jail, "ignoreip")), expected_ignoreip()
    check("%s.ignoreip" % jail, got == want,
          "deployed=%s expected=%s" % (sorted(got), sorted(want)))

def logpath_check(jail, path):
    raw = out("get", jail, "logpath")
    check("%s.logpath" % jail, path in raw, "expected contains %s" % path)

# ── sshd jail (real port) ────────────────────────────────────────
if "sshd-real-port-resolvable" not in fails:
    numeric_jail_checks("sshd",
                        conf("F2B_BANTIME_SSH", "10m"),
                        conf("F2B_FINDTIME_SSH", "600"),
                        conf("F2B_MAXRETRY_SSH", "5"))
    increment_checks("sshd", conf_bool("F2B_INCREMENT", "true"),
                     conf("F2B_INCREMENT_MAXTIME", "3650d"),
                     conf("F2B_INCREMENT_MULTIPLIERS", "1 525600"))
    ignoreip_check("sshd")
    got = jail_ports("sshd")
    check("sshd.port", got == {rp},
          "deployed=%s expected={%s}" % (sorted(got), rp))

# ── sshesame jail (honeypot) ─────────────────────────────────────
if hp_enabled:
    if out("get", "sshesame", "bantime").strip() == "":
        check("sshesame.jail-present", False, "jail missing or not running")
    else:
        check("sshesame.jail-present", True)
        numeric_jail_checks("sshesame",
                            conf("HP_BANTIME", "30d"),
                            conf("HP_FINDTIME", "600"),
                            conf("HP_MAXRETRY", "3"))
        logpath_check("sshesame", conf("HP_LOGPATH", "/var/log/honeyfleet/sshesame/sshesame.json"))
        ignoreip_check("sshesame")
        got = jail_ports("sshesame")
        check("sshesame.port", got == {hp_port},
              "deployed=%s expected={%s}" % (sorted(got), hp_port))

# ── recidive jail ────────────────────────────────────────────────
rec_path = conf("RECIDIVE_LOGPATH", "/var/log/fail2ban.log")
if out("get", "recidive", "bantime").strip() == "":
    check("recidive.jail-present", False, "jail missing or not running")
else:
    check("recidive.jail-present", True)
    numeric_jail_checks("recidive",
                        conf("RECIDIVE_BANTIME", "3650d"),
                        conf("RECIDIVE_FINDTIME", "30d"),
                        conf("RECIDIVE_MAXRETRY", "2"))
    logpath_check("recidive", rec_path)
    ignoreip_check("recidive")

if fails:
    print("fail2ban-stack: verify FAIL (%d checks failed: %s)" % (len(fails), ", ".join(fails)))
    sys.exit(1)
print("fail2ban-stack: verify PASS (all deployed jail parameters match config)")
PY
    hf_f2b_repo_consumer_gate || rc=1
    if [ $rc -eq 0 ]; then
        hf_log "fail2ban-stack: verify PASS"
    else
        hf_warn "fail2ban-stack: verify FAIL — deployed fail2ban state does not match $HF_CONF_FILE (see FAIL lines above)"
    fi
    return $rc
}

hf_fail2ban_stack_status() {
    local st; st=$(systemctl is-active fail2ban 2>/dev/null || echo inactive)
    local line="fail2ban-stack: service=$st"
    local j b
    for j in sshd sshesame recidive; do
        if b=$(sudo fail2ban-client status "$j" 2>/dev/null | sed -n 's/^.*Currently banned:[[:space:]]*//p' | head -1); then
            line="$line $j(banned=${b:-0})"
        else
            line="$line $j(n/a)"
        fi
    done
    printf '%s\n' "$line"
}

hf_fail2ban_stack_remove() {
    # restore the pre-honeyfleet jail policy from the newest backup (keep 2)
    local bdir="$HF_STATE/backups/etc/fail2ban/jail.d"
    local prev; prev=$(ls -1t "$bdir/.honeyfleet.local".* 2>/dev/null | head -1 || true)
    if [ -n "$prev" ] && [ -f "$prev" ]; then
        sudo cp -a "$prev" "$JAIL_FILE"
        hf_log "fail2ban-stack: restored previous jail policy from $prev"
    else
        hf_backup "$JAIL_FILE" 2>/dev/null || true
        sudo rm -f "$JAIL_FILE"
        hf_log "fail2ban-stack: no previous jail policy — removed $JAIL_FILE"
    fi
    hf_backup "$FILTER_FILE" 2>/dev/null || true
    sudo rm -f "$FILTER_FILE"
    # reset dbpurgeage? intentionally kept: ban database retention is forensic state.
    sudo systemctl daemon-reload 2>/dev/null || true
    sudo fail2ban-client reload > /dev/null 2>&1 || true
    hf_registry 0 "$MOD"
    hf_log "fail2ban-stack: removed (ban database /var/lib/fail2ban kept for forensics)"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    case "${1:-}" in
        install) hf_fail2ban_stack_install ;;
        verify)  hf_fail2ban_stack_verify ;;
        status)  hf_fail2ban_stack_status ;;
        remove)  hf_fail2ban_stack_remove ;;
        *) hf_die "usage: fail2ban-stack.sh install|verify|status|remove" ;;
    esac
fi
