#!/usr/bin/env bash
# honeyfleet module: firewall-baseline — INPUT default-DROP baseline, per-port
# service allows with optional source whitelists, explicit blocked sources
# (every rule carries a provenance comment), optional outbound stratum/mining
# port block, SSH cooperation with modules/ssh-hardening.sh, and persistence.
#
# Anti-lockout: before ANY change the current ruleset is snapshotted and a 60s
# watchdog is armed (audited b5 pattern): if the module does not explicitly
# disarm it after a successful apply+verify, the watchdog restores the
# snapshot in memory AND on disk. Idempotency: when live state already matches
# the desired rule set (spec-level equality) the module is a NO-OP.
#
# The baseline OWNS the INPUT chain: on apply, pre-existing INPUT rules are
# replaced (fail2ban f2b-* jumps are preserved verbatim, deduplicated), the
# FORWARD chain and the OUTPUT policy are left untouched, and foreign OUTPUT
# rules are preserved. The persisted rules.v4 is stored WITHOUT f2b chains so
# that fail2ban re-inserts its jumps at boot (avoids duplicate mounts —
# 2026-08-29 regression lesson). IPv6 (ip6tables) is out of scope here.
#
# Contract: docs/MODULE-CONTRACT.md — hf_firewall_baseline_{install,verify,status,remove}.
set -uo pipefail
MOD=firewall-baseline
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"

# lib/common.sh hf_backup has a path mismatch: mkdir creates only dirname($f)
# while the cp target nests the basename as an extra directory component, so
# cp fails and backups silently never happen. Re-defined here with ONE
# consistent layout ($HF_STATE/backups/<path-sans-slash>/.$basename.<UTC>) and
# the same "keep newest 2" retention. Drop this override once lib/common.sh is fixed.

PERSIST_DIR=/etc/iptables
PERSIST_V4=$PERSIST_DIR/rules.v4
WATCHDOG_S=60
FWOK=$HF_STATE/fw-baseline.ok
MINING_PORTS_DEFAULT="3333 4444 5555 7777 8048 14444"   # stratum standard list (config overridable via HF_FW_MINING_PORTS)

DESIRED_IN=()
MINING_LINE=""
MINING_ENABLED=false
WHITELIST_PORTS=""
LIVE_SAVE=""

hf_root_check() { [ "$(id -u)" = 0 ] || hf_die "$MOD: must run as root (sudo)"; }

hf_strip_f2b() { grep -Ev '^(#|:f2b|-A f2b)| -j f2b-'; }

hf_norm() { hf_strip_f2b | sed -E 's/ \[[0-9]+:[0-9]+\]$//'; }

hf_norm_src() { # bare IPv4 → /32 so authored rules match iptables-save output
    case "$1" in */*) printf '%s' "$1" ;; *) printf '%s/32' "$1" ;; esac
}

hf_valid_cidr() {
    local ip=${1%%/*} mask="" o
    case "$1" in */*) mask=${1#*/} ;; esac
    [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for o in "${BASH_REMATCH[@]:1}"; do [ "$o" -le 255 ] || return 1; done
    [ -n "$mask" ] || return 0
    [[ "$mask" =~ ^[0-9]{1,2}$ ]] || return 1
    [ "$mask" -le 32 ] || return 1
}

hf_sshd_bin() { command -v sshd 2>/dev/null || printf '%s' /usr/sbin/sshd; }

# SSH port cooperation: config value wins; 'random' means ssh-hardening has
# not resolved/persisted it yet → fall back to the live sshd port, else 22.
hf_resolve_ssh_port() {
    local v live
    v=$(hf_conf SSH_REAL_PORT random)
    case "$v" in
        random)
            live=$("$(hf_sshd_bin)" -T 2>/dev/null | awk '$1 == "port" { print $2; exit }')
            case "$live" in ''|*[!0-9]*) live="" ;; esac
            if [ -n "$live" ] && [ "$live" != 22 ]; then printf '%s\n' "$live"; return 0; fi
            hf_warn "$MOD: HF_SSH_REAL_PORT=random and sshd not yet migrated — allowing tcp/22 only"
            printf '22\n' ;;
        ''|*[!0-9]*) hf_die "$MOD: HF_SSH_REAL_PORT invalid: '$v'" ;;
        *) printf '%s\n' "$v" ;;
    esac
}

# --------------------------------------------------------------- desired set
hf_build_desired() { # sets DESIRED_IN, MINING_LINE, MINING_ENABLED, WHITELIST_PORTS
    DESIRED_IN=(); MINING_LINE=""; MINING_ENABLED=false; WHITELIST_PORTS=""
    # base: stateful + loopback + icmp
    DESIRED_IN+=("-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment honeyfleet-base-established -j ACCEPT")
    DESIRED_IN+=("-A INPUT -i lo -m comment --comment honeyfleet-base-lo -j ACCEPT")
    DESIRED_IN+=("-A INPUT -p icmp -m comment --comment honeyfleet-base-icmp -j ACCEPT")
    # preserve live fail2ban jumps verbatim, deduplicated (f2b owns its chain mounts)
    local l
    while IFS= read -r l; do [ -n "$l" ] && DESIRED_IN+=("$l"); done < <(
        printf '%s\n' "$LIVE_SAVE" | awk '/^\*filter/ { f=1; next } /^\*/ { f=0 } f && /^-A INPUT/ && / -j f2b-/ { if (!seen[$0]++) print }')
    # explicit blocked sources, each with a provenance comment banned-<reason>
    local entry ip reason seen=""
    for entry in $(hf_conf FW_BLOCKED_SOURCES ""); do
        ip=${entry%%#*}; reason=${entry#*#}
        [ "$reason" = "$entry" ] && reason=manual
        hf_valid_cidr "$ip" || hf_die "$MOD: invalid blocked source '$ip' (use IPv4/CIDR, e.g. 203.0.113.0/24; entry: $entry)"
        reason=$(printf '%s' "$reason" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-64)
        case ",$seen," in *",$ip/$reason,"*) continue ;; esac
        seen="$seen,$ip/$reason"
        DESIRED_IN+=("-A INPUT -s $(hf_norm_src "$ip") -m comment --comment banned-$reason -j DROP")
    done
    # ssh: honeypot feed on 22 stays open; real port per config; optional source restriction
    local ssh_port s srcs restrict=false
    hf_conf_bool SSH_SOURCE_RESTRICT false && restrict=true
    ssh_port=$(hf_resolve_ssh_port)
    if [ "$restrict" = true ]; then
        srcs=$(hf_conf SSH_MANAGEMENT_SOURCES "")
        [ -n "$srcs" ] || hf_die "$MOD: HF_SSH_SOURCE_RESTRICT=true but HF_SSH_MANAGEMENT_SOURCES empty — refusing (self-lockout)"
        for s in $srcs; do hf_valid_cidr "$s" || hf_die "$MOD: invalid management source '$s'"; done
        # shares the comment convention with modules/ssh-hardening.sh — keep both in sync
        for s in $srcs; do
            DESIRED_IN+=("-A INPUT -s $(hf_norm_src "$s") -p tcp -m tcp --dport $ssh_port -m comment --comment honeyfleet-ssh-restrict-accept -j ACCEPT")
        done
        DESIRED_IN+=("-A INPUT -p tcp -m tcp --dport $ssh_port -m comment --comment honeyfleet-ssh-restrict-drop -j DROP")
        DESIRED_IN+=("-A INPUT -p tcp -m tcp --dport 22 -m comment --comment honeyfleet-ssh-allow-22 -j ACCEPT")
    else
        DESIRED_IN+=("-A INPUT -p tcp -m tcp --dport 22 -m comment --comment honeyfleet-ssh-allow-22 -j ACCEPT")
        [ "$ssh_port" = 22 ] || DESIRED_IN+=("-A INPUT -p tcp -m tcp --dport $ssh_port -m comment --comment honeyfleet-ssh-allow-real -j ACCEPT")
    fi
    # services (+ optional per-port source whitelist: HF_FW_SOURCE_WHITELIST_<port>)
    local svc port proto wl s2 accepted=""
    for svc in $(hf_conf FW_SERVICES ""); do
        case "$svc" in */*) port=${svc%%/*}; proto=${svc##*/} ;; *) port=$svc; proto=tcp ;; esac
        case "$proto" in tcp|udp) : ;; *) hf_die "$MOD: bad service entry '$svc' (expect port/tcp or port/udp)" ;; esac
        case "$port" in ''|*[!0-9]*) hf_die "$MOD: bad port in service entry '$svc'" ;; esac
        case ",$accepted," in *",$port/$proto,"*) continue ;; esac
        wl=$(hf_conf "FW_SOURCE_WHITELIST_${port}" "")
        if [ -n "$wl" ]; then
            for s2 in $wl; do hf_valid_cidr "$s2" || hf_die "$MOD: invalid whitelist source '$s2' for port $port"; done
            for s2 in $wl; do
                DESIRED_IN+=("-A INPUT -s $(hf_norm_src "$s2") -p $proto -m $proto --dport $port -m comment --comment honeyfleet-whitelist-accept-$port -j ACCEPT")
            done
            DESIRED_IN+=("-A INPUT -p $proto -m $proto --dport $port -m comment --comment honeyfleet-whitelist-drop-$port -j DROP")
            WHITELIST_PORTS="$WHITELIST_PORTS $port"
        else
            DESIRED_IN+=("-A INPUT -p $proto -m $proto --dport $port -m comment --comment honeyfleet-service-$port -j ACCEPT")
        fi
        accepted="$accepted,$port/$proto"
    done
    # if a whitelisted port collides with an ssh allow above, drop the blanket
    # ssh accept so the whitelist drop cannot be shadowed by our own rule
    local out=() r port_p
    for r in "${DESIRED_IN[@]}"; do
        case "$r" in
            *honeyfleet-ssh-allow-22*|*honeyfleet-ssh-allow-real*)
                port_p=$(printf '%s' "$r" | sed -n 's/.*--dport \([0-9]*\).*/\1/p')
                case ",$WHITELIST_PORTS," in *",$port_p,"*) hf_log "$MOD: tcp/$port_p is whitelisted — skipping blanket ssh allow"; continue ;; esac
                ;;
        esac
        out+=("$r")
    done
    DESIRED_IN=("${out[@]}")
    # outbound stratum/mining block
    if hf_conf_bool FW_MINING_PORT_BLOCK false; then
        local mp mports="" m
        mp=$(hf_conf FW_MINING_PORTS "$MINING_PORTS_DEFAULT")
        for m in $mp; do
            case "$m" in ''|*[!0-9]*) hf_die "$MOD: bad mining port '$m'" ;; esac
            case ",$mports," in *",$m,"*) continue ;; esac
            mports="$mports,$m"
        done
        if [ -n "$mports" ]; then
            mports=${mports#,}
            MINING_LINE="-A OUTPUT -p tcp -m multiport --dports $mports -m comment --comment mining-out-block -j DROP"
            MINING_ENABLED=true
        else
            hf_warn "$MOD: FW_MINING_PORTS resolved empty — mining block skipped"
        fi
    fi
}

# ----------------------------------------------------------- transform/apply
hf_transform_live() { # $1 = live iptables-save → full restore file on stdout
    local joined
    joined=$(printf '%s\n' "${DESIRED_IN[@]}")
    printf '%s\n' "$1" | awk -v inp="$joined" -v outapp="$MINING_LINE" '
        /^\*filter$/ { inf = 1; print; next }
        /^\*/        { inf = 0; print; next }
        inf && $0 == "COMMIT" {
            if (inpdone == 0 && length(inp) > 0) { print inp; inpdone = 1 }
            if (outpend == 1 && length(outapp) > 0) print outapp
            print; inf = 0; next
        }
        inf && /^:INPUT/    { print ":INPUT DROP [0:0]"; next }
        inf && /^-A INPUT/  { if (inpdone == 0) { if (length(inp) > 0) print inp; inpdone = 1 } next }
        inf && /^-A OUTPUT/ {
            outpend = 1
            if ($0 !~ /mining-out-block/ && $0 !~ /--comment honeyfleet-/) print
            next
        }
        { print }
    '
}

hf_collect_live_hf() {
    LIVE_HF_IN=$(iptables -S INPUT 2>/dev/null | grep -E -- '--comment (honeyfleet-|banned-|mining-out-block)' || true)
    LIVE_HF_OUT=$(iptables -S OUTPUT 2>/dev/null | grep -E -- '--comment (honeyfleet-|banned-|mining-out-block)' || true)
}

hf_check_shadow() { # $1 port — our whitelist-drop must precede any foreign ACCEPT for the port
    local port=$1 rule ports seen_drop=0
    while IFS= read -r rule; do
        case "$rule" in
            *"honeyfleet-whitelist-drop-$port"*) seen_drop=1; continue ;;
            *honeyfleet-*) continue ;;
            *"-j ACCEPT"*)
                ports=$(printf '%s' "$rule" | sed -n 's/.*--dports \([0-9,:]*\).*/\1/p')
                [ -n "$ports" ] || ports=$(printf '%s' "$rule" | sed -n 's/.*--dport \([0-9]*\).*/\1/p')
                [ -n "$ports" ] || continue
                case ",$ports," in *",$port,"*) [ "$seen_drop" = 0 ] && return 1 ;; esac
                ;;
        esac
    done < <(iptables -S INPUT 2>/dev/null)
    return 0
}

hf_state_matches() { # desired already built → 0 when live needs no changes
    [ "$(iptables -S INPUT 2>/dev/null | head -n 1)" = "-P INPUT DROP" ] || return 1
    local live_in live_out l found stale=0
    live_in=$(iptables -S INPUT 2>/dev/null)
    live_out=$(iptables -S OUTPUT 2>/dev/null)
    for l in "${DESIRED_IN[@]}"; do
        printf '%s\n' "$live_in" | grep -Fxq -- "$l" || return 1
    done
    if [ "$MINING_ENABLED" = true ]; then
        printf '%s\n' "$live_out" | grep -Fxq -- "$MINING_LINE" || return 1
    fi
    while IFS= read -r l; do
        [ -n "$l" ] || continue
        found=0
        printf '%s\n' "${DESIRED_IN[@]}" | grep -Fxq -- "$l" && found=1
        [ "$found" = 0 ] && [ -n "$MINING_LINE" ] && [ "$l" = "$MINING_LINE" ] && found=1
        if [ "$found" = 0 ]; then stale=1; break; fi
    done <<EOF
$LIVE_HF_IN
$LIVE_HF_OUT
EOF
    [ "$stale" = 0 ] || return 1
    for l in $WHITELIST_PORTS; do hf_check_shadow "$l" || return 1; done
    return 0
}

hf_fw_disarm() {
    printf 'ok\n' > "$FWOK" 2>/dev/null || true
    [ -n "${WDPID:-}" ] && kill "$WDPID" 2>/dev/null
    rm -f "$FWOK"
    WDPID=""
}

hf_persist_rules() { # write current live state, f2b-free, to rules.v4
    sudo mkdir -p "$PERSIST_DIR"
    if command -v netfilter-persistent >/dev/null 2>&1; then
        sudo netfilter-persistent save >/dev/null 2>&1 || true
    fi
    local tmp; tmp=$(mktemp)
    iptables-save 2>/dev/null | hf_strip_f2b > "$tmp"
    if [ -f "$PERSIST_V4" ] && cmp -s <(hf_norm < "$tmp") <(hf_norm < "$PERSIST_V4"); then
        rm -f "$tmp"; return 0
    fi
    hf_backup "$PERSIST_V4"
    sudo install -o root -g root -m 0644 "$tmp" "$PERSIST_V4"
    rm -f "$tmp"
    hf_log "$MOD: persisted $(grep -c '^-A' "$PERSIST_V4") rules to $PERSIST_V4 (f2b-free; fail2ban re-inserts at boot)"
}

hf_apply_with_watchdog() {
    local live=$1 transformed snap foreign WDPID=""
    transformed=$(hf_transform_live "$live")
    snap="$HF_STATE/firewall-pre-$(date -u +%Y%m%dT%H%M%SZ).v4"
    printf '%s\n' "$live" > "$snap"
    chmod 600 "$snap" 2>/dev/null || true
    hf_backup "$PERSIST_V4"
    rm -f "$FWOK"
    nohup bash -c "sleep $WATCHDOG_S; if [ -f '$FWOK' ]; then rm -f '$FWOK'; exit 0; fi; iptables-restore < '$snap' && cp '$snap' '$PERSIST_V4' 2>/dev/null; logger -t honeyfleet-fw-watchdog 'baseline ROLLED BACK (watchdog)'; rm -f '$FWOK'" >/dev/null 2>&1 &
    WDPID=$!
    hf_log "$MOD: snapshot saved ($snap); watchdog armed pid=$WDPID (auto-rollback in ${WATCHDOG_S}s unless disarmed)"
    if ! printf '%s\n' "$transformed" | iptables-restore --test 2>/dev/null; then
        hf_fw_disarm
        hf_die "$MOD: iptables-restore --test rejected the candidate ruleset — nothing applied"
    fi
    if ! printf '%s\n' "$transformed" | iptables-restore 2>/dev/null; then
        iptables-restore < "$snap" 2>/dev/null
        hf_fw_disarm
        hf_die "$MOD: iptables-restore failed — snapshot restored"
    fi
    # immediate self-verification before disarming the watchdog
    local l ok=1
    [ "$(iptables -S INPUT 2>/dev/null | head -n 1)" = "-P INPUT DROP" ] || ok=0
    for l in "${DESIRED_IN[@]}"; do
        iptables -C INPUT ${l#-A INPUT } 2>/dev/null || { ok=0; break; }
    done
    if [ "$ok" = 0 ]; then
        iptables-restore < "$snap" 2>/dev/null
        hf_fw_disarm
        hf_die "$MOD: post-apply verification failed — snapshot restored"
    fi
    hf_persist_rules
    hf_fw_disarm
    foreign=$(printf '%s\n' "$live" | awk '/^\*filter/ { f=1; next } /^\*/ { f=0 } f && /^-A INPUT/ && !/ -j f2b-/ && !/--comment (honeyfleet-|banned-|mining)/' | wc -l)
    hf_log "$MOD: applied baseline (INPUT rebuilt; $foreign pre-existing non-f2b INPUT rule(s) replaced; FORWARD/OUTPUT-policy untouched)"
}

hf_count_rules() {
    { iptables -S INPUT 2>/dev/null; iptables -S OUTPUT 2>/dev/null; } | grep -cE -- '--comment (honeyfleet-|banned-|mining-out-block)' || true
}

# ---------------------------------------------------------------- contract ops
hf_firewall_baseline_install() {
    hf_root_check
    command -v iptables >/dev/null 2>&1 || hf_die "$MOD: iptables not found (install iptables + iptables-persistent)"
    sudo mkdir -p "$HF_LIB" "$HF_ETC" "$HF_STATE"
    LIVE_SAVE=$(iptables-save 2>/dev/null)
    hf_build_desired
    hf_collect_live_hf
    if hf_state_matches; then
        if [ -f "$PERSIST_V4" ] && [ "$(hf_norm < "$PERSIST_V4")" = "$(printf '%s\n' "$LIVE_SAVE" | hf_norm)" ]; then
            hf_log "$MOD: already consistent (live + persisted) — NO-OP"
        else
            hf_persist_rules
            hf_log "$MOD: live rules already correct — persistence file refreshed"
        fi
        hf_registry 1 "$MOD"
        hf_log "$MOD: installed ($(hf_count_rules) honeyfleet rules enforced)"
        return 0
    fi
    hf_apply_with_watchdog "$LIVE_SAVE"
    hf_registry 1 "$MOD"
    hf_log "$MOD: installed ($(hf_count_rules) honeyfleet rules enforced; blocked sources: $(hf_conf FW_BLOCKED_SOURCES '' | wc -w); mining block: $MINING_ENABLED)"
}

hf_firewall_baseline_verify() {
    hf_root_check
    command -v iptables >/dev/null 2>&1 || { hf_warn "$MOD: verify FAIL (iptables missing)"; return 1; }
    local rc=0 fails="" live_in live_out l entry ip reason
    LIVE_SAVE=$(iptables-save 2>/dev/null)
    live_in=$(iptables -S INPUT 2>/dev/null)
    live_out=$(iptables -S OUTPUT 2>/dev/null)
    hf_build_desired
    hf_collect_live_hf

    [ "$(printf '%s\n' "$live_in" | head -n 1)" = "-P INPUT DROP" ] || fails="$fails input-policy-not-DROP"
    if [ -f "$PERSIST_V4" ]; then
        [ "$(hf_norm < "$PERSIST_V4")" = "$(printf '%s\n' "$LIVE_SAVE" | hf_norm)" ] || fails="$fails persisted!=live"
    else
        fails="$fails persisted-file-missing"
    fi
    for l in "${DESIRED_IN[@]}"; do
        printf '%s\n' "$live_in" | grep -Fxq -- "$l" || { fails="$fails missing-rule"; break; }
    done
    # named gate: every blocked source must be enforced WITH its banned-<reason> comment
    for entry in $(hf_conf FW_BLOCKED_SOURCES ""); do
        ip=${entry%%#*}; reason=${entry#*#}; [ "$reason" = "$entry" ] && reason=manual
        reason=$(printf '%s' "$reason" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-64)
        printf '%s\n' "$live_in" | grep -F -- "-s $(hf_norm_src "$ip")" | grep -qF -- "banned-$reason" || fails="$fails banned-$ip-no-comment-rule"
    done
    if [ "$MINING_ENABLED" = true ]; then
        printf '%s\n' "$live_out" | grep -Fxq -- "$MINING_LINE" || fails="$fails mining-out-block-missing"
    elif [ -n "$(printf '%s\n' "$live_out" | grep -F -- 'mining-out-block' || true)" ]; then
        fails="$fails mining-block-stale(config-disabled)"
    fi
    local desired_all; desired_all=$(printf '%s\n' "${DESIRED_IN[@]}"); [ -n "$MINING_LINE" ] && desired_all="$desired_all"$'\n'"$MINING_LINE"
    while IFS= read -r l; do
        [ -n "$l" ] || continue
        printf '%s\n' "$desired_all" | grep -Fxq -- "$l" || { fails="$fails stale-honeyfleet-rule"; break; }
    done <<EOF
$LIVE_HF_IN
$LIVE_HF_OUT
EOF
    for l in $WHITELIST_PORTS; do hf_check_shadow "$l" || fails="$fails whitelist-$l-shadowed"; done
    if [ -z "$fails" ]; then
        hf_log "$MOD: verify PASS (input=DROP persisted=match honeyfleet-rules=$(hf_count_rules) mining=$MINING_ENABLED)"
    else
        hf_warn "$MOD: verify FAIL ($fails)"
        rc=1
    fi
    return $rc
}

hf_firewall_baseline_status() {
    local policy persisted
    policy=$(iptables -S INPUT 2>/dev/null | head -n 1 | awk '{ print $3 }')
    if [ -f "$PERSIST_V4" ] && [ "$(hf_norm < "$PERSIST_V4")" = "$(printf '%s\n' "$(iptables-save 2>/dev/null)" | hf_norm)" ]; then
        persisted=match
    else
        persisted=stale
    fi
    printf '%s: input-policy=%s services=%s blocked-sources=%s mining=%s honeyfleet-rules=%s persisted=%s\n' \
        "$MOD" "${policy:-unknown}" \
        "$(hf_conf FW_SERVICES '' | wc -w)" \
        "$(hf_conf FW_BLOCKED_SOURCES '' | wc -w)" \
        "$(hf_conf_bool FW_MINING_PORT_BLOCK false && echo on || echo off)" \
        "$(hf_count_rules)" "$persisted"
}

hf_remove_commented_rules() {
    local chain=$1 r
    while :; do
        r=$(iptables -S "$chain" 2>/dev/null | grep -m1 -E -- '--comment (honeyfleet-|banned-|mining-out-block)') || break
        iptables -D "$chain" ${r#"-A $chain "} 2>/dev/null || break
    done
}

hf_firewall_baseline_remove() {
    hf_root_check
    if command -v iptables >/dev/null 2>&1; then
        hf_remove_commented_rules INPUT
        hf_remove_commented_rules OUTPUT
        if [ "$(iptables -S INPUT 2>/dev/null | head -n 1)" = "-P INPUT DROP" ]; then
            iptables -P INPUT ACCEPT
            hf_warn "$MOD: INPUT policy reset to ACCEPT — the node is no longer protected by the baseline"
        fi
        hf_persist_rules
    fi
    hf_registry 0 "$MOD"
    hf_log "$MOD: removed (backups kept under $HF_STATE/backups; f2b chains untouched)"
}

case "${1:-}" in
    install) hf_firewall_baseline_install ;;
    verify)  hf_firewall_baseline_verify ;;
    status)  hf_firewall_baseline_status ;;
    remove|uninstall) hf_firewall_baseline_remove ;;
    *) hf_die "usage: firewall-baseline.sh install|verify|status|remove" ;;
esac
