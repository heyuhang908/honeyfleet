#!/usr/bin/env bash
# honeyfleet common library — sourced by install.sh and every module.
# Rules: hf_conf is the ONLY way a module reads configuration (single source);
#        hf_die on unrecoverable errors; hf_backup before touching any file.

HF_ETC=/etc/honeyfleet
HF_LIB=/usr/local/lib/honeyfleet
HF_STATE=/var/lib/honeyfleet

hf_log()  { printf '[honeyfleet] %s\n' "$*"; }
hf_warn() { printf '[honeyfleet][WARN] %s\n' "$*" >&2; }
hf_die()  { printf '[honeyfleet][ERROR] %s\n' "$*" >&2; exit 1; }

# hf_conf KEY [default] — read a value from the loaded config
hf_conf() {
    local key=$1 def=${2:-}
    local -n ref="HF_$key" 2>/dev/null || { printf '%s' "$def"; return; }
    local v=${ref:-$def}
    printf '%s' "$v"
}

# hf_conf_bool KEY [default-bool] — normalizes true/false/yes/no/1/0
hf_conf_bool() {
    local v; v=$(hf_conf "$1" "${2:-false}")
    case "$(printf '%s' "$v" | tr '[:upper:]' '[:lower:]')" in
        true|yes|1) return 0 ;;
        *)          return 1 ;;
    esac
}

# hf_backup FILE — keep the most recent 2 backups per file (retention policy)
# NOTE: failures are WARNED (never silent) — a backup that silently doesn't
# happen is worse than no backup (2026-08-30 review finding).
#
# Falls back to sudo for the scattered-sudo call paths: a module may run against
# root-owned files without being root itself. fail2ban-stack and honeypot-ssh
# used to carry private copies of this function to get that fallback, under a
# comment claiming lib's version had a path bug. It did not — the mkdir and the
# cp target always agreed — so the copies only guaranteed the two layouts could
# drift. Folded back here 2026-09-29; the layout is unchanged (the doubled slash
# in $dest_dir collapses in the filesystem, so existing backups are still found).
hf_backup() {
    local f=$1 b dest_dir
    [ -f "$f" ] || return 0
    b=$(basename "$f")
    dest_dir="$HF_STATE/backups/$(dirname "$f")"
    mkdir -p "$dest_dir" 2>/dev/null || sudo mkdir -p "$dest_dir" 2>/dev/null || {
        hf_warn "hf_backup: cannot create $dest_dir (need root?)"
        return 1
    }
    cp -a "$f" "$dest_dir/.$b.$(date -u +%Y%m%dT%H%M%SZ)" 2>/dev/null \
        || sudo cp -a "$f" "$dest_dir/.$b.$(date -u +%Y%m%dT%H%M%SZ)" 2>/dev/null \
        || { hf_warn "hf_backup: copy failed for $f"; return 1; }
    # retention: keep newest 2 per family
    ls -1t "$dest_dir/.$b".* 2>/dev/null | tail -n +3 | while read -r old; do
        rm -f "$old" 2>/dev/null || sudo rm -f "$old" 2>/dev/null
    done
    return 0
}

# hf_install_if_changed CONTENT TARGET MODE — deploy TARGET unless it already
# matches. Returns 0 when written, 1 when it was already identical (the caller's
# NO-OP path).
#
# The comparison and the write live in ONE function on purpose: they must use the
# same printf form. Compare with a trailing newline and write without one (or the
# reverse) and the two differ by exactly one byte, the comparison never matches,
# and the caller's NO-OP branch becomes unreachable code.
# modules/waterline-alerts.sh had precisely that asymmetry from v1.0.0 to 1.0.2
# and silently re-deployed on every install.
hf_install_if_changed() {
    local content=$1 target=$2 mode=$3 tmp
    if [ -f "$target" ] && printf '%s
' "$content" | sudo cmp -s - "$target"; then
        return 1
    fi
    tmp=$(mktemp)
    printf '%s
' "$content" > "$tmp"
    hf_backup "$target"
    sudo install -o root -g root -m "$mode" "$tmp" "$target"
    rm -f "$tmp"
    return 0
}

# hf_copy_if_changed SRC DST MODE — the same idea for a file that already exists
# in the repo (module sources, the notifier library).
hf_copy_if_changed() {
    local src=$1 dst=$2 mode=$3
    if [ -f "$dst" ] && sudo cmp -s "$src" "$dst"; then
        return 1
    fi
    hf_backup "$dst"
    sudo install -o root -g root -m "$mode" "$src" "$dst"
    return 0
}

# hf_unit_write NAME UNITFILE — install a systemd unit atomically + daemon-reload
hf_unit_write() {
    local name=$1 tmp
    tmp=$(mktemp)
    cat > "$tmp"
    sudo install -o root -g root -m 0644 "$tmp" "/etc/systemd/system/$name"
    rm -f "$tmp"
    sudo systemctl daemon-reload
}

# hf_requires MODULE — declared dependency: exits with guidance if missing
hf_requires() {
    local dep=$1
    if ! grep -q "hf_mod_${dep}_installed=1" /var/lib/honeyfleet/registry 2>/dev/null; then
        hf_die "module '$dep' is required but not installed — run: install.sh --only $dep"
    fi
}

# hf_registry MARK — record module install state
hf_registry() {
    local mark=$1 mod=$2
    mkdir -p "$HF_STATE"
    touch /var/lib/honeyfleet/registry
    grep -v "hf_mod_${mod}_" /var/lib/honeyfleet/registry > /var/lib/honeyfleet/registry.tmp 2>/dev/null || true
    mv /var/lib/honeyfleet/registry.tmp /var/lib/honeyfleet/registry
    printf 'hf_mod_%s_installed=%s\n' "$mod" "$mark" >> /var/lib/honeyfleet/registry
}

# hf_registry_installed_modules [FILE] -- module names whose mark is exactly 1.
#
# The mark is NOT a flag you may ignore when it is 0: every module's remove
# path writes `hf_registry 0 "$MOD"`, so the file stays behind as a record of
# what was once installed.  A reader that strips only `_installed=1` then sees
# a `=0` line as a literal module name -- "fail2ban-stack-installed=0" -- and
# the consistency gate fails with "module file missing on this checkout" after
# any uninstall.  The failure is bogus and never self-heals: reinstalling a
# DIFFERENT module does not clear the stale line.  Match `=1` anchored, then
# print the captured name only.
hf_registry_installed_modules() {
    local file=${1:-/var/lib/honeyfleet/registry}
    [ -f "$file" ] || return 0
    sed -n 's/^hf_mod_\(.*\)_installed=1$/\1/p' "$file" | tr '_' '-'
}
