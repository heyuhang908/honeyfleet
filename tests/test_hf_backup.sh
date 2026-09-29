#!/usr/bin/env bash
# hf_backup — and the retention policy that is supposed to ride on it.
#
# docs/MODULE-CONTRACT.md rule 10: "Keep the most recent 2 backups per file
# family (hf_backup enforces this)." Rule 1: "Any file you write -> hf_backup
# first." Both hold only if the retention glob matches the layout hf_backup
# actually writes, so layout and retention are asserted together — a mismatch
# would make retention a silent no-op (unbounded backup growth) while every
# other test still passed.

set -uo pipefail
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=../lib/common.sh
. "$HF_ROOT/lib/common.sh"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

HF_STATE="$work/state"
target="$work/etc/thing.conf"
mkdir -p "$(dirname "$target")"
printf 'v1\n' > "$target"

# ── a missing file is not an error ──────────────────────────────────────────
# Every module's remove path calls hf_backup on paths that may not exist.
t_ok "backing up a missing file is a no-op, not an error" hf_backup "$work/nope.conf"
t_eq "a missing file wrote nothing" "0" "$(find "$HF_STATE" -type f 2>/dev/null | wc -l | tr -d ' ')"

# ── layout: where does the backup land, and is it the right content? ────────
hf_backup "$target"
dest_dir="$HF_STATE/backups/$(dirname "$target")"
saved=$(find "$dest_dir" -type f -name '.thing.conf.*' 2>/dev/null | head -1)
t_ok "a backup file was created" test -n "$saved"
if [ -n "$saved" ]; then
    t_eq "the backup holds the original content" "v1" "$(cat "$saved")"
fi

# ── retention: seed three older backups, add one, keep the newest two ───────
rm -f "$dest_dir"/.thing.conf.*
mkdir -p "$dest_dir"
for n in 1 2 3; do
    printf 'old%s\n' "$n" > "$dest_dir/.thing.conf.2026010${n}T000000Z"
done
touch -d '2026-01-01T00:00:00Z' "$dest_dir/.thing.conf.20260101T000000Z"
touch -d '2026-01-02T00:00:00Z' "$dest_dir/.thing.conf.20260102T000000Z"
touch -d '2026-01-03T00:00:00Z' "$dest_dir/.thing.conf.20260103T000000Z"

hf_backup "$target"

count=$(find "$dest_dir" -type f -name '.thing.conf.*' | wc -l | tr -d ' ')
t_eq "retention keeps exactly the newest 2" "2" "$count"
t_ok "the oldest backup was pruned" test ! -f "$dest_dir/.thing.conf.20260101T000000Z"
t_ok "the second-oldest backup was pruned" test ! -f "$dest_dir/.thing.conf.20260102T000000Z"
t_ok "the previously-newest backup survived" test -f "$dest_dir/.thing.conf.20260103T000000Z"

# ── retention is per file family, not global ────────────────────────────────
# Sibling files must not evict each other, or a chatty file starves a quiet one.
other="$work/etc/other.conf"
printf 'x\n' > "$other"
hf_backup "$other"
t_ok "a sibling file gets its own backup" \
    test -n "$(find "$dest_dir" -type f -name '.other.conf.*' 2>/dev/null | head -1)"
t_eq "the first family still has exactly 2" "2" "$(find "$dest_dir" -type f -name '.thing.conf.*' | wc -l | tr -d ' ')"

t_done "hf_backup"
