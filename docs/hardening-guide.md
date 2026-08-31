# Hardening Guide — the Anti-Lockout Manual

honeyfleet's most dangerous operation is also its most routine one: changing how your
server accepts *you*. This manual is the operator-facing half of the anti-lockout design
(the machine-facing half lives in `modules/ssh-hardening.sh` and
`modules/firewall-baseline.sh`).

The recovery hierarchy, in order, is:

1. **your running session** (never log out until the new state is proven),
2. **a second terminal** opened before the change,
3. **the provider console (VNC)** — out-of-band, works with no network path at all.

Everything below exists to make sure you never need rung 3.

---

## 1. Changing the SSH port — the four-rung ladder

### What the installer does automatically

When `HF_SSH_REAL_PORT` changes (or is `random` and unresolved), `install.sh install`
walks this ladder. Each rung fails closed: a failed rung rolls back every file touched so
far and leaves the running sshd untouched.

**Rung 0 — Warning first.** Before anything is written, the installer prints a banner:

```
ssh-hardening: PORT MIGRATION <old> -> <new>
KEEP A SECOND TERMINAL OPEN until you verified login via:
  ssh -p <new> <user>@<host>
The running session and the provider console are recovery paths.
```

Open that second terminal **now**, before continuing. It is your rung 1.

**Rung 1 — Validate the candidate config before anything runs.** The new drop-in is
written to `/etc/ssh/sshd_config.d/50-honeyfleet.conf` and validated with `sshd -t`.
A syntax error here means: rollback of the drop-in (and of any foreign `Port` directives
that were commented out), reload never happens, die. The running sshd keeps its old
in-memory config the whole time.

**Rung 2 — Prove a real login on the NEW port before the switch.** A standalone test
sshd is spawned on the new port (with `PidFile` isolation and the effective config from
`sshd -T`), and a real key-authentication login against it is attempted
(`ssh -p <new> ...@127.0.0.1 true`, BatchMode). Outcomes:

- login proven → proceed;
- no testable key identity (no authorized_keys for the invoking user or root) → **abort**,
  keep the old port, and tell you to deploy a key first. honeyfleet refuses to migrate to
  a port it cannot prove;
- login fails → abort, keep the old port.

During the migration window a temporary `honeyfleet-ssh-migration` ACCEPT rule pre-opens
the new port in the live firewall; it is removed on any abort.

**Rung 3 — Switch, then prove again, with automatic rollback.** Only now is sshd
reloaded. One second later the installer re-reads the effective port (`sshd -T`) and the
listener state (`ss -tln`). If the new port is not both effective and listening, every
changed file is restored from its timestamped backup (files created by this run are
deleted), `sshd -t` is re-checked, sshd is reloaded, and the migration dies.

Every file touched on the way — main `sshd_config`, drop-in, any foreign port directive —
had a `hf_backup` copy taken *before* it was modified. Backups live in
`/var/lib/honeyfleet/backups/<path>/` (newest 2 per file family, UTC-timestamped).

After a successful migration, the operator README is written to
`/etc/honeyfleet/README-ssh-hardening.txt` with the live port, the ladder, and the
rollback recipe. Read it once now, so you don't have to read it during an incident.

### Doing it manually (when you must)

If you ever have to change the port by hand, walk the same rungs:

```bash
# rung 0: second terminal open? provider console URL at hand?

# rung 1: candidate config must validate before any reload
sudo cp -a /etc/ssh/sshd_config.d/50-honeyfleet.conf \
           /var/lib/honeyfleet/backups/etc/ssh/sshd_config.d/50-honeyfleet.conf.manual.$(date -u +%Y%m%dT%H%M%SZ)
sudoedit /etc/ssh/sshd_config.d/50-honeyfleet.conf
sudo sshd -t || sudo cp -a <the-backup> /etc/ssh/sshd_config.d/50-honeyfleet.conf

# rung 2: prove the new port answers BEFORE reloading the main sshd
sudo /usr/sbin/sshd -p <new-port> -o PidFile=/tmp/sshd-test.pid   # temporary listener
ssh -p <new-port> <user>@<host> true && echo PROVEN
sudo kill $(cat /tmp/sshd-test.pid)

# rung 3: switch, verify, and know the rollback
sudo systemctl reload ssh
ss -tln | grep <new-port>                                          # listener present?
# if broken:
sudo cp -a <the-backup> /etc/ssh/sshd_config.d/50-honeyfleet.conf
sudo sshd -t && sudo systemctl reload ssh
```

Note that honeyfleet persists `random` port choices back into
`/etc/honeyfleet/honeyfleet.conf` (`HF_SSH_REAL_PORT="<chosen>"`) at install time —
hand-edits to the drop-in will be detected as drift by `install.sh verify` and rewritten
by the next `install`. Change the config, not the artifacts.

---

## 2. Source whitelists — why they are OFF by default

The default posture (`HF_SSH_SOURCE_RESTRICT=false`) is a deliberate lesson, not an
oversight: whitelisting your management source is the classic self-lockout. Home
broadband IPs rotate; a roaming egress IP changes; a laptop travels — and the whitelist that felt
safe on Monday locks you out on Friday, at the exact moment you need access most.

If you accept that tradeoff, opt in **with the safety net**:

```bash
# in /etc/honeyfleet/honeyfleet.conf — include EVERY source you might come from,
# in CIDR form; you can widen it later, you may not be able to log in to widen it
HF_SSH_SOURCE_RESTRICT=true
HF_SSH_MANAGEMENT_SOURCES="192.0.2.10 198.51.100.7 203.0.113.0/24"
```

Requirements the module enforces (all fail-closed):

- the list must be non-empty (`HF_SSH_SOURCE_RESTRICT=true` with an empty list refuses to
  run — that combination *is* the lockout);
- every entry must be a valid IPv4/CIDR (`hf_valid_cidr`); one malformed token aborts the
  whole whitelist;
- the rules are applied **behind a 60-second auto-rollback watchdog** (below);
- `firewall-baseline` builds the same rules into its desired set and verifies the drop
  rule is not shadowed by any foreign ACCEPT above it.

While the whitelist is live, port 22 (the honeypot feed) stays open — attackers keep
feeding the funnel; only the real port is restricted.

---

## 3. The 60-second watchdog

Every firewall-level change that could lock you out — the source whitelist, and the
entire firewall baseline apply — follows one pattern (the "b5 pattern", named after the
audited rollout that introduced it):

1. **Snapshot** the current live ruleset to
   `/var/lib/honeyfleet/firewall-pre-<UTC>.v4` (chmod 600) and back up the persisted
   `rules.v4`.
2. **Arm the watchdog**: a background `nohup` process sleeps 60 seconds; when it wakes,
   if the operator has not confirmed, it does `iptables-restore < snapshot` **and** copies
   the snapshot over the persisted `rules.v4`, then logs
   `honeyfleet-*-watchdog: ... ROLLED BACK`.
3. **Apply + verify** (`iptables-restore --test`, then apply, then a rule-by-rule
   self-check of the desired set).
4. **Disarm** only after verification passes (success flag + kill of the watchdog PID).
5. For the SSH whitelist specifically, the operator confirms by running:

   ```bash
   sudo /usr/local/lib/honeyfleet/ssh-hardening.sh confirm
   ```

   which writes the ok-flag and logs `source whitelist confirmed by operator`. If the
   flag never appears within 60 s, the whitelist is gone — memory and disk.

Two implementation details that matter under stress:

- A **stale ok-flag is removed before the rules are applied**, so a leftover flag file
  from a previous attempt can never silently disarm a fresh watchdog.
- The watchdog restores **both** the live ruleset and the persisted file, so a reboot
  cannot resurrect the dangerous state.

If you are ever unsure whether a whitelist is live: `install.sh status` shows
`restrict=on|off`, and `sudo iptables -S INPUT | grep honeyfleet-ssh-restrict` shows the
actual rules.

---

## 4. The provider console as the last rung

The provider console (VNC / "rescue console" in your VPS provider's web panel) reaches
the machine without any network path. It is the reason the ladder can be aggressive:
there is always one door that a misconfigured firewall cannot close.

When you are there, the on-box README (`/etc/honeyfleet/README-ssh-hardening.txt`) has
the recovery recipe:

```bash
# backups of every file honeyfleet touched:
ls -lt /var/lib/honeyfleet/backups/etc/ssh/
# restore the newest backup of the broken file:
sudo cp -a /var/lib/honeyfleet/backups/etc/ssh/sshd_config/.sshd_config.<TS> /etc/ssh/sshd_config
sudo sshd -t && sudo systemctl reload ssh
# firewall: restore the pre-change snapshot
sudo iptables-restore < /var/lib/honeyfleet/firewall-pre-<TS>.v4
```

Expect these two things on your first post-install connection — both are correct
behavior, not breakage:

- **`HOST KEY MISMATCH` warning when connecting to port 22.** The honeypot uses a
  deliberately different host key; a mismatch on 22 means the honeypot (or an imposter)
  answered — that is the tripwire signal. Pin the real key
  (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`) and connect to the real port.
- **Password login refused.** `PasswordAuthentication no` is the point. Use your key.

---

## 5. Discipline checklist (print this)

- [ ] Key-based login works from two machines before installing.
- [ ] Second terminal open before any `install.sh install` that touches sshd/firewall.
- [ ] `HF_SSH_MANAGEMENT_SOURCES` includes your current source — and a spare CIDR.
- [ ] After install: log in via the new port from the second terminal, then `exit` the old session.
- [ ] `install.sh verify` exits 0 before you close anything.
- [ ] Whitelist enabled? You ran `ssh-hardening.sh confirm` within 60 s.
- [ ] Provider console URL + credentials tested at least once, before you need them.
- [ ] `/etc/honeyfleet/README-ssh-hardening.txt` read once while calm.
