# Threat Model

Scope: honeyfleet v1.0 — honeypot-fronted SSH defense, fleet-wide self-monitoring, and the
consistency gate that keeps the monitoring honest. This document states what we protect,
who we defend against, where trust ends, which controls map to which threat, and — equally
important — what the system does **not** protect against.

Design principle (Kerckhoffs's principle): **the design is public, the configuration is
secret.** Everything in this repository — including this file — is assumed known to the
attacker. No mechanism below relies on obscurity of the code; every mechanism relies on
secrecy of configuration (the real SSH port, management sources, notifier tokens, the
central host) and on correctness of enforcement.

## 1. Assets

| Asset | Where | Why it matters |
|---|---|---|
| A1 — SSH access to the real sshd | `HF_SSH_REAL_PORT`, hardened drop-in `/etc/ssh/sshd_config.d/50-honeyfleet.conf` | The operator's only interactive path to the node. Loss = lockout or takeover. |
| A2 — sshd / fail2ban / firewall policy integrity | `/etc/ssh/sshd_config*`, `/etc/fail2ban/jail.d/honeyfleet.local`, `/etc/iptables/rules.v4` | A silent weakening of any of these silently removes the defense. |
| A3 — honeypot evidence logs | `/var/log/honeyfleet/sshesame/` (JSON, logrotated) | Attacker sources, credentials they try, timing — the early-warning value of tier 1. |
| A4 — fleet status data | `/var/lib/honeyfleet/fleet/<agent>.json` on the central | The operator's single pane of glass; tampering here hides incidents fleet-wide. |
| A5 — honeyfleet config + notifier credentials | `/etc/honeyfleet/honeyfleet.conf` | Contains the real port, management whitelist, and alert-channel tokens. |
| A6 — ban database | `/var/lib/fail2ban/fail2ban.sqlite3` | Bans surviving a reboot is what makes the funnel durable. |
| A7 — backups | `/var/lib/honeyfleet/backups/` (newest 2 per file family) | The rollback ladder's last local rung. |
| A8 — availability of the operator's own access | running session, second terminal, provider console | Not a file — a *state*. Every anti-lockout mechanism exists to preserve it. |

## 2. Attacker profiles

### T1 — Mass scanner / opportunistic brute-forcer (highest volume)

Internet-wide scanning for open SSH; credential stuffing against anything that answers.

- Sees: port 22 → the honeypot (tier 1). Their auth attempts are accepted, logged, and
  banned (3 tries / 10 min → 30 days, `HF_HP_*`).
- Sees: the real port only if it collides with a scan range → fail2ban `sshd` jail
  (5 tries → escalating bans up to 3650 days, `HF_F2B_*`).
- Re-offenders across ports and time: `recidive` jail (2 bans in 30 days → all-ports ban,
  up to 3650 days, `HF_RECIDIVE_*`).
- Residual: scanners never "win", they are the signal source. Their only real cost to the
  operator is noise, which the cooldowns and dedup suppress.

### T2 — Targeted attacker

Knows the operator, the stack, and this repository. Will fingerprint before attacking.

- Faces: default-DROP INPUT policy, a real port that is random per node and absent from
  any public listing, per-service ports that can be source-whitelisted
  (`HF_FW_SOURCE_WHITELIST_<port>`), explicit bans with provenance
  (`HF_FW_BLOCKED_SOURCES`, `ip#reason`), outbound mining-port block.
- **Can** fingerprint the honeypot (see §5.1) and infer that port 22 is fake. This costs
  them the element of surprise, not us the defense: the real surface is the moved,
  hardened sshd, not the banner.
- May attack the *management plane*: the operator's home IP, the central node, the
  notifier accounts. Controls: management sources are fail2ban `ignoreip` but never a
  blind trust anchor for the firewall unless explicitly whitelisted; alerts go to an
  out-of-band channel; the central accepts only validated, replay-checked snapshots.

### T3 — Insider misoperation / the operator themselves (most likely "attacker")

Statistics from the incidents that produced this codebase are unambiguous: the
overwhelming majority of outages were self-inflicted — a mistyped whitelist, a stale
config assumption, a port change without a proof step.

- Controls: the four-rung anti-lockout ladder (`docs/hardening-guide.md`), source
  whitelist default-OFF, 60 s auto-rollback watchdogs on every firewall/whitelist change,
  `sshd -t` and `iptables-restore --test` gates, second-channel login proof before any
  sshd switch, timestamped backups of every touched file, and an on-box README
  (`/etc/honeyfleet/README-ssh-hardening.txt`) documenting the recovery paths.
- The consistency gate exists for the same reason: honest counters and verify gates catch
  the "I changed the config but nothing actually changed" class of self-deception.

## 3. Trust boundaries

```
Internet (untrusted)
   │  port 22 — honeypot (accept-all, User=nobody, NoNewPrivileges, ProtectSystem=full)
   ▼
┌────────────────────────── node ──────────────────────────┐
│  fail2ban funnel (sshd/sshesame/recidive)                  │
│  firewall-baseline (INPUT DROP)      real sshd (moved)    │
│  file-integrity · waterline · local notifiers              │
└──────────────┬───────────────────────────────────────────┘
               │ SSH push key (forced command, no forwarding, no pty)
               ▼
        central node (HF_ROLE=central)
        receive-fleet.py: schema+timestamp validation, anti-replay,
        per-agent JSON store, stale scan, fleet summary via notifiers
```

**B1 — Internet vs honeypot.** The honeypot trusts nothing it receives; it runs as
`nobody` in a systemd sandbox with no write access outside its log dir. Compromise of the
honeypot yields the attacker a low-privilege foothold on a system with no secrets — and an
entry in the logs.

**B2 — Agent vs central.** The central trusts an agent snapshot only after validating
schema, hostname shape, and timestamps: a timestamp older than the stored one is rejected
(replay), a timestamp > 120 s in the future is rejected (skew abuse). A compromised
**agent** can poison only its own snapshot — it cannot read other agents' data, and its
lies are bounded by its last honest state. A compromised **central** can hide alerts, but
agents keep their local defenses and local alerts (waterline + notifiers run on every
node) — silencing the central does not silence the node.

**B3 — The federation assumption: central and agent do not fall simultaneously.**
The fleet design is honest about this: honeyfleet's self-monitoring assumes that the
central and any given agent are not compromised *at the same time by the same actor*.
Under that assumption, an attacker who suppresses monitoring on one side is exposed by the
other: stop the agent's pushes → central flags `fleet agent stale` within 10× the push
interval; tamper with the central → agents' local defenses and alerts continue, and the
central's fleet state can be re-derived from the agents' pushes. This is a detection
assumption, not a prevention guarantee; §5.2 states what happens when it is violated.

**B4 — Config vs code.** Code is public (Kerckhoffs); config is secret and lives only on
the node (`/etc/honeyfleet/honeyfleet.conf`, 0600 by umask of the operator's copy step).
No secret belongs in this repository — contract rule 7, enforced in review and CI.

## 4. Control mapping

| Threat | Control | Where |
|---|---|---|
| T1 scan/brute-force port 22 | Honeypot + `sshesame` jail | `honeypot-ssh`, `fail2ban-stack` (`HF_HP_*`) |
| T1/T2 brute-force real port | Hardened sshd (password auth off, MaxAuthTries) + `sshd` jail with escalating bans | `ssh-hardening`, `fail2ban-stack` (`HF_SSH_*`, `HF_F2B_*`) |
| T1/T2 repeat offenders | `recidive` all-ports escalation | `fail2ban-stack` (`HF_RECIDIVE_*`) |
| T2 service exposure | Default-DROP baseline, per-port allow, optional source whitelist with anti-shadowing check | `firewall-baseline` (`HF_FW_SERVICES`, `HF_FW_SOURCE_WHITELIST_<port>`) |
| T2 known-bad sources | Explicit bans with `banned-<reason>` provenance comments, verify-enforced | `firewall-baseline` (`HF_FW_BLOCKED_SOURCES`) |
| T2 cryptojacking egress | Outbound stratum/mining port block | `firewall-baseline` (`HF_FW_MINING_PORT_BLOCK`, `HF_FW_MINING_PORTS`) |
| T2 policy tampering | file-integrity on `/etc/ssh`, `/etc/fail2ban`, systemd units; drift is alerted, never auto-rebased | `file-integrity` (`HF_FI_TARGETS`) |
| T2 honeypot binary swap | Pinned upstream tag + fail-closed SHA256 gate (operator-overridable, reviewed) | `honeypot-ssh` (`HF_HP_SSHESAME_SHA256`) |
| T2 log drowning / tampering | logrotate (weekly + 10M, keep 8), evidence scoped to the current log window | `honeypot-ssh` |
| T3 self-lockout | Four-rung ladder, whitelist default-OFF, 60 s watchdogs, second-channel proof, backups | `ssh-hardening`, `firewall-baseline`; `docs/hardening-guide.md` |
| T3 config↔reality drift | Per-module verify gates + fleet consistency gate after install | every module, `install.sh verify` |
| T3 silent monitoring decay | Honest counters, dangling-target warnings, consumer enumeration, "unconfigured ≠ failure" notifier semantics | `file-integrity`, `MODULE-CONTRACT` rules 4–5, `notifiers` |
| T1/T2/T3 node goes dark or lies | Federation stale detection (10× push interval), recovery announcements, deduped summary with heartbeat | `federation` (`HF_PUSH_INTERVAL`, `HF_FLEET_SUMMARY_DEDUPE`) |
| Resource exhaustion killing the defense | Self-heal ordering: auto-restart or dedicated health probe; honeypot restart after 2 failed probes with cooldown; timers `Persistent=true` | `honeypot-ssh`, `MODULE-CONTRACT` rule 9 |

## 5. Known boundaries (what honeyfleet does NOT do)

### 5.1 The honeypot is fingerprintable — by design tradeoff

`sshesame` accepts every auth and offers decoy TCP services; a determined scanner can
detect this (e.g. by observing that any password "works", by behavioral timing, or by
known sshesame traits). The banner is calibrated byte-for-byte from the real sshd and the
host key is deliberately distinct (a known-hosts mismatch on port 22 is the operator's
tripwire), so passive banner matching does not trivially expose it — but active probing
can. Accepted residual risk: tier 1's value is early warning + ban feed, not deception of
a skilled targeted attacker. Do not rely on the honeypot to "hide" the real port; rely on
the firewall and the port randomization.

### 5.2 Root compromise = host-local detection failure

Every host-local control (file-integrity, timers, fail2ban, local logs) runs as root or
can be stopped by root. An attacker with root can rebase the integrity baseline, stop the
timers, edit the logs, and keep the fleet pushes alive with the node's own push key —
from that moment, host-local detection is theirs. honeyfleet's honest claims at that
point are only:

- the honeypot's `Restart=always` + health probe and the timers make *casual* suppression
  loud (state must be actively forged, which takes effort and leaves forensic traces);
- the fleet assumption (B3) gives one out-of-band signal — a node that stops pushing or
  pushes contradictory data stands out against the rest of the fleet;
- everything else (ban history, integrity state, backups, journals) is kept on removal
  for forensics, not for real-time defense.

The real mitigation for root compromise is out of scope for a host agent: out-of-band
logging, provider-console forensics, and image-based recovery. honeyfleet tells you
*when* to reach for those; it cannot replace them.

### 5.3 OOM is a designed sacrifice, not a failure mode

Under memory pressure, something must die. honeyfleet's ordering rule (contract rule 9):
everything it deploys either auto-restarts (`Restart=always`/`on-failure`) or ships its
own health probe with cooldowns, and the OOM-sacrifice targets must be the
fastest-healing components. In practice: the honeypot is the intended first victim
(seconds to recover via `Restart=always` + probe), while long-lived management components
get cgroup caps so a leak dies inside its own cgroup instead of triggering a global OOM
kill of the wrong process. The waterline memory alert (`HF_WATERLINE_MEM`) is the early
signal before the kernel ever gets involved. If you add your own services to the node,
give them the same treatment — or accept that they are candidates to be sacrificed.

### 5.4 IPv6 is out of scope of the firewall baseline

`firewall-baseline` manages IPv4 (`iptables`); `ip6tables` is deliberately untouched.
If the node has public IPv6, the baseline does not protect it — model this explicitly in
your own threat assessment (disable IPv6, or manage ip6tables separately) before
exposing the node.

### 5.5 The central is a component, not an authority

Fleet summaries are deduped and heartbeat-bearing; stale detection is a timer, not a
judgment call. But the central holds no secrets beyond the fleet JSONs and the push user.
Treat it as a monitored console, back it up, and do not concentrate credentials there.
