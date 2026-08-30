# honeyfleet

**Honeypot-fronted SSH defense with a three-tier enforcement funnel, fleet-wide self-monitoring, and a consistency gate that keeps the monitoring itself honest — one config, N servers, pluggable alerting.**

honeyfleet turns a stock Ubuntu/Debian server into a hard target: the real sshd moves to a
randomized high port behind a default-DROP firewall, a fake SSH (the honeypot) inherits port 22
and feeds an escalating fail2ban funnel, and every node continuously self-monitors its own
defenses — pushing status to a central node so that a silenced monitor is itself an alert.

Defensive tooling only. No proxy, tunneling-for-circumvention, or traffic-obfuscation code is
included or accepted (see `docs/MODULE-CONTRACT.md` rule 8).

---

## ⚠️ Read this before you install (anti-lockout)

honeyfleet deliberately makes your server **hard to reach** — including for you. Password SSH
login is disabled, the real SSH port moves, and the firewall defaults to DROP. Before running
the installer:

1. **Keep a second terminal open.** Your running session is recovery path #1.
2. **Make key-based login work first.** If you can only log in with a password, fix that
   before installing — the installer disables password authentication.
3. **Know your provider console (VNC) URL.** It is the out-of-band recovery path that works
   even when the network path is broken.
4. **Source whitelists are OFF by default on purpose** (dynamic-IP self-lockout lesson).
   If you opt in with `HF_SSH_SOURCE_RESTRICT=true`, a 60-second watchdog automatically
   rolls the whitelist back unless you run `sudo /usr/local/lib/honeyfleet/ssh-hardening.sh
   confirm` in time. Full manual: [`docs/hardening-guide.md`](docs/hardening-guide.md).

Every change that touches sshd or the firewall goes through the same ladder: validate the
candidate config (`sshd -t` / `iptables-restore --test`) → prove a real login through a
standalone test sshd on the NEW port before the switch → keep a timestamped backup of every
touched file → roll back automatically on any failed step. If anything fails, the previous
working state is restored and the running sshd is never left holding a broken config.

## Quick Start

```bash
# 0. clone / copy the repo onto the server (as root or via sudo)

# 1. copy the config — the single source of truth
sudo mkdir -p /etc/honeyfleet
sudo cp config/honeyfleet.conf.example /etc/honeyfleet/honeyfleet.conf
sudoedit /etc/honeyfleet/honeyfleet.conf      # set HF_ROLE and the keys you care about

# 2. install (the --role value must match HF_ROLE in the config)
sudo ./install.sh install --role agent        # or: --role central

# 3. verify — consistency gates + end-to-end checks; a non-zero exit means fix it, don't walk away
sudo ./install.sh verify

# anytime: one-line health per module
sudo ./install.sh status
```

The installer is a dispatcher: every parameter comes from the one config file, modules are
idempotent (re-running install is a NO-OP on a consistent system), and dependencies are
declared and resolved automatically (`./install.sh plan` prints the order without changes).

## The three-tier enforcement funnel

| Tier | What answers | What happens |
|---|---|---|
| 1. Honeypot (port 22) | A fake SSH server (`sshesame`, SHA256-pinned) | ANY touch is evidence; 3 attempts in 10 min = 30-day ban; the banner is calibrated byte-for-byte from your real sshd so the fake looks real |
| 2. Real sshd (moved port) | Your actual sshd, hardened (password auth off) | Brute force against the real port: 5 failures = escalating ban (multipliers up to 3650 days) |
| 3. Recidive (repeat offenders) | fail2ban recidive jail | Anyone re-banned repeatedly within 30 days loses **all ports** for up to 10 years |

Port 22 stays open **by design** — it is the honeypot feed. Every connection to it is an
attacker or a misconfigured client, and both are useful signals.

## Modules (8)

| Module | One line |
|---|---|
| `ssh-hardening` | Moves the real sshd to a randomized (or fixed) high port with a four-rung anti-lockout ladder, disables password auth, writes an operator README on-box; optional opt-in source whitelist behind a 60 s auto-rollback watchdog. |
| `firewall-baseline` | INPUT default-DROP baseline with per-service allows, provenance-commented blocked sources (`banned-<reason>`), optional outbound mining/stratum port block, and a 60 s auto-rollback watchdog; persists an f2b-free `rules.v4` so fail2ban re-mounts its own chains at boot. |
| `fail2ban-stack` | Three jails (sshd / sshesame / recidive) deployed from one managed file; its verify gate reads **every** deployed parameter back from the running fail2ban and compares it to the config — the consumer gate for the whole parameter-consistency incident class. |
| `honeypot-ssh` | Fake SSH on port 22: pinned upstream binary with a fail-closed SHA256 gate, dedicated host key (a known-hosts mismatch on port 22 is the tripwire, not an accident), banner calibrated from the real sshd, systemd sandbox (User=nobody, NoNewPrivileges, ProtectSystem=full), and a 3-minute health probe that restarts a stalled honeypot. |
| `file-integrity` | Minute-cadence SHA256 monitoring of security-critical files with **honest counters**: `files_tracked` always equals the real baseline size, dangling targets are warned — never silently skipped — and the verify gate cross-checks the counter against the baseline it protects. |
| `waterline-alerts` | Disk/memory/swap threshold alerts rendered from the config with a cooldown, delivered through the pluggable notifier; the verify gate compares the rendered thresholds against the live config. |
| `notifiers` | Pluggable alert channels — `telegram` \| `wecom` \| `dingtalk` \| `smtp` — behind one `hf_notify` interface with "unconfigured ≠ failure" semantics; deployed as a shared library, never a hardcoded endpoint. |
| `federation` | Fleet self-monitoring: agents push a status snapshot over SSH every 60 s to a central receiver that validates schema + timestamps (anti-replay), stores one JSON per agent, and sends a deduped fleet summary; agents silent for > 10× the push interval are flagged **stale — staleness is never silent**, and recovery is announced. |

Every module follows [`docs/MODULE-CONTRACT.md`](docs/MODULE-CONTRACT.md): one config source
(`hf_conf`), idempotent installs, a verify gate that checks behavior (not file existence),
declared dependencies, and backups (newest 2 per file family) before any write.

## The consistency gate: keeping the monitoring honest

A security tool that lies about its own state is worse than no tool. honeyfleet's answer:

- **Every module ships a verify gate.** `install.sh verify` re-derives the desired state from
  the config and compares it with the *deployed, running* state — deployed fail2ban parameters
  are read back via `fail2ban-client get`, rendered alert thresholds are diffed against the
  config, the integrity counter is checked against the baseline itself.
- **Counters must be honest.** "N items monitored" means N protected items, not N config lines.
- **Every parameter consumer is enumerated.** If two components validate the same value, a
  change must update both in the same commit — enforced by contract rule 4 and by cross-module
  gates (e.g. the honeypot gate re-checks the fail2ban jail port).
- **After every install**, the dispatcher runs the fleet-wide verify pass
  (`verify/consistency-gate.sh`), so drift between what you configured and what actually runs
  is caught at deploy time, not at incident time.

Rationale, with the three real-world incidents that produced these mechanisms:
[`docs/design-rationale.md`](docs/design-rationale.md).

## Threat model in one paragraph

Mass scanners hit port 22, feed the honeypot, and get banned long before they matter. A
targeted attacker faces a default-DROP firewall, a moved and hardened sshd, and
whitelist-aware service ports — and the honeypot's accept-all behavior **is** fingerprintable
by a determined scanner; its value is early warning and ban feed, not perfect deception. The
most realistic "attacker" is you: a mistyped whitelist or a changed home IP that locks you
out — hence the anti-lockout ladder above. If root is compromised, host-local detection
(integrity checks, timers, logs) can be disabled by the attacker; the residual signal is the
fleet: a node that stops pushing is flagged stale by the central within 10 minutes, and the
federation design assumes central and agent do not fall **simultaneously**. Full model:
[`docs/threat-model.md`](docs/threat-model.md).

## Documentation

| Doc | Contents |
|---|---|
| [`docs/user-manual.md`](docs/user-manual.md) | 用户手册（中文）：安装、全部配置键、运维命令、告警处理、卸载、故障排查 |
| [`docs/hardening-guide.md`](docs/hardening-guide.md) | Anti-lockout manual: the four-rung port-change ladder, whitelists, watchdogs, provider console |
| [`docs/threat-model.md`](docs/threat-model.md) | Assets, attacker profiles, trust boundaries, control mapping, known limits |
| [`docs/design-rationale.md`](docs/design-rationale.md) | Three production incidents and the mechanisms they became |
| [`docs/MODULE-CONTRACT.md`](docs/MODULE-CONTRACT.md) | The contract every module must satisfy |
| [`CHANGELOG.md`](CHANGELOG.md) | Release history |
| [`SECURITY.md`](SECURITY.md) | How to report vulnerabilities |

## Support matrix & license

- **Supported:** Ubuntu 20.04+, Debian 11+ (systemd, bash, python3, curl, iptables).
  Other distributions may work (fail2ban-stack falls back to dnf/yum) but are untested.
- **License:** GPL-3.0 — see [`LICENSE`](LICENSE).
- **No warranty.** This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
  A PARTICULAR PURPOSE. See the GNU General Public License (version 3, section 15) for
  details. A firewall that locks you out is a real possibility if you skip the warnings
  above; honeyfleet automates the safety ladder, it cannot remove the risk.

All example values in this repository use RFC 5737 documentation ranges
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and `example.com`.
Real IPs, domains, keys, and tokens are forbidden here by contract rule 7.
