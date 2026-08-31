# Changelog

All notable changes to this project are documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/); versioning: SemVer.

## [Unreleased]

### Changed

- Notifier default channel `telegram` → `wecom` (domestic-friendly default; telegram
  remains an optional pluggable channel). Config example, `hf_notify` fallback default,
  and the user manual updated to match.
- `docs/hardening-guide.md`: anti-lockout rationale reworded to remove a compliance-scan
  trigger word (meaning unchanged).

## [1.0.0] — 2026-08-30

Initial release.

### Added — core

- **Installer / dispatcher** (`install.sh`): `install` / `verify` / `status` / `uninstall` /
  `plan` modes; `--role central|agent` (validated against the config), `--only MODULE`,
  `--config FILE`; declared module dependencies resolved into execution order; idempotent
  NO-OP re-runs; fleet-wide verify pass after every install
  (`verify/consistency-gate.sh`).
- **Single config source** (`config/honeyfleet.conf.example` → `/etc/honeyfleet/honeyfleet.conf`):
  every parameter reaches modules only via `hf_conf` / `hf_conf_bool`; no hardcoded ports,
  paths, thresholds, or addresses anywhere in the code.
- **Common library** (`lib/common.sh`): config access, backup helper (newest 2 per file
  family, failures warned — never silent), atomic systemd unit writing, dependency check
  (`hf_requires`), module registry.
- **Module contract** (`docs/MODULE-CONTRACT.md`): 10 rules every module must satisfy —
  single config source, idempotency, behavior-checking verify gates, consumer enumeration,
  honest counters, declared dependencies, sanitization (RFC 5737 / `example.com` only),
  no circumvention features, self-heal ordering, backup retention.

### Added — modules (8)

- **ssh-hardening**: real-sshd port migration with the four-rung anti-lockout ladder
  (operator warning / `sshd -t` pre-validation / standalone test sshd with a real
  key-auth login proof on the NEW port / automatic rollback of every touched file);
  password authentication disabled; `random` port resolution persisted back to the
  config; on-box operator README; opt-in source whitelist (`HF_SSH_SOURCE_RESTRICT`)
  behind a 60-second auto-rollback watchdog with an explicit `confirm` command.
- **firewall-baseline**: INPUT default-DROP with stateful/loopback/icmp base, per-service
  allows, optional per-port source whitelists (with anti-shadowing checks), explicit
  blocked sources with `banned-<reason>` provenance comments, optional outbound
  mining/stratum port block; pre-change snapshot + 60-second auto-rollback watchdog;
  `iptables-restore --test` gate; persisted `rules.v4` stored f2b-free so fail2ban
  re-inserts its own chains at boot.
- **fail2ban-stack**: three jails from one managed file (`sshd` on the real port,
  `sshesame` on the honeypot port, `recidive` all-ports escalation); escalating bans with
  multipliers; `ignoreip` always covers loopback + management sources; `dbpurgeage`
  aligned with the recidive horizon; verify gate reads every deployed parameter back via
  `fail2ban-client get` and compares with the config (consumer gate).
- **honeypot-ssh**: fake SSH on port 22 via a pinned upstream sshesame binary with a
  fail-closed SHA256 gate; banner calibrated byte-for-byte from the real sshd; dedicated
  honeypot host key (known-hosts mismatch on 22 = operator tripwire); systemd sandbox
  (User=nobody, NoNewPrivileges, ProtectSystem=full, CAP_NET_BIND_SERVICE,
  Restart=always); 3-minute health probe (systemd + TCP accept + banner) with restart
  after 2 consecutive failures and cooldown; logrotate (weekly + 10M, keep 8); verify
  gates for listener, banner equality, timer, cross-module fail2ban jail consistency,
  and binary hash.
- **file-integrity**: minute-cadence SHA256 monitoring of security-critical files from
  `HF_FI_TARGETS`; baseline built on first install, explicit `rebase` command; honest
  counters — `files_tracked` equals the real baseline size, dangling targets are warned
  and excluded rather than silently counted; bidirectional drift detection (missing file
  = drift, unmonitored target = drift); verify gate cross-checks the counter against the
  baseline itself.
- **waterline-alerts**: disk/memory/swap threshold alerts rendered from the config into
  the deployed check script; per-metric cooldown; verify gate diffs rendered thresholds
  against the live config; trips never fail the unit (alerting is a side effect).
- **notifiers**: pluggable alert library behind one `hf_notify` interface —
  `telegram`, `wecom`, `dingtalk` (optional HMAC signing), `smtp` (relay-mandatory);
  "unconfigured ≠ failure" semantics; payload building via python3 with
  MarkdownV2/HTML escaping and per-channel size limits; never exits into the caller.
- **federation**: agent pushes a status snapshot (live fail2ban counters, file-integrity
  state, waterline metrics) over SSH every `HF_PUSH_INTERVAL` seconds; central receiver
  (python3, stdlib only) validates schema/hostname/timestamps with anti-replay and
  future-skew rejection, stores one JSON per agent atomically, replies
  `OK <agent> age=0 entries=N`, sends a deduped fleet summary with hourly heartbeat;
  stale scan flags agents silent for > 10× the push interval (`fleet agent stale`) and
  announces recovery — staleness is never silent; least-privilege forced-command push-key
  setup documented; verify gates include an end-to-end real push (agent) and a
  py_compile + selftest (central).

### Added — documentation & tooling

- `README.md` / `README.zh-CN.md` (with the defensive-only scope statement), `SECURITY.md`
  (advisory mailbox, 90-day coordinated disclosure), `docs/threat-model.md` (assets,
  attacker profiles, trust boundaries, control mapping, known limits), 
  `docs/design-rationale.md` (three production incidents and the mechanisms they became),
  `docs/hardening-guide.md` (anti-lockout manual), `docs/user-manual.md` (Chinese user
  manual), `CHANGELOG.md`.
- `tools/gen-copyright-pages.py`: software-copyright source-material generator
  (first/last N pages, 50 lines per page).

### Security

- Consistency-gate mechanisms derived from audited production incidents: consumer-side
  read-back verification, honest counters, explicit warnings on every skip path, and
  loud backup failures.
- Repository hygiene: all example values use RFC 5737 ranges and `example.com`; real
  IPs, domains, keys, and tokens are forbidden (contract rule 7); no proxy/circumvention
  functionality (rule 8).
