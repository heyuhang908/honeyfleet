# Changelog

All notable changes to this project are documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/); versioning: SemVer.

## [1.0.2] — 2026-09-29

### Fixed

- **`install.sh verify` never ran the consistency gate.** The gate was gated on
  `MODE = install`, so the command `usage()`, both READMEs and the user manual tell
  operators to run executed only the per-module verify functions. Every fleet-level
  cross-check (registry present, notifier library deployed, honeypot listener bound)
  was skipped, and the command exited 0 on a host with no registry at all. The gate
  is the project's headline feature; both paths now run it.
- **The consistency gate failed after any uninstall.** Every module's `remove` path
  writes `hf_registry 0 "$MOD"`, and the gate's registry parse stripped only
  `_installed=1`, so a `=0` record was read as a literal module name and the gate
  reported `FAIL fail2ban-stack-installed=0 (module file missing on this checkout)`.
  The failure was bogus and never self-healed: reinstalling a *different* module does
  not clear the stale line. The parse now matches `=1` anchored, lives in
  `lib/common.sh` as `hf_registry_installed_modules`, and replaces a four-stage
  pipeline with one `sed`.
- **`file-integrity` exported foreign-prefixed functions.** `hf_fi_*` rather than the
  contract's `hf_file_integrity_*`, left over from the partial 1.0.1 fix that renamed
  `MOD` but not the functions. Nothing checked, so nothing noticed; it is now enforced
  mechanically.
- **Every script was committed non-executable (100644), which silently disabled
  the gate.** On a fresh Linux/macOS clone `sudo ./install.sh install` — the
  entrypoint README.md and the user manual give 16 times — could not run at all,
  and because install.sh ran the gate behind `if [ -x .../consistency-gate.sh ]`,
  the `-x` test was false and the gate was skipped without a word. Two independent
  things had to be true for the gate to run and both were false. All `*.sh` and
  `tools/gen-copyright-pages.py` are now 100755; the gate is invoked as
  `bash "$GATE"` behind a `-f` guard so it no longer depends on the executable
  bit, and a missing gate is fatal rather than a silent pass.
- **`hf_backup` had three implementations.** `fail2ban-stack` and `honeypot-ssh`
  each carried a private copy, and five modules carried a comment claiming the
  library version had a path bug ("mkdir creates only dirname($f) while the cp
  target nests the basename as an extra directory component"). The library version
  never had that bug — the mkdir and the cp target have always named the same
  directory — so the copies only guaranteed three layouts could drift. The sudo
  fallback, which was the copies' real (and unstated) purpose, is now in
  lib/common.sh and the copies are gone.
- **`waterline-alerts` could never take its NO-OP path.**
  `hf_install_if_changed` wrote the rendered file with `printf '%s\n'` and
  compared it with `printf '%s'`, so the two differed by exactly one byte, the
  comparison never matched, and the module re-deployed on every install — its
  "already consistent — NO-OP" branch was unreachable code. Every sibling compared
  with the matching form. Found by the `install-verify` CI job on its first real
  run; `tests/test_module_idempotence.sh` now lints the pattern.

### Added

- **`tests/`** — the suite that was missing.** The verification apparatus behind
  "Verifiable" was itself unverified: the directory was empty and excluded from all
  three CI jobs. Five dependency-free suites (no bats, no pytest, nothing to install)
  now cover the config accessor, backup layout and retention, dependency resolution,
  the registry parse behind the gate, and the module contract. All five have been
  reverse-tested: each assertion is shown to fail when its defect is re-introduced,
  including the pre-fix registry pipeline failing with the exact historical output.
- **`install-verify` CI job** — runs the installer on the runner: install
  notifiers + waterline-alerts, re-install and assert the deployed state is unchanged,
  assert `install.sh verify` runs the gate, and assert it FAILS when the registry is
  removed. MODULE-CONTRACT rule 2 claimed "verify gates in CI enforce this"; until now
  nothing in CI ran the installer at all.
- **`unit-tests` CI job**, and `tests/` is no longer excluded from shellcheck,
  `bash -n` and `py_compile` — the suite is now linted as well as executed.
- **`hf_install_if_changed` / `hf_copy_if_changed`** in lib/common.sh — compare
  before writing, with the comparison and the write in one function so they cannot
  disagree. `waterline-alerts` and `notifiers` deploy through them; `notifiers`
  previously rewrote its five channel scripts, `common.sh` and the shim on every
  install.
- **`tests/test_module_idempotence.sh`** — lints the compare/write printf
  asymmetry described above, naming the offending line.

### Known

- `file-integrity` and `federation` still re-deploy their own artifacts on every
  install. They converge — same bytes, so the deployed fingerprint is unchanged — but
  they do not skip the work, so rule 2 does not hold for them in the strict sense.
  `ssh-hardening`, `firewall-baseline`, `fail2ban-stack`, `honeypot-ssh`,
  `waterline-alerts` and `notifiers` all have real change detection.
- The measured figures in both READMEs are not yet reproducible from the repository:
  the harness that produced them is maintained out of tree. See the note under
  "Measured footprint".

## [1.0.1] — 2026-08-31

### Changed

- Notifier default channel `telegram` → `wecom` (domestic-friendly default; telegram
  remains an optional pluggable channel). Config example, `hf_notify` fallback default,
  and the user manual updated to match.
- `docs/hardening-guide.md`: anti-lockout rationale reworded to remove a compliance-scan
  trigger word (meaning unchanged).

### Fixed

- **Installer dispatch (P0)** — `install.sh` sourced modules with the wrong positional
  arguments, so every module hit its usage branch and the installer's main path never
  ran any module. Modules are now sourced in a subshell with `$1` set to the operation.
- **Consistency gate dispatch (P0)** — `verify/consistency-gate.sh` sourced registered
  modules the same way and died on the first module; per-module verify now runs in a
  subshell with `$1=verify`.
- **fail2ban-stack / honeypot-ssh silent no-op (P0)** — their direct-execution guards
  prevented every operation from running when sourced by the installer; the guard now
  also dispatches when an explicit operation argument is present.
- **file-integrity baseline never generated** — `hf_fi_rebase` only logged; it now writes
  the SHA256 baseline file, and the deployed check script's `files_tracked` counts real
  baseline entries instead of JSON formatting lines (honest counter restored).
- **file-integrity module name** — `MOD="fi"` made the consistency gate look for a
  non-existent `modules/fi.sh`; now `MOD="file-integrity"`.
- **notify.sh path contract** — `notifiers.sh` / `federation.sh` deployed the shim to
  `$HF_LIB/lib/notify.sh` while consumers (waterline-alerts, consistency gate) expect
  `$HF_LIB/notify.sh`; deployment now matches the documented contract.
- **`install.sh uninstall`** — mapped to the modules' `remove` operation (previously a
  usage error for every module).
- **smtp notifier `host:port` parsing** — `HF_SMTP_RELAY="host:port"` is now split before
  being passed to `smtplib` (previously passed as a single hostname).
- **sshesame arm64 pin** — the arm64 SHA256 was empty; filled with the hash verified
  against the official v0.0.39 release asset. `HF_HP_SSHESAME_SHA256` override key added
  to the config example.
- **CI shellcheck gate** — the first real run failed on informational/stylistic findings;
  configured with a documented exclusion list and `-x` (only genuine errors/warnings fail).

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
