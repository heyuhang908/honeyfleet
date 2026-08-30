# Design Rationale — Three Real Incidents and the Mechanisms They Became

honeyfleet's most opinionated mechanisms are not security folklore; each one is the
productized form of a specific production failure. The source material is the project's
internal audit record (regression-fix report and reaudit/cleanup verification rounds,
2026-08-29/30). This document describes each incident in sanitized form — what happened,
the root cause, and the mechanism honeyfleet ships so the class of failure cannot recur
quietly.

The common thread: in every incident, the system *looked* healthy while it was not. The
consistent answer is the **consistency gate** — verify deployed reality against declared
intent, make every skip loud, and make every counter honest.

---

## Incident 1 — "Producer, consumer, and copy must change together" → the consumer gate

### What happened

During an SSH port migration (22 → a high port) on a production node, the daily
health-report script had its expected port hardcoded. The fix updated the **producer**
(the collector that emitted the expected value) and the **copy** (the human-readable alert
text) — but missed one **consumer**: a comparison site that still compared against the old
port literal. Result: `expected = new-port` vs `compared-to = 22` could never match, so
the "fail2ban policy check" reported unhealthy on every single daily report, forever.

Worse, the first verification *passed*:

- it only exercised the producer-side collector (`healthy=True` proved the snapshot was
  well-formed — not that the comparison agreed with it);
- "no alert for 20 minutes" was actually the alert edge-dedup doing its job (unchanged
  fingerprint → no resend), which was mistaken for "everything is fine".

The same incident class recurred days later in the same codebase: a *fourth* consumer (a
deployment script's baseline validation) and a *fifth* consumer (another component's
expected-ports constant) had both been missed during the same migration and were only
caught by a full-script smoke test.

### Root cause

Three distinct failures, one class:

1. **Literal duplication** — the same parameter existed as hardcoded literals in several
   places; "we changed it" meant "we changed the ones we remembered".
2. **Consumer enumeration by memory, not by search** — humans are bad enumeration
   structures; `grep` is a good one.
3. **Verification on the wrong side** — proving the producer produces does not prove the
   consumer consumes. And "no alerts" was read as "healthy" when it only meant
   "unchanged".

### What it became in honeyfleet

- **Single config source (MODULE-CONTRACT rule 1).** Every parameter lives in
  `honeyfleet.conf` and is read via `hf_conf`/`hf_conf_bool`. Code carries no port
  literals to forget, so the "change it in N places" problem starts at N=1.
- **Consumer gates read back deployed state, not written files.**
  `modules/fail2ban-stack.sh` verify queries the *running* fail2ban (`fail2ban-client
  get jail param`) for bantime/findtime/maxretry/increment/multipliers/ignoreip/logpath
  and compares every value with the config. What the daemon actually runs is the only
  caliber that matters.
- **Cross-module consumer checks.** The honeypot module's verify gate re-checks the
  fail2ban `sshd` jail port from the honeypot's side (gate 5), and the real-sshd
  parameters via `sshd -T` readback — the same parameter validated by a second,
  independent consumer.
- **Consumer enumeration is a contract rule (rule 4).** "If your module validates a
  parameter that another script also validates, grep the whole repo for that literal
  before finishing. Every consumer must be updated in the same change."
- **Verify runs at deploy time.** `install.sh` ends with the fleet-wide verify pass
  (`verify/consistency-gate.sh`), so config↔reality drift is caught when it is created,
  not on the next incident report.
- **"Unchanged" must be proven, not assumed.** Writes are gated on `cmp` equality
  (jail file, rendered thresholds, deployed scripts); a NO-OP claim is backed by
  byte-equality. And alert-dedup is documented as what it is — a dedup, not a health
  signal.

---

## Incident 2 — "41 tracked" that were really 40 → honest counters

### What happened

The integrity monitor of the predecessor deployment reported a final state of
"tracked = 41" (and 23 on a second node). Independent re-verification found that each
node's target list contained one **dangling entry** — a path whose directory no longer
existed. The rebase silently excluded it; the check silently skipped it; and the counter
counted *target-list lines*, not *baseline keys*. Actual monitored files: 40 and 22. The
headline number was wrong in the flattering direction, and nothing in the toolchain could
have told you.

The same re-verification found a second, related claim was false: the honeypot's
self-healing probe (three files) was reported as "added to integrity monitoring" but was
in neither the target list nor the baseline — the monitor's own guard was unmonitored.
A blind spot exactly where a blind spot is most dangerous.

### Root cause

1. **Proxy metrics.** The counter measured config lines (easy) instead of protected
   items (true). Any proxy metric eventually diverges from reality — and diverges in the
   direction that makes the report look better.
2. **Silent skip in both directions.** rebase excluded without recording; check skipped
   without reporting. A dangling entry produced zero observable events end-to-end.
3. **No cross-check.** Nothing ever compared "what the counter says" against "what the
   baseline actually contains", so the divergence was invisible indefinitely.

### What it became in honeyfleet

- **Honest counters are a contract rule (rule 5):** "Any 'N items monitored' figure must
  equal the actual number of protected items (baseline keys), not config line counts."
- **The implementation enforces it.** `modules/file-integrity.sh` writes
  `files_tracked` = the actual number of keys in the baseline (the code comment calls it
  what it is: "tracked reports the REAL baseline size, not the config line count").
- **Dangling targets are loud.** A configured target that does not exist on the node is
  warned at target-expansion time ("skipped (counted in dangling report)") and listed
  explicitly at rebase time — and it is *excluded* from the baseline, so
  `files_tracked` always equals genuinely protected files.
- **Drift detection is bidirectional.** A baseline file that vanishes from disk is
  drift; a live target missing from the baseline is also drift. Nothing exits monitoring
  silently from either side.
- **The verify gate cross-checks the counter against the baseline itself:**
  `state.files_tracked == len(baseline.files)` (plus `last_result == clean` and
  `drift_count == 0`). A counter that lies fails the gate — the lesson of this incident
  is a runtime assertion now.
- **Monitor the monitor.** honeyfleet's deployed assets (`/etc/honeyfleet/`,
  `/usr/local/lib/honeyfleet/`, systemd units) are legitimate integrity targets, and the
  operator guidance (`docs/user-manual.md`) recommends adding them to `HF_FI_TARGETS`.
  The integrity monitor protecting itself is a configuration choice the docs refuse to
  leave to chance.

---

## Incident 3 — The silent-skip family (BOM/CRLF, dangling entries, silent backups) → explicit warnings everywhere

### What happened

Three seemingly unrelated findings from the same audit period shared one property: the
failure looked exactly like success.

1. **BOM + CRLF in a hand-maintained target list.** A targets file edited under Windows
   carried a byte-order mark and CRLF line endings. On reinstall, the tool silently
   skipped **every entry** — the integrity monitor ran "clean" against an empty baseline.
   A whole control, wholesale and invisibly gone.
2. **Dangling entries skipped without record** (the mechanism behind incident 2): files
   that no longer existed produced no warning in either rebase or check.
3. **Backups that silently never happened.** The shared backup helper had a path-
   composition bug (`mkdir` created only the file's directory while `cp` targeted an
   extra directory component), so every backup copy failed — and the failure was
   swallowed. Every "backup taken" log line was a lie. As the code comment now puts it:
   *"a backup that silently doesn't happen is worse than no backup."*

### Root cause (the family trait)

Each mechanism treated *"nothing happened"* as *"nothing is wrong"*. Skip and failure
paths returned success or silence, so the human-facing surface stayed green. None of
these were exotic bugs; they were ordinary edge cases rendered catastrophic by one
design choice: **quiet degradation**.

### What it became in honeyfleet

- **Machine-generated artifacts instead of hand-maintained lists.** The deployed
  integrity targets file is regenerated at every install from the config
  (`targets_list` → one canonical absolute path per line). There is no hand-edited list
  to accumulate BOM/CRLF lineage; the config itself is sourced by bash and kept ASCII —
  and the on-box generated artifacts are compared byte-for-byte before being rewritten.
- **Every skip is a warning.** Nonexistent target → `hf_warn` with the path and a note
  that it is counted in the dangling report; rebase lists dangling entries explicitly;
  a stale honeypot config, a stale firewall rule, an unresolvable port — all warn. The
  contract's verify gates convert silent skips into FAIL lines.
- **Backups fail loudly and are capped by policy.** `hf_backup` warns on directory or
  copy failure and returns non-zero; retention is fixed at "newest 2 per file family,
  never delete beyond that" (contract rule 10); every module backs up before every
  write, because the rollback ladders in `ssh-hardening` and `firewall-baseline` are
  built on those backups and are only as real as they are.
- **Honeyfleet's own deployment refuses silent drift.** The modules that write rendered
  artifacts (jail policy, check scripts, systemd units) `cmp` the candidate against the
  deployed file and log the outcome either way; "NO-OP" is a proven equality, not an
  unverified assumption.

---

## Supporting lessons (same audit cycle, same principle)

- **Accept-stall self-healing.** The honeypot once sat "active but dead" — process
  running, zero events, connections queued in backlog. A process being alive says
  nothing about it accepting work. honeyfleet's honeypot health probe therefore checks
  three independent things (systemd active, TCP accept on loopback, SSH banner present),
  restarts after 2 consecutive failures with a cooldown, and keeps loopback in the
  fail2ban `ignoreip` so the probe can never self-ban (contract rule 9).
- **OOM sacrifice ordering.** Under memory pressure the kernel kills by score, not by
  importance. honeyfleet deploys only components that heal in seconds
  (`Restart=always`/`on-failure` or a dedicated probe), positions the fast-healing
  honeypot as the acceptable first victim, and alerts on waterlines *before* the kernel
  is ever forced to choose (threat-model §5.3).

## The one-sentence version

Every incident above was a system reporting health while degraded; every mechanism in
honeyfleet exists to make "deployed reality" and "declared intent" meet in a checkable
place — a read-back, a cross-check, a loud warning, or an honest counter — so that the
next failure announces itself instead of waiting to be discovered.
