# Security Policy

Supported languages: English or Chinese (中文均可).

## Reporting a vulnerability

Do **not** open a public GitHub issue for anything you believe is a security
vulnerability (lockout bugs included — a bug that locks operators out of their own
servers is a security bug here).

Report by email to:

```
security@example.com        # PLACEHOLDER — replace with the project's real advisory mailbox before release
```

Include, where possible:

- affected component (module name, e.g. `ssh-hardening`, `fail2ban-stack`) and version;
- the exact config keys involved (values redacted) and the observed vs expected behavior;
- a minimal reproduction (commands, not links to live systems);
- your assessment of impact and exploitability.

You will receive an acknowledgement within **72 hours**. If you receive no reply within
72 hours, assume the mailbox failed and escalate by opening a GitHub issue that contains
**no** technical detail beyond "please check the security mailbox".

## Encrypted communication

Reporters who need confidentiality can request our current PGP public key by replying to
the acknowledgement email; we will send it out-of-band and confirm the fingerprint over a
second channel before anything sensitive is exchanged.

```
PGP fingerprint (PLACEHOLDER — publish the real fingerprint here):
0000 0000 0000 0000 0000  0000 0000 0000 0000 0000
```

If you cannot use PGP, plain email is acceptable: please avoid including live
credentials, tokens, or customer data in any report.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x   | yes       |
| < 1.0   | no        |

Only the latest minor line receives security fixes. If you run an older release, the fix
is: upgrade.

## Scope

In scope:

- the installer (`install.sh`) and every module under `modules/`, `notifiers/`, `lib/`,
  `tools/`, `verify/`;
- the anti-lockout guarantees (a configuration that silently disables the rollback
  ladder, the watchdogs, or the second-channel login proof is a security defect);
- the honesty guarantees of the consistency gate (counters that overstate coverage,
  verify gates that pass on drifted state, silent skip paths);
- the federation trust boundary (snapshot validation, anti-replay, stale detection on
  the central node; push-key least privilege on agents).

Out of scope:

- upstream software honeyfleet deploys (sshesame, fail2ban, OpenSSH, systemd) — report
  those upstream; we will track and pin;
- denial-of-service against the honeypot by design: the honeypot *wants* connections,
  and banning scanners is its job;
- self-inflicted lockout by editing files the modules manage directly instead of the
  config (the on-box README files warn about this).

## Disclosure policy

- We follow a **90-day coordinated disclosure** timeline, counted from the first
  acknowledgement (not from first contact).
- You publish whenever you like after the fix ships; if you prefer to coordinate, we
  will agree on a disclosure date within the 90-day window.
- If a fix cannot ship in 90 days (e.g. it requires an upstream change), we publish a
  mitigation on day 90 — a workaround, a config-level disable, or a documented risk
  acceptance — and keep the full fix on track.
- We credit reporters by name or handle in the release notes unless you ask to stay
  anonymous. No legal action will be taken against good-faith research that respects
  this policy: do not access systems you do not own, do not exfiltrate data, and stop
  and report as soon as a vulnerability is confirmed.

## Safe-harbor note for operators

If your own honeyfleet node alerted you during someone else's authorized testing, that
is the system working. Alerts are evidence, not accusations.
