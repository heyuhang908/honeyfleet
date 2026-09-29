# Module Contract (v1)

Every honeyfleet module is a single bash file in `modules/` exposing four
functions named `hf_<module-with-dashes-as-underscores>_{install,verify,status,remove}`
plus an optional `hf_<mod>_load` (per-run setup).

## Rules

1. **Single config source.** Read parameters ONLY through `hf_conf KEY [default]`
   / `hf_conf_bool KEY`. Never hardcode a port, path, threshold, or IP.
2. **Idempotent.** `install` re-run on an installed system must be a NO-OP.
   Write through `hf_install_if_changed` / `hf_copy_if_changed` (lib/common.sh):
   they compare before writing and return 1 when the target already matches, which
   is the branch that logs NO-OP. Keep the comparison and the write in one place —
   if they disagree by a single byte the comparison never matches and the NO-OP
   branch becomes unreachable code, which is exactly how `waterline-alerts` failed
   from v1.0.0 to 1.0.2. Any file you write → `hf_backup` first.
3. **Verify gate.** `verify` must fail (non-zero) when the deployed state does
   not match the config, and must print one PASS/FAIL line. A verify that only
   checks "the file exists" is not a verify — check behavior AND parameters.
4. **Consumer enumeration.** If your module validates a parameter that another
   script also validates, grep the whole repo for that literal before finishing.
   Every consumer must be updated in the same change (f2b incident, 2026-08-29).
5. **Counters must be honest.** Any "N items monitored" figure must equal the
   actual number of protected items (baseline keys), not config line counts
   (dangling-entry incident, 2026-08-29).
6. **Dependencies declared.** `hf_requires <module>` at install start; the
   installer resolves order via `deps()`.
7. **Sanitization.** Example values use RFC 5737/5737 documentation ranges
   (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and `example.com`.
   Real IPs, domains, keys, and tokens are forbidden in this repository.
8. **No circumvention features.** This project is defensive only. Proxy,
   tunneling-for-circumvention, and traffic-obfuscation code is out of scope
   and will be rejected.
9. **Self-heal ordering.** Anything you deploy must either auto-restart
   (systemd Restart=) or ship its own health probe with cooldowns. OOM
   sacrifice targets must be the fastest-healing components.
10. **Backups.** Keep the most recent 2 backups per file family (`hf_backup`
    enforces this). Never delete beyond that automatically.

## Function signatures

```
hf_<mod>_install   # deploy; idempotent; registers via hf_registry 1 <mod>
hf_<mod>_verify    # exit 0 = consistent; prints PASS/FAIL line
hf_<mod>_status    # one human-readable line, no side effects
hf_<mod>_remove    # clean removal; keep state files for forensics
```

Additional operations are allowed (e.g. `file-integrity`'s `rebase`,
`ssh-hardening`'s `confirm`) provided they follow the same `hf_<mod>_` prefix and
are routed from the module's own `case "${1:-}"` dispatcher.

## What CI enforces

Prose rules are worth only what the checks behind them are worth — and rule 2
previously claimed "verify gates in CI enforce this" while CI ran no installer at
all. Keep this table true whenever `.github/workflows/ci.yml` changes.

| Rule | Enforced by | Not covered |
| --- | --- | --- |
| 1 single config source | `tests/test_hf_conf.sh` — the accessor behaves correctly | a module reading `$HF_*` directly instead of via `hf_conf` |
| 2 idempotent | `install-verify` job asserts a real NO-OP for `notifiers` and `waterline-alerts` plus an unchanged deployed fingerprint; `test_module_idempotence.sh` lints the compare/write asymmetry | `file-integrity` and `federation` re-deploy their own artifacts unconditionally — same bytes, so the state converges, but they do not skip the work |
| 3 verify gate | `test_module_contract.sh` asserts each module defines and dispatches `verify`; the `install-verify` job runs the gate and requires it to fail on a missing registry | the *content* of each gate (it must check behaviour, not existence) — reviewed by hand |
| 4 consumer enumeration | not checked | the f2b 2026-08-29 incident class |
| 5 honest counters | not checked directly | each module's own verify gate is expected to cross-check |
| 6 dependencies declared | `tests/test_expand_modules.sh` asserts the ordering the declared edges produce | a missing `hf_requires` call in a module |
| 7 sanitization | not checked | `bench/` (untracked) is not yet sanitized |
| 8 no circumvention | reviewed by hand | — |
| 9 self-heal ordering | not checked | — |
| 10 backups | `tests/test_hf_backup.sh` asserts the layout *and* "keep the newest 2" together | — |
| naming / dispatch | `tests/test_module_contract.sh` (function prefixes, `MOD`, dispatcher arms) | — |
