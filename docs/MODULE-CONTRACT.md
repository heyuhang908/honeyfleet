# Module Contract (v1)

Every honeyfleet module is a single bash file in `modules/` exposing four
functions named `hf_<module-with-dashes-as-underscores>_{install,verify,status,remove}`
plus an optional `hf_<mod>_load` (per-run setup).

## Rules

1. **Single config source.** Read parameters ONLY through `hf_conf KEY [default]`
   / `hf_conf_bool KEY`. Never hardcode a port, path, threshold, or IP.
2. **Idempotent.** `install` re-run on an installed system must be a NO-OP
   (verify gates in CI enforce this). Any file you write → `hf_backup` first.
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
