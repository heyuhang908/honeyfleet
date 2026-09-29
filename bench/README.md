# bench — the measurement harness

Numbers in this project's README are measurements, not estimates. This directory is
what produced them, and what reproduces them.

```bash
# produce your own numbers
bench/collector.sh                 # sample a node's real state (cron every 10 min)
python3 bench/aggregate.py         # sample JSONL -> data/telemetry.json (fails closed on bad rows)
python3 bench/charts.py            # data/telemetry.json -> report/*.png
```

| Path | What it is |
| --- | --- |
| `collector.sh` | Sampling script for a node: reads live `fail2ban-client` counters, the file-integrity state file and waterline metrics, appends one JSONL line. Made to run from cron for 30 days. |
| `aggregate.py` | Folds sampled JSONL into `data/telemetry.json`. Malformed rows are dropped loudly, never interpolated. |
| `charts.py` | Renders `data/telemetry.json` to `report/*.png` (matplotlib). |
| `data/telemetry.example.json` | The schema, with a worked example. Copy it to `data/telemetry.json` and fill it from your own run. |
| `diagrams/` | Fleet topology as Mermaid (`fleet.mmd`), draw.io (`fleet.drawio`), and the v1.1+ threat-sharing sketch. |
| `实测文案-资源与VPS适配.md` | The written-up resource and VPS-fit measurements behind the README's footprint table. |

Everything above is generic: it reads its own inputs and prints no assumptions about
whose deployment it is running against.

## What is deliberately not in this repository

The figures in the root README came from **real production forensics**, and those raw
artefacts are **not** published here. They contain, among other things:

- the addresses of hostile hosts and the ASN-level attribution of the networks they
  sit in — most of them compromised machines belonging to someone else;
- the operator's own node addresses, real `sshd` ports and jail parameters;
- one complete worm-delivery transcript.

Contract rule 7 forbids real IPs, domains, keys and tokens in this repository, and
publishing named attribution of third-party infrastructure would be a bad idea even
if it did not. So the evidence stays out of tree, and `data/telemetry.example.json`
carries the **schema plus anonymised aggregates** instead.

Consequence, stated plainly: **the attack and honeypot figures in the root README are
not reproducible from this repository.** The resource figures are — they are
measurements of honeyfleet itself, and `collector.sh` regenerates them.

## Sanitisation rules used here

- IPs: RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`).
- Ports in the diagrams: illustrative (`22222` / `22223`), not the deployment's.
- Attack data: aggregate counts and ratios only — no addresses, no ASN names, no host
  identities.
- A stage that has not been measured stays `null`. The harness prints nothing rather
  than an estimate, and the charts draw a gap rather than a guess.
