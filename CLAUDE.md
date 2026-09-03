# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Zero Trust Network Access built on the CSA **Software Defined Perimeter** model with a
NIST SP 800-207 policy engine. Three components, mapped in the root `README.md`:

| Directory | SDP role | Status |
|---|---|---|
| `sdp-controller/` | Controller — Policy Engine + trust algorithm | **the only implemented code** |
| `sdp-gateway/` | Accepting Host — nftables PEP, SPA listener | README-only design stub (roadmap weeks 3–7) |
| `sdp-client/` | Initiating Host — client agent, SPA sender | README-only design stub (roadmap week 4) |

The two stub READMEs are the spec for unwritten code — read them before implementing
anything in those directories. The root `README.md` holds the 9-week roadmap and the
two-layer detection design (controller-side = "is this device compromised?",
gateway-side = "is this session attacking the resource?").

## Commands

Everything runs from `sdp-controller/`. A venv already exists there (Python 3.12).

```bash
cd "sdp-controller"
source .venv/bin/activate            # or: python3 -m venv .venv && pip install -r requirements.txt

# One-time / after changing FEATURES — regenerates ml/dataset.csv, model.joblib, model_report.txt
python -m ml.generate_dataset
python -m ml.train
python -m ml.train --data /path/to/cic-ids.csv --seed 7   # real dataset / different seed

# Detection pipeline → telemetry_snapshot.json
python run_pipeline.py --benign
python run_pipeline.py --attack
python run_pipeline.py --eve /var/log/suricata/eve.json --flows myflows.json --out snap.json

# Policy evaluation
python demo.py                       # all 8 scenarios
python demo.py --scenario 2          # one scenario, 1-indexed
python demo.py --watch               # re-renders on save of policies/scenarios/snapshot
python demo.py --request '{"user":{...},"device":{...},"resource":{...},"context":{...}}'

# Individual extractors (both have their own CLI)
python -m detection.suricata_signal data/eve_attack.json
python -m detection.ml_signal data/flows_attack.json
```

Run as `python -m …` from the controller root: `ml/` and `detection/` are packages, and
`engine`/`trust_scorer` are imported as top-level modules.

**There is no test suite, linter, or git repo.** The verification loop is behavioral:
`run_pipeline.py --attack && python demo.py` and check scenario #2 (Bob) flips 85 → 45
and DENY, against the expected-verdict table in `sdp-controller/README.md`.

## Architecture

Two stages that communicate **only** through `telemetry_snapshot.json` on disk:

```
data/eve_*.json    → detection/suricata_signal.py ─┐
data/flows_*.json  → detection/ml_signal.py ───────┴→ run_pipeline.py → telemetry_snapshot.json
                                                                              │
scenarios.yaml → trust_scorer.enrich_request ←────────────────────────────────┘
                        ↓ (device.trust_score + trust_breakdown)
policies.yaml  → engine.evaluate → Decision → demo.py renders
```

### Invariants worth knowing before editing

- **Source IP is the join key.** Both extractors bucket by Suricata `src_ip` / flow
  `src_ip`; `enrich_request` looks up `request.context.ip` in the snapshot. A scenario
  whose `context.ip` is absent from the snapshot silently gets the no-telemetry path,
  not an error.
- **Trust weights must sum to 100** — `POSTURE_WEIGHTS` (60) + `SURICATA_MAX` (25) +
  `ML_MAX` (15), enforced by a module-level `assert` in `trust_scorer.py`. Adding a
  posture signal means rebalancing the others.
- **Three telemetry states**, in precedence order (`enrich_request`):
  1. explicit `device.trust_score` on the request → returned untouched (test override),
  2. snapshot entry present → missing sub-signals mean "pipeline ran, saw nothing" (full credit),
  3. no snapshot at all → falls back to the `no_suricata_alerts` / `ml_anomaly_score_ok`
     booleans in `device.signals`, else **half credit** (unknown ≠ trusted).
  `demo.py --request` never loads telemetry, so inline requests always take path 1 or 3.
- **Policy semantics are collect-all, not first-match** (`engine.evaluate`): every rule is
  evaluated, any matching `deny` wins immediately, and at least one matching `allow` is
  required or it's an implicit deny. `require_mfa` / `require_stepup` attach obligations
  on top of an allow. **`priority` only orders rows for display** — it does not affect the
  verdict.
- **Trust thresholds live in `policies.yaml`, not in code**: `< 40` hard deny; `>= 50`
  public/internal; `>= 60` contractor; `>= 70` confidential and admin. This is why the
  attack demo lands on DENY at score 45 — no *allow* rule fires, not because the deny rule
  triggered.
- **`when:` expressions run through a whitelisted AST walker**, not `eval` — so
  `policies.yaml` stays safe to live-edit. New operators or functions require extending
  `_BIN_OPS` / `_CMP_OPS` / `_SAFE_CALLS` in `engine.py`. An unknown name raises
  `PolicyExprError`, which is caught per-policy, shown as `ERR` in the demo table, and
  treated as non-matching — a typo in a rule degrades quietly rather than failing loudly.
- **`FEATURES` in `ml/generate_dataset.py` is the schema contract** (15 CIC-IDS2017-style
  columns, fixed order). `ml/train.py` and `detection/ml_signal.py` both import it and rely
  on positional order. Editing the list invalidates `ml/model.joblib` — retrain.
- The model is loaded lazily and cached in a module global (`_model` in `ml_signal.py`);
  it does not pick up a retrain within a running process.

### Generated, not authored

`ml/dataset.csv`, `ml/model.joblib`, `ml/model_report.txt`, `ml/feature_names.json`,
`telemetry_snapshot.json`. They are present in the tree; regenerate rather than hand-edit.

### Swapping in real data

The bundled `data/eve_*.json` files match Suricata's real eve.json schema (line-delimited
JSON, severity 1 = critical … 3 = medium), so `--eve /var/log/suricata/eve.json` works
against a live sensor with no parser changes. Real CIC-IDS2017 needs only column renaming
to match `FEATURES`, then `python -m ml.train --data …`.
