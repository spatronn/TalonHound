# Held-out Threat Library evaluation

Independent evaluation corpus for **previously unseen** publisher report
structures. This directory is intentionally separate from:

| Directory | Role |
|---|---|
| `../cases/` | Development / regression golden fixtures (may have driven extractor fixes) |
| `../real-reports/` | Labeled real-report identities (private source store required) |
| `heldOut/cases/` | Independently labeled held-out evaluation fixtures |
| `heldOut/unlabeled/` | Exploratory inputs — **no accuracy metrics** |

## Rules

1. Do **not** invent ground-truth labels.
2. Do **not** treat model-generated IOC lists as verified ground truth.
3. Once a held-out case is used to tune extraction rules, move it out of
   `heldOut/cases/` into the regression corpus (`../cases/` or an audit
   regression test) and record that promotion in the case provenance.
4. Prefer evidence extracts / authorized local artifacts over redistributing
   copyrighted full reports.
5. Metrics (TP/FP/FN/precision/recall/F1) are computed **only** when
   independently verified labels exist.

## Case shape

Held-out labeled cases reuse the same JSON schema as `../cases/`
(`validateBenchmarkCase`). Unlabeled exploratory entries may omit
`ground_truth.indicators` and set `"evaluation": "exploratory"`.

## Running

```bash
# Workflow / schema tests (safe, no private sources required)
node --test lib/threatLibrary/benchmark/heldOut/*.test.js

# Score whatever labeled held-out cases are present (often zero today)
node scripts/threat-library-held-out.js
```

When zero labeled held-out cases are present, the runner reports
`labeled_cases: 0` and does not fabricate scores.
