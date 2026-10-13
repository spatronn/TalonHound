# Threat Library extraction benchmark

A repeatable way to measure IOC extraction. It catches regressions before an analyst finds them in a report.

The benchmark runs the deterministic extraction stage (`extractionStages.extractReportCandidates`) on frozen fixtures, the same stage the import pipeline and Refresh extraction use. It never calls a model, a database or the network.

```bash
cd backend
npm run benchmark:threat-library                # table + diff against baseline.json
npm run benchmark:threat-library -- --json      # full JSON report
npm run test:threat-library-benchmark           # the CI gate
```

## Cases

Cases live in `backend/lib/threatLibrary/benchmark/cases/*.json`, one case per file:

| Field | Meaning |
|---|---|
| `id` | lowercase slug, unique |
| `source.kind` | `html_file`, `pdf_items` (pdf.js text items), `canonical` (canonical document JSON) or `layout_variant` |
| `source.path` | relative to the case file |
| `ground_truth.provenance` | **required**: how the labels were verified (`method`, `verified_by`, `verified_at`) |
| `ground_truth.indicators` | the complete publisher-asserted Indicator set; `assertion` is an exact `source_assertion` or `explicit` (any `explicit_*`) |
| `ground_truth.context_only` | must be Context Only (references, contact domains, provider context) |
| `ground_truth.excluded_legitimate` | legitimate observables that must never be Indicators (signed binaries, vendor API URLs, loopback) |
| `ground_truth.not_indicators` | must not be Indicators, otherwise unconstrained (MODE A narrative hashes) |
| `ground_truth.sections` | `{ heading, expected: authoritative \| narrative \| excluded, until? }`: zone class of the content under a publisher heading |

Mark an entry `"ai_dependent": true` when the semantic (model) layer, not the deterministic stage, owns its decision (MODE B narrative). Such entries are reported separately and left out of the deterministic precision and recall.

**Ground truth is never TalonHound output.** Label from the publisher's own evidence: the IOC appendix, a machine-readable IOC file, or an advisory CSV/STIX. Record that evidence in `provenance`. Never copy current production classifications into a case.

### Layout variants (metamorphic)

`layoutVariants.js` renders one publisher IOC set in many equivalent layouts:
- h2/h3/h4 hierarchies
- bold headings
- Filename|MD5 tables
- `<pre>` hash and filename/hash lines
- level-less PDF headings
- mixed C2 and loader/plugin sub-sections

Membership must be identical across all of them.

### Private cases

Retained publisher HTML/PDF usually cannot be committed. Put cases in the same format in a private directory and run with `TL_BENCHMARK_PRIVATE_DIR=/path` (or `--private-dir`). Private cases are scored but never written to `baseline.json`.

## Metrics

- Candidate extraction recall: was the labeled value extracted at all, in any state.
- Indicator precision, recall and F1. False negatives are split into **not extracted** and **extracted but not a member**, because they have different causes.
- Context Only accuracy, legitimate exclusion accuracy, non-indicator promotions.
- Assertion accuracy and section (structural scope) accuracy.
- Unsupported Indicators: a member whose value does not occur in the source text.
- Extraction time, and quality warnings per case (see `extractionQuality.js`).

## Baseline and known failures

`baseline.json` stores each case's Indicator members and headline counts. The gate fails on **any** membership change. A regression is a new FN or FP; an improvement means the baseline is stale, and a stale baseline hides the next regression. After reviewing a change, refresh it:

```bash
npm run benchmark:threat-library -- --write-baseline
```

`knownFailures.js` records cases that still fail, with a diagnosed cause. Their expectations stay strict. They run as `todo`, and a ratchet test fails once one starts passing, so a fix retires its entry.
