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
- Indicator precision, recall and F1. False negatives are split into **not extracted**, **wrong type** (the value exists only under another candidate type, such as an MD5 read as an artifact) and **extracted but not a member**, because they have different causes and fixes.
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

## Detector validation notes

Thresholds and rules live in `EXTRACTION_QUALITY_THRESHOLDS`. Several were chosen or refined after looking at the synthetic failures, so the synthetic detection rate is optimistic until real reports are scored:

| Rule | Basis | Check |
|---|---|---|
| ≥ 3 row values per run | Same as `OBSERVABLE_LIST_MIN_ROWS` in `documentZones.js` | — |
| Observable-dense block | Added after two merged-PDF failures went undetected | Negative tests: narrative hash paragraphs |
| Appendix-hash check counts only appendix or adjacent rows | Added after a unit test showed a false warning on a distant analysis inventory | — |
| "Adjacent" means rows **after** an authoritative section (`tl-quality-v2`) | Scope loss pushes rows forward; a dropped-files table right before an appendix was a measured false warning | Rows after a closing sub-heading still warn |
| A table not read as explicit is silent when all its IOC values are Indicators (`tl-quality-v3`) | Production read-only scan: 35 of 35 such warnings were false (CISA, ReliaQuest tables fully captured) | A table whose values never became Indicators still warns |
| Prose values left to the model are silent when each is the platform of a more specific Indicator (`tl-quality-v3`) | Production: a "GitHub / Cloudflare are shared platforms" caveat warned although the exact repository URLs and Worker host were Indicators | Other unasserted values still warn |
| Structural-discovery Indicators (`indicators_from_structural_discovery`, `tl-quality-v3`) | Independent real-report ground truth: resolution IPs of a body Domain/IP table, triaged look-alike samples and services named as legitimate became Indicators with no other signal | Discovery rows still governed by a publisher IOC opener (a sub-heading closed the zone) are not reported |

Measured layouts (`extractionQuality.test.js`):
- **Clean:** references after the appendix, legitimate detection tables, narrative hash paragraphs.
- **Info:** a dropped-files table before or far from the appendix.
- **Warning (known, possibly false):** vendor URLs written as prose inside the appendix (`authoritative_section_values_not_asserted`, the pre-existing structural-completeness signal).

Measure real false-warning rates with `npm run scan:threat-library-quality -- --clean <verified ids>` before relying on severities.

## Real-report validation (2026-10-15, tl-candidates-v25 / tl-zones-v9 / tl-quality-v3)

Ground truth for 26 retained production sources was labelled independently of TalonHound. A line-based labeler with its own refang and regexes read only the publisher's IOC section; section ranges were chosen by a human from the outline, and no TalonHound zone, scope, typing or classification was used. These are private `--private-dir` cases, not committed.

- **Corpus:** 24 HTML and 2 PDF reports.
- **Publishers:** Securelist (7), FortiGuard (3), Genians (2), SOCRadar (2), Huntress, Hatching, Cisco Talos, Gen Digital, Infoblox, ESET, Zscaler, ReliaQuest, Dream Research, The Raven File, Recorded Future Insikt, CISA.
- **Control:** one NCSC advisory with no IOC list.

| | Expected | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|---|
| All (supported types) | 2105 | 2105 | 13 | 0 | 99.4% | 100% |
| HTML | 1066 | 1066 | 13 | 0 | 98.8% | 100% |
| PDF | 1039 | 1039 | 0 | 0 | 100% | 100% |

- **Unsupported type:** 37 publisher-listed email addresses (Genians GitPower) are not candidates, because email is not a candidate type. They are reported separately, not as FN.
- **Label corrections:** 25 CISA values were verified against wrapped PDF lines; the line-based labeler had fragmented them. One Raven "MD5" was a SLAPSHOT auth token. Both were corrected in the labels; the extractor was right.
- **False positives:** 13 FPs in 4 reports, with one shared shape: structural discovery grants MODE A authority to body content.
  - **NCSC (6):** an unlabelled list of services the advisory calls legitimate (`applyObservableListZones`).
  - **DTrack (3):** resolution IPs of a body `Domain | IP | First seen | ASN` table (`looksLikeIocTableHeader`).
  - **Huntress (3):** a body `Indicator | SHA256 | Description` table of triaged look-alike samples, including one described as potentially legitimate.
  - **Raven (1):** a bare URL prefix inside the IOC block.
- **Detector:** v3 flags the NCSC, DTrack and Huntress FPs with `indicators_from_structural_discovery`; NCSC is info, the other two are warnings. The production read-only scan (42 reports) has 2 warnings, both real FPs; v2 had 3 warnings, all false.
- **Masked scope loss:** in GitPower and RokRAT, a sub-heading ("C2", or a `<p>` "5. IoC" heading) closes the appendix. The rows survive only because the observable-list fallback re-opens them. Changing discovery to fix the FPs above would expose this scope loss, so the two must be fixed together.
