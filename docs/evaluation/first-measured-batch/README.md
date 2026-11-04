# First measured batch: frozen baseline

Status: **baseline frozen, labels not started, nothing imported.** `first_pass_accuracy` stays `not_yet_validated`. The general protocol is in [threat-library-first-pass-evaluation.md](../../threat-library-first-pass-evaluation.md); this file records what applies to this batch.

## Frozen code

| Item | Value |
|---|---|
| Deployed commit | `edf2b2c7ac6d486cbf024c0acb49dd81b967b337` (2026-11-04) |
| Contract fingerprint | `81a6e1a30019b5d66d78da789bbfee1b` |
| Candidates / zones / tables | `tl-candidates-v58` / `tl-zones-v17` / `tl-table-v18` |
| Type resolver / section tree / scope engine | `tl-type-resolver-v25` / `tl-section-tree-v16` / `tl-scope-engine-section-tree-v3` |
| HTML / PDF | `threat_library_html_v10` / `threat_library_pdf_v7` |
| Membership / quality / evidence integrity | `tl-membership-decision-v3` / `tl-quality-v16` / `tl-evidence-integrity-v3` |
| Source scope / structured sources / dispositions | `tl-ioc-source-scope-v8` / `tl-ioc-source-structured-v2` / `tl-dispositions-v1` |
| AI model | `qwen3.5:9b` through Ollama, recorded per run in `ai_provenance` |

If the fingerprint on production differs when the batch is imported, this baseline no longer applies: redraw nothing, but record the change and treat the result as a different contract.

## First-pass recording, verified on the frozen code

Synthetic report 35772 (soft-deleted afterwards) produced run 693: `is_first_pass=true`, this fingerprint, 5 dispositions, a discovery run with its reference, AI provenance, and an unapproved source. On the database, a unique index allows one first pass per report, and all 8 ledger tables carry the append-only trigger.

## Sample

| Step | Result |
|---|---|
| Feed items not in the library | 1,547 from 16 publisher feeds. Titles and URLs only |
| Dated from 2026-08-01 | 258 |
| Title rule removes product, marketing and digest posts (`popfilter` terms below) | 212 |
| Already in the library, by title or resolved URL | 6 removed (all Fortinet feed redirects) |
| Translated copies removed, locale and tracking normalized | see `population.json` |
| Screened: page visibly carries indicators | `indicators_visible` |
| **Drawn** | **32 with indicators + 8 negative controls = 40, 9 for a second labeler** |

Seeds: `first-measured-batch-2026-11-04:indicators`, `first-measured-batch-2026-11-04:controls`. Files: [population.json](population.json), [manifest.json](manifest.json).

**The screen** looks for defanged text, a hex digest, or the words "indicators of compromise" / "IOC" in the page. It shares no code with the extractor, keeps no values, and only sets the group. `package_announced` is a similar check for a GitHub IOC link, used only for strata.

**What this sample cannot say:**

- **No PDFs.** Every entry is an HTML article, so PDF extraction is not measured. Add PDF reports to a later batch.
- **Missing publishers.** The Zscaler, Hunt.io and Infoblox feed URLs tried returned 404, and SentinelOne pages could not be fetched. Microsoft, CISA, eSentire and others are thin or absent.
- **Publisher balance, not volume.** Round-robin strata spread the sample across publishers, so results describe this mix and not the import stream.
- **A screen bias.** A report whose indicators are only in images or a script-rendered page lands in the control group. Labelers must record it; do not move it.
- **Thin frame.** Only about 40 new pages visibly carry indicators, because earlier imports consumed most of them. Most of the frame is drawn, so this is close to a census of a small recent set.
- **Some drawn pages are not threat reports.** The title rule is crude. Labelers still label them, and an empty `indicators` list is a valid label.

## Labeling

Two people who have not seen TalonHound's output for these reports. An AI model may not be a labeler: a model's reading is not ground truth, and that includes the assistant that prepared this batch.

```bash
node scripts/threat-library-eval.js packets ../docs/evaluation/first-measured-batch/manifest.json --out packets/
```

1. Label each packet from the publisher's page and any package it links. Do not open TalonHound, IOC rows or approved Indicators.
2. Document values go in `ground_truth.indicators` / `context_only` / `ambiguous`. Packages go in `ground_truth.linked_packages` with `url` and `expected_identities`.
3. Every value needs `type`, `value`, `role` and `evidence` (section, table row or quoted sentence).
4. Reports flagged `second_labeler` go to the second person, blind. Run `agreement`, then resolve each disagreement against the source and record it in `provenance`.
5. Save finished cases under `backend/lib/threatLibrary/benchmark/sealed/cases/`, then run `validate`.

## Run order

1. Confirm the fingerprint on production matches this file.
2. Set `THREAT_LIBRARY_GITHUB_TOKEN`, or stagger inspections. A rate-limited inspection is not a discovery miss.
3. Finish the labels **before** importing.
4. Import the 40 through the normal route with no code changes. Do not auto-approve anything, and do not refresh.
5. Record the first-pass score with `npm run benchmark:threat-library -- --scorecard` before any fix is written.
6. Fix what the score shows. A case used for a fix leaves the sealed set for good.

## Scoring

Scored only on independently labelled reports. Document and package results are always separate.

| Measure | Definition |
|---|---|
| Precision | Members also in `indicators`, over members. `ambiguous` not scored |
| Recall, strict | `indicators` that are members |
| Recall, with review | `indicators` that are members or `needs_review`. Report both |
| F1 | From strict precision and recall; state which |
| Exact match | Report's member set equals its `indicators` |
| Package discovery | Labelled packages reached by discovery, over labelled packages. Rate-limited = not evaluated |
| Package coverage | Identities extracted from a reached package. Needs the fetched files, not scored by the tool yet |
| Controls | Members produced on negative controls: expected 0 unless the label says otherwise |

Record each error by stage (fetch, canonical document, section authority, table, type resolver, membership, AI, source discovery, source parser) and by defect class.
