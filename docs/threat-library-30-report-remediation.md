# Threat Library — 30-report IOC remediation (2026-10-24)

Remediation for the publisher ground-truth audit of the 30 `review_required` reports (ids 30355–31377). Extraction contracts: **`tl-candidates-v37`**, **`tl-section-tree-v8`**, **`tl-table-v9`**, **`tl-type-resolver-v15`**, **`tl-evidence-integrity-v3`**, **`tl-quality-v10`**, discovery lead-in **v3**.

Production data was **not** modified by this work. Linked IOC Source discovery remains analyst-gated (no automatic ingestion or approval).

## Corrected ground-truth baseline

Independent offline replay of primary-document Indicators (retained model decisions + production section-tree engine):

| Metric | Before (production audit) | After (offline replay) |
|---|---:|---:|
| True Positives | 1011 | **1025** |
| False Negatives | 14 | **0** |
| False Positives | 17 | **0** |
| Uncertain | 5 | **5** |
| Exact-match reports | 21/30 | **30/30** |
| Linked packages discovered | 3/12 | **12/12** (32 files) |
| Linked packages ingested | 0 | **0** (by design) |

Do **not** use the earlier incorrect aggregate of 1013 TP / 14 FN / 15 FP. Two label corrections after the first audit pass:

1. **`decrypt.support`** (report 31337 / PaperCut) — local part of an email address, never a domain Indicator.
2. **`samuelelena.co`** (report 31339 / RansomHub) — derived only from a malformed publisher URL host; the directory URLs remain Indicators; the bare domain is `not_indicators`.

These metrics are offline primary-document membership. They do **not** prove linked-source ingestion or production Refresh of the 30 reports.

## Root-cause → fix mapping

| RC | Defect | Fix (generic) |
|---|---|---|
| RC-1 | Actor “Files Used by …” hash inventories fell into MODE B; ungrounded LLM demotions stuck | `sectionTree/annotate.js` actor-hash inventory captions; `evidenceIntegrity` v3 requires grounded demotions |
| RC-2 | `http//`, `https:/`, wrapped cell URLs, `tcp://host:port` lost | `defang.js` scheme recovery; `tableSemantics.joinWrappedUrlTail`; transport-endpoint host identity |
| RC-3 | Explicit IOC-table directory URLs (`…/555/`) marked incomplete prefixes | Explicit single-value IOC row exemption in `markIncompleteUrlPrefixes` |
| RC-4 | Tool Source / Reference / Download / Homepage URLs promoted | Reference-column attribution → Context Only |
| RC-5 | SSH/ED25519 key fingerprints and banner hashes as file hashes | `digestSemantics` row-description / banner-hash kinds |
| RC-6 | IP in command cells / domain in description cells missed | Description-clause role assertion + compound-cell parse |
| RC-7 | Legitimate Files and Tools promoted | Existing benign / legitimate stance kept as Context Only |
| RC-8 | CISA STIX / Elastic `/indicators/` packs undiscovered | Sibling lead-in text + package cues (`discover` / `externalIocReference` v3) |
| RC-9 | Retry reuse dropped scope / type / quality metadata | In-memory `rereadForReuse` + `loadReportCandidatesForAnalysis` provenance restore |
| RC-10 | Silent failure classes | Quality v10 checks 19–23 + read-time overlays (`ioc_package_not_discovered`, `extraction_quality_missing`) |

## Extraction behaviour changes

- Publisher-attributed hash inventory tables open authoritative scope without an “Indicators” heading.
- Model Context Only / demotion updates need grounded publisher evidence; Refresh never re-applies a previously refused demotion.
- Malformed and wrapped publisher URLs recover only when a dotted host (or IPv4) follows the broken scheme.
- Directory URLs that are their own explicit IOC-table row are complete values.
- Reference-labelled URL columns never become Indicators.
- Non-file digests (keys, fingerprints, banner hashes) stay out of file-hash Indicator membership.
- Email local-parts and hunting-query regex fragments (`\|currentversion.run\b\|`) are never domains.

## IOC Source discovery

Discovery and ingestion stay separate. Lead-in sentences such as “For a downloadable copy of IOCs, see:” and “observables” anchors over `/indicators/` paths are scored; ordinary citations are not. Expected for this audit set: **12 packages / 32 files**, zero discoveries in the other 18 reports. Analysts still approve and ingest in the UI.

## Retry-path guarantees

When candidate reuse is eligible, Retry re-reads the matching document in memory (`pipeline.rereadForReuse`). The fresh extraction must match the stored identity set exactly; otherwise reuse is refused and a full re-extraction path runs. Restored evidence fields include scope-engine markers, type resolution and policy decisions so quality records can be regenerated without rewriting persisted rows before AI processing.

## Quality v10

New / extended diagnostics (membership unchanged):

- `ioc_section_url_prefix_excluded` (check 19)
- `reference_column_values_context` / `reference_column_indicator` (check 20)
- `non_file_digest_indicator_suspect` (check 21)
- `ioc_package_announced` (check 22)
- `ai_demoted_table_rows` (post-merge check 23)
- Read-time: `ioc_package_not_discovered`, `extraction_quality_missing`

## Benchmark methodology

1. **Unit regressions** — `thirtyReportAuditRegressions.test.js` (synthetic shapes for RC-1…RC-10).
2. **Committed labels** — `backend/lib/threatLibrary/benchmark/real-reports/` (30 audit labels + prior real-report labels). Private HTML stays outside git (`C:\Proje\talonhound-benchmark-sources` / host equivalent).
3. **Offline corpus replay** — `node scripts/threat-library-corpus-replay.js <snapshot.jsonl.gz> [--labels] [--out …]`. Uses `computeExtractionRefresh` (deterministic extraction + retained model decisions + analyst state). Deterministic-only scoring is **not** sufficient proof for AI-dependent membership.
4. **CI gates** — `npm run test:threat-library`, `npm run test:threat-library-benchmark`. Optional: `TL_CORPUS_SNAPSHOT=…` and `TL_BENCHMARK_SOURCE_DIR=…`.

```bash
cd backend
npm run test:threat-library
npm run test:threat-library-benchmark
TL_CORPUS_SNAPSHOT=/path/to/corpus-snapshot-2026-10-24.jsonl.gz \
  node --test lib/threatLibrary/corpusReplayAcceptance.test.js
node scripts/threat-library-corpus-replay.js "$TL_CORPUS_SNAPSHOT" --labels --out /tmp/replay-after.json
```

## Five unresolved uncertain observables

Left as `ambiguous` in labels (never auto-promoted or dismissed for a perfect score). See the Unit 42 Shai-Hulud npm label and any other `ground_truth.ambiguous` entries among the 30: each carries a publisher-evidence rationale. Analysts decide at review time.

## Known limitations

- Offline replay proves membership given **retained** model decisions; a fresh model run can still disagree until Refresh/Retry is executed in a controlled window.
- Linked packs are discovered only; ingestion, approval and Create IOCs are separate production steps.
- Historical reports 24456 and 30328 may show documented pre-existing label drift; they are accounted explicitly in the historical corpus harness.
- Private corpus HTML and the JSONL snapshot must never be committed.

## Production deployment and rollback

**Do not merge this document’s PR into a silent production Refresh.** After merge:

1. Deploy backend / threat-library-worker images as usual ([`docs/deployment.md`](deployment.md)).
2. Confirm zero live TL analyze/retry/refresh jobs.
3. Controlled acceptance: Refresh extraction (or Retry where required) on a small subset of the 30, review membership and quality codes, then widen.
4. Linked-source ingestion remains manual per discovered pack.
5. **Rollback:** redeploy previous backend image tag; contracts are versioned — older workers ignore newer quality codes. Do not bulk-revert analyst decisions (none were made for these 30 at audit time).

## Tests

| Suite | Command |
|---|---|
| Threat Library unit + routes | `npm run test:threat-library` |
| Benchmark gate | `npm run test:threat-library-benchmark` |
| RC regressions | included in `test:threat-library` (`thirtyReportAuditRegressions.test.js`) |
| Corpus acceptance | `corpusReplayAcceptance.test.js` (snapshot optional) |
| Integration (Postgres) | `npm run test:threat-library-integration` |
