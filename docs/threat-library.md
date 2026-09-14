# Threat Library

Threat Library ingests heterogeneous threat intelligence reports and converts them into TalonHound’s **canonical intelligence model**, then matches observables against the existing `ioc_items` store.

**No second IOC datastore.** Candidates are not IOCs until an analyst explicitly approves creation via the existing manual IOC creation path.

## Architecture

```text
URL / PDF / THIB
      │
      ▼
SOURCE ADAPTER
      │
      ▼
CANONICAL DOCUMENT (blocks)
      │
      ├── deterministic candidate extraction
      ├── AI semantic analysis (URL/PDF only)
      └── IOC bulk match (existing ioc_items)
      │
      ▼
ANALYST REVIEW
      │
      ▼
THREAT LIBRARY + optional new IOCs
```

THIB imports skip AI entirely.

## URL import

1. Validate URL (http/https only).
2. SSRF-safe fetch (reuses custom threat feed SSRF/DNS-pinning controls).
3. Extract article-like HTML into canonical blocks (`threat_library_html_v2`: a real DOM walk — `article` → `main` → `body`, then id/class/`itemprop`/`role` content roots — that keeps headings, paragraphs, list items, code and **tables as structured blocks**; text split across inline tags / `<wbr>` / entities stays one value). Plain-text sources (`threat_library_text_v2`) turn Markdown pipe tables and tab/space-aligned rows into the same table blocks.
4. The fetched HTML is retained as a `url_fetch` artifact (`reports/<id>/<sha256>.html`) so a later extractor contract change re-extracts without a network fetch; only reports imported before retention existed are re-fetched on Retry.
5. Deterministic IOC candidates → AI classification → bulk IOC match → review.

### SSRF protections

- http/https only; reject embedded credentials
- reject localhost, loopback, link-local, RFC1918, CGNAT, cloud metadata hosts
- validate redirects; redirect limit; size + timeout limits
- content-type allowlist (HTML/text; PDF-via-URL deferred to PDF upload)

## PDF import

- `application/pdf` validation, size limit, safe filename, SHA-256
- Text extraction via `pdf-parse` with page-aware block ids (`p17-b08`)
- Layout reconstruction (`threat_library_pdf_v3`) rebuilds lines from pdf.js item geometry: headings (non-body font / size / numbering), indicator rows (one observable per line), wrapped URLs, letter-spaced headings (`I O C` → `IOC`) and printed header/footer lines (page-edge band + repetition). No language keywords are needed for this step. Canonical documents stored by an older extractor are re-extracted from the stored PDF on the next Retry.
- **Tables** (v3): a run of lines whose cells align into ≥ 2 columns (span overlap, so centred headers still match their column) becomes a canonical `table` block. Rows are grouped by column conflict + vertical gap, so a cell that wraps onto a second visual line (a 64-hex SHA256 printed in two pieces, with the Type / Description cells vertically centred between them) is re-joined into one cell — hex runs and URL paths without a space, prose with one. Header rows are recognised by typography (a font no data row uses). Overlays printed on top of body text (floating banners), lines repeated on many pages and single-column prose never seed a table.
- Scanned/image-only PDFs are detected and **fail clearly** with `requires_ocr` (OCR not in V1)

Storage: `/data/threat-library` (not web-executable). Storage keys are relative; absolute paths are never returned to clients.

## AI provider configuration

Admin UI: **Threat Library → AI settings** / Administration Settings card.

Supported providers:

- OpenAI
- Anthropic
- Ollama / local
- OpenAI-compatible endpoint

Settings: provider, base URL, model, API key, connection / first-response / inactivity / total analysis timeouts, max characters per chunk.

Secrets:

- Stored in `threat_library_ai_settings.api_key`
- API responses return **masked** keys only
- Keys are never logged

### Privacy

TalonHound is self-hosted. Enabling an **external** provider means selected report text may leave the instance. The UI requires an explicit privacy acknowledgement before enablement. Local Ollama/compatible endpoints can keep processing on-prem. No report content is sent until an administrator configures and enables a provider.

### Evidence model (deterministic before AI)

Candidate extraction (`tl-candidates-v5`) produces one candidate per observable identity (type + normalized value) that aggregates **occurrences** — real text spans with block id, page, zone, section heading, source relation and form (`standalone`, `url`, `ip_port`, `list_row`, `table_row`).

#### Typed indicator tables (`tl-table-v1`)

Every canonical table block (HTML `<table>`, PDF geometry, Markdown / aligned text) goes through one generic interpreter (`tableSemantics.js`) before any regex pass:

- Column intent (`type` / `indicator` / `description`) comes from normalized header labels when they are recognisable (English, Turkish, German, Spanish, Portuguese, French, Russian, CJK hints) and otherwise from the cells themselves: a column whose cells parse as observables is the indicator column whatever its header says; a column of type labels (`SHA256`, `IP Address & Port`, `IP 地址`, `Alan Adı`) is the type column. Unknown-language headers therefore still work.
- A declared type is a **hint validated against the value**, never authority: `SHA256 | <40 hex>` is extracted as SHA1 with `declared_type_mismatch` recorded; a declared `Domain` / `Hostname` overrides the filename heuristic.
- Each valid row becomes a source assertion with row provenance (`evidence.table_rows[]`: table id, page, row index, declared type, type cell, raw indicator cell, description). The description cell is kept verbatim as evidence; observables inside it (`PivotC2 client on 46.151.29[.]58:8443`) are `related_values` of that row and **never** standalone candidates — the same independent-evidence rule as URL hosts. `IP Address & Port` rows are IP candidates with `port` provenance (no endpoint URL, no fake domain).
- The table proves IOC semantics by its own structure: a typed / labelled / dense IOC table is `explicit_ioc_section` even under a heading in an unknown language. Identifier tables (CVE ids, ATT&CK techniques), version tables, and tables under victim / target / affected / fixed headings or in negative zones are never explicit.
- Dedupe is by normalized identity only: two hashes with the same description stay two candidates. Hash values are strings end to end (`005e6014…` keeps its leading zeros).
- Completeness gate: per report the extractor logs `explicit_ioc_rows_seen / _valid / _rejected` (with rejection reasons) and `explicit_ioc_candidates_created`; a valid explicit row that produced no candidate is logged as `explicit IOC extraction inconsistency` and persisted in `analysis_progress.extraction_diagnostics` for diagnosis. Malformed rows are counted, never fatal.

- A URL occurrence creates a URL candidate only. Its host/port/path basename are kept as `parsed` metadata; the host is **not** promoted to a separate IP/domain candidate unless the report mentions it outside URL syntax (independent occurrence).
- `1.2.3.4:443` is an IP candidate whose occurrence carries `port=443` (faithful original value, no fake URL).
- Zones: explicit IOC / C&C / operational-infrastructure / sample tables are **strong** (heading hints in several languages — `IoCs`, `Indicators of Compromise`, `Host Indicators`, `Network Indicators`, `C2 Servers`, `VPN Nodes`, `IP Ranges`, appendix/annex titles that declare those intents, a table header row such as `Type Indicator Description` / `Tür Gösterge Açıklama` — any run of ≥ 3 indicator-only rows, a packed CIDR paragraph, or a typed indicator table). Repeated running headers/footers never close an open indicator section. References, printed source URL, header/footer, navigation and vendor boilerplate are **negative**. An unrecognised heading closes the current zone unless it is a short wrapped continuation of the previous title.
- Indicator scope: when the document contains at least one authoritative indicator section, the final Review Indicators set is those source-curated observables (plus body mentions that assert a direct operational relation such as “malware connects to X”). Narrative-only vendor/service/provider usage stays `context_only` (`source_assertion = provider_service`, role `hosting_platform` / `legitimate_service`) — buying VPS/VPN/proxy from a service does not make the service domain malicious. Reports with no appendix keep the existing body semantic pipeline (`ai_needed`).
- CIDR ranges (`1.2.3.0/24`) are first-class `cidr` candidates: prefix length is preserved and the range is never exploded into host IPs. Canonical `ioc_items` still has no CIDR type, so analysts review them as operational observables without auto-creating IP IOCs.
- Deterministic decisions: strong-zone occurrence → `malicious` with `source_assertion = explicit_ioc | explicit_c2 | explicit_operational_infrastructure` (the model may only refine the role); only negative occurrences, RFC example names and private / reserved address space → `context_only`; provider/service usage → `context_only` even at high AI confidence; filenames / code identifiers → excluded. Body mentions in a curated report that are not operational relations → `context_only` without an AI maliciousness call. Remaining `body_mention` rows are what the model classifies (`ai_needed`). `ai_needed = false` never removes a candidate — it means the candidate is already resolved and is sent to the model only as context.
- Final candidate set = deterministic candidates ∪ AI classification of the `ai_needed` subset (`mergeAiCandidateUpdates`): the model output is never the list of indicators, an update can only refine a candidate that exists, and an explicit assertion cannot be demoted. The deterministic set is persisted before the AI stage starts, so an AI failure never loses it.
- Review UI: explicit rows show `Explicit IOC · <declared type> · Report evidence`, the row description, table / row position and **Source asserted** instead of a percentage; AI-classified rows keep their model confidence.
- Provenance is persisted per candidate (`evidence` JSONB) and shown in review; THIB indicators carry `evidence.source_assertion / pages / ports / url_host`. No vendor or domain allowlists are used anywhere.

### Presentation phases (candidate rows are not a review set until committed)

Deterministic candidates are persisted before the AI stage and rewritten by the pipeline until `review_required`, so the API derives one phase from `analysis_status` (`backend/lib/threatLibrary/reportPhase.js`) and exposes it on every report payload as `review_phase` / `candidate_state`, together with `raw_candidate_count` (persisted rows) and `review_candidate_count` (rows that belong in the analyst review set):

| `analysis_status` | `review_phase` | `candidate_state` | UI |
|---|---|---|---|
| `pending`, `fetching`, `extracting`, `analyzing`, `matching` | `preparing` | `preliminary` | progress checklist + **Indicators are being refined** card (preliminary count, current stage, chunk progress; collapsed "Show preliminary observables" list, no actions) |
| `review_required` | `review_ready` | `review_ready` | **Review indicators** (`Review candidates: N`), review actions, Finalize |
| `ready`, `skipped` | `finalized` | `finalized` | **Indicators** (persisted set, no Finalize) |
| `failed` | `failed` | `preliminary` | "Analysis failed before the final indicator set was prepared", Retry, no review actions |

Review actions (`POST …/review`) and `POST …/finalize` are refused server-side with `409 { code: "report_not_ready_for_review", phase, report }` while the phase is `preparing` or `failed`; the page adopts the returned report state and keeps polling. Polling ignores responses older than the report on screen (`updated_at`), overlapping detail fetches apply latest-only, and Retry clears the previous rows immediately.

### Chunking / limits

- `max_input_chars` is the **per-request / per-chunk** budget (not “take first N and discard the rest”)
- Long reports are split into canonical-document chunks and processed sequentially
- Body chunks exclude header/footer, navigation, source-provenance and reference rows; each chunk prompt carries the resolved indicator list (compact) plus only the `ai_needed` candidates whose occurrences fall in that chunk
- Completed chunks are checkpointed with `threat-library-semantic-v5` and their block-id fingerprint; **Retry analysis** resumes unfinished, compatible chunks without re-fetching the URL/PDF. A contract bump (document extractor, candidate extraction or semantic schema) invalidates only the incompatible layer
- The optional final synthesis runs over validated chunk results only, is skipped when the remaining budget is short, and never fails the run; repair calls are likewise budget-bounded (one per chunk)
- Ollama requests set `think: false` — reasoning models otherwise spend minutes on hidden chain-of-thought before the schema-constrained JSON starts; structured output is the contract
- Every provider call is timed (headers / first token / output chars) into `analysis_progress.timing` and the worker log; a total-deadline failure records completed/remaining chunks so the UI can explain what a Retry will resume
- AI responses go through: provider structured output → JSON extraction → deterministic normalization → Zod schema → reference checks → persist
- Categorical confidence words such as `high` map to documented numeric values; invalid items in optional relationships are dropped with diagnostics rather than discarding an entire valid chunk
- Separate timeouts: connection, first-token, inactivity (resets on stream activity), and total analysis ceiling
- Ollama uses native streaming (`/api/chat` + JSON Schema `format` when supported + `keep_alive`) so long local generations are not mistaken for hung connections
- Failed AI validation stores capped model-output samples and issue paths on the analysis chunk for diagnosis (not full report prompts)
- Provider API keys are never logged; progress is persisted server-side (browser navigation does not cancel the job)

Prompt injection: report text is labeled UNTRUSTED DATA; the model cannot redefine tasks, request secrets, or invoke tools.

### Confidence policy

Central thresholds in `backend/lib/threatLibrary/constants.js` (`CONFIDENCE_POLICY`):

- High: ≥ 0.85
- Review floor: &lt; 0.4 (unknown/suspicious → needs_review)
- Suggest approve-all malicious: ≥ 0.9

AI confidence is not truth; analysts approve IOC creation.

## Canonical intelligence model

Tables (migration `019_threat_library.sql`):

- `threat_reports`
- `threat_report_artifacts`
- `threat_report_candidates` (`matched_ioc_id` → local IOC when matched)
- `threat_entities` + aliases + `threat_report_entities`
- `threat_relationships` (subject/object claims with evidence)
- `threat_library_jobs`
- `threat_library_ai_settings`

Deleting a Threat Library report removes TL-owned rows/artifacts only — **never** canonical `ioc_items`.

## THIB 1.0

Format: `talonhound-intelligence-bundle`  
File convention: `*.thib.json`  
Machine-readable schema: [`docs/schema/thib-1.0.schema.json`](./schema/thib-1.0.schema.json)

Integrity: SHA-256 over canonical JSON with sorted object keys. The entire `integrity` object is excluded from the hashed payload (so the hash cannot recurse into itself).

Rules:

- Portable UUID-style ids only (`indicator--…`, `entity--…`, `thib--…`)
- **Never** export local DB ids
- Do not embed full third-party PDFs/articles
- Duplicate `bundle_id` import → `Already imported`
- Conflicts: prefer keep-both claims (local + imported)
- TLP:RED export requires deliberate admin confirmation

## TLP 2.0

Stored values: `clear`, `green`, `amber`, `amber_strict`, `red`  
Legacy WHITE → CLEAR on ingest. UI displays `TLP:CLEAR` etc. Restricted export gated for RED.

## Permissions

| Action | Roles |
|--------|--------|
| View Threat Library | authenticated (readonly OK) |
| Import / review / finalize / export | admin, analyst |
| Delete reports | admin |
| AI settings | admin |
| Create IOCs from candidates | admin, analyst (existing IOC create path) |

## Audit trail

Every Threat Library write operation produces **one** `audit_logs` row per user action
(never one per candidate), attributed to the authenticated user with the request IP,
`source` (web / api / mcp / worker) and the per-request `request_id`.

| Action | When | Notable metadata |
|--------|------|------------------|
| `threat_library.report.imported.pdf` / `.url` / `.thib` | import request accepted | report id/title, TLP, file name + sha256 (pdf), redacted source URL (url), count summary (thib), job id |
| `threat_library.report.import_failed` | import request threw | safe `error_code` only |
| `threat_library.report.analysis.completed` / `.failed` | worker finished the job | actor = user from `threat_library_jobs.requested_by`, `executed_by: threat-library-worker`, `source: worker`, candidate counts |
| `threat_library.candidates.approved` / `.context_only` / `.ignored` | review action (grouped) | selected / changed / already_in_state, type distribution, candidate ids (bounded) |
| `threat_library.iocs.created` | **Create IOCs** committed | selected / eligible / created / already_existing / not_approved / unsupported / failed, `candidate_types`, `created_ioc_ids`, bounded per-candidate `results` with `results_total` / `results_shown` / `results_omitted`, `operation_id`; `status` = success / partial / failed |
| `threat_library.report.finalized` | report finalized | final review summary |
| `threat_library.report.source_url.updated` | provenance edit | old / new URL with credentials and token-like query values masked |
| `threat_library.report.deleted` | report deleted | title / public id / source type snapshot (no live join needed) |
| `threat_library.thib.exported` | THIB downloaded | TLP, indicator / entity counts, `confirm_red` |

IOC-level traceability: each IOC created by Create IOCs also gets the normal `ioc.created`
row (visible in the IOC's own audit history) carrying `origin: threat_library`,
`threat_report_public_id`, `threat_report_title`, `threat_report_candidate_id` and
`threat_library_operation_id`, and it shares the parent's `request_id`. Candidates that
already match an IOC are counted as `already_existing` (with the matched `ioc_id`) and
never emit `ioc.created`; the link is persisted on the candidate (`matched_ioc_id`) and
in `threat_relationships` only — no source membership is added to the existing IOC.

Never stored in audit metadata: report body / summary, canonical document, evidence
paragraphs, PDF bytes, AI prompts or raw outputs, the THIB payload, API keys or
URL-embedded tokens. Indicator values and IOC ids are stored (same policy as `ioc.created`).

Historical rows written before this model (`threat_library.import.*`, actor `—`) are not
rewritten; they only receive a readable label.

## Limitations (V1)

- No OCR for scanned PDFs (architected for later)
- No STIX/TAXII export (model kept mappable)
- No digital signatures on THIB (hash only)
- URL→PDF auto-ingest not supported (upload PDF tab)
- Not a MISP/OpenCTI replacement

## Async processing

BullMQ queue `threat-library` + `threat-library-worker` service. Stages persist on `threat_reports` / `threat_library_jobs` for real UI progress.

The worker must run the same backend image as the API (`talonhound-backend:local`). Building only the `backend` service and recreating workers without a shared image tag previously left the worker on a stale AbortController timeout path.

## Future STIX note

Canonical entities/relationships intentionally resemble STIX concepts (threat-actor, malware, indicator, relationship) without implementing STIX 2.1 in V1.
