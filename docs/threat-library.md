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
- Layout reconstruction (`threat_library_pdf_v4`) rebuilds lines from pdf.js item geometry: headings (non-body font / size / numbering), indicator rows (one observable per line), wrapped URLs, letter-spaced headings (`I O C` → `IOC`) and printed header/footer lines (page-edge band + repetition). No language keywords are needed for this step. Canonical documents stored by an older extractor are re-extracted from the stored PDF on the next Retry.
- **Heading levels and dense inventories** (v5 / v6): structural headings carry an inferred `level` (numbering depth, else relative font height; equal sizes infer equal levels). A visual line that is a pure filename/hash inventory — every token a filename or a file hash, one consistent pair order, two or more pairs (`a.dll <md5> b.dll <md5> c.dll <md5>`) — is an observable row with one pair per line (`threat_library_pdf_v6`), so it can no longer merge into a narrative paragraph with an adjacent lead-in sentence. Zone annotation (`tl-zones-v11`) re-types an already-merged pure inventory the same way, keeping the block id, and treats equal PDF-inferred heading levels as unknown hierarchy: an indicator-group sub-label ("Samples", "Loaders") over a publisher IOC table keeps the open IOC appendix exactly as it does over indicator rows. Real same-level HTML siblings still close it.
- **Tables** (v3): a run of lines whose cells align into ≥ 2 columns (span overlap, so centred headers still match their column) becomes a canonical `table` block. Rows are grouped by column conflict + vertical gap, so a cell that wraps onto a second visual line (a 64-hex SHA256 printed in two pieces, with the Type / Description cells vertically centred between them) is re-joined into one cell — hex runs and URL paths without a space, prose with one. Header rows are recognised by typography (a font no data row uses). Overlays printed on top of body text (floating banners), lines repeated on many pages and single-column prose never seed a table.
- **Geometry robustness** (v4): line height is the item transform's glyph scale whenever pdf.js reports a larger `item.height` (pdf.js 1.x double-scales text sized in the text matrix with `1 Tf`, which otherwise merges every table row on a page into one line). Wrapped-line pitch comes from the document's prose lines, never from a table's own row spacing; a region whose line gaps are bimodal (rows centred against a taller multi-line cell) breaks rows only at the larger gap. A cell straddling two established columns splits at the item boundary in the gutter; whitespace pdf.js inserted inside one item (`2-  12`) is not an overlay; a digest wrapped inside a labelled cell (`SHA-256: <63 hex>` + `5`) re-joins. Labelled hash cells (`MD5: … SHA-256: …`) make the Hashes column the indicator column (tl-table-v4), and a dotted value in a file-name column (`back.pl` among `.php` / `.jsp` names) is a file, not a domain.
- **Version columns** (tl-table-v5): a table column whose header explicitly names a software version (`Version`, `Versions Affected`, `Affected Versions`, `Software / Product / Firmware Version`, `Build Number`) is never an indicator column. An IPv4-shaped release number found only in such a column (`2.3.20.2` under *Versions Affected*) is kept as a `technical_artifact` (kind `metadata`, reason `version_column`), never an IP; the same string in any other cell, in prose or in an IP column stays an IPv4. A header-less continuation table inherits the previous table's version columns only across page-break chrome and only at the same width; ambiguous headings (`Value`, `Details`) suppress nothing.
- **Versions in prose** (tl-candidates-v19, `ipv4VersionContext.js`): outside publisher IOC sections and rows, an IPv4-shaped token reads as a software version only on explicit clause-level evidence — a version keyword right before it (`version`, `Version=`, `release`, `build`, `versions include / prior to / through`, `upgrade from`), a range whose other end is not an IPv4 (`2.3.19 to 2.3.20.2`), a following version phrase (`is vulnerable`, `and earlier`), or a product name right before it when the same clause speaks of a vulnerability / release (never in code, never in a `value: label` row). A network cue at the token (`C2 IP`, `server`, `connected to`, `address`) always keeps the IPv4, and ambiguous prose keeps the IPv4. The same value under both readings yields both identities, each with its own evidence.
- Scanned/image-only PDFs are detected and **fail clearly** with `requires_ocr` (OCR not in V1)

Storage: `/data/threat-library` (not web-executable). Storage keys are relative; absolute paths are never returned to clients.

## AI provider configuration

Admin UI: **Threat Library → AI settings** / Administration Settings card.

Supported providers:

- OpenAI
- Anthropic
- Ollama / local
- OpenAI-compatible endpoint

Settings: provider, base URL, model, API key, connection / first-response / inactivity / total analysis timeouts, max characters per chunk, and **concurrent report analyses**.

Secrets:

- Stored in `threat_library_ai_settings.api_key`
- API responses return **masked** keys only
- Keys are never logged

### Privacy

TalonHound is self-hosted. Enabling an **external** provider means selected report text may leave the instance. The UI requires an explicit privacy acknowledgement before enablement. Local Ollama/compatible endpoints can keep processing on-prem. No report content is sent until an administrator configures and enables a provider.

### Evidence model (deterministic before AI)

Candidate extraction (`tl-candidates-v9`, zones `tl-zones-v2`) produces one candidate per observable identity (type + normalized value) that aggregates **occurrences** — real text spans with block id, page, zone, section heading, source relation, form (`standalone`, `url`, `ip_port`, `list_row`, `table_row`) and structural **occurrence kind** (`typed_table_row`, `standalone_indicator_row`, `list_item`, `endpoint`, `narrative_assertion`, `narrative_context`, `narrative_mention`, `reference`).

#### Observable-type resolver (`tl-type-resolver-v2`)

A string that merely *looks* domain-like or URL-like is not a network IOC. Every syntactic guess goes through one central resolver (`observableTypeResolver.js`) before it can become a review candidate:

`raw occurrence → syntactic guess → context-aware type resolver → canonical value validator → evidence / promotion gate → review candidate`

- **Domains** need hostname-compatible syntax **and** source semantics compatible with a network reading. Positive evidence: a `Domain` / `Host` / `C2` type cell, column header or sub-heading, an explicit indicator row inside a curated IOC section, a stated relation at the token (*connects to X*, *resolves to X*, *served from X*, *bağlanır*, *连接*, …), the host of a parsed URL (metadata, not a separate IOC). Negative evidence: a `Mutex` / `Class` / `Config` / `Registry` / `File` / `Path` type label or inline label (*named mutex X*, *single-instance identifier: X*, *互斥体 X*), an assignment position (`a.b.c = …`), symbolic identifier shape in the original spelling (`Loader.Program.Main`, `embed.FS`, `LocalFoo.Client.SingleInstance`), a code-word or file-extension label in TLD position (`agent.server.timeout`, `payload.enc`). Public-suffix knowledge is only a *syntax strength* signal, never the sole rule: `update.corp.lan` promotes when the source asserts a network relation or lists it as an indicator. Every occurrence of a dotted token is resolved in its own context and the token is typed **once per document** from the weighed readings, so a stray "module" in one sentence cannot split one identity into two.
- **URLs** must be absolute (`scheme://host…` with a hostname-compatible or IP host, refanged forms accepted). `/clickfix/abc/file`, `/api/v1/upload`, `../payload`, `C:\Users\Public\payload.exe`, `%TEMP%\x.json` are never URL IOCs; they are retained as `relative_path` / `file_path` context with the path and any prose-stated port (`… on port 8081`, `8081 portu`, `端口 8081`) preserved. Nothing is synthesised: path + port + a host mentioned elsewhere never become `http://host:port/path`. Candidate boundaries stop before prose: a cell `https://evil.example/a on port 8080` yields the URL `https://evil.example/a` only.
- **Non-network artifacts** (`technical_artifact` with `artifact_kind` mutex / code / config / registry / file / path / command / process / metadata, plus `relative_path`, `file_path`) are `is_ioc = false`, `source_assertion = non_ioc`, `policy_decision = ioc_excluded_non_network`: excluded from Review Indicators, IOC matching, AI classification, approval and Create IOCs, but kept as report context (Context Only tab) when the source itself presents them (typed table row, indicator list row, labelled mention). Incidental code identifiers in prose are dropped.
- **Canonical gate (AI cannot bypass):** `applyEvidencePolicy` re-validates every network candidate's canonical shape (`validateCanonicalIocValue`) before any promotion, including after the AI merge; an invalid shape is `ioc_excluded_invalid_canonical`. The model can only refine candidates that exist with the same type and value — it cannot retype an artifact into a domain or a path into a URL.
- **Diagnostics:** each candidate carries `evidence.type_resolution` (`raw`, `syntax_guess`, `resolved_type`, `reason`, `promotion`, `normalized_path`, `port`, signals, per-document scores) and per-report counts are logged and stored in `analysis_progress.extraction_diagnostics.type_resolution` (syntactic occurrences, network IOC candidates, artifact candidates, dropped artifact occurrences, relative paths, canonical rejections, excluded reasons). The review UI shows *Not a network IOC · Mutex / single-instance name · mutex label* on such rows.
- Short **typed sub-headings** (`Domain`, `IP Addresses`, `Hash Values (SHA-256)`, `Mutex`) under an open IOC heading continue the section instead of closing it and type the value rows beneath them; an observable-only line is never treated as a heading.

#### Typed indicator tables (`tl-table-v2`)

Every canonical table block (HTML `<table>`, PDF geometry, Markdown / aligned text) goes through one generic interpreter (`tableSemantics.js`) before any regex pass:

- Column intent (`type` / `indicator` / `description`) comes from normalized header labels when they are recognisable (English, Turkish, German, Spanish, Portuguese, French, Russian, CJK hints) and otherwise from the cells themselves: a column whose cells parse as observables is the indicator column whatever its header says; a column of type labels (`SHA256`, `IP Address & Port`, `IP 地址`, `Alan Adı`) is the type column. Unknown-language headers therefore still work.
- A declared type is a **hint validated against the value**, never authority: `SHA256 | <40 hex>` is extracted as SHA1 with `declared_type_mismatch` recorded; a declared `Domain` / `Hostname` overrides the filename heuristic. The raw type cell also feeds the type resolver: `Mutex | LocalFoo.Client.SingleInstance` and `ClickFix path | /clickfix/x on port 8081` are non-IOC artifact rows (kept with row provenance), and a table made only of such rows is an `artifact_table` (never explicit).
- Each valid row becomes a source assertion with row provenance (`evidence.table_rows[]`: table id, page, row index, declared type, type cell, raw indicator cell, description). The description cell is kept verbatim as evidence; observables inside it (`PivotC2 client on 46.151.29[.]58:8443`) are `related_values` of that row and **never** standalone candidates — the same independent-evidence rule as URL hosts. `IP Address & Port` rows are IP candidates with `port` provenance (no endpoint URL, no fake domain).
- The table proves IOC semantics by its own structure: a typed / labelled / dense IOC table is `explicit_ioc_section` even under a heading in an unknown language. Identifier tables (CVE ids, ATT&CK techniques), version tables, and tables under victim / target / affected / fixed headings or in negative zones are never explicit.
- Dedupe is by normalized identity only: two hashes with the same description stay two candidates. Hash values are strings end to end (`005e6014…` keeps its leading zeros).
- Completeness gate: per report the extractor logs `explicit_ioc_rows_seen / _valid / _rejected` (with rejection reasons) and `explicit_ioc_candidates_created`. Completeness compares **asserted** explicit-table IOC identities (recorded before `add()`) to created identities. A valid explicit assertion that candidate validation later rejects is persisted as `dropped_asserted_identities` / `missing_identities` with `inconsistent=true` — diagnostic only; rejected values are never forced into the candidate set. Malformed rows are counted, never fatal.

- A URL occurrence creates a URL candidate only. Its host/port/path basename are kept as `parsed` metadata; the host is **not** promoted to a separate IP/domain candidate unless the report mentions it outside URL syntax (independent occurrence).
- `1.2.3.4:443` is an IP candidate whose occurrence carries `port=443` (faithful original value, no fake URL).
- Zones: explicit IOC / C&C / operational-infrastructure / sample tables are **strong** (heading hints in several languages — `IoCs`, `Indicators of Compromise`, `Host Indicators`, `Network Indicators`, `C2 Servers`, `VPN Nodes`, `IP Ranges`, appendix/annex titles that declare those intents, a table header row such as `Type Indicator Description` / `Tür Gösterge Açıklama`, a packed CIDR paragraph, or a typed indicator table). Repeated running headers/footers never close an open indicator section. References, printed source URL, header/footer, navigation and vendor boilerplate are **negative**.
- Section scope model (`documentZones.js`): *heading → section role → authoritative scope → inheritance → occurrence-level relation → promotion*, never "run length → malicious" or "section name → malicious".
  - **Discovery.** A heading that *starts* with an indicator concept and continues with descriptive text (`Indicators: Three Casinos and a Thousand Lookalikes`, `Indicators – Network Infrastructure`, `IOCs (Type 3)`, `Göstergeler: Ek Altyapı`, `威胁指标：活动A`) declares an indicator section; it is only authoritative when the section actually contains indicator structure (list / table / observable rows) — a title that merely introduces prose is not an appendix (`indicator_heading_unconfirmed`). A heading that only *contains* the word (`Why these indicators matter`) declares nothing. The ≥ 3 indicator-only-row heuristic remains a **discovery fallback for unlabelled lists in body text**; it never gates rows that already sit inside an authoritative section.
  - **Inheritance.** Inside a proven section every block inherits the scope until a real boundary: sub-labels (`Scambling Domains (Type 2)`, `Supporting IP Addresses …`, `Decoy domains`) — a short heading naming an indicator-group concept that is nested deeper in the DOM (`h3` under `h2`) or directly followed by indicator rows — continue the section (`subgroup_label`), as do typed sub-headings and wrapped titles; single-column HTML table rows and descriptive separator paragraphs never reset. A 1-row or 2-row subgroup therefore keeps its scope. Scope closes on a heading of the same or higher hierarchy that names a new topic (`Conclusion`, `Frequently Asked Questions`, `Mitigations`), on a heading that opens another section role (References, About, Disclaimer), and at document end — never on a running header/footer, a page break, a short local run, or a descriptive label.
  - **Occurrence kinds.** Zone is evidence, not proof. Inside an authoritative section a *row* (typed table row, list item, value-only line, `value – note` / `label: value` line, a line made only of observables, `ip:port`) is a source assertion; *prose* is read for its relation: an operational clause (`connects to`, `payload from`, `hosted at`, `C2`, …) is a `narrative_assertion`; a research / report / vendor / organisation mention (`Research by …`, `Example Consulting (example.net) flagged …`, `according to`, `araştırma`, `安全公司`) or provider usage is `narrative_context` → `context_only` (`context_only_contextual_mention_in_indicator_section`) even at high AI confidence; an unmarked prose mention inside the section (`narrative_mention`) is neither promoted nor discarded deterministically — it goes to the model with the section as context (`ai_needed_authoritative_narrative`). If the same observable is also listed as an explicit row, the row wins.
  - **Scheme-less resources.** `js.cache-mcp[.]com/layer.js` written without a scheme is one URL occurrence in the publisher's exact spelling (`typing_reason = scheme_less_url_with_dns_host`, `parsed.scheme = null`, `parsed.path = /layer.js`, host as parsed metadata). No `http://` / `https://` is invented, the path is never dropped, the basename is never a domain or artifact, and the host is not a separate domain candidate unless the report mentions it on its own — the same no-over-derivation rule as absolute URLs. Only DNS-shaped hosts qualify (`Node.js/Express` stays a technical artifact).
  - **Diagnostics** (`analysis_progress.extraction_diagnostics.scope`, developer-facing, not in the review UI): the scope trace (which heading opened / continued / closed which zone, with form and DOM level), occurrence-kind and relation-marker counts, policy-decision counts, and per-candidate occurrence readings (block id, heading, zone reason, opening heading, kind, relation, marker, asserted); `type_resolution.scheme_less_resources` lists preserved host/path resources. Persisted evidence occurrences carry `occurrence_kind`, `relation_marker`, `asserted`, `zone_reason`, `scope_opening_id`.
- Indicator scope: when the document contains at least one authoritative indicator section, the final Review Indicators set is those source-curated observables (plus body mentions that assert a direct operational relation such as “malware connects to X”). Narrative-only vendor/service/provider usage stays `context_only` (`source_assertion = provider_service`, role `hosting_platform` / `legitimate_service`) — buying VPS/VPN/proxy from a service does not make the service domain malicious. Reports with no appendix keep the existing body semantic pipeline (`ai_needed`).
- CIDR ranges (`1.2.3.0/24`) are first-class `cidr` candidates: prefix length is preserved and the range is never exploded into host IPs. Canonical `ioc_items` still has no CIDR type, so analysts review them as operational observables without auto-creating IP IOCs.
- Deterministic decisions: an *asserted* strong-zone occurrence (row placement or operational clause inside an authoritative section) → `malicious` with `source_assertion = explicit_ioc | explicit_c2 | explicit_operational_infrastructure` (the model may only refine the role); only negative occurrences, RFC example names and private / reserved address space → `context_only`; provider/service usage → `context_only` even at high AI confidence; technical artifacts (mutex / code / config identifiers, relative and file-system paths, filenames) → excluded from the IOC set but retained as context. Body mentions in a curated report that are not operational relations → `context_only` without an AI maliciousness call. Remaining `body_mention` rows are what the model classifies (`ai_needed`). `ai_needed = false` never removes a candidate — it means the candidate is already resolved and is sent to the model only as context.
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

### Retry, Refresh extraction, Re-run AI analysis

Three separate operations, one explicit job mode each (`backend/lib/threatLibrary/jobModes.js`, persisted as `threat_library_jobs.job_type`, migration 036). The worker validates the mode and rejects unknown values.

| Action | Endpoint | Allowed `analysis_status` | Job type | Runs AI |
|---|---|---|---|---|
| **Retry analysis** (failed-state button) | `POST …/reports/:id/retry` | `failed` (plus orphaned active-status recovery; an active job answers `already_running`) | `retry` | yes — resumes the failed pipeline, reusing document, candidates and completed chunks |
| **Refresh extraction** (overflow menu) | `POST …/reports/:id/refresh-extraction` | `review_required`, `ready` (finalized stays finalized only when nothing review-relevant changed; a semantic change returns `review_required`) | `refresh_extraction` | **never** |
| **Re-run AI analysis** (overflow menu) | `POST …/reports/:id/rerun-ai` | `review_required` | `rerun_ai` | yes — new analysis run, cached model output is not replayed |

Retry on a `review_required` / finalized report is refused with `409 retry_not_applicable`; a refresh / AI re-run on a failed report is refused (`409`, use Retry); a finalized report is never reopened implicitly by an AI re-run. All three are analyst/admin only, CSRF-protected, return `202` for accepted work, and share the analysis slot budget. Refresh and AI re-run claim the report atomically (`UPDATE … WHERE analysis_status = ANY(allowed) AND NOT EXISTS (queued/running job)`), so concurrent requests produce exactly one job; the loser gets `409 analysis_already_running`. Cancelling a maintenance job before a worker claims it returns the report to the status it was requested from.

**Refresh extraction** (`extractionRefresh.js`) is what to run after a deterministic extractor contract change (`tl-candidates-vN → vN+1`). It reuses the stored canonical document (re-extracted from the retained HTML / stored PDF when the document contract is outdated — it never re-fetches; without a retained source it fails with `refresh_source_unavailable`), then reruns candidate extraction, canonicalization, occurrence / assertion construction, publisher IOC membership, IOC matching and the candidate counts. Its static import graph contains no `./ai/*` module (enforced by `extractionRefresh.test.js`); it writes no entities, relationships, report tags, summary, confidence, report type, TLP, `ai_result`, analysis chunks or run id. Per canonical identity `(candidate_type, normalized_value)`:

- **surviving identity** — extraction-owned fields (occurrences, assertion, evidence, typing, policy) are recomputed; a stored model decision (`evidence.decision_source = 'ai'` / `ai_role_suggestion`) is replayed through the same `mergeAiCandidateUpdates` step the pipeline uses, so the current evidence policy still gates it; matching is recomputed; analyst state is kept (`review_status`, the Context only decision, the Context Only → IOC promotion override and `promoted_from`, `promotion_outcome`, row id / public id). Unchanged rows are not written.
- **analyst-state reconciliation contract** (`candidateAnalystState.applyAnalystState`, hotfix after P1):
  - *Publisher Indicator membership* is the current deterministic reading (extraction + replayed AI + matching). It is the only source of `is_ioc`, `assessment`, `role`, `source_assertion`.
  - *Review status* is analyst-owned and always kept. A row with a Create-IOCs outcome that is still `pending` keeps its implied approval, unless a later Context Only / Ignore / Reject decision stands.
  - *Explicit promotion* (`promote_to_ioc`, recorded in `evidence.promoted_from`, review `approved`) is re-applied after extraction: the row stays an IOC candidate.
  - *Historical Create IOCs* (`promotion_outcome = created | already_existing`) is history, not membership. It no longer forces `is_ioc = true`; a contract fix can move a created identity out of the Indicators. That move is a protected loss (reviewed + IOC-linked → admin acceptance).
  - *Global IOC link* (`matched_ioc_id`) is a fact about the identity. When the catalog lookup is skipped because the row is now non-IOC, the stored link is carried (`iocMatch.preserveStoredIocLinks`) only if the stored `ioc_items` record still has the candidate's observable type and normalized value. A deleted or mismatched record is not carried; the guard reports that as `ioc_link_changed`. `match_state` is recomputed with the carried link. The global IOC record itself is never changed or deleted by refresh.
  - `promotion_outcome` / `promotion_detail` / `promoted_at` are never rewritten by reconcile.
- **new identity** — inserted as extraction produces it; an `ai_needed` candidate stays `ai_needed` (no classification is fabricated; use Re-run AI analysis to classify it).
- **removed identity** — deleted (relationship rows pointing at it cascade, as on every candidate rebuild). State never moves to a different identity (e.g. `technical_artifact|X` → `domain|x`).

On completion a `review_required` report stays `review_required`. A finalized report (`ready`) stays finalized when the reconcile diff has no review-relevant change (added/removed canonical identity, or a change to assessment, role, review, match, IOC link, `is_ioc`, or source assertion). Occurrence and evidence metadata alone do not unfinalize it. A review-relevant change sets `review_required` and the job result reports `reopened_for_review`. A failed refresh returns the report to the status it had before the job (it never strands a report in `failed`) and records the error on the job and in `analysis_progress.last_refresh`. The worker log and the `threat_library.report.analysis.completed` audit event carry `job_type`, the extraction contract, added / updated / removed counts, `ai_invoked: false`, and `review_reopened` when a finalized report was sent back to review. Retry and Re-run AI persist candidates through the same reconciler, so a surviving canonical identity keeps its row id and analyst decisions (review, Context Only, Promote to IOC, Create-IOC outcome and IOC link).

#### Membership guard (`tl-refresh-guard-v2`)

Before reconciling, a refresh compares the report Indicator membership it would produce with the stored one (`refreshMembershipGuard.js`). The diff records:
- added and removed Indicators, each removal with a reason code (`identity_left_document`, `publisher_assertion_lost`, `became_context_only`, `excluded_by_type_gate`, `mode_changed`, `membership_rule`)
- newly Context Only rows
- classification changes
- analyst-reviewed rows that would be deleted
- the MODE change
- new extraction-quality warnings
- global IOC link changes on surviving rows (`ioc_link_changes`: `matched_ioc_id` cleared or moved, with `from_ioc_id` / `to_ioc_id`) — v2

The diff is saved in `analysis_progress.last_refresh.membership_diff` and in the job progress.

Material losses are protected. The **default policy `protect` blocks** a refresh that would:
- remove an analyst-reviewed Indicator (`reviewed_indicator_removed`)
- delete a reviewed or Create-IOC row (`reviewed_candidate_deleted`)
- drop a publisher-asserted Indicator (`publisher_assertion_lost`)
- remove at least 5 Indicators that are also at least 20% of the set (`bulk_membership_loss`)
- clear or move a stored global IOC link on a surviving row, even when Indicator counts are unchanged (`ioc_link_changed`, v2)

A blocked refresh writes nothing: no candidates and no publication date. The report keeps its status, and the job fails with `refresh_membership_loss_blocked` and a message naming the reasons.

MODE changes, new quality warnings, additions and ordinary reclassification of pending rows are recorded but do not block.

- **Preview:** `GET …/reports/:id/refresh-extraction/preview` returns the same diff and guard verdict and never writes. The UI's **Refresh extraction** action opens this preview first.
- **Explicit acceptance:** `POST …/refresh-extraction` with `{ "membership_changes": "accept", "reason": "…", "preview_fingerprint": "<membership_diff.material_fingerprint>" }` (reason ≥ 8 characters) applies the previewed changes. The policy rides the job dispatch, and the refresh audit event records `membership_guard` with the decision, reasons, `accepted_reason`, `accepted_preview_fingerprint` and the initiating analyst.
- **Stale previews:** the fingerprint covers every Indicator that leaves the original set (identity, reason, row outcome), every reviewed row that would be deleted, every global IOC link change (identity, from, to) and every IOC-linked row that leaves the Indicators or is deleted; additions do not change it. v1 fingerprints never match a v2 diff (the version is hashed), so a preview taken before the upgrade must be re-taken. The worker recomputes the diff when the job runs. A missing fingerprint is refused (`preview_fingerprint_missing`), and so is one that no longer matches the losses (`preview_stale`). An acceptance therefore never authorizes a materially different refresh.
- **Concurrent changes (time of use):** the guard first runs on rows read outside the write transaction. Inside the reconcile transaction, after every candidate row of the report is locked (`SELECT … FOR UPDATE`), the refresh checks two things before writing:
  - The locked rows must equal that snapshot: review state, assessment, role, IOC flag, assertion, match, promotion outcome, original-document flag and `updated_at`, with no row added or removed. A review, Create IOCs, promotion or IOC Source change committed in between aborts the refresh with `refresh_candidates_changed_concurrently`. Nothing is written and the report returns to its prior status; run Refresh extraction again.
  - The guard runs again against the locked rows and the current IOC Source links. A block there, for example an accepted preview whose losses changed because a link disappeared, is an ordinary blocked refresh.

  The publication date is written only after this guarded save. A review issued while the locks are held waits and then applies to the committed set. No new lock is taken: these are the same per-report candidate row locks the save already used. `refreshGuardConcurrency.integration.test.js` races a second connection at both points on real Postgres.
- **Who may accept (RBAC):** running Refresh extraction, viewing its preview, and refreshes with no material loss stay Analyst + Admin. Accepting a material loss depends on what is lost:

  | Lost by the accepted refresh | Accept as |
  |---|---|
  | Analyst-reviewed Indicator (any review decision or Create IOCs outcome), including one a linked IOC Source keeps | Admin |
  | Publisher-asserted Indicator (explicit IOC / C2 / operational row) | Admin |
  | Reviewed candidate row deleted | Admin |
  | Candidate tied to a global IOC (`matched_ioc_id` or created) leaving the Indicators or deleted | Admin |
  | Global IOC link cleared or moved on a surviving row (`ioc_link_changed`) | Admin |
  | Only unreviewed, non-publisher-asserted, IOC-free candidates (for example a bulk loss of model-only rows) | Analyst or Admin |

  The preview reports this as `guard.authorization` (`required_role`, `categories`). The rule is enforced at two points, and the preview fingerprint, reason requirement and transaction checks are unchanged:
  1. **Route:** a non-admin acceptance of admin-only losses gets `403 refresh_acceptance_requires_admin` before the report is claimed. The denial is audited (`…acceptance_requested`, status failed, `result: denied_requires_admin`).
  2. **Worker:** when the job runs, and again under the row locks, the worker resolves the acceptor's current role from `users` (active users only). The maintenance CLI operator resolves as `system`, which is admin-equivalent. An unresolvable principal is never admin (`acceptance_not_authorized`), so a demoted admin, a passive account or a role claim in the request or dispatch payload cannot authorize. A refused acceptance is an ordinary blocked refresh with nothing written.

  The dialog shows an analyst why an admin is needed instead of offering the acceptance. A protected refresh is unchanged for every role.
- **Acceptance audit:** queueing an explicit acceptance writes `threat_library.refresh_extraction.acceptance_requested` with the actor, reason, preview fingerprint and job. The worker's outcome event follows, recording whether the acceptance was applied, refused as stale or blocked, with the resulting membership diff counts. `membership_guard.affected` names the identities an acceptance covered (bounded to 40 each): removed Indicators, deleted reviewed rows and IOC link changes (`identity`, `from_ioc_id`, `to_ioc_id`).
- **Linked IOC Sources:** a row that leaves the original document but has IOC Source provenance is kept with its analyst state (`original_occurrence_cleared`, still in the union inventory). It is not counted as a deleted reviewed row. A publisher-asserted Indicator that leaves the original document stays a material loss either way. Removed and deleted entries carry the matched IOC id; refresh never deletes the global IOC record.
- **CLI:** the maintenance CLI does the same with `refresh-extraction --apply --accept-membership-changes --reason "…" [--preview-fingerprint <from a dry-run>]`, and its dry-run shows the verdict and fingerprint.

#### Extraction quality warnings (`tl-quality-v1`)

Every extraction (import, Retry, Re-run AI and Refresh) runs `extractionQuality.assessExtractionQuality`: deterministic, read-only checks over the zone-annotated document and the candidates. It never changes candidates, membership, MODE or review state. The checks cover:
- row-shaped IOC values outside authoritative scope, adjacent to it (`warning`) or elsewhere (`info`)
- an IOC appendix with zero or few hash Indicators
- authoritative sections without Indicators
- structural-completeness and explicit-table inconsistencies
- suspicious Indicators: example, legitimate-marker, publisher-domain, email-only or missing-provenance

Each warning has a stable code, severity, candidate identities, block ids, section context, evidence excerpts, an explanation and extractor versions. Thresholds live in `EXTRACTION_QUALITY_THRESHOLDS`.

**Check 9 (`tl-quality-v5`): `analyst_state_membership_divergence`.** On a fresh extraction that replays stored analyst state (Refresh extraction, Retry / Re-run AI), the deterministic publisher membership is compared with the membership after analyst state is re-applied. A difference caused by an explicit analyst decision (`promote_to_ioc` keeps an Indicator, a Context Only review excludes one) is an `info` note; any other difference is a `warning` listing the unexplained identities. The warning carries `divergence` (`added_by_replay`, `removed_by_replay`, `causes`). It never changes membership. Stored `tl-quality-v1`…`v4` records stay readable unchanged; a report gets a v5 record on its next import / refresh.

The record is stored in `analysis_progress.extraction_diagnostics.quality` and returned as `extraction_quality` on report payloads. The report page shows it as **Overview → Extraction quality** (status, analyst wording per reason code, section context and affected values; no block ids, zones or versions), plus a header chip when something needs review. Warnings are labelled as automatic signals, not confirmed errors. MCP `get_threat_report` returns a summary (status, counts, codes). Reports imported before `tl-quality-v1` have `null` until their next refresh. The benchmark (`docs/threat-library-benchmark.md`) measures the detector's false warnings and detection rate.

`npm run scan:threat-library-quality` (backend container) runs the same read-only preview over stored reports: a read-only DB session, no model, no network. It prints each report's quality status, the guard verdict a refresh would get and its Indicator diff. `--clean <ids>` counts warnings on analyst-verified reports as false warnings. Use it before any bulk refresh.

### Chunking / limits

- `max_input_chars` is the **per-request / per-chunk** budget (not “take first N and discard the rest”)
- Long reports are split into canonical-document chunks and processed sequentially
- Body chunks exclude header/footer, navigation, source-provenance and reference rows; each chunk prompt carries the resolved indicator list (compact) plus only the `ai_needed` candidates whose occurrences fall in that chunk
- Completed chunks are checkpointed with `threat-library-semantic-v9` and their block-id fingerprint; **Retry analysis** resumes unfinished, compatible chunks without re-fetching the URL/PDF. A contract bump (document extractor, candidate extraction or semantic schema) invalidates only the incompatible layer
- The optional final synthesis runs over validated chunk results only, is skipped when the remaining budget is short, and never fails the run; repair calls are likewise budget-bounded (one per chunk)
- Ollama requests set `think: false` — reasoning models otherwise spend minutes on hidden chain-of-thought before the schema-constrained JSON starts; structured output is the contract
- Every provider call is timed (headers / first token / output chars) into `analysis_progress.timing` and the worker log; a total-deadline failure records completed/remaining chunks so the UI can explain what a Retry will resume
- AI responses go through: provider structured output → JSON extraction → deterministic normalization → Zod schema → reference checks → persist
- Categorical confidence words such as `high` map to documented numeric values; invalid items in optional relationships are dropped with diagnostics rather than discarding an entire valid chunk
- Separate timeouts: AI capacity wait, connection, first response (from request sent, after a slot is acquired), inactivity (resets on stream activity), per-request execution limit, and the active-analysis ceiling — see [AI inference capacity](#ai-inference-capacity)
- Ollama uses native streaming (`/api/chat` + JSON Schema `format` when supported + `keep_alive`) so long local generations are not mistaken for hung connections
- Failed AI validation stores capped model-output samples and issue paths on the analysis chunk for diagnosis (not full report prompts)
- Provider API keys are never logged; progress is persisted server-side (browser navigation does not cancel the job)

Prompt injection: report text is labeled UNTRUSTED DATA; the model cannot redefine tasks, request secrets, invoke tools, or invent tags from instructions inside the report.

### Report tags (AI Analyst)

URL/PDF analysis (`threat-library-semantic-v9`) may also emit compact **report-level** tags. They are not copied onto extracted IOCs.

**What a report tag is.** A short, reusable label that tells an analyst what the report is *primarily* about: the kind of operation, targeted sectors or regions, exploited technology or vulnerability class, and the techniques that define the operation. Tags optimise retrieval and situational awareness; they do not enumerate everything the report mentions. Boundaries:

- Named threat actors, malware families, campaigns and tools are **entities**, not tags.
- Threat categories that the tag catalog retired into **Threat Classifications** (`ransomware`, `phishing`, `c2` are disabled catalog tags) are not linked even when the model proposes them.
- A detail that appears only in passing (one command line, one utility, one IOC note) is not a tag.

**Pipeline.**

- Each chunk call returns up to 5 tags, most representative first (provider grammar `maxItems: 5`). The instruction gives no example tag vocabulary: v8 listed example words that the local model copied verbatim into unrelated reports.
- The chunk merge normalizes names (`credential-theft` → `credential theft`), drops filler words (`security`, `cyber`, `malware`, `report`, …), IOC values, URLs, hashes and CVEs, and drops a tag the report text does not support (every content word must occur in the title/body, inflections tolerated, never synonyms; non-English reports skip this lexical check). Ranking: number of chunks proposing the tag, then first-seen order. Up to 10 ranked suggestions reach persistence.
- Persistence resolves suggestions in rank order against the `tags` catalog (name, then slug), reuses existing tags, creates new ones (`ensureCatalogTag` + `ON CONFLICT` / unique name+slug), skips disabled catalog tags without using a slot, and links at most 5 per analysis.
- Links are additive on `threat_report_tags`. Re-analysis never unlinks a tag (analyst-added or from an earlier analysis). Manual add/remove on the report remains the same API/UI. A `semantic-v8` checkpoint is never reused, so Retry re-asks for tags; existing links are not rewritten.

Old reports without AI tags keep an empty `tags` array. Historical reports are not mass re-analyzed.

Threat Library automatic MITRE ATT&CK mapping was removed after quality evaluation (`threat-library-semantic-v8`). Existing historical DB rows (`threat_report_mitre_mappings`, migration 034) are retained but no longer generated or exposed; a `semantic-v7` checkpoint is never reused and a legacy `mitre_attack` property is ignored.

### Confidence policy

Central thresholds in `backend/lib/threatLibrary/constants.js` (`CONFIDENCE_POLICY`):

- High: ≥ 0.85
- Review floor: &lt; 0.4 (unknown/suspicious → needs_review)
- Suggest approve-all malicious: ≥ 0.9

AI confidence is not truth; analysts approve IOC creation.

### Context Only is not an IOC candidate

A candidate row is **Context Only** when any of `assessment`, `match_state` or `review_status` is `context_only` (the pipeline sets the first two; the *Context only* review action sets all three). Such rows are context, never IOC candidates, and the rule is enforced at item level on both sides regardless of the active filter:

- **Toolbar.** In the Context Only view the IOC lifecycle actions (*Approve*, *Create IOCs*, *Approve high-confidence malicious*, the redundant *Context only*) are not rendered at all; the toolbar is `Promote to IOC…` + `Ignore`. In every other view (including *All*) *Approve* / *Context only* / *Create IOCs* enable only when the selection contains at least one IOC candidate, and a mixed selection sends only the IOC-candidate ids (the banner reports how many Context Only rows were left out).
- **Backend.** `approve` and `approve_high_confidence_malicious` filter context-only / `is_ioc = false` rows out in SQL (`NOT_CONTEXT_ONLY_SQL`) and return `updated` (actual row count) plus `skipped_context_only`; `create_iocs` classifies them `not_applicable`; the high-confidence candidate set additionally passes `isActionableReviewIndicator`.
- **Row-level exception.** `POST …/review { action: "promote_to_ioc", candidate_ids: [id] }` is the only way out: exactly one context-only row of a creatable type (`400 promote_single_row_only`, `409 promote_not_context_only` / `promote_unsupported_type` otherwise). The row is re-classified `review_status = approved`, `assessment = suspicious`, `is_ioc = true`, `match_state = new | existing` (context roles reset to `unknown`), the original classification is kept in `evidence.promoted_from` (`policy_decision = analyst_promoted_from_context_only`, `decision_source = analyst`), and the row then goes through the normal Create IOCs path (dedup / link / outcome / `ioc.created` audit). The UI offers it as a confirmed single-selection action in the Context Only view.

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
| `threat_library.candidates.approved` / `.context_only` / `.ignored` | review action (grouped) | selected / changed / already_in_state / skipped_context_only, type distribution, candidate ids (bounded) |
| `threat_library.candidates.promoted` | **Promote to IOC…** (single Context Only row re-classified as an approved IOC candidate) | same shape, `target_state: approved`; followed by the `threat_library.iocs.created` event of its Create IOCs run |
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

## Report list dates

The Threat Library list (`/threat-intelligence/threat-library`) shows two independent timestamps:

| Column | Canonical field | Meaning |
|---|---|---|
| **Published** | `threat_reports.published_at` (+ `published_date` / `published_at_precision` / `published_at_source`) | When the original intelligence/report was published. Same value as report detail. Date-only sources render as a calendar day; missing values show `—`. Never inferred from import time. |
| **Imported** | `threat_reports.created_at` | When TalonHound ingested the report. |

The list endpoint already selected these columns (`SELECT r.*`); the list serializer is `publicReport` / `serializePublicationDate`.

## Report list sorting

Column headers on `/threat-intelligence/threat-library` are three-state and **server-side**: default → ASC → DESC → default. Only one explicit sort is active. Default (third click, or no `sort`/`order` query params) is exactly `ORDER BY r.created_at DESC` — the pre-existing newest-imported-first order. Do not simulate default with Published or Imported.

API: `GET /api/threat-library/reports?sort=&order=` with a whitelist. Unsupported values fall back to the default order; user input is never interpolated into SQL.

| Column | `sort=` | ORDER BY |
|---|---|---|
| Report | `report` | `LOWER(title)` NULLS LAST |
| Source | `source` | list display source (`source_name`, else URL / PDF name / THIB) NULLS LAST |
| TLP | `tlp` | stored TLP 2.0 restriction rank (clear → red) |
| Entities | `entities` | `entity_count` (integer) |
| Indicators | `indicators` | `indicator_count` (integer; the list SELECT alias, not a formatted string) |
| Matched | `matched` | `matched_count` (integer) |
| Status | `status` | `analysis_status` NULLS LAST |
| Published | `published` | `published_at` **NULLS LAST both directions** (never `created_at`) |
| Imported | `imported` | `created_at` |

Explicit sorts add `created_at DESC, id DESC` (Imported uses `created_at` + `id` in the requested direction). `ORDER BY` is applied to the filtered set before `LIMIT`/`OFFSET`. Changing sort or search resets to page 1; page/page-size changes keep the active sort. URL: `?sort=published&order=desc` — omitted when default.

## Async processing

BullMQ queue `threat-library` + `threat-library-worker` service. Stages persist on `threat_reports` / `threat_library_jobs` for real UI progress.

URL and PDF imports share one analysis pipeline and one concurrency budget. THIB imports skip AI.

### Concurrent report analyses

AI Settings field: `max_concurrent_report_analyses` (UI: **Concurrent report analyses**).

| | |
|---|---|
| Default | **2** — matches the historical `THREAT_LIBRARY_WORKER_CONCURRENCY` default so existing installations keep the same throughput until an administrator changes the setting |
| Range | integer **1–4** (backend + frontend validated; DB CHECK) |
| Applies to | the common URL/PDF pipeline jobs (`analyze` / `retry` / `refresh_extraction` / `rerun_ai`), not a batch size |
| Persistence | `threat_library_ai_settings` (same singleton row as provider settings). Takes effect without restart |

**Queue.** Import HTTP creates the report + a `threat_library_jobs` row (`status=queued`, `bullmq_job_id` null) and returns 202. A job occupies a slot only after it is claimed (`bullmq_job_id` set) and while `status` is `queued` or `running`. Unclaimed jobs stay **Queued** (`analysis_status=pending`) — they do not look like Analyzing.

**FIFO.** Claim order is `created_at ASC, id ASC`. A new import cannot jump ahead of older queued jobs.

**Claim.** `dispatchQueuedThreatLibraryAnalyses` takes `pg_advisory_xact_lock(hashtext('threat-library.analysis_slots'))`, counts occupied slots, then `SELECT … FOR UPDATE SKIP LOCKED` of the next eligible jobs. Two schedulers cannot both observe `occupied=0` and start work when the limit is 1.

**Slot release.** Completing, failing, or cancelling a claimed job (including a terminal retry-exhausted state) frees a slot. The worker then claims the next queued job automatically — no Refresh / Analyze / Finalize / restart.

**Runtime changes.** Increasing the limit immediately claims more queued jobs. Decreasing it never kills in-flight analyses; new claims wait until `active < new limit`.

**Restart / stale jobs.** Queued (`bullmq_job_id` null) jobs survive backend/worker restart. A worker claims a job in PostgreSQL before running it (`owner_token` + `heartbeat_at`, every 15s); a second delivery of the same job (BullMQ stalled re-delivery, re-dispatch after recovery) yields to a live owner. A `running` job is re-queued only when its owner's heartbeat is older than 2 minutes, regardless of the BullMQ state (a crashed worker's job stays "active" until its lock expires); legacy rows without an owner fall back to the BullMQ state check. On graceful shutdown the worker aborts in-flight AI requests and re-queues its jobs immediately (`Queued (resuming)`), so the next worker resumes from completed chunks. Dispatch never claims a second pipeline job for a report that already has one claimed. A 30s safety net runs recovery and dispatch (including due automatic retries); import/complete/settings already wake the scheduler directly.

**Worker process ceiling.** `THREAT_LIBRARY_WORKER_CONCURRENCY` (Compose default 4) is the BullMQ worker capacity. It must be ≥ the setting maximum so a runtime increase does not require a compose change. The setting is the real limiter.

### AI inference capacity

`max_concurrent_report_analyses` limits how many reports are in the pipeline; it does not limit how many requests reach the AI provider. Every AI request — chunk, repair, compact recovery, synthesis and the Settings connection test — first takes a slot from the shared inference scheduler (`lib/threatLibrary/ai/inferenceScheduler.js`, table `threat_library_ai_capacity_leases`).

| Setting (AI Settings) | Default (local / hosted) | Meaning |
|---|---|---|
| `max_concurrent_ai_requests` | 1 / 4 | Requests the provider endpoint runs at once, shared by all processes. Raise only when the host runs requests in parallel (Ollama `OLLAMA_NUM_PARALLEL`). |
| `capacity_wait_timeout_ms` | 60 / 15 min | Cumulative time one analysis may wait for slots → `ai_capacity_wait_timeout` |
| `provider_execution_timeout_ms` | 20 / 10 min | One request, streaming included → `provider_execution_timeout` |
| `auto_retry_max_attempts` | 2 | Bounded automatic retries of transient failures (0 disables) |

- **Fair and bounded.** Slots are granted strictly FIFO per endpoint (`provider|base_url`; models on one host share it). Chunks of a report run one at a time, so FIFO alternates between reports and no report monopolizes the provider. Waiting holds no database connection.
- **Crash-safe.** Slots are leases: holders heartbeat every 15s, waiters refresh while polling; a dead process's lease expires (60s holding, 15s waiting). A holder that cannot confirm its lease aborts its request (`ai_capacity_lease_lost`).
- **Timing.** The first-response timer starts when the request is sent, after the slot is acquired: queueing behind other analyses is never reported as `first_token_timeout`. `total_analysis_timeout_ms` bounds active analysis time; capacity waits are excluded and bounded by `capacity_wait_timeout_ms`.
- **Transport.** Provider calls use `node:http(s)` without Node fetch's implicit 300s header/body timeouts. Every failure aborts the request and waits (≤5s) for the socket to close.
- **Quarantine.** A closed socket does not prove the provider stopped (a lost FIN, a provider that ignores the disconnect). When TalonHound aborts a local-provider request that was already sent, the slot is not released: it stays `holding` as a durable quarantine row (`quarantined_at`) — it survives the worker process — until a 1-token probe sent inside that slot is served promptly (provider proven idle), or the request's worst-case bound (`provider_execution_timeout_ms` from when it was sent) passes. The head-of-queue waiter (any process) and the worker safety net (every 30s, even with nobody waiting) run the probe, at most once per 10s per slot; connect failures and provider-reported errors release immediately; hosted providers are not quarantined.
- **Fail-closed.** For local providers time never frees capacity. A holding lease that expires (worker crash, database outage, network partition) is converted into a quarantine (`purpose = quarantine:lease_expired`) by whoever reaches the database first, never handed out. A quarantine past its worst-case bound is kept; new analyses then fail fast with `ai_capacity_quarantined` (transient: bounded automatic retry) instead of waiting. Recovery: a successful probe, or **AI Settings → Release quarantined capacity** (admin, confirmation required, audited as `threat_library.ai_capacity.released`) after confirming the provider is idle (e.g. restarted).
- **Ownership fencing.** Every write of a worker-run analysis or Refresh extraction runs in a transaction that locks the job row and checks `owner_token` (`lib/threatLibrary/jobFence.js`): a takeover or recovery serializes against in-flight writes, and a worker that lost the job commits nothing. Each outcome commits as one fenced transaction — analysis: candidate reconcile, entities, relationships, review_required, job completion; refresh: candidate reconcile (with its drift re-check against concurrent review), publication date, grounding, status, job completion.
- **Residual contention.** A request that held a TalonHound slot but still queued inside Ollama (an external client on the same host) is logged as `residual provider contention` with `provider_queue_ms`.
- **Automatic retry.** Only `first_token_timeout`, `provider_inactivity_timeout`, `connection_timeout`, `provider_unreachable`, HTTP 429/5xx and scheduler availability failures. Backoff 60s × 2^(n−1) + 0–25% jitter (≤15 min), one live pipeline job per report, every attempt goes through the scheduler and resumes from checkpoints. The report shows **Retry scheduled**; Retry Analysis makes a scheduled retry due immediately.
- **Telemetry.** Per call (`analysis_progress.timing`, chunk `timing` and worker log): `slot_wait_ms`, `slot_max_position`, `headers_ms`, `first_token_ms`, `stream_ms`, `total_ms`, `provider_queue_ms`, Ollama token counts, `cancel_outcome`. Earlier chunk attempts are kept in `threat_library_analysis_chunks.attempt_history` (last 10).

The worker must run the same backend image as the API (`talonhound-backend:local`). Building only the `backend` service and recreating workers without a shared image tag previously left the worker on a stale AbortController timeout path.

## Additional IOC Sources

A Threat Library report may reference multiple external IOC datasets (for example a publisher GitHub IOC directory) in addition to the original HTML/PDF document.

```text
Report analysis completes
      │
      ▼
Selective auto-discovery of explicit publisher IOC references
(HTML href + text cues + IOC heading; never bare github.com/)
      │
      ▼
`discovered` rows only — never fetch / attach / extract / approve
      │
      ▼
Analyst inspects → Approve & Attach → deterministic extract
      │
      ▼
Same candidate identity + source provenance links → existing review workflow
```

Discovery requires textual IOC-dataset evidence (or a strong `/ioc|indicators/`
path). Destination-only anchors such as “Indicators of Compromise can be found
here” are preserved as structured `block.links` (htmlBlocks v6 / HTML extractor
v7) and scored by the shared `externalIocReference` module used by both
discovery and section-tree authority. An empty formal IOC section that
explicitly points at an external pack does **not** delegate Indicator authority
into the article body. Discovery still never attaches or extracts.

**Discovery precision (tl-ioc-source-discovery-v2).** Evidence is anchor-local:
the link text and its own sentence / block. An IOC section heading adds weight
but never validates a link by itself, so tag / author pages, "Cancel", next /
previous posts and comment-policy links that sit after an IOC heading are not
sources. Never accepted: lookup / sandbox / search services (opentip, VirusTotal,
urlscan …) and per-indicator links whose text is the observable; payload,
archive and code files (`.zip`, `.exe`, `.js` …); same-site navigation unless
the anchor presents a data file as an IOC pack; and, outside a code host, any
destination that is not a data file or an IOC path (product pages, advisories,
other blog posts). Discovery is insert-only: an existing row (discovered,
inspected, extracted or dismissed) is never rewritten by analysis, retry or
refresh.

**Campaign scope (tl-ioc-source-scope-v1).** A linked pack contributes only what
the publisher ties to this report:

- A folder `README.adoc` / `README.md` (ESET `malware-ioc` style) is read
  structurally — AsciiDoc headings and `|===` tables — never as flat text, so a
  "Hosting provider" cell stays a column.
- A README must link the report (or carry a section titled like it). A
  multi-campaign README contributes only that section; its folder-wide hash
  lists (`samples.*`) are deselected because they cannot be attributed. A README
  not tied to the report contributes nothing (`campaign_scope_unresolved`).
- MITRE ATT&CK / reference sections and links to the publisher's own articles
  are never linked indicators.
- A repository root is never enumerated. The campaign folder is resolved from
  the report's own distinctive names (title words, proper-name headings such as
  `UAC-0099`) within bounded breadth / depth and accepted only when its README
  links the report; otherwise the source is `unsupported` with
  `campaign_scope_unresolved`.
- A publisher remediation note ("no longer infected") is a remediated stance:
  the value is Context Only.

Report detail and MCP `get_threat_report` overlay a read-time
`linked_ioc_source_not_ingested` quality warning (and `linked_ioc_sources`
lifecycle counts) while a publisher-declared source is not extracted: Linked
and Union are incomplete until the analyst inspects and extracts it.

**Counts (must stay aligned across UI, API, MCP, SQL):**

| Count | Meaning |
|---|---|
| Original indicators (`review_candidate_count`) | Unchanged MODE A/B publisher membership on original-document occurrences |
| Total unique | Original Indicators ∪ approved linked-source Indicators |
| Linked-only | In the union, not in the original set |

Approving a source authorizes extraction and report association. It does **not** approve IOCs into the global inventory. Linked-source extraction is deterministic (no AI) in the first delivery. Unsafe URLs fail at the source only and never alter the parent report’s analysis status.

Lifecycle: `discovered → inspecting → inspected → attached → extracting → extracted`, with `dismissed`, `blocked`, `unsupported`, `failed`, and `stale` (refresh reserved for a later phase).

## Email IOC support (backlog)

Email addresses are not an IOC type in this promotion-safety change. Adding one is a separate contract, not a review-gate exception. The work has to land together:

- **Data model.** A new `email` observable type on `ioc_items` and `threat_report_candidates`, with a canonical form (lowercase local-part and domain, no display name, no `mailto:`). Uniqueness stays `(observable_type, normalized_value)`. A bare domain taken from an email address stays a domain candidate only when the report states the domain itself; the address does not promote the domain.
- **Normalization.** One normalizer shared by extraction, Create IOCs, search, and feeds. Reject display names, commas, and unexpanded placeholders. Internationalized domains go through the existing domain canonicalizer.
- **API.** Create, lookup, bulk lookup, search, and Threat Library review accept `email` only after the type is in the creatable set. Responses include the type in the same fields as `domain` and `url`. MCP `lookup_ioc` / `search_iocs` / `import_iocs` use that type; they do not invent a side channel.
- **UI.** Indicator tables, IOC detail, filters, and Create IOC forms offer `email` with the same validation the API enforces. Promotion still requires positive publisher evidence or an audited operational corroboration of that exact address.
- **Integrations.** Feed import, enrichment providers, and published-feed output either carry `email` explicitly or reject it with a typed error. Silent coercion to `domain` is not part of the change.

Until that contract is implemented and tested, an email-shaped token stays context or is excluded. It is not promoted by the narrative gate.

## Future STIX note

Canonical entities/relationships intentionally resemble STIX concepts (threat-actor, malware, indicator, relationship) without implementing STIX 2.1 in V1.
