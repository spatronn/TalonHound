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
3. Extract article-like HTML into canonical blocks.
4. Deterministic IOC candidates → AI classification → bulk IOC match → review.

### SSRF protections

- http/https only; reject embedded credentials
- reject localhost, loopback, link-local, RFC1918, CGNAT, cloud metadata hosts
- validate redirects; redirect limit; size + timeout limits
- content-type allowlist (HTML/text; PDF-via-URL deferred to PDF upload)

## PDF import

- `application/pdf` validation, size limit, safe filename, SHA-256
- Text extraction via `pdf-parse` with page-aware block ids (`p17-b08`)
- Scanned/image-only PDFs are detected and **fail clearly** with `requires_ocr` (OCR not in V1)

Storage: `/data/threat-library` (not web-executable). Storage keys are relative; absolute paths are never returned to clients.

## AI provider configuration

Admin UI: **Threat Library → AI settings** / Administration Settings card.

Supported providers:

- OpenAI
- Anthropic
- Ollama / local
- OpenAI-compatible endpoint

Settings: provider, base URL, model, API key, timeout, max input chars.

Secrets:

- Stored in `threat_library_ai_settings.api_key`
- API responses return **masked** keys only
- Keys are never logged

### Privacy

TalonHound is self-hosted. Enabling an **external** provider means selected report text may leave the instance. The UI requires an explicit privacy acknowledgement before enablement. Local Ollama/compatible endpoints can keep processing on-prem. No report content is sent until an administrator configures and enables a provider.

### Chunking / limits

- Max input chars (default 120000)
- Document chunked (bounded chunks) before prompt construction
- Provider timeout; AI output validated with Zod before persistence
- Deterministic candidates are passed to the model for classification (not rediscovery)

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

## Limitations (V1)

- No OCR for scanned PDFs (architected for later)
- No STIX/TAXII export (model kept mappable)
- No digital signatures on THIB (hash only)
- URL→PDF auto-ingest not supported (upload PDF tab)
- Not a MISP/OpenCTI replacement

## Async processing

BullMQ queue `threat-library` + `threat-library-worker` service. Stages persist on `threat_reports` / `threat_library_jobs` for real UI progress.

## Future STIX note

Canonical entities/relationships intentionally resemble STIX concepts (threat-actor, malware, indicator, relationship) without implementing STIX 2.1 in V1.
