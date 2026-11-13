# Pipeline freeze — unseen first-pass-10

Recorded before any import in this experiment. **Do not change extraction code or refresh these reports until first-pass captures are stored.**

| Field | Value |
|---|---|
| Freeze timestamp (UTC) | 2026-11-12T22:25:00Z |
| Workspace contract fingerprint | `ee233e2fdf4e69bee40f1de64f56b091` |
| Contract bundle | see `freeze-contract.json` |
| Host SSH verify | **failed** (`Permission denied` to `192.168.1.190`) — production commit not re-read at freeze; production import will stamp extractor versions on each report run |
| Sealed 40 fingerprint (historical) | `81a6e1a30019b5d66d78da789bbfee1b` (different contract — this experiment is **not** scored into sealed) |
| Experiment id | `unseen-first-pass-10-2026-11-13` |
| Sealed eligible | **false** |

## Bundle (workspace at freeze)

```
candidates=tl-candidates-v63
zones=tl-zones-v18
tables=tl-table-v19
type_resolver=tl-type-resolver-v26
html=threat_library_html_v10
pdf=threat_library_pdf_v7
section_tree=tl-section-tree-v17
scope_engine=tl-scope-engine-section-tree-v3
quality=tl-quality-v16
evidence_integrity=tl-evidence-integrity-v3
ioc_source_scope=tl-ioc-source-scope-v8
structured_sources=tl-ioc-source-structured-v2
dispositions=tl-dispositions-v1
membership=tl-membership-decision-v3
```

## Rules during the experiment

1. No extraction code edits.
2. One production import per URL via normal Threat Library → Import Intelligence → URL (MCP `threat_library_import_url`).
3. No refresh extraction, no review decisions, no Create IOCs, no finalize before first-pass capture.
4. Capture review surface (`threat_library_get_review`) as soon as `ingestion_complete`.
5. Keep all artifacts under `docs/evaluation/unseen-first-pass-10/` — never copy into `backend/lib/threatLibrary/benchmark/sealed/cases/`.
