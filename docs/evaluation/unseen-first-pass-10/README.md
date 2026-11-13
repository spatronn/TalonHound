# Unseen first-pass-10 evaluation

**Status:** complete — all 10 first-pass captures scored; see [FIRST-PASS-QUALITY-REPORT.md](FIRST-PASS-QUALITY-REPORT.md) (aggregate P≈0.933, R≈0.929; Trend linked-pack membership failure is the main finding).

## Purpose

Measure current Threat Library first-pass quality on **10 genuinely never-imported** public reports (not familiar corrected reports, not the sealed 40).

## Freeze

See [FREEZE.md](FREEZE.md) and [freeze-contract.json](freeze-contract.json).

Workspace contract fingerprint at freeze: `ee233e2fdf4e69bee40f1de64f56b091` (`tl-candidates-v63` bundle). Host SSH re-verify failed at freeze time; production run stamps are recorded per report in first-pass captures.

## Sample (all `exists=false` at selection; not in sealed 40; not fixture source URLs)

| id | Publisher | Traits |
|---|---|---|
| msft-gsocket | Microsoft | IOC table, narrative, legit tool abuse |
| huntress-sckit | Huntress | IOC table, narrative, ScreenConnect abuse |
| rf-markirat | Recorded Future | IOC appendix, phishing domains |
| trend-installfix | Trend Micro | IOC table, fake installers |
| trend-kongtuke | Trend Micro | compromised WordPress / mixed benign |
| trend-teampcp | Trend Micro | supply chain / linked packages |
| unit42-falcon-c2 | Unit 42 | browser extension IOC list |
| groupib-ghost-stadium | Group-IB | fraud domain/IP tables |
| unit42-cairn | Unit 42 | sparse IOC (2 IPs) + narrative |
| google-tag-apt42 | Google TAG | phishing IOC list / abused cloud |

Sophos ScreenConnect was intended as #10 but HTML fetch timed out twice; replaced with Google TAG APT42 (also never imported).

## Workflow

1. Source HTML retained under `_source_html/` (gitignored) with sha256 in packets.
2. Empty Evidence-First packets in `packets/` — label from source only (`worksheets/HOW-TO-COMPLETE.md`).
3. Import once via production MCP (`import-ledger.json`) — **no refresh, no review, no finalize**.
4. Capture first-pass with `threat_library_get_review` → `first-pass-captures/<id>.json`.
5. Score with `_score.mjs` (membership = `indicator_membership`) → `score-summary.json`.
6. Consolidated report: [FIRST-PASS-QUALITY-REPORT.md](FIRST-PASS-QUALITY-REPORT.md).

## Separation

- `sealed_eligible: false`
- Do not copy into `backend/lib/threatLibrary/benchmark/sealed/cases/`
- Separate from pilot-qwen-candidates and first-measured-batch sealed labeling
