# Held-out corpus inventory

## Historical pilot baseline (pre-fix, 2026-10-25)

Combined 9 cases (5 real + 4 synthetic): TP 51 / FP 4 / FN 0 — precision 0.9273 / recall 1.0 / exact 7/9.

| Split | Reports | TP | FP | FN | Precision | Recall | Exact |
|---|---:|---:|---:|---:|---:|---:|---:|
| Real publisher extracts | 5 | 43 | 0 | 0 | 1.0 | 1.0 | 5/5 |
| Synthetic structural | 4 | 8 | 4 | 0 | 0.6667 | 1.0 | 2/4 |

Pilot FP identities (investigation):

1. `domain:ifconfig.me` — **INCORRECT GROUND TRUTH** (IOC-table row with malice co-mention; MODE A assertion intended). Label adjudicated.
2. Three Host/Port rows under H1 containing `IOC-shaped` — **CONFIRMED ENGINE DEFECT** (mid-title `\biocs?\b` opened MODE A). Defect promoted to regression; fixture title cleaned for continued unlabelled-row evaluation.

## Current inventory

| id | split | publisher | notes |
|---|---|---|---|
| heldout-talos-uat-9686 | pilot | Cisco Talos | real extract |
| heldout-talos-uat-7237 | pilot | Cisco Talos | real extract |
| heldout-eset-promptspy | pilot | ESET | real extract |
| heldout-unit42-panos-cve | pilot | Unit 42 | real extract |
| heldout-cisa-aa24-290a | pilot | CISA | real extract |
| heldout-microsoft-chaindrop | expansion | Microsoft | untouched real |
| heldout-microsoft-macsync | expansion | Microsoft | untouched real |
| heldout-talos-uat-8302 | expansion | Cisco Talos | untouched real |
| heldout-unknown-nested-appendix | pilot | synthetic | structural |
| heldout-unknown-benign-near-malicious | pilot | synthetic | dual-use adjudication |
| heldout-unknown-empty-appendix | pilot | synthetic | quality |
| heldout-unknown-three-unlabelled-rows | pilot | synthetic | unlabelled rows (title cleaned) |

**Target:** 15–20 real / 30–50 long-term. **Real labeled now:** 8. **Synthetic:** 4.
