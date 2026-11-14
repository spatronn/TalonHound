# Freeze — import audit 35880–35889 (first pass)

Captured 2026-11-13/14 from production, before any refresh, review, Create IOCs or
finalize. All 10 reports were `review_required`, 0 candidates decided.

## Contract at capture

| Item | Value |
|---|---|
| Production commit | `cab54b1` (PR #111) |
| Contract fingerprint (every first-pass extraction run) | `e133fab1e4ec284c2b8991e7d3511232` |
| Bundle | tl-candidates-v66, tl-zones-v18, tl-table-v19, tl-type-resolver-v27, threat_library_html_v11, threat_library_pdf_v7, tl-section-tree-v19, tl-scope-engine-section-tree-v3, tl-quality-v16, tl-evidence-integrity-v3, tl-ioc-source-scope-v8, tl-ioc-source-structured-v2, tl-dispositions-v1, tl-membership-decision-v3 |
| Reproducibility | Offline replay of the stored canonical documents at `cab54b1` reproduces stored Indicator membership for all 10 reports (0 differences). |

## Reports

| ID | Publisher | Retained source artifact (sha256) |
|---|---|---|
| 35880 | ESET | `7ec988924225e14973a816c8a09c3bb6a9e66fa00ab70073cc8d58c8ebef476f` |
| 35881 | Elastic | `92457530826e25b931153102acaa08af11b15ec4066e061121e506c445e79ed8` |
| 35882 | Check Point | `a217172e356ecd527fbb05d54cf0db7fd207217e818c7516fe82a44709c716a0` |
| 35883 | Fortinet | `da40e2c6a420bc1a78e201868e70be3b03215930a04780b0599fecfa394dbe7f` |
| 35884 | Huntress | `4f3e0f0acd87d9b7c81b2dc19d228ff13a7a7af9426d2127e966135328839741` |
| 35885 | Securelist | `d0c59904be860df2bc2cd704c708b92db6716585bd96fe39197711711df19dd3` |
| 35886 | Symantec | `1dca801c5d6c9cf01c038602bd6e98e1b88a9803d860a6dbbb9a17d40e06ba18` |
| 35887 | Group-IB | `f055b1f331cb3656a8b6236292b493f89d89d5d69145bef5c882446206465501` |
| 35888 | ReversingLabs | `6e8b6387ddc10b4f9ab921be4395d2b3d3a6b5a8aa8cb57e659876bc33bc1a62` |
| 35889 | AhnLab ASEC | `0a7e36c596461498d9d50fcba971219b52857a6924744ad2192c487f5807fd63` |

Each artifact was copied from the production artifact store and its sha256 checked
against `threat_report_artifacts.sha256` (10/10 match).

## Files

Committed (derived, no full publisher text):

| File | sha256 |
|---|---|
| `first-pass-extraction-runs.jsonl` | `9ef8e51f9abb5023b8621046c657e4816e10e83ddbf2579749c33cb3f4bb92bf` |
| `first-pass-captures/35880-eset-turla-cereal.json` | `34051a0bf2ff2faaf0a73f2a2d5f7d0d25ced3d408ec7cd9e1cdac3d9d2ae808` |
| `first-pass-captures/35881-elastic-sansar.json` | `5019f0dab0d506e7b8e03849bbd33b1e1871142e07fec3f1a053c3e1a5f59ea5` |
| `first-pass-captures/35882-checkpoint-php2shell-gateway.json` | `e46bb9b47554bdcc5f64b2c57a1f1275353c1c568a11c51e87588c913c053d9b` |
| `first-pass-captures/35883-fortinet-tsql-mssql.json` | `79de251bebfde3d5df5c2866ef91630ce4da4ef7664a7a22cfaf5d3802d25cce` |
| `first-pass-captures/35884-huntress-geovision.json` | `0829bccb9d0ee4cc072a22e80860c317c6ed28ee84f42900642047fff5b859e5` |
| `first-pass-captures/35885-securelist-esxi.json` | `218377347008de7b47f4af673cc9cfbe7da6cb667295fb2120a06a8ef1c77662` |
| `first-pass-captures/35886-symantec-ai-retailer.json` | `7273df42a13d13631d09a74ebc66d285b3ace9f0ce0c3d8a75bfd79a5dde7bb0` |
| `first-pass-captures/35887-groupib-darklunnen.json` | `540f3a7cb5cf2ee8578f7967253e55d28bd2ef39e17e010e811bf065f28bf611` |
| `first-pass-captures/35888-rl-midnight-blizzard.json` | `d4415975c5f4a329127d73462fbb685e40dc25bcda95b6d55f1242c9383cf325` |
| `first-pass-captures/35889-asec-snakekeylogger.json` | `55e747603006050bd1cb1ff2dc6dfef6d75c054225eb67742523be6692688ddd` |

Private (gitignored; publisher content):

| File | sha256 |
|---|---|
| `_corpus/first-pass-db-snapshot.jsonl` (candidate rows + linked sources) | `65b30a60a592a1160fa3d0735cf575eae50584a8339d710c66e2b404a708ecff` |
| `_corpus/first-pass-35880-35889.jsonl` (reports with canonical documents + rows; corpus-replay format) | `6e8764e34732124938f36e6d8b96c012fe8b56f744e99d9bdb442de88c4fdbd6` |
| `_source_html/<id>.html` | as in the report table |
| `_linked_sources/eset-malware-ioc-turla-README.adoc` | `c5682e6504bfb7bbd8ca62e96f844bd39f821fa7d94ade804a8d4958eba95013` |
| `_linked_sources/turla-cereal-tricks.pdf` | `6038734d906125ba23fd567b325cd205fe9cd9bf8e101fbf9fee1b5d33cd9ad6` |

The production artifact store keeps the source HTML under the same sha256 keys, so
the private files can be re-fetched from it.

## Separation

- `sealed_eligible: false`. Do not copy into `backend/lib/threatLibrary/benchmark/sealed/`.
- No frozen dataset (sealed / held-out / first-measured-batch / unseen-first-pass-10) was modified.
