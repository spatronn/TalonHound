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
| `first-pass-captures/35880-eset-turla-cereal.json` | `6f7d209991dac1cf79d4672bc0e935f055dce5b34a9e8e4ff2ccab7aa8041e30` |
| `first-pass-captures/35881-elastic-sansar.json` | `77d11dafb07d31d005f1a4c511a5a2b66014e692e1e25bd039308e2e4f34c0be` |
| `first-pass-captures/35882-checkpoint-php2shell-gateway.json` | `e5a46002ea71e3841e90be7240530ff4aa85f1b8fc9d2fec77f3b39ee4ce4c2c` |
| `first-pass-captures/35883-fortinet-tsql-mssql.json` | `3aae47c3e7242eb5e1ea105b10c8275c62b1d7ec396825ab852074354d93e475` |
| `first-pass-captures/35884-huntress-geovision.json` | `d8136c00129e31610b2eb8d774749ffcf859eba9422a7f69ef6c4e9eafba429f` |
| `first-pass-captures/35885-securelist-esxi.json` | `0a703514b9e53da3024425b78ce653a01f04be9ec41252d0ad4d00a38d1e6518` |
| `first-pass-captures/35886-symantec-ai-retailer.json` | `86e7261d0c28aa8a1947bdbfa954a2d6baa4a384394039ce4c9eeea8bf06c327` |
| `first-pass-captures/35887-groupib-darklunnen.json` | `ec9657d743a04063494c975286b4cfcebe48688351ea6be0296c9d24904c6197` |
| `first-pass-captures/35888-rl-midnight-blizzard.json` | `bcfeed899663b96397bad41b5fb1d9665972e14a6d9e1cafed3ae79330dcfec1` |
| `first-pass-captures/35889-asec-snakekeylogger.json` | `3b9e2b3ed294199942a17503606d424d2d419f814b60a905bf974fa9cad07fe6` |

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
