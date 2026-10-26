# Threat Library — 24-report Huntress IOC remediation (2026-10-26)

This change remediates the confirmed defects from the independent publisher ground-truth audit of the 24 Huntress reports 33332–33355, which were imported between 2026-10-25 and 2026-10-26.

**Production baseline:** `bca741f`.

**Contracts after this change:**

| Contract | Before | After |
|---|---|---|
| Candidate extraction | `tl-candidates-v39` | **`tl-candidates-v40`** |
| Table semantics | `tl-table-v11` | **`tl-table-v12`** |
| Type resolver | `tl-type-resolver-v16` | **`tl-type-resolver-v17`** |
| Section tree | `tl-section-tree-v8` | **`tl-section-tree-v9`** |
| Extraction quality | `tl-quality-v13` | **`tl-quality-v14`** |
| IOC Source scope | `tl-ioc-source-scope-v2` | **`tl-ioc-source-scope-v3`** |
| Structured IOC Source parser | `tl-ioc-source-structured-v1` | **`tl-ioc-source-structured-v2`** |

Unchanged: `tl-zones-v16`, `threat_library_html_v8`.

**Scope of this work:**

- No production data was modified. Nothing was refreshed, approved, dismissed, created, linked, finalized, migrated or deployed.
- Linked IOC Sources stay analyst-gated: nothing is ingested or approved automatically.
- The fixes are deterministic. No new AI dependency was added, and no defect originated in model reasoning.

## Result

All figures are offline. "Primary" is original-document Indicator membership, from the production Refresh path: deterministic extraction, then replayed model decisions, then analyst-state preservation, on the retained canonical documents.

| | Before (`bca741f`, = stored) | After (this branch) |
|---|---:|---:|
| Primary expected | 319 | 319 |
| Primary TP / FN / FP | 296 / 23 / 44 | **319 / 0 / 0** |
| Source-only expected (src 197) | 67 | 67 |
| Source-only reachable after an analyst extraction of src 197 (offline-simulated) | 0 | **67** |
| Uncertain (unscored) | 4 | 4 |
| Exact primary reports | 16 / 24 | **24 / 24** |

The 67 source-only values are **not repaired in production** by this change. Src 197 is still `discovered`. The offline simulation (section F) shows that extracting it with this code adds exactly the audited 67 identities.

## A. Root-cause matrix

The pipeline stages are: publisher → canonical document → section tree → authority → table semantics → candidate extraction → promotion / review → IOC Source union. Every defect was traced to the stage where it originates; no fix was placed in a later stage.

| # | Report(s) | Defect | Stage | Root cause | Fix (location) |
|---|---|---|---|---|---|
| A | 33332 (7 FN) | A mixed table cell dropped every hash. The cell held file paths, a plural `MD5s:` label and several MD5s, or a path with spaces such as `…\Local Settings\[RANDOM FILE NAME].exe`. | Table semantics | `parseDeclaredType` did not read the plural `MD5s`. `decomposeMixedCell` turned the whole remainder into a reported-only residual as soon as one token was unparseable. | Plural digest labels (`tableSemantics.js:124`). In `decomposeMixedCell` (`tableSemantics.js:558`), digests that the cell labels (or that a hash-typed column declares) are values of the cell, owned by the leading file identity. Unlabelled digests in a prose remainder stay reported-only. |
| B | 33332, 33351 (3 FN) | `7.tcp.eu.ngrok[.]io:12684.`, `poronto[.]com:688`, `giovettiadv[.]com:688` were rejected. | Normalization | `parseToken` split a port only from IPv4 values. | `HOST_PORT_CELL_RE` (`tableSemantics.js:298`). The host is the observable (a domain; TalonHound has no endpoint IOC type) and the port is kept on the occurrence. Dotted-token typing reads the host without the port (`candidateExtraction.js:1037`), so `loader.exe:1234` stays a file name. |
| C1 | 33344 (6 FN) | The `## Network` table lost authority. | Section tree | `## Indicators of Compromise` holds only a lead-in ("…provided below"), and its groups are same-level H2 siblings. A same-level real heading popped the appendix. | `leadInWithSiblingGroups` / `siblingGroup` (`sectionTree/annotate.js:301`, `:424`). A lead-in-only formal IOC heading continues into the same-level indicator-class siblings that follow it (Network / Host / File / Domains / Hashes / C2 …, ≤ 60 characters, with inventory). The first other heading closes it. |
| C2 | 33345 (6 FN) | `## Primary IOCs` was not an IOC heading. | Section authority | Closed qualifier list in `INDICATOR_HEAD_RE`. | Inventory-grade qualifiers (`primary`, `secondary`, `main`, `core`, `full`, `complete`, `confirmed`, `extended`, `supplementary`, `notable`) at `indicatorScope.js:171`. The concept must still lead the heading and be closed by punctuation, `of`, or the end of the heading. |
| C3 | 33344 (side effect of C1) | `<token>` template URLs became Indicators once their table became authoritative. | Typing | The URL boundary cut the closing `>` (`…/curl/<token`), so the placeholder rule missed it. | `<name` / `%3Cname` without a close is a placeholder (`observableTypeResolver.js:553`). |
| D1 | 33332 (41 FP) | Hosts-file sinkhole lines (`0.0.0.0 telemetry.vendor`) were promoted. | Table semantics | A sinkhole/host pair read as a network value. | `markHostsFileEntries` (`tableSemantics.js:501`): a cell made only of ≥ 2 `<sinkhole> <host>` pairs marks its hosts `hosts_file_entry`. The flag flows through the occurrence, the relations (`indicatorScope.attachOccurrenceRelations`) and the policy (`context_only_hosts_file_entry`, `evidencePolicy.js:480`). Mixed cells are untouched. |
| D2 | 33339 (1 FP) | A Cloudflare tunnel **account tag** was stored as a malware MD5. | Typing | `classifyHexDigest` had no identifier class. | `DIGEST_KINDS.IDENTIFIER` (`digestSemantics.js:68`): account / tunnel / tenant / client / device / bot / campaign / session tag, id, uuid or guid. It is non-file, and a file noun keeps the hash reading ("MD5 of tunnel.exe"). Corpus side effect: 30326 `"SessionID":"A12B…"` is now an identifier; it was Context Only already. |
| D3 | 33348 (1 FP) | `boots.com` was promoted from `boots <hello[@]boots[.]com>` ("Spoofed sender impersonating Boots UK"). | Candidate extraction | Email-domain detection saw only a literal `@`. | A defanged at-sign (`[@]`, `(@)`, `{@}`, `[at]`, `(at)`) counts as an address when the same line says the sender is spoofed or impersonated (`SPOOFED_SENDER_RE`, `candidateExtraction.js:549`). Other defanged addresses keep their reading (RansomHub `brahma2023[@]onionmail.org` is unchanged). |
| D4 | 33351 (1 FP) | A publisher typo in a body line, `C2 base URL: …/8250d149-…-ea925eae0a4` (truncated), was promoted beside the table's correct `…ea925eae0a4c/`. | Candidate extraction | A body "C2" analysis heading opens `c2_section` authority over its lines. | `markTruncatedUrlDuplicates` (`candidateExtraction.js:527`): a non-table URL that stops **inside a path segment** of a table-listed URL is `truncated_duplicate` (`context_only_truncated_duplicate`). A prefix at a segment boundary (`https://host/` vs `https://host/gate`) is untouched. A broader "C2 analysis heading" gate was tried first and **rejected**: it removed adjudicated, IOC-created Indicators in finalized reports 24465 and 30332. |
| E | 33340 (1 FN) | The lure URL `docsend.com/view/…` ("Lure link on legitimate dropbox service") was demoted. | Promotion (relation) | The row-level benign stance was read from "legitimate". | `ROW_MALICIOUS_RESOURCE_RE` (`indicatorScope.js:364`): a **structural row** that calls its value a lure / phishing / decoy resource asserts it, whatever it says about the hosting service. Prose is unchanged: Tycoon2FA's "…the legitimate microsoft.com/devicelogin" stays Context Only. A broader "benign adjective + service noun" rule was tried and rejected (Tycoon2FA regression). |
| F1 | 33342, 33343 (latent) | The month-folder sources (`tree/main/2026/2026-07`) hold only another report's CSV. Approving them would attach those IOCs. | Source scope | Folder scoping was README-only; Huntress CSVs carry their report in a `description,<URL>` row. | `inventoryBacklinkScope` (`campaignScope.js:396`) + `applyCampaignFileSelection` (`inspect.js:73`): a folder file whose metadata row names another article is deselected. If every file is deselected, the source becomes `campaign_scope_unresolved`. |
| F2 | (latent) | Extraction re-listed a folder whose files were all deselected, and never scoped an uninspected folder. | Source extraction | `(!selected.length \|\| !files.length) && gh` re-enumerated the folder. | Fail closed when files exist but none is selected (`extract.js:156`), and apply the same back-link scope during extraction. |
| F3 | 33340 src 197 | The `ip_path` rows (`192.253.248[.]181/api/v1/getscpt/`) became bare IPs, so the publisher's URL was lost. | Source parsing | `ip_path` was not a declared type. | `ip_path` / `host_path` / `url_path` … → `url` (`structuredSources.js:43`). |
| F4 | 33340 src 197 | Scheme-less pack URLs would duplicate the report's `https://` identity. | Source union | No scheme folding across document and pack. | `foldSchemeLessLinkedUrls` (`extract.js:37`): the same rule as the document extractor's `foldSchemeLessUrlAliases`. It folds only when exactly one absolute spelling exists. |
| Q | 33339, 33340 | Quality was `clean` / `info` despite defects. | Quality | — | See section C. |

## B. Code changes

Backend (`backend/lib/threatLibrary/`):

- `tableSemantics.js`: plural digest labels, labelled residual digests, `host:port`, hosts-file entries.
- `candidateExtraction.js`: host-only typing token, `hosts_file_entry` occurrence flag, `markTruncatedUrlDuplicates`, spoofed defanged sender domain.
- `indicatorScope.js`: qualifiers; lure / phishing / decoy row cue; relations for the new flags.
- `evidencePolicy.js`: `context_only_hosts_file_entry` / `context_only_truncated_duplicate`; serialization of the flags.
- `sectionTree/annotate.js`, `sectionTree/version.js`: lead-in sibling groups.
- `digestSemantics.js`: identifier kind.
- `observableTypeResolver.js`: cut placeholders.
- `extractionQuality.js`: checks 26–27, plus the four new codes.
- `iocSources/campaignScope.js`, `inspect.js`, `extract.js`, `structuredSources.js`, `linkedSourceStatus.js`: back-link scope, fail-closed extraction, `ip_path`, scheme folding, read-time scope-mismatch warning.

Frontend: analyst wording for the four new quality codes (`frontend/src/components/threatLibrary/extractionQualityUi.js`).

Version pins: tests that pin the contract versions were updated, following the repo convention. `decideCandidateReuse` now treats `tl-candidates-v39` as changed, so maintenance refresh and retry re-extract instead of reusing v39 candidates.

Two existing test expectations changed, each because a requirement of this remediation reverses the old behaviour:

- `mixedCellCertificateDottedRegressions.test.js`: a labelled hash after a path with spaces is now a value (requirement A), not reported-only. "No bogus fragment artifact" is still asserted.
- `thirtyOneReportAuditRegressions.test.js`: the linked-source summary gained `scope_mismatch`.

## C. Quality checks (tl-quality-v14)

New stored checks. They are informational and never change membership:

- `hosts_file_entries_context`
- `truncated_url_duplicate_context`
- `authoritative_table_rows_demoted`: URL and domain values only, which is what the 33340 shape needs. On hash rows it was noise ("Legitimate Microsoft binary" is about the file itself), so hash rows are excluded.

New read-time overlay: `linked_ioc_source_scope_mismatch` (warning). It fires when a linked source resolved to other reports' inventories or to no corroborated campaign folder.

**Correction to the audit:** at read time, 33340 already showed `linked_ioc_source_not_ingested` as a **warning**. The audit read only the stored record (`info`).

Noise: on the 90 committed benchmark cases, the new checks fire in 3 cases (all `info`). Across the 219-report corpus, quality codes change on 4 reports outside the batch:

- 30326: `non_file_digest_reclassified`, from the session-ID identifier.
- 30267, 30279: the new `authoritative_table_rows_demoted` (`info`).
- 31391: `analyst_state_membership_divergence` (`info`). Host:port parsing now reads `xmr.kryptex.network` as a publisher Indicator, but an analyst had marked it Context Only. Membership is unchanged.

## D. Regression evidence

| Check | Result |
|---|---|
| `npm run test:threat-library` | 1599 pass, 0 fail, 119 skipped of 1718 (DB / private-store gated) |
| `npm run test:threat-library-benchmark` (no store) | 79 pass, 3 skipped |
| `TL_BENCHMARK_SOURCE_DIR=… npm run test:threat-library-benchmark` | 82 / 82 |
| Benchmark CLI, 170 cases (90 committed + 80 private real-report labels incl. the 24 new) | **170 / 170 exact**, TP 4728, FP 0, FN 0; 0 regressions vs baseline |
| `TL_CORPUS_SNAPSHOT=… corpusReplayAcceptance.test.js` | 4 / 4 (30-report audit 1025 / 0 / 0, historical drift accounted) |
| Corpus replay, 219 production reports, read-only snapshot 2026-10-26 | Membership changes **only** in 33332, 33339, 33340, 33344, 33345, 33348, 33351 (exactly the audited deltas); 4 other reports change quality codes only; 80 / 80 labelled reports exact (TP 3260) |
| `npm run test:mcp` | 216 / 216 |
| Frontend `npm run test:threat-library` | 295 / 295 |

New regression tests are in `twentyFourReportAuditRegressions.test.js` (22 tests). Every defect shape is covered with its negative control, and the tests assert exact membership. The tests:

- run through `extractCanonicalDocumentFromHtml`, so canonical conversion is part of the fixture;
- cover the hosts-file shape: its C2 row stays an Indicator and the sinkhole IP stays Context Only;
- cover truncated URLs: a different path is untouched;
- cover sibling groups: no leakage into `MITRE ATT&CK`, `Conclusion`, or a later "Network …" sibling of a non-lead-in heading;
- cover `Primary IOCs` vs narrative "Primary indicators suggest…";
- cover legitimate sideloading rows and legitimate prose sites;
- cover folder back-link deselection, fail-closed extraction, `ip_path`, scheme folding and the scope-mismatch overlay.

24 real-report labels were added (`benchmark/real-reports/huntress-*.json`, `audit_24_2026_10_26`, 319 Indicators, 2 ambiguous):

- Expected = audit-verified members plus confirmed FN; confirmed FP and the analyst-judgment values were removed.
- One spelling was aligned to production normalization: the 33344 table writes `main.sdhomeinspectors.com/modules/wallets` without a scheme, and the body writes it with `https://`. The pipeline merges the two spellings into one identity, `https://…`. The expected value is the same.

Rejected candidate fixes, recorded so they are not re-tried:

1. A "C2 analysis heading" authority gate. It flipped finalized, adjudicated Indicators in 24465 and 30332.
2. A global `lure` malice cue. It promoted Tycoon2FA's legitimate `microsoft.com/devicelogin`.
3. Treating every defanged address domain as an email domain. It demoted RansomHub's labelled `onionmail.org`.

## E. 24-report scorecard (offline)

| Report | Primary expected | Source-only expected | Union expected | Before TP | Before FN | Before FP | After TP (primary) | After FN (primary) | Source-only pending extraction | After FP | Uncertain |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 33332 | 19 | 0 | 19 | 11 | 8 | 41 | 19 | 0 | 0 | 0 | 1 |
| 33333 | 14 | 0 | 14 | 14 | 0 | 0 | 14 | 0 | 0 | 0 | 0 |
| 33334 | 14 | 0 | 14 | 14 | 0 | 0 | 14 | 0 | 0 | 0 | 0 |
| 33335 | 28 | 0 | 28 | 28 | 0 | 0 | 28 | 0 | 0 | 0 | 0 |
| 33336 | 58 | 0 | 58 | 58 | 0 | 0 | 58 | 0 | 0 | 0 | 0 |
| 33337 | 2 | 0 | 2 | 2 | 0 | 0 | 2 | 0 | 0 | 0 | 0 |
| 33338 | 3 | 0 | 3 | 3 | 0 | 0 | 3 | 0 | 0 | 0 | 0 |
| 33339 | 15 | 0 | 15 | 15 | 0 | 1 | 15 | 0 | 0 | 0 | 0 |
| 33340 | 26 | 67 | 93 | 25 | 68 | 0 | 26 | 0 | 67 | 0 | 0 |
| 33341 | 4 | 0 | 4 | 4 | 0 | 0 | 4 | 0 | 0 | 0 | 0 |
| 33342 | 7 | 0 | 7 | 7 | 0 | 0 | 7 | 0 | 0 | 0 | 2 |
| 33343 | 16 | 0 | 16 | 16 | 0 | 0 | 16 | 0 | 0 | 0 | 0 |
| 33344 | 13 | 0 | 13 | 7 | 6 | 0 | 13 | 0 | 0 | 0 | 0 |
| 33345 | 27 | 0 | 27 | 21 | 6 | 0 | 27 | 0 | 0 | 0 | 0 |
| 33346 | 7 | 0 | 7 | 7 | 0 | 0 | 7 | 0 | 0 | 0 | 0 |
| 33347 | 11 | 0 | 11 | 11 | 0 | 0 | 11 | 0 | 0 | 0 | 0 |
| 33348 | 13 | 0 | 13 | 13 | 0 | 1 | 13 | 0 | 0 | 0 | 1 |
| 33349 | 10 | 0 | 10 | 10 | 0 | 0 | 10 | 0 | 0 | 0 | 0 |
| 33350 | 1 | 0 | 1 | 1 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| 33351 | 19 | 0 | 19 | 17 | 2 | 1 | 19 | 0 | 0 | 0 | 0 |
| 33352 | 3 | 0 | 3 | 3 | 0 | 0 | 3 | 0 | 0 | 0 | 0 |
| 33353 | 5 | 0 | 5 | 5 | 0 | 0 | 5 | 0 | 0 | 0 | 0 |
| 33354 | 2 | 0 | 2 | 2 | 0 | 0 | 2 | 0 | 0 | 0 | 0 |
| 33355 | 2 | 0 | 2 | 2 | 0 | 0 | 2 | 0 | 0 | 0 | 0 |
| **Total** | **319** | **67** | **386** | **296** | **90** | **44** | **319** | **0** | **67** | **0** | **4** |

Separation:

1. **Primary-document extraction improvements:** 23 FN and 44 FP fixed, in 7 reports.
2. **Linked-source improvements:**
   - F1–F4 are in code. The 67 src-197 values are reachable only through analyst inspect + extract.
   - Offline simulation of the production parser on the publisher CSV, with scheme folding against the report rows, gives exactly 67 source-only identities: 57 SHA256, 7 domains, and 3 URLs that fold onto the report's existing `http(s)://` rows.
3. **Cases that still need source inspection:**
   - src 198 / 199: both resolve `other_report` (the Meta-phishing CSV).
   - src 201: repository root, fails closed.
   - src 200: matches, adds 0 values.
4. **Analyst judgment:** the 4 uncertain values (section F).

## F. Remaining unresolved cases (analyst decisions — not changed)

| Report | Value | Evidence | Recommendation |
|---|---|---|---|
| 33332 | md5 `1ec9eff863dc4418d1498bc3d904899d` (Indicator) | IOC-table row "Yandex web browser" (`%TEMP%\YandexPackLoader.exe`). Huntress's own GTA6 CSV lists no hashes, so it neither confirms nor refutes. | **Context Only.** The row describes a browser the ISO installs, not a malicious component. Verify the hash reputation before deciding. |
| 33348 | sha256 `dc8a31a1…715046` (Indicator) | `gm.exe`, "Gammadyne Mailer (legitimate commercial bulk-mail tool, abused)". | **Context Only,** consistent with the 30346 PsExec precedent: a legitimate commercial binary's hash matches every legitimate install. Keep it in All with the abuse note. |
| 33342 | sha256 `b43a909a…bbd3`, url `http://193.29.224.151/92392991a0cca55?force=1` (body, non-member / Context Only) | Listed in Huntress `2026-08/20260806_mac-drain-stealer.csv`, whose description row links this report. The report itself links `tree/main/2026/2026-07`, which does not contain it. | **Add** `https://github.com/huntresslabs/threat-intel/blob/main/2026/2026-08/20260806_mac-drain-stealer.csv` as a manual linked IOC Source, then inspect and extract. Its back-link matches the report (verified offline), so it would add exactly these 2 values. |

Source-count note: the audit's working notes once said "6 linked sources". The database holds **5** (197–201). The final audit count of 5 is correct; the 6 was a transient miscount in a progress message, not a missing row.

## G. Production remediation plan — DO NOT EXECUTE (each write needs separate authorization)

Run on `192.168.1.190`, `/opt/TalonHound`. Snapshots go to `/tmp/fix24-*`.

**1. Rollback point:**

```bash
docker image tag talonhound-backend:local talonhound-backend:rollback-bca741f
cp .env /tmp/env-backup-pre-fix24
```

**2. Pre-deploy snapshot.** Run the audit snapshot SQL (24 reports, 672 candidates, sources, global fingerprints: candidates, finalized, sources, `ioc_items` max, `audit_logs` max, jobs max) into `/tmp/fix24-pre.json`. Baseline fingerprints from 2026-10-26:

- all candidates: `e4eb4987d413615f5d9361864c53c35e`
- finalized: `d585fc4b24c96b74a372d93a26f5a743`
- sources: `9884913c42ee27a567080025fd7652b2`

**3. Deploy** (after PR approval and merge only):

```bash
git fetch && git merge --ff-only origin/main
docker compose build backend
docker compose up -d backend threat-library-worker
```

**4. Health and contract verification:**

- `docker compose ps`: backend healthy, worker up.
- The deployed `lib/` md5 manifest equals the merge commit.
- `THREAT_LIBRARY_SCOPE_ENGINE=section_tree`.
- Node in the container prints `tl-candidates-v40`, `tl-section-tree-v9`, `tl-quality-v14`, `tl-ioc-source-scope-v3`.

**5. Protected dry-runs,** read-only, one per report (33332, 33339, 33340, 33344, 33345, 33348, 33351):

```bash
docker compose exec -T backend node scripts/threat-library-report-maintenance.js refresh-extraction --report <uuid>
```

Expected Indicator diffs (exactly):

| Report | Indicators | Added | Removed |
|---|---|---|---|
| 33332 | 53 → 20 | 7 MD5 + `7.tcp.eu.ngrok.io` | the 41 hosts-file domains |
| 33339 | 16 → 15 | — | `md5:5568cd69…` |
| 33340 | 25 → 26 | `url:docsend.com/view/evdfym2aj5tend76` | — |
| 33344 | 7 → 13 | `agenticsora.com`, `malwareaudit.com`, `85.206.161.241`, `103.216.221.95`, `https://main.sdhomeinspectors.com/modules/wallets`, `main.southcarolinacounselor.com/modules/wallets` | — |
| 33345 | 21 → 27 | 3 SHA256, `download-app.us`, `5ca8758c-…com`, the claude.ai artifact URL | — |
| 33348 | 15 → 14 | — | `domain:boots.com` |
| 33351 | 18 → 19 | `poronto.com`, `giovettiadv.com` | the truncated trindastal URL |

Any other diff: **stop.** Record each preview fingerprint.

**6. Removal guard.** 33332, 33339, 33348 and 33351 remove Indicators. The refresh membership guard will block them unless `--accept-membership-changes --reason "24-report audit RC-D" --preview-fingerprint <fp>` is given. Use that flag only with the user's explicit approval.

**7. Reviewed-row and IOC-link protection:**

- All 672 candidates are `pending` (no analyst decision), and no candidate has `matched_ioc_id` set by Create IOCs. Verify again just before applying.
- No finalized report is touched: the finalized fingerprint must be unchanged after every step.

**8. Sequential apply.** Apply the dry-runs one report at a time (`--apply`, same fingerprint). Re-snapshot after each one, and compare against both the dry-run and the expected diff above.

**9. Linked sources.** These are separate authorizations, and src 197 comes after its report's refresh:

- **Inspect 197** (33340). Expect back-link `matches` and 89 linked values, 67 of them source-only. Then **extract 197** and verify 67 new union members.
- **Inspect 198 and 199.** Expect `unsupported` / `campaign_scope_unresolved` with `other_report_files: 2026-07/20260707_fbphish-IOCs.csv`. Then **dismiss** (analyst).
- **Inspect 200.** Expect `matches` with 0 source-only values. Extract only for provenance, or leave it.
- **Inspect 201.** Expect `campaign_scope_unresolved` (repository root). Then dismiss.
- **33342 manual source** (`2026-08/20260806_mac-drain-stealer.csv`): only on the analyst's decision (section F).

**10. Post-refresh verification:**

- Re-run the audit scoring on the persisted rows: primary 319 / 0 / 0, and the 33340 union 93 after the src 197 extraction.
- Uncertain values stay pending.
- Only the 7 reports' fingerprints changed; finalized and other-report fingerprints are unchanged.
- `ioc_items` gains only background feed rows (no Threat Library creates).

**11. No finalization.** Do not finalize any of the 24 reports until the persisted accuracy above is confirmed and the 4 analyst decisions are made.

Rollback:

```bash
docker image tag talonhound-backend:rollback-bca741f talonhound-backend:local
docker compose up -d backend threat-library-worker
```

Applied refreshes are rolled back from `/tmp/fix24-pre.json`, per report, inside one transaction.
