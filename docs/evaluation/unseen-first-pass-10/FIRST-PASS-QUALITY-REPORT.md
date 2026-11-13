# Unseen First-Pass Extraction Quality Report

**Experiment:** `unseen-first-pass-10-2026-11-13`  
**Sealed eligible:** false (kept separate from the frozen 40-report sealed benchmark)  
**Freeze:** `ee233e2fdf4e69bee40f1de64f56b091` (`tl-candidates-v63` … `tl-membership-decision-v3`, quality `tl-quality-v16`) — see `FREEZE.md` / `freeze-contract.json`  
**Scored set:** first-pass `indicator_membership === true` vs source-only ground truth in `packets/unseen-*.json`  
**Constraints honored:** one production import per URL; no refresh; no review / Create IOCs / finalize; no extraction code changes; GT from publisher source only (not Claude/Qwen/TalonHound outputs)

---

## Verdict

On **table-heavy / explicit-IOC** reports the frozen pipeline is strong (several perfect or near-perfect scores). On **Trend Micro narrative + linked TXT pack** reports it **discovers** publisher observables as candidates but **fails to promote** most of them into first-pass Indicator membership (`indicators=0` or near-zero), so membership discovery recall collapses even when candidate recall is complete. Mixed legitimate/abused infrastructure still produces systematic **context→indicator** errors.

**Aggregate (10/10 scored):**

| Metric | Value |
|---|---:|
| IOC precision (membership) | **0.933** (224 TP / 16 FP) |
| Discovery recall (membership) | **0.929** (224 TP / 17 FN) |
| Evidence-classification errors | **6** |
| Reports with perfect P&R | 3 (`huntress-sckit`, `unit42-falcon-c2`, `unit42-cairn`) |

Membership recall is inflated by large appendix-style reports (MarkiRAT, Ghost, TAG). The Trend Micro subset alone is **2/15 = 0.133** membership recall despite **15/15** candidate discovery of GT indicators.

---

## Per-report scorecard

| Report | Publisher | GT ind | FP ind | P | R | FN | FP | Class err | First-pass notes |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| msft-gsocket | Microsoft | 8 | 11 | 0.727 | 1.000 | 0 | 3 | 3 | Legit GSocket CDNs promoted |
| huntress-sckit | Huntress | 24 | 24 | 1.000 | 1.000 | 0 | 0 | 0 | Clean table + narrative |
| rf-markirat | Recorded Future | 68 | 71 | 0.958 | 1.000 | 0 | 3 | 0 | 2 filename-as-domain + 1 hash |
| trend-installfix | Trend Micro | 6 | 0 | — | **0.000** | 6 | 0 | 1 | All GT seen as candidates; **0** members; pack pending |
| trend-kongtuke | Trend Micro | 8 | 2 | 1.000 | **0.250** | 6 | 0 | 0 | 8/8 candidates; 2/8 members; pack pending |
| trend-teampcp | Trend Micro | 1 | 0 | — | **0.000** | 1 | 0 | 0 | Catbox URL candidate, non-member; pack pending |
| unit42-falcon-c2 | Unit 42 | 26 | 26 | 1.000 | 1.000 | 0 | 0 | 0 | Explicit IOCs |
| groupib-ghost-stadium | Group-IB | 55 | 61 | 0.852 | 0.945 | 3 | 9 | 2 | Scheme-less URL keys; legit payment domains; SHA1 digests |
| unit42-cairn | Unit 42 | 2 | 2 | 1.000 | 1.000 | 0 | 0 | 0 | Thin explicit IP section |
| google-tag-apt42 | Google TAG | 43 | 43 | 0.977 | 0.977 | 1 | 1 | 0 | Trailing-slash normalization pair only |

All captures: `generation=first_pass_recorded`, `contract_freshness=current`. No report was approved or finalized.

---

## Source-backed discrepancies

### 1. Membership under-promotion with linked packs (critical)

**Reports:** InstallFix, KongTuke, TeamPCP  
**Evidence:** Quality codes include `authoritative_section_empty`, `malicious_assessed_non_members`, `linked_ioc_source_not_ingested`. Linked TXT packs are `lifecycle_status=discovered`, `extraction_status=pending` (not ingested until analyst review — by design). Narrative IOCs carry `source_assertion=body_mention` and `indicator_membership=false` even when `assessment=malicious`.

| Report | GT indicators | Seen as candidates | Membership TP | Membership FN |
|---|---:|---:|---:|---:|
| InstallFix | 6 | 6 | 0 | 6 |
| KongTuke | 8 | 8 | 2 | 6 |
| TeamPCP | 1 | 1 | 0 | 1 |

**Examples (publisher prose → non-member):**

- InstallFix: `download-version.1-5-8.com`, `oakenfjrod.ru`, sample SHA1/SHA256, delivery URL — all assessed malicious / present, none in Indicator set. `77.91.97.244` forced to context (`context_only_narrative_with_authoritative_scope`) while GT labels it indicator → class error.
- KongTuke: only `https://ainttby.com/6f54.js` and `https://ctpsih.com/2d5h.js` members; `foodgefy` URLs, C2 IPs, POST URL remain non-members despite malicious/unknown assessments.
- TeamPCP: `https://litter.catbox.moe/iqesmbhukgd2c7hq.sh` present as candidate, not a member.

**Root-cause hypothesis:** When the formal IOC section is empty because the publisher offloads the roster to a linked pack, membership decision (`tl-membership-decision-v3`) treats narrative body mentions as non-actionable until the pack is extracted. First-pass Indicator set therefore under-represents operational infrastructure that is fully supported in the HTML. This is a **pipeline policy/promotion** failure relative to source GT, not a string-extraction miss.

**Uncertainty:** Linked TXT contents were not retained in this experiment’s source artifacts (`expected_identities: []`). Pack-level recall after analyst extract is **out of scope** for first-pass membership scoring; first-pass still should score narrative-supported indicators.

### 2. Legitimate / dual-use infrastructure promoted as indicators

**Microsoft GSocket (3 FP = 3 class errors):** `gsocket.io`, `cdn.gsocket.io`, `gsgg.b-cdn.net` labeled context (legitimate GSocket project / CDN) but first-pass Indicator with `assessment=malicious`, `role=malicious_infrastructure`.

**Group-IB Ghost Stadium (2 class errors + related FPs):** `billplz.com` and `testnet.chainugo.com` labeled context (payment / test infra) but promoted as malicious indicators. `www.billplz.com/bills/...` URL also promoted without GT indicator support.

**Root-cause hypothesis:** Abuse-of-legit-service language in narrative is insufficiently gated; dual-use hostnames inherit campaign malice without an explicit attacker-control assertion.

### 3. URL normalization / scheme stripping (apparent FN+FP)

**Ghost Stadium:** GT has `https://fifa-tickets.vip/...`; first-pass emits scheme-less `fifa-tickets.vip/...` as Indicator members. Scorer records 3 FN + 3 FP that are the **same identities** under different URL serialization.

**Google TAG:** GT `https://visioneditor.loseyourip.com` vs FP `https://visioneditor.loseyourip.com/` (trailing slash) — single normalization miss counted twice.

**Root-cause hypothesis:** Type resolver / URL canonicalization does not always emit a scheme or strip trailing `/` consistently with publisher display forms. Operational impact is low if UI/dedup later merges them; **metric impact is material** on precision/recall.

### 4. Filename / non-network digests as domains or indicators

**MarkiRAT FPs:** `yemplayer.zip`, `pis2rayvpn.zip` typed as `domain` + Indicator; one extra SHA256 not in GT appendix.

**Ghost Stadium:** three SHA1 values promoted as malware_sample Indicators; quality flag `non_file_digest_indicator_suspect`.

**Root-cause hypothesis:** Path/filename tokens and non-file digests leak into network/hash indicator membership without enough structural authority.

### 5. Strong paths (controls)

Huntress SCKit, Unit42 Falcon C2, Unit42 Cairn: explicit IOC sections / clean tables → perfect membership P&R. Shows the frozen contract **can** hit source GT when authority is in-document and pack-independent.

---

## Ambiguous / unsupported GT (recorded, not scored as FN)

From Evidence-First packets (not counted in FN):

- **InstallFix:** victim-unique `oakenfjrod.ru` URL pattern; outbound IPs `104.21.0.95` / `185.177.239.255` (observed but weak attacker-control assertion); hunting-query-only `get-version.com`.
- **Ghost Stadium:** publisher says public blog is partial vs customer report; only rendered HTML labeled.
- **Trend packs:** linked TXT not fetched for GT identities — residual coverage gap on pack-only IOCs.

---

## Quality-code frequency (first-pass captures)

| Code | Reports |
|---|---|
| `malicious_assessed_non_members` | InstallFix, KongTuke, TeamPCP, Huntress, MarkiRAT, Falcon |
| `authoritative_section_empty` | InstallFix, KongTuke, TeamPCP |
| `linked_ioc_source_not_ingested` | InstallFix, KongTuke, TeamPCP |
| `ai_escalation_unsupported` | InstallFix, KongTuke, TeamPCP, Huntress |
| `ai_evidence_ungrounded` | KongTuke, Ghost, Google TAG |
| `non_file_digest_indicator_suspect` | Ghost |
| clean | Cairn, (Microsoft GSocket codes empty) |

The quality subsystem **already surfaces** the Trend membership failure (`malicious_assessed_non_members` + empty authoritative section + pending pack). First-pass product behavior still ships zero Indicators for InstallFix/TeamPCP.

---

## Experiment integrity checklist

| Control | Status |
|---|---|
| Never-imported at selection (`threat_library_check_report_urls`) | Yes — see packets `library_check.exists=false` |
| Excluded sealed-40 | Yes (`sealed_eligible: false`) |
| Excluded known fixtures/evaluation URLs | Yes (selection grep + screen) |
| Pipeline freeze recorded before import | Yes |
| Source HTML + sha256 retained | Yes under `_source_html/` / packet `source.sha256` |
| Source-only GT (no TH/Claude/Qwen as truth) | Yes — `gt-labeling-notes.md` |
| One production import; first_pass_recorded capture | Yes — `import-ledger.json` + `first-pass-captures/` |
| No review / create / finalize / refresh before capture | Yes |
| Results path separate from sealed cases | Yes — `docs/evaluation/unseen-first-pass-10/` only |

**Caveat:** Host SSH re-verify of production commit failed at freeze (`Permission denied`); contract fingerprint is workspace freeze + per-report `contract_freshness=current` on captures.

---

## Bottom line

The current frozen pipeline is **not uniformly reliable on genuinely unseen reports**. It is reliable when publishers keep an **in-document authoritative IOC section**. It is **not** reliable for the common Trend Micro pattern of **narrative IOCs + linked TXT pack**: candidate extraction works, first-pass Indicator membership does not. Secondary failure modes are dual-use infrastructure over-promotion and URL canonicalization mismatches.

**Do not treat familiar sealed-40 scores as a substitute for this result.** Highest-priority follow-ups (out of band; not applied here): (1) first-pass promotion of high-evidence `body_mention` when authoritative section is empty and pack is only discovered; (2) dual-use / legitimate-service demotion; (3) URL scheme and trailing-slash canonicalization for scoring and membership keys.
