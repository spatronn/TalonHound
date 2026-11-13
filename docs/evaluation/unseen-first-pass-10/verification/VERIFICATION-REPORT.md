# First-Pass Evaluation Verification

**Experiment:** `unseen-first-pass-10-2026-11-13`  
**Verification id:** `verification-v1` (2026-11-13)  
**Scope:** measurement audit only — no extraction changes, no refresh/review/finalize, no production mutation  
**Originals preserved:** `score-summary.json`, `first-pass-captures/`, `packets/`, `FIRST-PASS-QUALITY-REPORT.md`  
**Versioned outputs:** `fp-fn-disposition-v1.json`, `score-summary.equivalence-v1.json`, `score-summary.verified-provisional-v1.json`

---

## Executive answer

The published scorecard (**P=0.933 / R=0.929**, 16 FP / 17 FN) is **arithmetically correct under strict string keys**, but it **overstates pipeline defects**. After publisher-evidence review:

| Bucket | FN (of 17) | FP (of 16) |
|---|---:|---:|
| **Verified pipeline defects** | **0** | **2** |
| Intentional MODE A / pending-pack policy | 12 | 0 |
| URL serialization / scoring-key mismatch | 4 | 4 |
| GT error / omission (publisher inventory contradicts packet) | 0 | 7 |
| GT dispute (dual-use / weak assertion) | 1 | 3 |

**Equivalence-aware (host/path + trailing-slash, existing fold rules):** P=**0.950**, R=**0.946** (TP 228 / FP 12 / FN 13).  
**Verified-provisional (policy + GT corrections; see caveats):** P≈**0.992**, R=**1.000** (TP 235 / FP 2 / FN 0) — **not** a replacement human GT; provisional only.

---

## GT provenance audit (critical)

Every packet carries:

- `verified_by: "source-reviewer-unseen-fp10"`
- `second_labeler: null`

That labeler identity is the **evaluation labeling agent pass**, not an independent human dual-annotator. **Do not treat these packets as certified human ground truth.** They are publisher-source–oriented draft labels. This verification re-checked disputed FP/FN against retained `_source_html/`; it does **not** re-certify the full 241-indicator GT set.

---

## Deployed contract / runtime revision

| Source | Finding |
|---|---|
| Workspace freeze | `ee233e2fdf4e69bee40f1de64f56b091` (`tl-candidates-v63` … `tl-membership-decision-v3`, `tl-quality-v16`) |
| Host SSH at freeze | **failed** (`Permission denied`) — production git SHA **not** verified |
| Captures | All `generation=first_pass_recorded`, `contract_freshness.status=current` |
| Live InstallFix (`get_threat_report`) | `extraction_quality.version=tl-quality-v16`, **mode A**, codes include `authoritative_section_empty`, `malicious_assessed_non_members`, `linked_ioc_source_not_ingested` |
| Uncertainty remaining | Exact host commit / container image digest unknown; bundle fingerprint inferred from freeze + freshness stamps only |

---

## Trend Micro 15/15 candidates vs 2/15 membership

**Verdict: mostly intentional policy behavior, not a string-extraction defect.**

Evidence:

1. All three Trend reports are **MODE A** (`document_has_authoritative_scope`) with a formal IOC heading that **only** points at an external TXT pack.
2. Section-tree contract documents that an **external IOC pointer under an empty formal section suppresses delegated body authority** — the linked IOC Source owns the pack (`sectionTree/version.js`).
3. Membership contract (`indicatorMembership.js` MODE A): narrative `body_mention` is **not** Indicator membership without publisher assertion / analyst promote.
4. Packs remain `lifecycle_status=discovered`, `extraction_status=pending` until analyst extract/dismiss — **by design** before review.
5. Quality warnings (`authoritative_section_empty`, `malicious_assessed_non_members`, `linked_ioc_source_not_ingested`) correctly flag the operational gap; they do **not** change membership.

**Residual defect (product consistency, not the 15/15 framing):** KongTuke still promotes **2** narrative URLs (`ainttby`, `ctpsih`) into membership while demoting peer narrative IOCs (`foodgefy`, C2 IPs). That asymmetry is a **promotion inconsistency**, not proof that MODE A pack deferral is accidental.

**Scoring implication:** Treating all 13 Trend membership misses as pipeline FNs conflates **contractual first-pass Indicator set** with **“every publisher-asserted narrative IOC before pack extract.”** Candidate discovery 15/15 shows extraction worked; membership 2/15 shows Mode A + pack gate.

---

## FP/FN dispositions (publisher-backed)

### Verified pipeline defects (keep as errors)

| Kind | Identity | Evidence |
|---|---|---|
| FP | `rf-markirat` `domain:yemplayer.zip` | Source shows filename `YEMPlayer.zip`, not a domain |
| FP | `rf-markirat` `domain:pis2rayvpn.zip` | Source shows filename `Pis2rayVPN.zip` |

### Intentional policy exclusions (not verified FNs)

12 Trend FNs (InstallFix×5 narrative/hash/url, KongTuke×6, TeamPCP×1): present as candidates, non-members under MODE A + pending pack.

### URL serialization (scoring / canonicalization, not miss)

| Pair | Notes |
|---|---|
| Ghost `https://fifa-tickets.vip/...` FN vs scheme-less member FP (×3) | Publisher table is scheme-less; GT invented `https://`; pipeline matches publisher spelling |
| Google `visioneditor.loseyourip.com` vs `.../` | Trailing-slash only |

Equivalence using existing host/path identity + trailing-slash fold removes these 4 FN + 4 FP.

### GT errors / omissions (publisher inventory contradicts packet)

| Identity | Notes |
|---|---|
| GSocket `gsocket.io`, `cdn.gsocket.io`, `gsgg.b-cdn.net` (3 FP) | Microsoft **IOC table Domain rows**; GT demoted to `legitimate_service` — **GT wrong vs publisher inventory** |
| MarkiRAT SHA256 `3b172281…` (1 FP) | Present in retained RF HTML; absent from GT |
| Ghost SSL SHA1s ×3 (FP) | Publisher table type **SSL fingerprint**; GT omitted; pipeline membership vs table is OK, **role=`malware_sample` is wrong** (`non_file_digest_indicator_suspect`) |

### GT disputes (dual-use / weak assertion — leave uncertain)

| Identity | Notes |
|---|---|
| InstallFix `77.91.97.244` FN | Failed SYN / unreachable; GT indicator vs pipeline context — **weak** |
| Ghost `billplz.com`, `testnet.chainugo.com`, billplz example URL | In publisher IOC tables as abused gateway / crypto gateway / example bill; GT `legitimate_service` — Evidence-First demotion vs inventory fidelity |

---

## Score summary

| Scorecard | P | R | TP | FP | FN |
|---|---:|---:|---:|---:|---:|
| Original (preserved) | 0.933 | 0.929 | 224 | 16 | 17 |
| Strict recompute | 0.933 | 0.929 | 224 | 16 | 17 |
| Equivalence-aware v1 | **0.950** | **0.946** | 228 | 12 | 13 |
| Verified-provisional v1 | **0.992** | **1.000** | 235 | 2 | 0 |

Verified vs disputed counts:

- **Verified FP:** 2 (filename→domain)  
- **Verified FN:** 0  
- **Disputed / non-defect FN:** 17 − 0 = 17 reclassified (12 policy + 4 serialization + 1 GT dispute)  
- **Disputed / non-defect FP:** 14 reclassified (3 GT error + 4 GT omission + 3 GT dispute + 4 serialization)

---

## Confirmed pipeline defects

1. **Filename tokens typed as domains** (MarkiRAT `.zip`) — clear type-resolver / demotion miss.  
2. **SSL fingerprint digests labeled `malware_sample`** (Ghost) — membership vs publisher table OK; **role/type semantics wrong** (already quality-flagged).  
3. **KongTuke partial narrative membership** under MODE A — inconsistent promotion among peer body mentions (secondary).

## Intentional policy exclusions

- MODE A + empty formal IOC section + linked pack pointer → narrative body mentions stay non-members until pack extract/analyst promote.  
- Linked pack not auto-ingested on first-pass (discover → pending review).

## GT / scoring defects

- GSocket domain demotion contradicts Microsoft IOC table.  
- Missing MarkiRAT hash and Ghost SSL fingerprints in GT.  
- Strict URL keys without host/path / trailing-slash equivalence inflate FN+FP.  
- Entire GT set lacks independent human second labeler.

---

## Top 3 recommended engineering changes

Ranked by **expected measurement/ops benefit** vs **regression risk** (no implementation in this pass):

1. **Eval harness URL equivalence (host/path + trailing slash) using existing fold helpers**  
   - Benefit: removes Ghost/Google false FN+FP pairs; cleaner unseen evals.  
   - Risk: **low** (scoring-only; does not change stored IOC identities).  
   - Expected impact on this set: +4 TP, −4 FP, −4 FN → P/R ≈ 0.95 / 0.95.

2. **Harden filename / archive-basename rejection for `domain` type** (`.zip` / `YEMPlayer.zip` class)  
   - Benefit: kills confirmed MarkiRAT FPs; generalizes to similar table cells.  
   - Risk: **low–medium** (watch for real domains ending in unusual TLDs; demote not drop).  

3. **Productize Mode A + pending-pack first-pass semantics** (pick one, do not silently do both):  
   - (A) Auto-extract linked packs into first-pass membership before `first_pass_recorded`, **or**  
   - (B) Keep gate but expose separate metrics/UI: *document members* vs *pending pack inventory*, and stop scoring narrative IOCs as membership FN while pack is pending.  
   - Benefit: **high** for Trend-like publishers (largest “recall” illusion in the original report).  
   - Risk: **high** if (A) without dual-use controls; **low** if (B) is measurement/UX only.

---

## Integrity

- Original scorecard untouched.  
- No refresh, review decisions, Create IOCs, finalize, code edits, or deployment.  
- Verification artifacts only under `docs/evaluation/unseen-first-pass-10/verification/`.
