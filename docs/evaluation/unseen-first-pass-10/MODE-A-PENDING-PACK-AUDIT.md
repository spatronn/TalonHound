# MODE A + pending linked IOC sources — audit (recommendations only)

**Experiment:** `unseen-first-pass-10-2026-11-13`  
**Scope:** product-behavior audit. **No** auto-promotion of narrative IOCs and **no** auto-extract of linked packs in this change set.

## What we observed

| Report | Candidates covering GT | Indicator membership TP | Pack |
|---|---:|---:|---|
| InstallFix | 6/6 | 0 | discovered, pending |
| KongTuke | 8/8 | 2 | discovered, pending |
| TeamPCP | 1/1 | 0 | discovered, pending |

Live InstallFix stamps: `extraction_quality.mode=A`, codes `authoritative_section_empty`, `malicious_assessed_non_members`, `linked_ioc_source_not_ingested`.

## Is this intended?

**Yes, for the membership contract as written.**

1. Trend articles use a formal IOC heading that only links an external TXT pack (empty in-document inventory).
2. Section-tree policy: an external IOC pointer under an empty formal section **suppresses delegated body authority** — the linked IOC Source owns the pack.
3. MODE A (`document_has_authoritative_scope`): Indicator membership requires a publisher assertion (explicit_* / authoritative zone occurrence). Narrative `body_mention` is All / Context / pending_actionable material, not automatic Indicator membership.
4. Pack extract is gated on analyst `threat_library_review_ioc_source` — first-pass correctly leaves packs `discovered`/`pending`.

So “15/15 candidate discovery, 2/15 membership” is **consistent with intended first-pass Indicator semantics**, not a string-extraction failure. Scoring those rows as FN against “every narrative IOC should be a member before pack extract” conflates product layers.

## KongTuke inconsistency

Two narrative URLs (`ainttby.com/6f54.js`, `ctpsih.com/2d5h.js`) received `indicator_membership=true` / `original_document_member=true`, while peer narrative IOCs (`foodgefy`, C2 IPs) did not — all under MODE A + pending pack.

**Hypothesis (for a follow-up investigation, not fixed here):** structural row / list-item reading near the initial-access analysis treated those two as asserting indicator rows, while later prose stayed `body_mention`. Worth a focused parity test on Trend list-vs-prose under empty IOC + pack pointer, without relaxing MODE A evidence rules.

## Recommendations (policy decision required)

Do **not** silently auto-promote narrative IOCs or auto-extract packs.

Preferred low-risk product improvements:

1. **Metrics / scorecards:** report separately  
   - `document_indicator_membership`  
   - `pending_linked_pack_declared`  
   - `candidate_discovery_of_gt`  
   so Trend-like reports are not scored as membership FN while packs are pending.
2. **Quality / UI:** keep the existing warnings; add an explicit first-pass banner: “Authoritative IOC inventory is a linked pack — Indicators tab is empty/partial until the pack is extracted or dismissed.”
3. **Workflow:** optional analyst shortcut to extract the discovered pack as the next step (already gated); do not change first-pass membership rules without a product decision.
4. **KongTuke follow-up:** investigate why two peer narrative URLs became members under MODE A; fix structural consistency, not evidence thresholds.

## Out of scope for this PR

- Changing `tl-membership-decision-v3` / MODE A promotion  
- Auto-extract of linked IOC Sources  
- Re-running production imports / refresh of frozen captures
