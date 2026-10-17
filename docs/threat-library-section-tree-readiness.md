# Section-tree architecture — production readiness

**Branch intent:** `feat/section-tree-shadow-readiness`  
**Phase:** shadow diagnostics only — **not** authoritative membership  
**Qwen:** out of scope for activation (design notes only)

## 1. Production-readiness assessment

### PoC findings (verified)

The Shadow Hybrid PoC showed section-tree ancestry recovers the Blinder Tunnel MODE A false negatives (8 SHA256s) and raised labeled-corpus membership recall from 0.982 → 1.000 across 14 cases, without changing the shared 2 false positives.

### PoC shortcuts **not** copied into production

| PoC shortcut | Risk | Production response |
|---|---|---|
| Remap = membership | Couples structure to product contracts | Structure (`annotate`) and membership **preview** are separate modules |
| `rowShaped` length ≤ 120 | Promoted narrative domains (`google.com`) | Tighter shape + **focused-value** guard |
| Always-on experiment path | Accidental authority | Feature flag default **OFF**; candidates never mutated |
| Unbounded traces / body text in diagnostics | Log leakage | Compact diffs: identities + short section paths only |
| English-only group labels as sole authority | Fragile | Labels are hints; inventory look-ahead required for synthetic subgroups |
| Experiments package as runtime dependency for product | Coupling | Product code lives in `lib/threatLibrary/sectionTree/`; fixtures replay may still use experiments loaders offline |

### Verdict

**Ready for controlled shadow deployment behind a flag.**  
**Not ready** to replace linear zones as authoritative membership without a gated cutover and production impact review.

---

## 2. Section-tree integration design

```
CanonicalDocument.blocks
        │
        ▼
 annotateSectionTree()          ← structural only (tl-section-tree-v1)
        │  section_path, authoritative_ancestor_id/zone, tree_zone
        ▼
 previewMembershipAdditive()    ← diagnostics preview (does not write candidates)
        │
        ▼
 compareMembershipSets(det, tree)
        │
        ▼
 diagnostics.section_tree_shadow (bounded)
```

**Authoritative path (unchanged):** linear `annotateDocumentZones` → candidate extraction → `isReportIndicatorMember`.

**Shadow path (optional):** same candidates → section-tree preview → disagreement metrics only.

### Feature flag

| Env | Default | Effect |
|---|---|---|
| `THREAT_LIBRARY_SECTION_TREE_SHADOW` | unset/false | No shadow work |
| `THREAT_LIBRARY_SECTION_TREE_SHADOW=1` | — | Attach `section_tree_shadow` to extraction diagnostics |
| `THREAT_LIBRARY_SECTION_TREE_SHADOW_FULL_REZONE=1` | unset | Also compute aggressive full-rezone preview (diagnostics only) |

Shadow failures set `section_tree_shadow.ok=false` and **must not** fail extraction / import.

---

## 3. Experimental code review findings

Reviewed: `experiments/shadowHybrid/sectionTree.js`, `sectionTreeMembership.js`, `RESULTS.md`.

**Sound ideas retained:** heading stack ancestry; synthetic subgroup nesting when inventory follows; additive upgrade of focused IOC rows; fail-open Qwen lesson applied to shadow (optional engine).

**Rejected for production authority:** treating section-tree remap as live membership; full-document Qwen; automatic Indicator promotion.

---

## 4–5. Implementation & regression / impact

Host run artifacts (2026-10-17): `/tmp/section-tree-readiness/`  
Unit tests: `sectionTree/sectionTree.test.js` — **5/5 pass** on backend container.  
Flag smoke: default OFF leaves diagnostics untouched; `THREAT_LIBRARY_SECTION_TREE_SHADOW=1` attaches bounded `section_tree_shadow`.

### Golden / PoC accuracy matrix (fixture replay)

```bash
node scripts/section-tree-shadow-replay.js --fixtures --out /tmp/section-tree-fixture-replay.json
```

| Case | Det F1 | Tree F1 | Δ membership | Notes |
|---|---:|---:|---|---|
| control-api-examples-c2-topic | 1.0000 | 1.0000 | +0/−0 | |
| control-legitimate-binaries | 1.0000 | 1.0000 | +0/−0 | |
| control-loopback-contact-narrative | 1.0000 | 1.0000 | +0/−0 | |
| control-mode-b-narrative | 0.6667 | 0.6667 | +0/−0 | shared MODE B FP (not tree) |
| golden-checkpoint-mois-cybercrime | 1.0000 | 1.0000 | +0/−0 | |
| golden-elastic-apex-accelerator | 0.9787 | 0.9787 | +0/−0 | shared URL FP (not tree) |
| golden-huntress-muddywater-chain | 1.0000 | 1.0000 | +0/−0 | |
| golden-levelblue-blind-eagle | 1.0000 | 1.0000 | +0/−0 | |
| golden-microsoft-needymantis | 1.0000 | 1.0000 | +0/−0 | focused-value guard holds |
| golden-unit42-ai-enabled-malware | 1.0000 | 1.0000 | +0/−0 | |
| golden-unit42-ppi-untracked-nightmares | 1.0000 | 1.0000 | +0/−0 | |
| pdf-kimsuky-360-appendix | 1.0000 | 1.0000 | +0/−0 | |
| pdf-pivotc2-socradar | 1.0000 | 1.0000 | +0/−0 | |
| **shadow-unit42-blinder-tunnel** | **0.7500** | **1.0000** | **+8/−0** | 8 SHA256 recovered under IoC ancestry |

**Aggregate (14 labeled cases):** section-tree additive TP/FP/FN = **451 / 2 / 0** (det was 443 / 2 / 8). Exact membership sets equal on 13/14; only Blinder differs, and only by additions.

### Production-document impact preview

```bash
node scripts/section-tree-shadow-replay.js --db-export /path/to/exports --out /tmp/section-tree-prod-preview.json
```

Offline replay over **40** stored production canonicals (incl. Blinder):

| Metric | Count |
|---|---:|
| Total reports | 40 |
| Unchanged (exact membership) | **39** |
| With additions | **1** |
| With removals | **0** |
| Shadow errors | **0** |

**Only differing report:** `98ae9ac2-4be0-4860-b381-610e67baede7` (Unit 42 Blinder Tunnel) — **+8 SHA256**, −0.  
Evidence: all eight under section path  
`… → Indicators of Compromise → Blinder Tunnel malware payloads and hashes`  
with `authoritative_zone=explicit_ioc_section`, reason `section_tree_authoritative_ancestry`.  
Root cause: linear synthetic-paragraph zone reset dropped inventory hashes; ancestry retains the IoC heading.

No other publisher diffs; no unexpected removals; no quality diagnostic regressions in the additive preview.

### Known deterministic FPs (investigated, not “fixed” in this phase)

From the PoC corpus, the two persistent FPs are **shared by deterministic and section-tree** (not introduced by the tree):

1. **Elastic Apex** — `url:https://ccmihr.com/macos/jquery.js` labeled non-Indicator in GT but still a member (structural URL in authoritative / C2-adjacent scope). Classifier / evidence-policy issue, not section-tree ancestry.
2. Second FP on the 14-case aggregate tracks the same Elastic URL plus MODE B control residual (`control-mode-b-narrative` F1 0.6667 on both engines) — narrative MODE B membership, outside appendix-tree scope.

Section-tree must not be blamed for these; do not silently retune baselines.

---

## 6. Cutover safety design (future — not this phase)

### Activation prerequisites (measurable)

1. Shadow enabled in staging/prod with flag; **0 import failures** attributable to shadow for ≥N days.  
2. Fixture replay: section-tree additive F1 ≥ deterministic F1; Blinder Tunnel FN = 0; golden-six exact (or documented intentional diffs).  
3. Production preview: **removals_total = 0** on additive mode across sampled reports, or every removal has analyst-accepted rationale.  
4. Explicit cutover flag distinct from shadow (e.g. `THREAT_LIBRARY_SECTION_TREE_AUTHORITATIVE`) — **not implemented yet**.  
5. Separate human approval ticket.

### Kill switch / rollback

- Turn off authoritative flag → linear zones only.  
- Shadow flag independent (can stay on for metrics).  
- No automatic reprocessing; reviewed Indicators preserved by existing refresh guards.

### Initial deploy posture (this PR)

Ship with **`THREAT_LIBRARY_SECTION_TREE_SHADOW` unset/OFF**.  
Authoritative membership remains linear zones. Enabling shadow later is an env-only change on the backend / threat-library worker — no code deploy required for the flag flip, and disabling it instantly stops shadow work with no membership side effects.

### Provenance

- Persist `section_tree_version` / `membership_preview_version` in diagnostics when shadow runs.  
- On future cutover, stamp extractor versions the same way as `tl-zones-v*`.

### Monitoring

- Counters: reports with additions / removals / shadow errors / equal.  
- Alert on shadow error rate and on unexpected removal spikes if authoritative mode is ever enabled.

---

## 7. Qwen follow-up design (do not implement)

Keep independent discovery experimental.

**Smallest viable verifier:** when `appendix_heading_nonmember_rows` (or empty appendix) fires **and** section-tree additive preview still disagrees with quality evidence, send only the **section-tree packet** for that heading subtree (block ids, types, table grids, heading path) — not deterministic candidate lists — to Qwen appendix-window style discovery. Ground proposals; queue for analyst review; never auto-approve.

Coupling rule: Qwen consumes **canonical blocks under a section_path**, not `candidate_updates` identities.

Full-document Qwen remains **NO-GO**.

---

## 8. Remaining risks

- Synthetic heading detection still heuristic (bold paragraphs).  
- Multilingual group labels incomplete (inventory look-ahead mitigates).  
- PDF inferred levels can still mis-nest without font-weight signals.  
- Additive preview can miss removals needed for FP cleanup (full-rezone preview is optional diagnostics).  
- Shadow on every import adds CPU; keep flag off until cost measured.  
  Measured overhead (host, representative fixtures): typically **1–20 ms** shadow vs **3–53 ms** deterministic extract; Blinder excerpt +8 membership preview ~5 ms. Compact additive JSON ~200–3000 chars (bounded, no body text).  
- Experiments fixture loader still used by offline replay scripts (acceptable for tooling).

---

## 9. Recommendation

| Decision | Verdict |
|---|---|
| **Shadow diagnostics activation** (`THREAT_LIBRARY_SECTION_TREE_SHADOW=1`) | **GO** — controlled; default remains OFF until ops enables the flag |
| **Authoritative membership cutover** | **NO-GO** this phase — requires separate flag, approval, and acceptance gates in §6 |
| **Production Qwen extraction** | **NO-GO** — keep experimental; appendix-window design only (§7) |

**Evidence for shadow GO:** fixture parity on golden/controls/PDFs; Blinder +8/−0; production sample 39/40 unchanged with **0 removals / 0 shadow errors**; fail-soft hook in `extractionStages.js`; candidates never mutated.

**Success criterion for this phase (met):** section-tree can replace fragile linear scope *safely as a shadow structural interpreter* — Blinder-class FNs visible as additive diffs — without changing live Indicator membership.
