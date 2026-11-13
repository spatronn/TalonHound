# Targeted First-Pass Quality Improvements — Technical Report

**Branch:** `fix/filename-zip-domain-and-eval-url-equiv`  
**Date:** 2026-11-13  
**Scope:** two low-risk corrections + MODE A recommendations. No architecture redesign, no new AI components, no narrative auto-promote, no pack auto-extract.

---

## 1. Filename / domain false positives (implemented)

### Root cause

MarkiRAT div-grid cells `YEMPlayer.zip` / `Pis2rayVPN.zip` inherit a C2 heading’s `declaredType=domain`. Because `.zip` is both a **file extension** and a **delegated gTLD**, `declared_network_type` promoted the bare two-label token to a domain Indicator (`explicit_c2`). Sibling `.msi` names correctly stayed `technical_artifact` (`.msi` is not a DNS suffix).

`resolveDottedToken('YEMPlayer.zip')` without inherited network declaration already returned `technical_artifact`; the defect was the declared-network short-circuit for dual-use suffixes.

### Fix (`tl-type-resolver-v27`)

In `observableTypeResolver.js`, when `declaredNetwork` is set, a **bare two-label** FILE_EXT ∩ gTLD collision that is **not** defanged and **not** a typed Domain *table* cell falls through to file-extension rules.

Kept as domain (negative cases):

- Defanged hosts (`evil[.]zip`)
- Typed Domain table cells (`archive-sync.war`)
- Multi-label hosts (`cdn.files.zip`)

### Tests

`backend/lib/threatLibrary/filenameZipDomainCollision.test.js` — positive MarkiRAT-shaped cases + negative .zip TLD / table / defang cases. Version pins updated to `tl-type-resolver-v27`; benchmark baseline updated.

### Impact on frozen captures

Frozen first-pass captures are **unchanged** (no refresh). Re-extraction of MarkiRAT HTML locally after the fix yields `technical_artifact` for both zips and keeps `yemplayer.site` as domain. Production reports will pick this up on **new** imports / authorized refresh only.

---

## 2. Evaluation URL equivalence (implemented, scoring-only)

`docs/evaluation/unseen-first-pass-10/_score.mjs` now writes:

| File | Mode |
|---|---|
| `score-summary.json` | **Strict** (original semantics) |
| `score-summary.equivalence.json` | Host/path + trailing-slash fold |

Does **not** rewrite stored IOC identities or captures.

### Old vs new (frozen captures, unchanged pipeline output)

| Scorecard | P | R | TP | FP | FN |
|---|---:|---:|---:|---:|---:|
| Strict (preserved) | 0.933 | 0.929 | 224 | 16 | 17 |
| Equivalence-aware | **0.950** | **0.946** | 228 | 12 | 13 |
| Delta | +0.017 | +0.017 | +4 | −4 | −4 |

Delta matches Ghost scheme-less URL pairs (×3) + Google trailing-slash pair (×1).

---

## 3. MODE A + pending packs (audit only — no code change)

See `MODE-A-PENDING-PACK-AUDIT.md`.

**Verdict:** Trend 15/15 candidate discovery with 2/15 membership is **consistent with intended MODE A + empty IOC heading + linked pack pointer** behavior. Quality warnings already surface the gap. KongTuke’s two narrative members are a residual consistency question for a later investigation — not fixed by weakening evidence rules.

**Recommendations:** separate metrics for document membership vs pending pack; UI banner; no auto-extract / auto-promote without a product-policy decision.

---

## 4. Production revision verification

| Check | Result |
|---|---|
| SSH to `192.168.1.190` (`Hostname`, `talonhound`, `ubuntu`, `root`, … + local keys) | **Permission denied** |
| `http://192.168.1.190/api/system/version` | Reachable but **401 Unauthorized** |
| MCP live reads | Available; InstallFix still `tl-quality-v16` / mode A / `contract_freshness=current` |

**Cannot independently claim a host git SHA or deployed image digest in this session.** Workspace change is `tl-type-resolver-v27`; production still runs the frozen capture contract until deploy + re-import/refresh (not performed).

---

## 5. Verification / CI

- Host test run: **blocked** (SSH).  
- Local reproduction of MarkiRAT extract: zip → artifact, `.site` → domain.  
- Equivalence scorer: delta as above.  
- Frozen captures: preserved.  
- CI: expected to run `filenameZipDomainCollision.test.js` + existing type-resolver suites on PR.

---

## 6. Files touched (this PR)

**Code**

- `backend/lib/threatLibrary/observableTypeResolver.js` (`tl-type-resolver-v27`)
- `backend/lib/threatLibrary/filenameZipDomainCollision.test.js` (new)
- Version pin asserts + `benchmark/baseline.json`

**Eval (scoring / docs only)**

- `docs/evaluation/unseen-first-pass-10/_score.mjs`
- `docs/evaluation/unseen-first-pass-10/MODE-A-PENDING-PACK-AUDIT.md`
- `docs/evaluation/unseen-first-pass-10/TARGETED-FIXES-TECHNICAL-REPORT.md`
- Regenerated `score-summary.json` / `score-summary.equivalence.json` (strict preserved semantics)

**Not changed**

- Membership / MODE A / pack extract pipeline  
- Frozen `first-pass-captures/*` contents from production first-pass  
- Production deployment
