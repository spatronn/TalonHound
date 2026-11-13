# Targeted First-Pass Quality Improvements — Technical Report

**Branch:** `fix/filename-zip-domain-and-eval-url-equiv` (`670f8c1`)  
**PR:** https://github.com/spatronn/TalonHound/pull/111 (CI green)  
**Date:** 2026-11-13  
**Scope:** two low-risk corrections + MODE A recommendations. No architecture redesign, no new AI components, no narrative auto-promote, no pack auto-extract.

---

## 1. Filename / domain false positives (implemented)

### Root cause

MarkiRAT div-grid cells `YEMPlayer.zip` / `Pis2rayVPN.zip` inherit a C2 heading’s `declaredType=domain`. Because `.zip` is both a **file extension** and a **delegated gTLD**, `declared_network_type` promoted the bare two-label token to a domain Indicator (`explicit_c2`). Sibling `.msi` names correctly stayed `technical_artifact` (`.msi` is not a DNS suffix).

`resolveDottedToken('YEMPlayer.zip')` without inherited network declaration already returned `technical_artifact`; the defect was the declared-network short-circuit for dual-use suffixes.

### Fix (`tl-type-resolver-v27`)

In `observableTypeResolver.js`, when `declaredNetwork` is set, a **bare two-label** FILE_EXT ∩ gTLD collision that is **not** defanged (raw or surrounding) and **not** a typed Domain *table* cell falls through to file-extension rules.

Kept as domain (negative cases):

- Defanged hosts (`evil[.]zip`, including raw `evil.zip` with surrounding defang)
- Typed Domain table cells (`archive-sync.war`, IOC Type=Domain rows)
- Multi-label hosts (`cdn.files.zip`)

### Tests / evidence

- `filenameZipDomainCollision.test.js` — positive MarkiRAT-shaped cases + negative .zip TLD / table / defang cases
- Benchmark control `control-filename-zip-gtld-collision` (+ baseline refresh)
- Version pins → `tl-type-resolver-v27`

### Impact on frozen captures

Frozen first-pass captures are **unchanged** (no refresh). Re-extraction of MarkiRAT HTML after the fix yields `technical_artifact` for both zips and keeps `yemplayer.site` as domain. Production reports pick this up on **new** imports / authorized refresh only.

**Projected frozen-scorecard effect (if re-extracted):** −2 verified FPs (`yemplayer.zip`, `pis2rayvpn.zip`) on MarkiRAT; strict aggregate would move from P≈0.933 toward ≈0.942 on the same GT, without changing production identities in the freeze.

---

## 2. Evaluation URL equivalence (implemented, scoring-only)

`docs/evaluation/unseen-first-pass-10/_score.mjs` writes:

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

**Recommendations (product-policy pending):**

1. Score separately: `document_indicator_membership` vs `pending_linked_pack_declared` vs `candidate_discovery_of_gt`
2. First-pass UI banner when authoritative inventory is a linked pack
3. Keep pack extract analyst-gated; no auto-promote / auto-extract
4. Follow-up: why KongTuke promoted exactly two peer narrative URLs under MODE A

---

## 4. Production revision verification

| Check | Result |
|---|---|
| SSH to `192.168.1.190` | **Permission denied** |
| `http://192.168.1.190/api/system/version` | **401 Unauthorized** |
| MCP live reads | Available; InstallFix still mode A / `contract_freshness=current` |

**Cannot independently claim a host git SHA or deployed image digest.** Workspace tip is `tl-type-resolver-v27`; production still runs the frozen capture contract until deploy + re-import/refresh (not performed).

---

## 5. Verification / CI

| Item | Result |
|---|---|
| Host SSH tests | Blocked |
| MarkiRAT local re-extract | zip → artifact; `.site` → domain |
| Equivalence rescore | +4 TP / −4 FP / −4 FN vs strict |
| Frozen captures | Preserved |
| PR #111 CI | **All green** (Backend, Frontend, Compose, Release, Docker smoke, Snyk) |
| CI recovery notes | First commits mojibaked UTF-8 in resolver/fixtures; restored; dual-use gate refined for surrounding defang; benchmark control + baseline refresh for contract gate |

---

## 6. Files touched (this PR)

**Code / tests**

- `observableTypeResolver.js` (`tl-type-resolver-v27`)
- `filenameZipDomainCollision.test.js`
- `benchmark/cases/control-filename-zip-gtld-collision.{html,json}`
- Version pins + `benchmark/baseline.json`

**Eval (scoring / docs only)**

- `docs/evaluation/unseen-first-pass-10/_score.mjs` (+ equivalence summary)
- `MODE-A-PENDING-PACK-AUDIT.md`, this report, freeze/score artifacts

**Not changed**

- Membership / MODE A / pack extract pipeline  
- Frozen `first-pass-captures/*`  
- Production deployment
