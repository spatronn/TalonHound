# Shadow Hybrid IOC Extraction PoC — Results

**Date:** 2026-10-17  
**PoC version:** `tl-shadow-hybrid-poc-v1`  
**Constraint:** offline / shadow only — no production writes, no commit/deploy

Artifacts on host: `/tmp/shadow-hybrid-poc/`  
Code: `backend/lib/threatLibrary/experiments/shadowHybrid/` + `backend/scripts/run-shadow-hybrid-poc.js`

## Dataset

14 independently labeled cases with materializable sources (all available labeled fixtures that load without a private source store):

| Group | Count | Notes |
|---|---:|---|
| Golden real-report excerpts | 7 | including Unit 42 PPI |
| HTML controls | 4 | MODE B / legitimate / loopback |
| PDF fixtures | 2 | Kimsuky appendix, PivotC2 |
| Shadow Blinder Tunnel | 1 | full production canonical, independent GT |

A 15th private-store report was not available on this host. Labels were never passed to Qwen.

## Aggregate membership (14 cases, no Qwen)

| Approach | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| Deterministic | 443 | 2 | 8 | 0.9955 | 0.9823 | 0.9888 |
| Section-tree | 451 | 2 | 0 | 0.9956 | **1.0000** | **0.9978** |
| Qwen independent | — | — | — | — | — | not run on full suite |
| Det ∪ Qwen hybrid | 443 | 2 | 8 | 0.9955 | 0.9823 | 0.9888 |
| Tree ∪ selective Qwen | 451 | 2 | 0 | 0.9956 | 1.0000 | 0.9978 |

All 8 deterministic FNs are the Blinder Tunnel SHA256 Indicators.

## Blinder Tunnel (target failure)

| Approach | TP | FP | FN | F1 | Notes |
|---|---:|---:|---:|---:|---|
| Deterministic | 12 | 0 | 8 | 0.75 | hashes extracted but MODE A non-members |
| Section-tree | 20 | 0 | 0 | **1.00** | recovers all 8 hashes |
| Qwen appendix_window r1 | 20 | 0 | 0 | **1.00** | ~224s, 1 chunk, 77 blocks |
| Qwen appendix_window r2 | 20 | 0 | 0 | **1.00** | consistent with r1 |
| Qwen full-document | 1 | 1 | 19 | 0.09 | 10 grounding rejects; chunk failure; **do not use** |
| Validated hybrid (det∪appendix Qwen) | 20 | 0 | 0 | 1.00 | Qwen-only correct = 8 SHA256 |

## Selective triggers (14 cases)

| Metric | Value |
|---|---:|
| Would trigger | 3 / 14 |
| Known FN cases | 1 (Blinder) |
| Would catch known FN | 1 / 1 |
| Clean-but-has-FN | **0** |
| False triggers (no FN) | 2 (Elastic `authoritative_section_empty`, Needymantis `authoritative_section_empty`) |

Quality warnings are useful but not perfect: they catch Blinder, and do not miss FNs on this corpus, but over-trigger on empty authoritative headings without membership loss.

## Performance

| Workload | Latency | Tokens (approx) |
|---|---|---|
| Det + section-tree (14 cases) | ~few seconds total | n/a |
| Qwen appendix_window (Blinder) | ~224 s / run | prompt_eval≈3671, eval≈3627 |
| Qwen full Blinder | ~minutes, unstable | multi-chunk; one fetch failure |

Ollama: `192.168.1.8` / `qwen3.5:9b`, concurrency 1, abort-if-busy honored (busy skips leave deterministic intact).

## Failure isolation

Simulated Qwen unavailable → hybrid ≡ deterministic on every scored case. **Pass.**

## Architecture decision

| Option | Verdict |
|---|---|
| A Deterministic only | Leaves Blinder-class FNs |
| B Section-tree only | **Best verified recall lift** on this corpus (+8 TP, 0 added FN, same shared FPs) |
| C Det + always-on Qwen | Full-doc Qwen harmful/unstable; high cost |
| **D Section-tree + selective Qwen** | **Recommended MVP**: tree as primary fix; Qwen only on quality-triggered appendix windows as shadow safety net |

## Go / No-Go

| Decision | Evidence |
|---|---|
| **GO** — continue section-tree toward production (shadow → gated cutover) | Recall 1.0 on 14 labeled cases; Blinder exact; golden Needymantis exact after focused-value guard |
| **CONDITIONAL GO** — selective Qwen appendix-window shadow | Recovers Blinder when scoped; consistent 2/2; must not run full-document by default |
| **NO-GO** — always-on / full-document independent Qwen | Full-doc Blinder recall 0.05 with FPs and timeouts |
| **NO-GO** — production cutover of Qwen membership without more held-out full reports | Fleet-wide Qwen precision/cost still under-measured |

### Minimum next gates before any production merge

1. Section-tree shadow parity on all golden + this Blinder fixture; no golden F1 regressions.  
2. Persist Qwen-only proposals as experimental review items only (never auto-approve).  
3. Optional engine failure must not fail imports (already true for this PoC; not true of today’s analysis pipeline).  
4. Expand held-out labels to ≥15–30 full reports before enabling selective Qwen outside shadow mode.
