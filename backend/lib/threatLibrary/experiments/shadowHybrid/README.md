# Shadow Hybrid IOC Extraction PoC

**Experimental only.** Not wired into the import pipeline, Refresh, workers, or UI.

Compares:

1. Current deterministic extraction / MODE A membership  
2. Shadow section-tree membership (heading ancestry)  
3. Independent Qwen3.5:9b discovery with source-span grounding  
4. Validated hybrids (deterministic ∪ grounded Qwen; section-tree ∪ selective Qwen)

## Safety

- No PostgreSQL writes  
- No report refresh / IOC creation / analyst decision changes  
- Qwen runs with caller-enforced concurrency 1 and aborts if Ollama is busy  
- Qwen failure leaves deterministic membership unchanged (see `failureIsolation.js`)

## Run

From the backend container (or a Node 24 environment with backend deps):

```bash
# Deterministic + section-tree only (no Ollama)
node scripts/run-shadow-hybrid-poc.js --no-controls --out /tmp/shadow-hybrid-poc/det-tree.json

# Blinder Tunnel + selective Qwen (when Ollama idle)
node scripts/run-shadow-hybrid-poc.js --qwen --qwen-mode selective \
  --ids shadow-unit42-blinder-tunnel \
  --out /tmp/shadow-hybrid-poc/blinder-qwen.json

# Full-document Qwen on Blinder (expensive)
node scripts/run-shadow-hybrid-poc.js --qwen --qwen-mode full \
  --ids shadow-unit42-blinder-tunnel --max-chunks 12 \
  --out /tmp/shadow-hybrid-poc/blinder-full.json
```

Place the Blinder Tunnel canonical fixture at:

`experiments/shadowHybrid/fixtures/blinder-tunnel-ioc-excerpt.json` (IoC-appendix excerpt; full production canonical exports are gitignored)

(exported read-only from production for the PoC).

## Dataset

- Golden regression cases (`benchmark/cases/golden-*`) with independent publisher labels  
- Control cases (`control-*`)  
- Shadow case `shadow-unit42-blinder-tunnel` (this failure class)

Ground-truth labels are never passed to Qwen.

## Results

See [`RESULTS.md`](./RESULTS.md) for the measured accuracy matrix, Blinder Tunnel
comparison, selective-trigger evaluation, and Go/No-Go recommendation.

**Headline:** on 14 labeled cases, shadow section-tree lifts membership recall from
0.982 → **1.000** (recovers all 8 Blinder SHA256 FNs). Appendix-window Qwen also
recovers them (2/2 consistent runs) but full-document Qwen does not. Recommended
MVP: **section-tree primary + selective appendix-window Qwen as optional shadow
safety net** — not always-on dual-engine.
