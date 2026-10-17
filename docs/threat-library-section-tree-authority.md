# Section-tree authoritative scope engine

## Engine selector

| Env | Default | Effect |
|---|---|---|
| `THREAT_LIBRARY_SCOPE_ENGINE=legacy` | emergency rollback | Linear `annotateDocumentZones` owns occurrence authority |
| `THREAT_LIBRARY_SCOPE_ENGINE=section_tree` | **production target** | Heading-ancestry remaps occurrence zones; evidence policy re-runs |

Exactly one engine determines final Indicator membership. Shadow diagnostics (`THREAT_LIBRARY_SECTION_TREE_SHADOW`) remain independent and never override the selector. Invalid values fail extraction (`strict`) rather than silently changing membership.

Compose wires the flag to both `backend` and `threat-library-worker`.

## Rollback

1. Set `THREAT_LIBRARY_SCOPE_ENGINE=legacy` in `/opt/TalonHound/.env`
2. `docker compose up -d --no-deps --force-recreate backend threat-library-worker`
3. Verify both containers: `printenv THREAT_LIBRARY_SCOPE_ENGINE` → `legacy`

Do not automatically reprocess historical reports when switching engines.

## Offline compare

```bash
docker compose exec -T backend node scripts/section-tree-authority-compare.js --fixtures
docker compose exec -T backend node scripts/section-tree-authority-compare.js --db-export /app/tmp/st-corpus-export
```

## Provenance

Candidates and diagnostics stamp:

- `scope_engine` / `scope_engine_version` (`tl-scope-engine-section-tree-v1`)
- `section_tree_version` (`tl-section-tree-v2`)

## Architecture

```
Publisher document → Canonical document
  → Section-tree construction (heading ancestry)
  → applySectionTreeAuthority (sole zone authority when selected)
  → Deterministic observable extraction (already run) + evidence policy recompute
  → MODE A / MODE B membership
  → Candidate persistence → Analyst review
```

Legacy linear zones remain available as the `legacy` engine and still participate in typing/table/quality paths before authority remap.
