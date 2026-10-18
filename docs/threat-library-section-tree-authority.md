# Section-tree authoritative scope engine

## Engine selector

| Env | Default | Effect |
|---|---|---|
| `THREAT_LIBRARY_SCOPE_ENGINE=legacy` | emergency rollback | Linear `annotateDocumentZones` owns occurrence authority |
| `THREAT_LIBRARY_SCOPE_ENGINE=section_tree` | **production default** (compose default since tl-scope-engine-section-tree-v2) | Heading-ancestry remaps occurrence zones; evidence policy re-runs |

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

- `scope_engine` / `scope_engine_version` (`tl-scope-engine-section-tree-v2`)
- `section_tree_version` (`tl-section-tree-v4`)

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

## Empty formal IOC sections (delegated scope, tl-section-tree-v3)

Some publishers keep an "Indicators of compromise" heading whose only content is a pointer to an
external release ("These indicators are also available for download here."). Treating that heading
as the whole curated inventory made every body assertion a narrative non-member (0 Indicators).

When **every** real formal IOC / C2 / sample heading of a document holds no observable inventory
(`hasObservableInventory`: no observable, or a single pointer sentence), the document stays MODE A
(an assertion is required) and its body blocks join the `delegated_ioc_scope` zone:

| Occurrence in the delegated scope | Asserted? |
|---|---|
| ip:port endpoint | yes |
| observable-only list / value line | yes |
| cell of a column the publisher typed as network / hash / indicator values ("Domain / IP", "Key infrastructure", "URL", "SHA256") | yes |
| free-form table cell ("Value", "Variable-name", "Name") | no |
| operational clause ("downloads the installer from X", "communicates with the C2 endpoint X") | yes |
| hash named as the analysed artifact ("we examine the following script: H", "Wave A. H …") | yes |
| neutral mention, provider platform ("abuse of the public X service"), legitimate / dual-use stance | no |

Reference sections, chrome and code blocks never join the delegated scope; a non-empty IOC section
anywhere in the document disables delegation (normal MODE A). Quality check 13
(`delegated_authority_applied`, warning) lists the delegated Indicators for review. Attach the
publisher's external IOC file as a linked IOC Source when it is available.

## Publisher evidence integrity (tl-evidence-integrity-v1)

The deterministic anchor (`evidence_text` + `block_id`) is the publisher evidence and is also stored
as `evidence.publisher_evidence`. A model quote replaces it only when it occurs verbatim (refanged,
quote marks ignored) in a canonical block that names the value; otherwise it is kept as
`evidence.ai_evidence_rejected`. A model malicious / suspicious label is applied only when it is
uncited or cites real publisher text naming the value; `evidence.ai_classification` records what the
model said, whether publisher text supports it and whether it was applied. A publisher legitimate /
dual-use / "not inherently malicious" stance wins over model labels unless another occurrence
asserts the value; that conflict is recorded (`stance_conflict`, quality check 15).

## Qualified inventory headings (tl-section-tree-v4 / tl-zones-v14)

Some vendor templates title their IOC table "Observations" (an `Observable | Type | Name |
Reference` table), others use the same word for a narrative findings section. A qualified inventory
heading ("Observations", "Key observations") opens an IOC section only when the first table of its
section, before the next heading, is a self-proving IOC table: an indicator column plus a declared
observable-type column (`interpretIocTable` `explicit` with `declared_type_column`). Prose, a
descriptive table or a value table without a type column leaves it narrative, so the heading alone
never sets MODE A. Both engines share the check (`confirmedQualifiedIocHeading`).

Inside such a table, a row whose own descriptor cells name the value a category-qualified provider
("Blockchain provider", "DNS resolver") or an explicitly public / legitimate / third-party service is
a provider relation and asserts nothing; a C2, staging, operational, lookalike or weaponized role
keeps the row assertion. A list whose lead-in object phrase names the listed values as providers /
explorers / resolvers ("… through three Blockscout providers:") carries the same stance.
