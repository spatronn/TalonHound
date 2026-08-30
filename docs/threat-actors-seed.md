# Threat Actor bundled catalog

TalonHound ships a version-controlled Threat Actor catalog used for fresh installations and upgrade reconciliation.

## Data source

TalonHound's bundled Threat Actor catalog is sourced from [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/).

The catalog is refreshed by TalonHound maintainers from Malpedia's Threat Actor dataset and included as a version-controlled snapshot in TalonHound releases (`backend/seeds/threat-actors.json`).

Malpedia's Threat Actor catalog incorporates threat-actor knowledge aligned with the [MISP Galaxy Threat Actor cluster](https://www.misp-galaxy.org/threat-actor/). See Malpedia and MISP Galaxy for upstream details. TalonHound does not claim ownership of this upstream data, and this document does not state a specific license for the upstream dataset.

Fresh installations, upgrades, and normal TalonHound runtime do **not** query Malpedia directly. They use the bundled snapshot shipped with the installed release.

Malpedia is contacted only when:

- a maintainer intentionally refreshes the bundled snapshot (`npm run threat-actors:refresh`), or
- an operator explicitly runs the manual Malpedia import command (`npm run import:malpedia-actors`).

When maintainers refresh the bundled snapshot, TalonHound fetches the current actor catalog from Malpedia's public API:

- [Malpedia Threat Actors API](https://malpedia.caad.fkie.fraunhofer.de/api/get/actors)

The bundled snapshot allows fresh installations to work without depending on Malpedia availability at install time.

## Bundled snapshot

- Path: `backend/seeds/threat-actors.json`
- Source: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/) (see [Data source](#data-source) above)

The bundled snapshot contains only TalonHound-supported fields:

- canonical actor name
- slug
- aliases
- description
- active state

It does **not** store raw Malpedia metadata, malware families, samples, YARA rules, or reference collections.

## Fresh installation

Fresh installs do **not** contact Malpedia.

During `npm run migrate`, TalonHound:

1. applies SQL migrations (`001_core.sql` and forward migrations)
2. ensures the system `Unknown` actor exists
3. reconciles the bundled snapshot into `threat_actors`

This step is idempotent and requires no network access.

## Existing installations / upgrades

Upgrades run the same bundled reconciliation during `npm run migrate`.

Reconciliation behavior:

- insert newly bundled canonical actors
- enrich exact canonical matches (aliases/description) conservatively when the actor is a confirmed bundled equivalent
- preserve existing actor IDs and foreign keys
- preserve user-created/custom actors
- preserve locally added aliases
- preserve the `Unknown` sentinel
- preserve Lazarus legacy name/slug mapping
- preserve administrator-disabled `active = false` state (bundled `active = true` does not re-enable an existing row)
- preserve useful local descriptions; only empty/legacy placeholder descriptions may be populated from bundled data

It never deletes or disables actors merely because they disappeared upstream.

## Manual vs bundled provenance

TalonHound stores catalog memberships on each actor in `threat_actors.catalog_sources`:

- `manual` — created through the admin Threat Actor API
- `bundled` — inserted or confirmed equivalent to the bundled/Malpedia catalog
- `legacy-seed` — reviewed legacy TalonHound seed rows (APT28, APT29, Lazarus)
- `system` — the `Unknown` sentinel

Pending manual/bundled review is stored separately in `threat_actors.bundled_catalog_collision_pending`. A pending collision is **not** a catalog source membership.

Canonical name and slug remain unique. TalonHound does not fuzzy-merge actors and does not merge actors solely because aliases overlap.

### Historical upgrade / backfill

Migration `012_threat_actor_catalog_sources.sql` introduced provenance columns. Migration `013_threat_actor_provenance_finalize.sql` moves pending collision state out of `catalog_sources`.

During `npm run migrate`, TalonHound also runs a deterministic provenance backfill before bundled reconciliation:

- `Unknown` → `system`
- reviewed legacy seed IDs (APT28, APT29, Lazarus) → `legacy-seed,bundled`
- rows created by bundled import operators → `bundled`
- rows whose slug exists in the bundled snapshot → `bundled`
- clearly admin-created rows (`created_by` email, not an import operator) → `manual`

Historical bundled rows are **not** classified as `manual` merely because older releases left `created_by` NULL.

### First-time manual/bundled canonical collision

If a **manual-only** actor (for example `XYZ` / `xyz`) already exists and a later bundled snapshot also contains the same canonical name/slug, reconciliation:

- preserves the existing row ID, name, slug, aliases, description, and active state
- does **not** automatically merge bundled aliases or overwrite the local description
- sets `bundled_catalog_collision_pending = true`
- prints a **Manual/bundled collisions requiring review** summary

This avoids silently treating analyst-created `XYZ` as confirmed equivalent to upstream `XYZ`.

### Confirming equivalence

If operators determine the manual actor and bundled actor are the same real-world entity, confirm equivalence with:

```bash
PATCH /api/admin/threat-actors/:id
{ "confirm_bundled_catalog": true }
```

This:

- adds `bundled` to `catalog_sources` while retaining `manual`
- clears `bundled_catalog_collision_pending`
- preserves ID, name, slug, local aliases, useful local description, and inactive state
- writes an audit event (`Threat Actor Bundled Identity Confirmed`) with before/after provenance and collision state

Only administrators may confirm. Bundled-only actors, manual actors without a pending collision, and `Unknown` reject confirmation.

Future bundled reconciliations and manual Malpedia imports may then perform normal conservative enrichment (alias additions, empty-description fill) while still preserving local data and inactive state.

Reviewed legacy mappings such as **Lazarus** (`Lazarus Group` → `Lazarus`) continue to reconcile without requiring manual confirmation.

### Runtime validation

On a deployed host:

```bash
docker compose exec backend bash scripts/validate-threat-actor-provenance-db.sh
```

This prints provenance counts, known-actor checks, duplicate detection, and any pending collisions (without auto-confirming them).

## Manual Malpedia import

The manual importer remains available for operators who explicitly want to import from live Malpedia:

```bash
docker compose exec backend npm run import:malpedia-actors -- --dry-run
docker compose exec backend npm run import:malpedia-actors -- --apply
```

Optional bundled-file mode:

```bash
docker compose exec backend npm run import:malpedia-actors -- --from-file --apply
```

Manual import and bundled seeding share the same normalization/reconciliation implementation in `backend/lib/threatActors/`.

## Maintainer snapshot refresh

Maintainers refresh the bundled snapshot intentionally when preparing a release. This is the only routine maintenance path that contacts Malpedia to obtain the current Threat Actor catalog and update TalonHound's bundled snapshot.

```bash
docker compose run --rm -v "$PWD/backend:/app" backend npm run threat-actors:refresh -- --dry-run
docker compose run --rm -v "$PWD/backend:/app" backend npm run threat-actors:refresh -- --write
```

The refresh command fetches actors from [Malpedia's Threat Actors API](https://malpedia.caad.fkie.fraunhofer.de/api/get/actors), normalizes them through the shared Threat Actor implementation, compares the result with the current bundled snapshot, and writes an updated `backend/seeds/threat-actors.json` when `--write` is used.

The diff summary may also list **Potential canonical identity changes** (for example an upstream actor removed and a new actor whose aliases contain the old name). These are informational only; runtime database actors are never auto-renamed or auto-merged from refresh output.

When running inside a long-lived backend container without a bind mount, `--write` updates the container filesystem only. Use the bind mount above so `backend/seeds/threat-actors.json` is updated in the repository checkout.

`--dry-run` fetches and compares without writing files or touching the database.

`--write` updates `backend/seeds/threat-actors.json` and prints a diff summary, including informational `Removed upstream` counts. Upstream removals do **not** delete installed database rows.

## Shared implementation

Single source of truth:

- `backend/lib/threatActors/normalization.js`
- `backend/lib/threatActors/malpedia.js`
- `backend/lib/threatActors/reconciliation.js`
- `backend/lib/threatActors/catalogSources.js`
- `backend/lib/threatActors/catalogBackfill.js`
- `backend/lib/threatActors/snapshot.js`
- `backend/lib/threatActors/seed.js`

`backend/lib/malpediaThreatActors.js` remains as a backward-compatible re-export surface.
