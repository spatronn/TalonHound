# TalonHound database migrations

TalonHound uses forward-only SQL migrations executed explicitly via `npm run migrate` (not on container startup).

## Public baseline (v0.1.0-beta.1)

`backend/migrations/001_core.sql` is the **canonical database baseline** for the first public Beta release. It contains the complete TalonHound application schema and required product/bootstrap seed data.

Fresh installations apply the public forward migrations present in the repository, currently:

```text
001_core.sql
002_first_run_setup.sql
003_reliability_retention.sql
004_published_feed_window_incremental.sql
005_published_feed_reconciliation_cursor.sql
006_published_feed_reconciliation_bucket.sql
007_ioc_partition_active_watermark_index.sql
008_published_feed_generation_chunks_fk.sql
009_published_feed_snapshots_chunk_owned.sql
010_certpl_warning_list.sql
011_trust_level_english_values.sql
```

`002_first_run_setup.sql` adds Setup Wizard columns on top of the baseline. `003_reliability_retention.sql` adds retention/cleanup support indexes for operational history. Private-development migration history before this baseline is **not** part of the public repository.

## After the first public release

Shipped migration files are **immutable upgrade history**:

- Released migration files are not edited, deleted, or squashed.
- Add schema changes as new sequential files: `004_*.sql`, `005_*.sql`, …

Migration identity is the **full filename** stored in `schema_migrations.name`. There are no checksums; already-applied files are skipped by exact name match.

After SQL migrations complete, `npm run migrate` also reconciles the bundled Threat Actor catalog from `backend/seeds/threat-actors.json` (no Malpedia/network dependency). See [threat-actors-seed.md](./threat-actors-seed.md).

## Existing installations

Installations that applied private-development migrations before the baseline squash may retain historical rows in `schema_migrations`. That is harmless: the runner only applies files present on disk that are not already recorded.

Backup manifests record the **repository** latest migration (public schema version), not the highest legacy row in `schema_migrations`.

## Validation tooling

Baseline validation scripts are under `scripts/baseline/`:

- `build-001-core.sh` — build baseline from a fully-migrated reference DB
- `compare-schema.sh` — normalized schema equivalence
- `compare-seed-data.sh` — canonical seed table equivalence
- `run-validation.sh` — full isolated validation suite
