# Quarantined migrations

Files here are **never** executed by `migrate.js` (only `backend/migrations/*.sql` ending in `.sql` are considered).

## `071_ioc_confidence_model.sql.disabled`

Disabled after a production incident where this migration ran automatically during container startup and held `AccessExclusiveLock` on `ioc_items`, blocking login and workers.

Problems in the original file:

- `NOT NULL DEFAULT` on `integration_feeds.default_confidence`
- `CHECK` constraints on new `ioc_items` columns
- Full-table `UPDATE` backfill on `ioc_items`

**Replacement:** apply `backend/migrations/072_ioc_confidence_model_safe.sql` via explicit one-shot migrate:

```bash
docker compose run --rm backend npm run migrate
```

Do not move this file back into `migrations/` without rewriting it to the safe pattern above.
