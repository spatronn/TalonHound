# Deployment workflow

> **Installer path:** `sudo ./installation.sh` then the browser **Setup Wizard** (see root [README](../README.md)).
>
> **Production upgrades:** prefer [`docs/upgrade.md`](./upgrade.md) (`sudo ./installation.sh --upgrade`).
>
> **This document** covers the manual Compose / source-build flow: explicit migrations, rebuilds, and service ordering.

Migrations are applied as an explicit one-shot step (`npm run migrate`) before application services; they are not run on container startup.

## Principles

- `backend` / workers / scheduler start with `node server.js` or their worker entrypoint only — no `migrate.js` in startup chains.
- Only files matching `backend/migrations/*.sql` (plain `.sql` suffix) are executed.
- Files ending in `.sql.disabled`, `.bak`, `.tmp`, or `.old` are ignored.
- The canonical public baseline is `001_core.sql` — see [database-migrations.md](./database-migrations.md).
- A Postgres advisory lock prevents parallel `migrate` processes.
- Run migrations **before** `backend` and **before** integration scheduler/workers when schema changes are included.

## Standard deploy order

For source-built deployments on an existing host after pulling application changes, see also [`scripts/release/deploy-application.sh`](../scripts/release/deploy-application.sh).

```bash
# 1. Infrastructure
docker compose up -d db redis

# 2. Build images (when code changed)
docker compose build backend frontend integration-worker integration-scheduler

# 3. List pending migrations
docker compose run --rm backend npm run migrate:list

# 4. Apply migrations
docker compose run --rm backend npm run migrate

# 5. Backend
docker compose up -d backend
docker compose logs backend --tail=200
# Startup entrypoint: node server.js (not migrate.js)

# 6. UI / proxy
docker compose up -d frontend proxy

# 7. Workers (after backend is healthy)
docker compose up -d \
  ioc-expiration-worker ioc-search-export-worker ioc-deep-search-worker \
  ioc-bulk-query-worker backup-worker integration-worker

# 8. Scheduler last (arms feed import schedules)
docker compose up -d integration-scheduler
```

Worker roles and queues: [container-operations-and-tuning.md](./container-operations-and-tuning.md).

## Migration commands

```bash
# List runnable .sql files in migrations/ (does not connect to DB)
docker compose run --rm backend npm run migrate:list

# Apply pending migrations
docker compose run --rm backend npm run migrate
```

Environment overrides (optional):

- `MIGRATION_LOCK_TIMEOUT` — default `5s` (Postgres `lock_timeout`)
- `MIGRATION_STATEMENT_TIMEOUT` — default `120s` (Postgres `statement_timeout`)

## Post-deploy verification

### Backend logs

```bash
docker compose logs backend --tail=200
```

Startup entrypoint is `node server.js` on port 3000; no `[migrate]` output during normal startup.

### DB lock waiters

```sql
SELECT
  count(*) FILTER (WHERE state <> 'idle') AS active_sessions,
  count(*) FILTER (WHERE wait_event_type = 'Lock') AS lock_waiters
FROM pg_stat_activity
WHERE datname = current_database();
```

Expected: `lock_waiters = 0` during steady state.

### Health endpoints

- `GET /healthz` — process alive (no DB)
- `GET /readyz` — DB/Redis readiness + Date & Time health (`date_time`)
- `GET /health` — legacy combined check (includes `date_time`)
- `GET /api/system/time-health` — dedicated timezone consistency snapshot

See [system-timezone.md](./system-timezone.md) for NTP responsibility, initial setup, and timezone change / restart procedures.

### First run: the Setup Wizard

There is **no default administrator password.** On a fresh install the first System
Administrator is created through the browser **Setup Wizard** (`https://<server-ip>` →
`/setup`), which also selects the system timezone. The wizard is gated by the one-time
**Setup Code** from `installation.sh` (server-side `SETUP_CODE_HASH` is SHA-256 only;
plaintext is not persisted). Setup completes atomically and permanently locks the setup
endpoints.

First-run state is DB-backed (`system_settings.setup_completed_at` / `setup_code_hash` +
`users`) and survives restarts, rebuilds, and upgrades. Installs that already have a user
skip the wizard.

Manual (non-installer) bring-up: if `SETUP_CODE_HASH` is unset, the wizard code step is
skipped. Set it (or use `installation.sh`) to require the code.

**Legacy default-admin bootstrap (opt-in, automation/CI):** enabled only via
`INITIAL_ADMIN_PASSWORD`/`SYSTEM_ADMIN_PASSWORD` (min 12 chars) or
`TALONHOUND_LEGACY_DEFAULT_ADMIN=1`. Uses no repository-known password, sets
`must_change_password=true`, and is not recreated after deletion. Public installs leave this
disabled and use the wizard.

On existing installs, create additional users via **Administration → Users**.

```bash
curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"<your-user>","password":"<your-password>"}'
```

Expected: `200`

### Parallel migrate guard

If two `npm run migrate` processes run concurrently, the second must exit non-zero with:

`Another migration process is already running.`

## IOC confidence schema

The canonical baseline (`001_core.sql`) includes the IOC confidence model (formerly `072_ioc_confidence_model_safe.sql`): nullable confidence columns, no backfill of existing rows.

## Emergency rollback

If a migration causes lock/contention during an explicit migrate run:

```bash
docker compose stop backend integration-worker integration-scheduler
# Remove or fix the problematic forward migration file (002_*.sql, ...)
docker compose build backend
docker compose up -d backend
```

Investigate `pg_stat_activity` / `pg_locks` before re-attempting migrate.

## Incident reference

Commit `1f71b2e` removed startup migrations after a migration took `AccessExclusiveLock` on `ioc_items` during parallel container startup. Migrations remain explicit one-shot steps only.
