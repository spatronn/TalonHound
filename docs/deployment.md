# Deployment workflow

Migrations **never** run automatically on container startup. They are applied in a controlled one-shot step before bringing up application services.

## Principles

- `backend` / workers / scheduler start with `node server.js` or their worker entrypoint only — no `migrate.js` in startup chains.
- Only files matching `backend/migrations/*.sql` (plain `.sql` suffix) are executed.
- Quarantined files under `backend/migrations_disabled/` (e.g. `*.sql.disabled`) are never executed.
- A Postgres advisory lock prevents parallel `migrate` processes.
- Run migrations **before** `backend` and **before** integration scheduler/workers when schema changes are included.

## Standard deploy order

```bash
# 1. Infrastructure
docker compose up -d db redis

# 2. Build images (when code changed)
docker compose build backend frontend integration-worker integration-scheduler

# 3. List pending migrations (optional sanity check)
docker compose run --rm backend npm run migrate:list

# 4. Apply migrations (one-shot, explicit)
docker compose run --rm backend npm run migrate

# 5. Backend + smoke test
docker compose up -d backend
docker compose logs backend --tail=200
# Expect: node server.js — NOT migrate.js

# 6. UI / proxy
docker compose up -d frontend proxy

# 7. Workers (after backend is healthy)
docker compose up -d ioc-expiration-worker integration-worker

# 8. Scheduler last (starts feed imports)
docker compose up -d integration-scheduler
```

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

## Pre-migration checks

Confirm quarantined 071 is not in the active migrations directory:

```bash
docker compose run --rm --entrypoint sh backend -lc \
  'ls -l /app/migrations | grep 071 || true; grep -R "IOC confidence model" -n /app/migrations || true'
```

Expected: no `071_ioc_confidence_model.sql` in `/app/migrations`. Safe replacement is `072_ioc_confidence_model_safe.sql`.

## Post-deploy verification

### Backend logs

```bash
docker compose logs backend --tail=200
```

Expect `node server.js` and listening on port 3000. No `[migrate]` output during normal startup.

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

### Login smoke test

**Clean first install only:** the backend creates a default local admin when the `users` table is empty and bootstrap has never run:

```text
admin@talonhound.local / admin
```

Password change is required on first login. This account is **not** recreated on later restarts or after deletion.

On existing installs, create users via **Administration → Users**.

```bash
curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"<your-user>","password":"<your-password>"}'
```

Expected: `200`

### Parallel migrate guard

If two `npm run migrate` processes run concurrently, the second must exit non-zero with:

`Another migration process is already running.`

## IOC confidence schema (072)

The unsafe `071` migration was quarantined to `migrations_disabled/071_ioc_confidence_model.sql.disabled`.

Apply the safe replacement explicitly:

```bash
docker compose run --rm backend npm run migrate
```

`072_ioc_confidence_model_safe.sql`:

- Adds **nullable** columns only (no `NOT NULL DEFAULT` on large tables)
- No `CHECK` constraints on `ioc_items`
- No full-table backfill on `ioc_items`
- Seeds `integration_feeds.default_confidence` for known feed keys only

Backend falls back to legacy `confidence` column when new columns are not yet applied.

## Emergency rollback

If a migration causes lock/contention during an explicit migrate run:

```bash
docker compose stop backend integration-worker integration-scheduler
# Move problematic file out of backend/migrations/ into migrations_disabled/
docker compose build backend
docker compose up -d backend
```

Investigate `pg_stat_activity` / `pg_locks` before re-attempting migrate.

## Incident reference

Hotfix commit `1f71b2e` disabled startup migrations after `071` caused `AccessExclusiveLock` on `ioc_items` during parallel container startup, blocking login and workers.
