# Deployment workflow

> **Normal installation** (operators): clone the repo and run `sudo ./installation.sh`, then
> finish in the browser-based **Setup Wizard** (see the root [README](../README.md)). The
> installer handles Docker, secrets, migrations, service ordering, and the one-time setup code.
>
> **This document** covers the manual developer/operator flow: explicit Docker Compose,
> one-shot migrations, and source rebuilds. Use it when you build from source or operate an
> existing install — not as the primary install path for new users.

Migrations **never** run automatically on container startup. They are applied in a controlled one-shot step before bringing up application services.

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

### First run: the Setup Wizard

**There is no default administrator password.** On a fresh install the first System
Administrator is created through the browser-based **Setup Wizard** (`https://<server-ip>` →
`/setup`), which also selects the system timezone. The wizard is protected by the one-time
**Setup Code** printed by `installation.sh` (stored server-side only as a SHA-256 hash in
`SETUP_CODE_HASH`; plaintext is never persisted). Setup completes atomically and permanently
locks the setup endpoints.

State that drives first-run is DB-backed (`system_settings.setup_completed_at` /
`setup_code_hash` + the `users` table) and survives restarts, rebuilds, and upgrades. An
existing install that already has a user is never sent through the wizard.

Manual (non-installer) bring-up on a **trusted** network works without a setup code: if
`SETUP_CODE_HASH` is unset the wizard's code step is skipped (open first-run). Set it (or use
`installation.sh`) to require the code.

**Legacy default-admin bootstrap (opt-in, automation/CI only):** the historical
`admin@talonhound.local` bootstrap now runs only when explicitly enabled — set
`INITIAL_ADMIN_PASSWORD`/`SYSTEM_ADMIN_PASSWORD` (min 12 chars) or `TALONHOUND_LEGACY_DEFAULT_ADMIN=1`.
It never uses a repository-known password, sets `must_change_password=true`, and is not
recreated after deletion. Normal public installs leave this **disabled** and use the wizard.

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

The canonical baseline (`001_core.sql`) includes the safe IOC confidence model (formerly `072_ioc_confidence_model_safe.sql`). New installations receive nullable confidence columns without destructive backfills.

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

Hotfix commit `1f71b2e` disabled startup migrations after an unsafe migration caused `AccessExclusiveLock` on `ioc_items` during parallel container startup. Migrations remain explicit one-shot steps only.
