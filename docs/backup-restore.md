# Backup and restore runbook

Docker Compose deployment for `demo-runbook`. Backup/restore is **CLI-first** in Faz 1; Admin UI/API will come later.

## What to back up

| Component | Critical data | Faz 1 |
|-----------|---------------|-------|
| **PostgreSQL** (`postgres_data`) | IOCs, incidents, users, audit logs, integration state, `schema_migrations` | **Required** — `postgres.dump` |
| **Redis** | BullMQ queues, cache | **Excluded** — reconcile queues after restore |
| **`.env`** | Secrets | **Not in bundle** — store separately |
| **TLS certs** (`proxy/certs/`) | HTTPS | Manual if not managed externally |

## Backup bundle layout

```text
backups/demo-runbook-YYYYMMDDTHHMMSSZ/
  manifest.json
  postgres.dump          # pg_dump -Fc
  checksums.sha256
  README.txt
```

Host path `backups/` is bind-mounted to `/backups` in the backend container for future API use. Generated bundles are git-ignored.

## Pre-backup checklist

1. Note stack version: `git rev-parse HEAD` (recorded in `manifest.json`)
2. **Quiet period recommended** — avoid backup during migrations or large feed imports
3. Optionally pause scheduler: `docker compose stop integration-scheduler`
4. Ensure no migration is running: `docker compose run --rm backend npm run migrate:list`

## Create backup (recommended)

```bash
cd /opt/demo-runbook
chmod +x scripts/backup-stack.sh scripts/restore-stack.sh

./scripts/backup-stack.sh
```

Custom output root:

```bash
BACKUP_ROOT=/data/backups ./scripts/backup-stack.sh
```

Verify:

```bash
ls -la backups/demo-runbook-*/
sha256sum -c backups/demo-runbook-*/checksums.sha256
```

## Restore (CLI only)

**Warning:** restore **overwrites** the current PostgreSQL database. Faz 1 does not expose a mutating restore API.

Preview (no changes):

```bash
./scripts/restore-stack.sh --backup backups/demo-runbook-YYYYMMDDTHHMMSSZ --dry-run
```

Execute restore:

```bash
./scripts/restore-stack.sh --backup backups/demo-runbook-YYYYMMDDTHHMMSSZ --confirm
```

The restore script will:

1. Verify `checksums.sha256` (unless `--skip-checksum`)
2. Stop writer services
3. `pg_restore --clean --if-exists` into `demo` database
4. `npm run migrate` (forward-only)
5. Start services again

### Manual PostgreSQL restore (equivalent)

```bash
docker compose stop backend integration-scheduler integration-worker signal-engine \
  ioc-expiration-worker llm-risk-worker syslog-receiver

docker compose exec -T db pg_restore -U demo -d demo --clean --if-exists \
  < backups/demo-runbook-YYYYMMDDTHHMMSSZ/postgres.dump

docker compose run --rm backend npm run migrate
docker compose up -d
```

## Post-restore verification

1. **Health**
   ```bash
   docker compose exec backend wget -qO- http://127.0.0.1:3000/readyz
   ```

2. **Migrations**
   ```bash
   docker compose run --rm backend npm run migrate:list
   ```

3. **Login** — use a database user (not env bootstrap unless configured for dev).

4. **Integration queue** — **Threat Intelligence → Job Queue Status** → Recover Queue if `recovery_needed` is true.

5. **Audit** — spot-check **Administration → Audit Logs**.

## RPO / RTO (demo / pilot)

| Metric | Target |
|--------|--------|
| **RPO** | 24h (daily backup) or per cron |
| **RTO** | 1–2h manual restore on single VM |

Test restore quarterly. No automatic retention in Faz 1.

## Disaster recovery (single VM)

1. Provision VM with Docker Compose
2. Clone repo at known git tag (match `manifest.json` `git_sha` when possible)
3. Restore `.env` from secret store
4. `docker compose up -d db redis` (minimal)
5. `./scripts/restore-stack.sh --backup <bundle> --confirm`
6. Run verification steps above
