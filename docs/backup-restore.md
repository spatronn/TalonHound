# Backup and restore runbook

Docker Compose deployment for `demo-runbook`. Adjust paths and volume names for your host.

## What to back up

| Component | Critical data | Notes |
|-----------|---------------|-------|
| **PostgreSQL** (`postgres_data`) | IOCs, incidents, users, audit logs, integration state | **Must back up** |
| **ClickHouse** (`clickhouse_data`) | Syslog logs, observables, evidence tables | **Must back up** if `LOG_STORAGE=clickhouse` |
| **Redis** | BullMQ job metadata, ephemeral caches | **Optional** — queues can be reconciled; do not rely on Redis for durable state |
| **TLS certs** (`proxy/certs/`) | HTTPS certificates | Back up if not managed externally |
| **`.env`** | Secrets | Store in a secret manager; never commit to git |

Redis holds BullMQ queues and short-lived cache keys. After restore, run integration queue recovery from **Threat Intelligence → Job Queue Status** if workers report stale jobs.

## Pre-backup checklist

1. Note stack version: `git rev-parse HEAD`
2. Prefer quiet period: pause scheduler if needed (`docker compose stop integration-scheduler`)
3. Ensure no migration is running

## PostgreSQL backup

```bash
cd /opt/demo-runbook
mkdir -p backups
STAMP=$(date -u +%Y%m%dT%H%M%SZ)

docker compose exec -T db pg_dump -U demo -d demo -Fc \
  > "backups/postgres-demo-${STAMP}.dump"
```

Verify archive:

```bash
ls -lh backups/postgres-demo-*.dump
```

## ClickHouse backup

Logical export (works for demo-scale volumes):

```bash
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP_DIR="backups/clickhouse-${STAMP}"
mkdir -p "$BACKUP_DIR"

for table in syslog_logs syslog_observables; do
  docker compose exec -T clickhouse clickhouse-client \
    --user demo --password "$CLICKHOUSE_PASSWORD" \
    --query "SELECT * FROM ${table} FORMAT Native" \
    > "${BACKUP_DIR}/${table}.native"
done

# Evidence schema (if initialized)
docker compose exec -T clickhouse clickhouse-client \
  --user demo --password "$CLICKHOUSE_PASSWORD" \
  --query "SHOW TABLES FROM security_evidence" 2>/dev/null || true
```

For larger deployments, use ClickHouse `BACKUP TO Disk(...)` or vendor snapshot tooling instead of full native exports.

## Optional helper script

```bash
./scripts/backup-stack.sh
```

## Restore PostgreSQL

**Warning:** restore overwrites the current database.

```bash
cd /opt/demo-runbook
docker compose stop backend integration-worker integration-scheduler signal-worker \
  ioc-correlation-worker ioc-retro-worker ioc-expiration-worker ioc-match-count-worker \
  llm-risk-worker syslog-receiver

DUMP=backups/postgres-demo-YYYYMMDDTHHMMSSZ.dump

docker compose exec -T db pg_restore -U demo -d demo --clean --if-exists < "$DUMP"

docker compose run --rm backend npm run migrate
docker compose up -d backend integration-worker integration-scheduler
```

## Restore ClickHouse

```bash
docker compose stop syslog-receiver ioc-correlation-worker ioc-retro-worker

BACKUP_DIR=backups/clickhouse-YYYYMMDDTHHMMSSZ

docker compose exec -T clickhouse clickhouse-client \
  --user demo --password "$CLICKHOUSE_PASSWORD" \
  --query "TRUNCATE TABLE syslog_logs"

docker compose exec -T clickhouse clickhouse-client \
  --user demo --password "$CLICKHOUSE_PASSWORD" \
  --query "INSERT INTO syslog_logs FORMAT Native" \
  < "${BACKUP_DIR}/syslog_logs.native"

docker compose up -d syslog-receiver ioc-correlation-worker ioc-retro-worker
```

Repeat for other exported tables as needed.

## Post-restore verification

1. **Health**
   ```bash
   curl -s http://localhost:3000/readyz | jq .
   ```
   Expect `"status":"ok"` and postgres/redis/clickhouse checks ok.

2. **Migrations**
   ```bash
   docker compose run --rm backend npm run migrate:list
   ```

3. **Login** — use a DB user (not env bootstrap unless configured for dev).

4. **IOC sample** — open IOC list in UI or:
   ```bash
   curl -s -b cookies.txt http://localhost:3000/api/ioc/list?page=1&page_size=5
   ```

5. **Integration queue** — open **Threat Intelligence → Job Queue Status**, click **Recover Queue** if `recovery_needed` is true.

6. **Audit** — confirm recent rows in **Administration → Audit Logs**.

## RPO / RTO guidance (demo / pilot)

| Metric | Practical target |
|--------|------------------|
| **RPO** | 24h (daily backup) or 1h (automated cron) |
| **RTO** | 1–2h manual restore on single VM |

Automate `pg_dump` via cron or your orchestrator. Test restore quarterly.

## Disaster recovery (single VM)

1. Provision replacement VM with Docker Compose
2. Clone repo at known git tag
3. Restore `.env` from secret store
4. Restore Postgres + ClickHouse dumps
5. `docker compose up -d` per `docs/deployment.md`
6. Run verification steps above
