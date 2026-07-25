# Backup and restore runbook

TalonHound system backups cover **PostgreSQL** (transaction-consistent `pg_dump -Fc`) with manifest + SHA-256 verification, Admin UI, scheduled retention, and a **CLI-only destructive restore**.

Restore never runs `pg_restore` inside the live API process. The UI prepares/confirms a restore request and shows the exact host command.

## What is backed up

| Component | Included | Notes |
|-----------|----------|-------|
| PostgreSQL (`postgres_data`) | **Yes** | IOCs, feeds, memberships, custom threat feeds, suppressions, tags, enrichments, users/RBAC, audit logs, scheduler/config, `schema_migrations` |
| Persistent user uploads | N/A | No upload volume in this deployment |
| Redis | **No** | Ephemeral BullMQ/cache — reconcile queues after restore |
| `.env` / secret files | **No** | Store separately; never inside the archive |
| TLS certs (`proxy/certs`) | **No** | Manual / externally managed |
| IOC search export CSVs | **No** | Regenerable (`ioc_export_data`) |
| ClickHouse | **No** | Not used in this project |
| node_modules / frontend build / images / logs / source | **No** | Not application data |

**Sensitive note:** Feed credentials and enrichment API keys stored in PostgreSQL are included in the dump (currently plaintext columns). Treat backup archives like secrets. Prefer `BACKUP_ENCRYPTION_ENABLED=true`.

## Archive layout (format version 2)

```text
backup-YYYYMMDD-HHMMSS-<id>.tar.gz          # or .tar.gz.enc when encrypted
  backup-YYYYMMDD-HHMMSS-<id>/
    manifest.json
    database/postgres.dump
    checksums.sha256
    README.txt
```

Archives are written atomically (temp → rename). Incomplete files never use the final name.

Legacy Faz-1 directories (`talonhound-*/postgres.dump`) remain readable by `scripts/restore-stack.sh`.

## Storage

- Docker named volume: `backup_data` → `/data/backups` (separate from `postgres_data`)
- Env: `BACKUP_DIR=/data/backups`
- Provider: local filesystem (`LocalFilesystemStorage`). S3-compatible storage is intentionally not shipped (interface reserved for a later release).

## Schedule and retention

| Variable | Default | Meaning |
|----------|---------|---------|
| `BACKUP_ENABLED` | `true` | Enable scheduled backups |
| `BACKUP_CRON` | `0 0 * * 0` | Every Sunday at 00:00 in the schedule timezone |
| `BACKUP_CRON_TIMEZONE` | _(unset)_ | IANA zone for cron wall-clock; falls back to `INTEGRATION_SCHEDULE_TIMEZONE` (default `UTC`) |
| `BACKUP_RETENTION_DAYS` | `30` | Delete completed backups older than N days |
| `BACKUP_MAX_CONCURRENT` | `1` | Only one backup at a time |
| `BACKUP_ENCRYPTION_ENABLED` | `false` | AES-256-GCM envelope |
| `BACKUP_ENCRYPTION_KEY_FILE` | _(empty)_ | Path to 32-byte or 64-hex key file |

Cron is evaluated in the **schedule timezone** (not silently as UTC). Example override for Istanbul Sundays at midnight:

```bash
BACKUP_CRON=0 0 * * 0
BACKUP_CRON_TIMEZONE=Europe/Istanbul
```

Weekly default implies a worst-case **RPO of about 7 days**. Take a **manual backup** before important deployments or migrations.

Retention never deletes: active (`queued`/`running`/`verifying`), restore-protected, or pending-verify backups. Deletion is audited.

## Encryption

1. Generate a key: `openssl rand -hex 32 > /secure/backup.key`
2. Mount the key into `backend` and `backup-worker` (read-only).
3. Set `BACKUP_ENCRYPTION_ENABLED=true` and `BACKUP_ENCRYPTION_KEY_FILE=/path/to/key`.
4. Keep the key **off** the backup volume and **out** of git. Restore requires the same key.

## Manual backup (Admin UI)

1. Sign in as **admin**.
2. Open **Administration → Backup & Restore**.
3. Click **Create Backup** (disabled while another backup runs).
4. Wait until status is `completed` and verify status is `passed`.
5. Optionally **Download** or **Verify** again.

## CLI

```bash
# Inside backup-worker / backend container
docker compose exec backup-worker npm run backup:create
docker compose exec backup-worker npm run backup:list
docker compose exec backup-worker npm run backup:verify -- --backup-id <id>
docker compose exec backup-worker npm run backup:retention

# Host scripts
./scripts/backup-stack.sh
./scripts/restore-stack.sh --backup-id <id> --dry-run
./scripts/restore-stack.sh --backup-id <id> --confirm
```

`npm run backup:restore -- --backup-id <id> --confirm` prints the host command; it does **not** execute `pg_restore`.

## Restore flow (safe architecture)

1. Admin opens Restore on a completed backup.
2. UI calls `POST /api/backups/:id/restore/prepare` → queues a **safety** backup and creates a restore record.
3. Admin types `RESTORE` or the `backup_id` and confirms (`POST .../restore/confirm`).
4. Confirm is rejected until the safety backup is `completed` (or fails → restore aborted).
5. UI shows:

   ```bash
   ./scripts/restore-stack.sh --backup-id <id> --confirm
   ```

6. Operator runs that command on the Compose host. The script:
   - verifies checksums
   - creates another safety dump of the live DB (aborts if it fails)
   - stops writer services (backend, workers, backup-worker, …)
   - `pg_restore --clean --if-exists`
   - `npm run migrate`
   - starts services again

Expected downtime: on the order of minutes for small DBs; larger IOC datasets may need 30–120+ minutes (see RTO).

## Disaster recovery — new server

1. Provision VM with Docker + Compose; clone/deploy the TalonHound bundle.
2. Place `.env` and (if used) the backup encryption key securely on the host.
3. Create volumes (`docker compose up -d db redis` once is enough to create them).
4. Copy the chosen archive into the `backup_data` volume (or host path readable by the restore script / `docker compose cp`).
5. Start PostgreSQL: `docker compose up -d db`.
6. Verify archive: `docker compose exec backup-worker npm run backup:verify -- --backup-id <id>` (after backend image build + migrate if listing from DB) **or** extract and `sha256sum -c`.
7. Run restore: `./scripts/restore-stack.sh --backup-id <id> --confirm`.
8. Confirm migrations: `docker compose run --rm backend npm run migrate:list`.
9. Start app: `docker compose up -d`.
10. Health: `docker compose exec backend wget -qO- http://127.0.0.1:3000/readyz`.
11. Spot-check login, IOC list, feeds, audit logs; recover integration queue if needed.

## Offsite copy

```bash
# Example: copy archive out of the named volume via a helper container
docker compose run --rm -v backup_data:/data/backups alpine \
  tar -C /data/backups -cf - backup-YYYYMMDD-HHMMSS-xxxx.tar.gz \
  | ssh backup-host 'cat > /offsite/talonhound/backup-….tar.gz'
```

Keep encryption keys separate from the archive transport.

## Disk space

Keep free space ≥ **2×** the PostgreSQL data directory size (dump + safety dump + temp archive). Monitor `Administration → Backup & Restore → Storage used`.

## RPO / RTO (single VM)

| Metric | Target |
|--------|--------|
| RPO | ~7 days with default weekly Sunday cron (tighten via `BACKUP_CRON`; always take a manual backup before major changes) |
| RTO | 1–2h typical manual restore on a single VM |

Run a restore drill at least quarterly: `./scripts/test-backup-restore-e2e.sh` (disposable DB) plus a full stack restore in a staging environment.

## API (admin only)

| Method | Path |
|--------|------|
| GET | `/api/backups/status` |
| GET | `/api/backups` |
| POST | `/api/backups` |
| POST | `/api/backups/:id/verify` |
| GET | `/api/backups/:id/download` |
| DELETE | `/api/backups/:id` |
| POST | `/api/backups/:id/restore/prepare` |
| POST | `/api/backups/:id/restore/confirm` |
| GET | `/api/backups/restores/:restoreId` |

All mutating routes are audited (`backup.*` / `restore.*` actions).
