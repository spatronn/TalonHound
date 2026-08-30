# Backup and restore runbook

TalonHound system backups cover **PostgreSQL** (transaction-consistent `pg_dump -Fc`) with manifest + SHA-256 verification, Admin UI management, scheduled retention, and host CLI restore via `scripts/restore-stack.sh` (drops and recreates the target database).

## Product decision

- **Backup** operations (create, verify, download, delete, schedule, retention) are managed from **Administration → Backup & Restore**.
- **Restore** runs only through the host CLI (`scripts/restore-stack.sh`).
- There is no restore feature in the GUI: restore requires host privileges outside the live API process, and the UI may be unavailable during disaster recovery.
- The API does not execute `pg_restore`.

## What is backed up

| Component | Included | Notes |
|-----------|----------|-------|
| PostgreSQL (`postgres_data`) | **Yes** | IOCs, feeds, memberships, custom threat feeds, suppressions, tags, enrichments, users/RBAC, audit logs, scheduler/config, `schema_migrations` |
| Persistent user uploads | N/A | No upload volume in this deployment |
| Redis | **No** | Ephemeral BullMQ/cache — reconcile queues after restore |
| `.env` / secret files | **No** | Store separately; not included in the archive |
| TLS certs (`proxy/certs`) | **No** | Manual / externally managed |
| IOC search export CSVs | **No** | Regenerable (`ioc_export_data`) |
| ClickHouse | **No** | Not used in this project |
| node_modules / frontend build / images / logs / source | **No** | Not application data |

**Sensitive data:** Feed credentials and enrichment API keys stored in PostgreSQL are included in the dump (currently plaintext columns). Archives contain secret material; `BACKUP_ENCRYPTION_ENABLED=true` is supported for AES-256-GCM envelope encryption.

**Secrets outside the archive:**

- `.env` is **not** inside the backup archive.
- The backup encryption key is **not** inside the archive.
- Encrypted backups require the same key on the restore host; without it they cannot be restored.
- Keep offsite copies of archives and keys on separate media.

## Archive layout (format version 2)

```text
backup-YYYYMMDD-HHMMSS-<id>.tar.gz          # or .tar.gz.enc when encrypted
  backup-YYYYMMDD-HHMMSS-<id>/
    manifest.json
    database/postgres.dump
    checksums.sha256
    README.txt
```

Archives are written atomically (temp → rename). Incomplete files do not use the final name.

Legacy Faz-1 directories (`talonhound-*/postgres.dump`) remain readable by `scripts/restore-stack.sh`.

Restore does **not** require a `system_backups` database registry row. An external archive can be restored with `--file` using only the archive’s own manifest and checksums.

## Storage

- Docker named volume: `backup_data` → `/data/backups` (separate from `postgres_data`)
- Env: `BACKUP_DIR=/data/backups`
- Provider: local filesystem (`LocalFilesystemStorage`). S3-compatible storage is not shipped (interface reserved for a later release).

Offsite copies (USB, remote host, object storage) are independent of the on-host `backup_data` volume.

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
| `BACKUP_STALE_JOB_TIMEOUT_MINUTES` | `60` | Interrupt queued/running/verifying with no progress |
| `BACKUP_ORPHAN_QUEUED_MINUTES` | `5` | Fail `queued` rows that did not receive a BullMQ `job_id` |

### Default product schedule

- Cron: **Sunday 00:00**
- Timezone: **UTC** (when `BACKUP_CRON_TIMEZONE` is unset)
- In Europe/Istanbul (EEST, UTC+3) that is **Sunday 03:00** local time
- The Admin UI shows the cron summary in the schedule timezone and, when your user timezone differs, the next fire in your timezone

To run wall-clock Sunday 03:00 in Istanbul instead:

```bash
BACKUP_CRON=0 3 * * 0
BACKUP_CRON_TIMEZONE=Europe/Istanbul
```

Scheduled backups are enqueued by the **`backup-worker`** process (30s ticker), not by the API container. Both `backend` and `backup-worker` must share the same Redis and `BACKUP_QUEUE_NAME` (`system-backup`).

Weekly default implies a worst-case **RPO of about 7 days**.

Retention does not delete active (`queued`/`running`/`verifying`) backups. Deletion is audited.

### Troubleshooting a stuck `queued` backup

Symptoms: History shows `queued`, size `0 B`, Create Backup disabled / “Backup running…”, worker may log enqueue errors.

1. Confirm `backup-worker` is up: `docker compose ps backup-worker`
2. Read logs: `docker compose logs --since 2h backup-worker`
3. Look for `Custom Id cannot contain :`, `ENQUEUE_FAILED`, or `schedule tick failed`
4. Confirm Redis queue (auth from `.env`): waiting/active lists for `bull:system-backup:*`
5. DB check:

```sql
SELECT backup_id, status, created_at, started_at, job_id, error_code
FROM system_backups
WHERE status IN ('queued', 'running', 'verifying')
ORDER BY created_at DESC;
```

6. If `status=queued` and `job_id IS NULL` for more than a few minutes, the row is an orphan (enqueue did not succeed). After deploying the colon-safe jobId fix, wait for the worker reconciler (`BACKUP_ORPHAN_QUEUED_MINUTES`, default 5) or mark failed:

```sql
UPDATE system_backups
SET status = 'failed',
    error_code = 'ENQUEUE_FAILED',
    error_message = 'BullMQ custom jobId contained colon (scheduled-*-T*:*); enqueue never succeeded',
    updated_at = NOW()
WHERE backup_id = '<backup_id>'
  AND status = 'queued'
  AND job_id IS NULL;
```

7. Restart worker after fixing code: `docker compose up -d --force-recreate backup-worker`
8. Create a manual backup from the UI to verify the pipeline.

## Encryption

1. Generate a key: `openssl rand -hex 32 > /secure/backup.key`
2. Mount the key into `backend` and `backup-worker` (read-only).
3. Set `BACKUP_ENCRYPTION_ENABLED=true` and `BACKUP_ENCRYPTION_KEY_FILE=/path/to/key`.
4. Keep the key off the backup volume and out of git. Restore requires the same key on the target host.

## Manual backup (Admin UI)

1. Sign in as **admin**.
2. Open **Administration → Backup & Restore**.
3. Click **Create Backup** (disabled while another backup runs).
4. Wait until status is `completed` and verify status is `passed`.
5. Use **Download**, **Verify**, **Details**, or **Delete** as needed.

## CLI backup helpers

```bash
# Inside backup-worker / backend container
docker compose exec backup-worker npm run backup:create
docker compose exec backup-worker npm run backup:list
docker compose exec backup-worker npm run backup:verify -- --backup-id <id>
docker compose exec backup-worker npm run backup:retention

# Host backup script
./scripts/backup-stack.sh
```

`npm run backup:restore -- --backup-id <id> --confirm` only **prints** the host command; it does **not** execute `pg_restore`.

## Scenario A — Restore on a running system

Use this when the Compose stack is healthy enough to stop writers and overwrite PostgreSQL in place.

**Access required**

- SSH / shell on the Docker Compose host
- Ability to run `docker compose`
- Encryption key file mounted/available if the archive is encrypted

**Steps**

1. Verify the chosen backup in the UI (or CLI verify) before restore.
2. Preview without mutating:

   ```bash
   ./scripts/restore-stack.sh --backup-id backup-YYYYMMDD-HHMMSS-hex --dry-run
   # or
   ./scripts/restore-stack.sh --file /path/to/archive.tar.gz --dry-run
   ```

3. Execute (writers are stopped for the duration):

   ```bash
   ./scripts/restore-stack.sh --backup-id backup-YYYYMMDD-HHMMSS-hex --confirm
   ```

4. The script:
   - resolves and validates the archive (manifest, checksums, dump readability; rejects unsafe tar members)
   - takes a pre-restore dump of the live DB when the target looks populated (skipped on empty/fresh DB; override with `--skip-safety`)
   - stops writer services
   - **drops and recreates** the target PostgreSQL database (`DROP DATABASE … WITH (FORCE)` then `CREATE DATABASE`)
   - runs `pg_restore` into the fresh database (**without** `--clean`)
   - runs `npm run migrate` (forward-only)
   - starts services again

   **Note:** `pg_restore --clean` is **not** used. TalonHound’s IOC schema uses declarative partitioning under `ioc_items`; `--clean` fails when dropping inherited partition primary keys.

   **Implementation:** Host-side dumps are copied into the `db` container with `docker compose cp` and restored from a file path. `docker compose exec … pg_restore -` does not reliably receive stdin on all hosts.
5. Healthcheck:

   ```bash
   docker compose exec backend wget -qO- http://127.0.0.1:3000/readyz
   docker compose run --rm backend npm run migrate:list
   ```

6. Confirm login, IOC list, feeds, suppressions, and audit logs. Redis queues are **not** restored — reconcile Job Queue Status if needed.

**Flags**

| Flag | Meaning |
|------|---------|
| `--file <path>` | Preferred for external archives (no DB registry required) |
| `--backup-id <id>` | Resolve from backup volume / `backups/` |
| `--backup <path>` | Legacy alias for `--file` |
| `--dry-run` | Validate + print plan only |
| `--confirm` | Required to mutate |
| `--skip-checksum` | Skip `checksums.sha256` check |
| `--skip-safety` | Skip live-DB pre-restore dump even if populated |

Missing `--confirm` aborts without changes.

## Scenario B — Full disaster recovery (new server)

1. Prepare the TalonHound repository / deployment bundle on the new host (Docker + Compose).
2. Create `.env` on the new host (it is **not** in the backup archive).
3. Install the backup encryption key on the new host if archives are encrypted (key is **not** in the archive).
4. Bring up PostgreSQL and base services (`docker compose up -d db redis` creates volumes).
5. Copy the external archive onto the host, for example:

   ```bash
   cp /mnt/usb/talonhound-backup-20260725.tar.gz /opt/TalonHound/backups/
   ```

6. Dry-run, then restore by file (no backup registry required):

   ```bash
   ./scripts/restore-stack.sh \
     --file /opt/TalonHound/backups/talonhound-backup-20260725.tar.gz \
     --dry-run

   ./scripts/restore-stack.sh \
     --file /opt/TalonHound/backups/talonhound-backup-20260725.tar.gz \
     --confirm
   ```

7. Archive is validated (manifest when present, checksums, path-safe extract into staging).
8. PostgreSQL is restored; migrations run.
9. Start the full stack: `docker compose up -d`.
10. Healthcheck: `docker compose exec backend wget -qO- http://127.0.0.1:3000/readyz`.
11. Verify sample IOC, feed, user, suppression, and audit records.
12. Reconcile integration queues if the UI reports recovery needed.

On an empty database, the script skips the pre-restore dump and logs that decision. On a populated database, the pre-restore dump runs unless `--skip-safety` is passed.

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
| RPO | ~7 days with default weekly Sunday cron (tighten via `BACKUP_CRON`) |
| RTO | 1–2h typical manual restore on a single VM |

Validation scripts:

- `./scripts/test-backup-restore-e2e.sh` (disposable DB)
- `./scripts/test-backup-restore-partition.sh` (partition-aware restore against compose or CI Postgres)
- Full stack restore: `./scripts/restore-stack.sh --file … --confirm`

## API (admin only)

| Method | Path |
|--------|------|
| GET | `/api/backups/status` |
| GET | `/api/backups` |
| POST | `/api/backups` |
| POST | `/api/backups/:id/verify` |
| GET | `/api/backups/:id/download` |
| DELETE | `/api/backups/:id` |

Mutating backup routes are audited (`backup.*` actions). Historical `restore.*` audit labels may still appear in old logs; the GUI prepare/confirm flow that emitted them has been removed.
