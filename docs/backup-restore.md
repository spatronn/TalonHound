# Backup and restore runbook

TalonHound system backups cover **PostgreSQL** (transaction-consistent `pg_dump -Fc`) with manifest + SHA-256 verification, Admin UI management, scheduled retention, and a **host CLI-only destructive restore**.

## Product decision

- **Backup** operations (create, verify, download, delete, schedule, retention) are managed from **Administration → Backup & Restore**.
- **Restore** operations are performed **only through the host CLI** (`scripts/restore-stack.sh`).
- There is **no restore feature in the GUI**. This is intentional: real disaster recovery assumes the old UI may be unavailable, and restore must run with host privileges outside the live API process.
- The API never executes `pg_restore`.

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

**Critical secrets (not in the archive):**

- `.env` is **not** inside the backup archive.
- The backup encryption key is **not** inside the archive.
- If the encryption key is lost, encrypted backups **cannot** be restored.
- Keep offsite copies of archives **and** keys on separate media.

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

Restore does **not** require a `system_backups` database registry row. An external archive can be restored with `--file` using only the archive’s own manifest and checksums.

## Storage

- Docker named volume: `backup_data` → `/data/backups` (separate from `postgres_data`)
- Env: `BACKUP_DIR=/data/backups`
- Provider: local filesystem (`LocalFilesystemStorage`). S3-compatible storage is intentionally not shipped (interface reserved for a later release).

Store production archives **outside** the production server when possible (USB, offsite host, object storage).

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

Retention never deletes active (`queued`/`running`/`verifying`) backups. Deletion is audited.

## Encryption

1. Generate a key: `openssl rand -hex 32 > /secure/backup.key`
2. Mount the key into `backend` and `backup-worker` (read-only).
3. Set `BACKUP_ENCRYPTION_ENABLED=true` and `BACKUP_ENCRYPTION_KEY_FILE=/path/to/key`.
4. Keep the key **off** the backup volume and **out** of git. Restore requires the same key on the target host.

## Manual backup (Admin UI)

1. Sign in as **admin**.
2. Open **Administration → Backup & Restore**.
3. Click **Create Backup** (disabled while another backup runs).
4. Wait until status is `completed` and verify status is `passed`.
5. Use **Download**, **Verify**, **Details**, or **Delete** as needed.

There is no Restore button or restore modal in the UI.

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

1. Prefer verifying the chosen backup in the UI (or CLI verify) before restore.
2. Preview without mutating:

   ```bash
   ./scripts/restore-stack.sh --backup-id backup-YYYYMMDD-HHMMSS-hex --dry-run
   # or
   ./scripts/restore-stack.sh --file /path/to/archive.tar.gz --dry-run
   ```

3. Execute (expect **downtime** while writers are stopped):

   ```bash
   ./scripts/restore-stack.sh --backup-id backup-YYYYMMDD-HHMMSS-hex --confirm
   ```

4. The script:
   - resolves and validates the archive (checksums; rejects unsafe tar members)
   - takes a **safety backup** of the live DB when the target looks populated (skipped automatically on empty/fresh DB; override with `--skip-safety`)
   - stops writer services
   - runs `pg_restore --clean --if-exists`
   - runs `npm run migrate`
   - starts services again
5. Healthcheck:

   ```bash
   docker compose exec backend wget -qO- http://127.0.0.1:3000/readyz
   docker compose run --rm backend npm run migrate:list
   ```

6. Spot-check login, IOC list, feeds, suppressions, audit logs. Redis queues are **not** restored — reconcile Job Queue Status if needed.

**Flags**

| Flag | Meaning |
|------|---------|
| `--file <path>` | Preferred for external archives (no DB registry required) |
| `--backup-id <id>` | Resolve from backup volume / `backups/` |
| `--backup <path>` | Legacy alias for `--file` |
| `--dry-run` | Validate + print plan only |
| `--confirm` | Required to mutate |
| `--skip-checksum` | Skip `checksums.sha256` check |
| `--skip-safety` | Skip live-DB safety dump even if populated |

Do not invent extra bypass flags. Missing `--confirm` aborts without changes.

## Scenario B — Full disaster recovery (new server)

Typical failure mode: the old system is gone or unusable. A new host is built from scratch and an **offsite archive** is restored.

1. Prepare the TalonHound repository / deployment bundle on the new host (Docker + Compose).
2. Create `.env` securely on the new host (it is **not** in the backup archive).
3. Install the backup encryption key on the new host if archives are encrypted (key is **not** in the archive).
4. Bring up PostgreSQL and base services as needed (`docker compose up -d db redis` is enough to create volumes).
5. Copy the external archive onto the host, for example:

   ```bash
   cp /mnt/usb/talonhound-backup-20260725.tar.gz /opt/TalonHound/backups/
   ```

6. Dry-run, then restore **by file** (no backup registry required):

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

On a **new/empty** database, the script skips the safety backup automatically and logs that decision. On a **populated** database, safety backup runs unless `--skip-safety` is passed.

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

Mutating backup routes are audited (`backup.*` actions). Historical `restore.*` audit labels may still appear in old logs; the GUI prepare/confirm flow that emitted them has been removed.
