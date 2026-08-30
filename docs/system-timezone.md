# System Timezone

TalonHound uses a single **System Timezone** for the entire installation. Browser local time is not used for UI display, schedules, logs, exports, or API timestamp formatting.

## NTP and host clocks

TalonHound does not manage NTP. Host and Kubernetes node clock synchronization is an infrastructure concern; TalonHound assumes those clocks are synchronized to a reliable time source.

## Installation adoption (no silent UTC)

Migration `129_system_timezone_settings.sql` **only creates** `system_settings` columns. It does **not** invent a timezone and does **not** silently set existing installs to UTC.

Adoption decisions happen at **backend bootstrap** (`adoptSystemTimezoneFromBootstrap`), transaction-safe under an advisory lock, and idempotent.

### A. Fresh / empty install

- `initial_setup_completed = false`
- Users are forced to `/setup`
- Workers and schedulers do not start until setup completes
- A valid IANA timezone must be chosen before normal app access

### B. Existing install + valid bootstrap timezone

Checked in order:

1. `SYSTEM_TIMEZONE`
2. Canonical app schedule env previously used (`INTEGRATION_SCHEDULE_TIMEZONE`)
3. `TZ` **only** when explicitly opted in (`TALONHOUND_USE_TZ_AS_SYSTEM=1` or `APP_TIMEZONE_FROM_TZ=1`)

When a valid IANA zone is found:

- `active_system_timezone` is set to that value
- `initial_setup_completed = true`
- `adoption_source` records the bootstrap source (for example `bootstrap:SYSTEM_TIMEZONE`)
- Startup / audit logs show the adopted timezone
- **No automatic UTC fallback**

### C. Existing install + missing or invalid bootstrap timezone

- Does **not** silently choose UTC
- Sets `timezone_configuration_required = true`
- Admins are directed to setup / timezone configuration
- Existing data is not rewritten
- Background jobs that would mint new timestamps (feeds, schedulers, expiration, backup, export) stay stopped
- Non-setup / non-health / non-auth APIs return **HTTP 428** with `TIMEZONE_CONFIGURATION_REQUIRED`

Once an administrator (or initial setup) has written a timezone into the database, later env values **do not overwrite** that choice.

## Active vs pending timezone

| Field | Meaning |
|---|---|
| `active_system_timezone` | Runtime truth for formatters, API, schedulers, workers |
| `pending_system_timezone` | Requested change waiting for restart / promotion |
| `timezone_restart_required` | True while a pending change awaits healthy restart |
| `timezone_config_version` / `active_timezone_config_version` | Versioning for pending vs promoted config |

**Until promotion succeeds, the new timezone is not active.** Settings UI shows:

- Active timezone: …
- Pending timezone: … / None
- Status: Restart required | Healthy | Configuration required

Runtime uses **active** while restart is pending; active and pending are not mixed. Time-dependent management actions that would bind to a new zone wait for promotion; new schedules created before restart still use the **active** timezone.

## Initial setup

1. Open the application → redirected to `/setup` when setup or configuration is required.
2. Choose a valid **IANA** timezone (`Europe/Istanbul`, `Europe/London`, `UTC`, …). Fixed offsets such as `UTC+3` are rejected.
3. Confirm after reviewing UTC and previewed system time.
4. On success: active = chosen zone, pending = null, restart required = false.

## Changing timezone after setup

Settings → **System Timezone** → **Change System Timezone** (admin only):

1. Select the new IANA zone.
2. Type `CHANGE SYSTEM TIMEZONE` to confirm.
3. Audit records old active, new pending, admin, request time, restart-required.
4. **Active is not changed.** Pending is set; `timezone_restart_required = true`.
5. UI message: **Timezone change is pending restart** (not “changed successfully”).
6. Perform Compose recreate or Kubernetes rollout (below).
7. On healthy restart, bootstrap promotes pending → active atomically; pending cleared; restart required false.
8. If timezone health checks fail: pending is **not** promoted; restart required stays true; health is degraded and reports which component is mismatched.

### Docker Compose recreate

```bash
docker compose up -d --force-recreate \
  backend integration-scheduler integration-worker \
  ioc-expiration-worker ioc-search-export-worker ioc-deep-search-worker \
  ioc-bulk-query-worker backup-worker frontend
```

### Kubernetes rollout

```bash
kubectl rollout restart \
  deploy/backend deploy/integration-scheduler deploy/integration-worker \
  deploy/ioc-expiration-worker deploy/ioc-search-export-worker \
  deploy/ioc-deep-search-worker deploy/ioc-bulk-query-worker \
  deploy/backup-worker deploy/frontend
```

TalonHound does not auto-recreate Compose services or roll out Kubernetes; it records pending config and shows these instructions.

## Canonical source

| Layer | Source |
|---|---|
| Runtime truth | `system_settings.active_system_timezone` |
| Pending change | `pending_system_timezone` until promote |
| Env bootstrap | Only for first adoption of existing installs (see above) |
| Schedulers | Active system timezone (BullMQ `tz`, backup cron matcher) |
| PostgreSQL session | `TimeZone` GUC aligned to active (or pending-on-restart apply before promote) |
| Frontend display | Active system timezone via `formatUserDateTime` |

## Timestamp storage

All timestamp columns remain **`TIMESTAMPTZ`**. Absolute instants are preserved. Changing the system timezone only changes how those instants are **displayed**; historical rows are not rewritten.

## IOC List vs Search timestamps

IOC List **Timestamp** column = platform first-import time (`ioc_items.created_at` / API `imported_at`). Stable across re-syncs and extra feed memberships. Sorted `ORDER BY created_at DESC`.

Source-change fields (`first_seen_in_source`, `last_changed_in_source`) remain for IOC detail, DSL filters, and export — they do **not** drive the list Timestamp. Technical `last_seen_in_feed` is not shown as Timestamp.

Shared helpers: `backend/lib/iocListTimestamps.js`.

## Docker Compose example

Empty defaults avoid inventing UTC for adoption:

```yaml
services:
  backend:
    environment:
      - SYSTEM_TIMEZONE=${SYSTEM_TIMEZONE:-}
      - TZ=${TZ:-}
```

Set `SYSTEM_TIMEZONE=Europe/Istanbul` (or London, UTC, …) explicitly when bootstrapping an existing install.

## Kubernetes ConfigMap example

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: talonhound-timezone
data:
  SYSTEM_TIMEZONE: "Europe/Istanbul"
---
# envFrom:
#   - configMapRef:
#       name: talonhound-timezone
```

## Time health troubleshooting

`GET /api/system/time-health` and `/readyz` / `/health` include a `date_time` section covering active timezone, UTC/system now, PostgreSQL session timezone, and restart / configuration flags. Failed promotion leaves the system degraded until a healthy restart promotes pending successfully.
