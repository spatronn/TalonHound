# TalonHound Integration

Queue + worker based hourly import service.

Current source policy: import `.rules` and `.txt`, but skip `*.suricata.rules` to reduce duplicate data.

## Feed policies

| Feed | Source | Update mode | Notes |
|------|--------|-------------|-------|
| ET blockrules | Emerging Threats index | incremental | Batch IP insert |
| Siber Güvenlik Başkanlığı / USOM | Official paginated JSON API | **incremental + reconciliation** | Per-type cursors with overlap; staged, atomic full reconciliation |
| ThreatFox | Full CSV export | **snapshot** | Hash diff for inserts; membership sync every run |
| URLhaus | Auth-Key **`recent.csv`** API export | **incremental** | Per-row upsert + membership; no snapshot finalization |
| MalwareBazaar | Auth-Key **`recent.csv`** API export | **incremental** | Per-row upsert + membership; no snapshot finalization |
| PhishTank | `online-valid.csv` (full list) | incremental | Hash diff for inserts only |

USOM uses the stable source identity `USOM:TR-CERT`. Incremental runs use per-type
timestamp/provider-ID highwaters, a 24-hour inclusive overlap, and a fixed run-start upper bound.
They only merge seen records and never mark absent memberships missing. A missing cursor set
returns `bootstrap_required`; an explicit successful `full_reconciliation` is required to create
the initial cursors. Full runs alone reconcile absences and refresh all non-empty type cursors.
Data, cursor/state, and the successful integration-run metrics commit in
one transaction. Lookup failures use a durable 24-hour cache when available and otherwise retain
the provider's raw codes.

URLhaus/MalwareBazaar use incremental mode because `recent.csv` is not a complete feed snapshot — running snapshot finalization would falsely expire most memberships.

## Components

- `scheduler.js`: registers repeatable feed jobs (default `0 * * * *`)
- `worker.js`: consumes queue jobs and runs ET + USOM + URLhaus + ThreatFox + MalwareBazaar + PhishTank imports
- `importer.js`: import logic, DB lock, run logs, checkpoint + dedup

## Env vars

- `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD` (URL built in code; password URL-encoded). Optional legacy `REDIS_URL` if set.
- `QUEUE_NAME` (default: `integration-imports`)
- `SCHEDULER_CRON` (default: `0 * * * *`)
- `INTEGRATION_JOB_TIMEOUT_MS` — cooperative job timeout in worker (per-feed overrides: `THREATFOX_JOB_TIMEOUT_MS`, etc.)
- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`
- `SOURCE_NAME` (default: `EmergingThreats:blockrules`)
- `SOURCE_INDEX_URL` (default: ET blockrules index)
- `USOM_API_BASE_URL` (default: `https://siberguvenlik.gov.tr/api`)
- `USOM_API_PER_PAGE` (default: `5000`; verified against the official API)
- `USOM_API_TIMEOUT_MS` (default: `30000`)
- `USOM_API_MAX_RETRIES` (default: `5`)
- `USOM_API_REQUEST_DELAY_MS` (default: `250`)
- `USOM_IMPORT_MODE` (`incremental` by default; `full_reconciliation` for an explicit full run)
- `USOM_INCREMENTAL_ENABLED` (default: `true`)
- `USOM_INCREMENTAL_OVERLAP_HOURS` (default: `24`)
- `USOM_INCREMENTAL_MAX_RECORDS` (default: `100000`; filter-ignored safety limit)
- `USOM_FULL_RECONCILIATION_ENABLED` (default: `true`)
- `USOM_FULL_RECONCILIATION_CRON` (default: `0 3 * * 0`)
- `USOM_FULL_RECONCILIATION_TIMEZONE` (default: `Europe/Istanbul`)
- `USOM_FULL_RECONCILIATION_MAX_AGE_DAYS` (default: `8`)
- `USOM_LOOKUP_CACHE_TTL_HOURS` (default: `24`)
- `USOM_JOB_TIMEOUT_MS` (recommended: `7200000` for a complete snapshot)
- `USOM_DB_STATEMENT_TIMEOUT_MS` (default: `1800000`; applies only to the final USOM transaction)
- `USOM_DB_IDLE_IN_TX_TIMEOUT_MS` (default: `600000`; applies only to the final USOM transaction)

Read-only API checks (no database writes):

- `npm run dry-run:usom` — one small page per IOC/lookup type
- `npm run dry-run:usom -- --full` — full reconciliation simulation with canonical snapshot hash
- `npm run dry-run:usom -- --incremental [--cursor=<ISO timestamp>]` — incremental simulation
  (defaults the cursor to dry-run start); both modes emit cursor/query metrics and never write the database
