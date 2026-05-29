# demo-integration

Queue + worker based hourly import service.

Current source policy: import `.rules` and `.txt`, but skip `*.suricata.rules` to reduce duplicate data.

## Feed policies

| Feed | Source | Update mode | Notes |
|------|--------|-------------|-------|
| ET blockrules | Emerging Threats index | incremental | Batch IP insert |
| USOM | `url-list.txt` (full list) | **snapshot** | Hash diff for inserts; membership sync every run |
| ThreatFox | Full CSV export | **snapshot** | Hash diff for inserts; membership sync every run |
| URLhaus | Auth-Key **`recent.csv`** API export | **incremental** | Per-row upsert + membership; no snapshot finalization |
| MalwareBazaar | Auth-Key **`recent.csv`** API export | **incremental** | Per-row upsert + membership; no snapshot finalization |
| PhishTank | `online-valid.csv` (full list) | incremental | Hash diff for inserts only |

USOM/ThreatFox snapshot sync refreshes `last_seen_in_feed` and detects removals even when the content hash is unchanged.

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
