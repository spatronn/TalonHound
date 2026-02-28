# demo-integration

Queue + worker based hourly import service.

Current source policy: import `.rules` and `.txt`, but skip `*.suricata.rules` to reduce duplicate data.
USOM policy: import indicators from `https://www.usom.gov.tr/url-list.txt` into unified `ioc_items` table.
USOM optimization: source hash + diff ingest (`integration_source_state`) — unchanged feed is skipped, changed feed ingests only newly added indicators.

## Components

- `scheduler.js`: registers repeatable `hourly-import` and `usom-import` jobs (default `0 * * * *`)
- `worker.js`: consumes queue jobs and runs ET blockrules + USOM TR-CERT imports
- `importer.js`: import logic, DB lock, run logs, checkpoint + dedup

## Env vars

- `REDIS_URL` (default: `redis://redis:6379`)
- `QUEUE_NAME` (default: `integration-imports`)
- `SCHEDULER_CRON` (default: `0 * * * *`)
- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`
- `SOURCE_NAME` (default: `EmergingThreats:blockrules`)
- `SOURCE_INDEX_URL` (default: ET blockrules index)
