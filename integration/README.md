# demo-integration

Queue + worker based hourly import service.

Current source policy: import `.rules` and `.txt`, but skip `*.suricata.rules` to reduce duplicate data.
USOM policy: import indicators from `https://www.usom.gov.tr/url-list.txt` into unified `ioc_items` table.
USOM optimization: source hash + diff ingest (`integration_source_state`) — unchanged feed is skipped, changed feed ingests only newly added indicators.
MalwareBazaar policy: import file-hash intelligence from `https://bazaar.abuse.ch/export/csv/full/` as `observable_type='sha256'` with metadata in `note`.

## Components

- `scheduler.js`: registers repeatable feed jobs (default `0 * * * *`)
- `worker.js`: consumes queue jobs and runs ET + USOM + URLhaus + ThreatFox + MalwareBazaar imports
- `importer.js`: import logic, DB lock, run logs, checkpoint + dedup

## Env vars

- `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD` (URL built in code; password URL-encoded). Optional legacy `REDIS_URL` if set.
- `QUEUE_NAME` (default: `integration-imports`)
- `SCHEDULER_CRON` (default: `0 * * * *`)
- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`
- `SOURCE_NAME` (default: `EmergingThreats:blockrules`)
- `SOURCE_INDEX_URL` (default: ET blockrules index)
