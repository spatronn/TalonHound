# demo-integration

Queue + worker based hourly import service.

## Components

- `scheduler.js`: registers repeatable `hourly-import` job (default `0 * * * *`)
- `worker.js`: consumes queue jobs and runs ET blockrules import
- `importer.js`: import logic, DB lock, run logs, checkpoint + dedup

## Env vars

- `REDIS_URL` (default: `redis://redis:6379`)
- `QUEUE_NAME` (default: `integration-imports`)
- `SCHEDULER_CRON` (default: `0 * * * *`)
- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`
- `SOURCE_NAME` (default: `EmergingThreats:blockrules`)
- `SOURCE_INDEX_URL` (default: ET blockrules index)
