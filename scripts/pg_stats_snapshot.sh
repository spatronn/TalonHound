#!/usr/bin/env bash
# Collect PostgreSQL stats snapshot for I/O benchmark attribution.
set -euo pipefail
OUT="${1:-/tmp/pg_stats_snapshot.txt}"
docker compose -f /opt/TalonHound/docker-compose.yml exec -T db psql -U talonhound -d talonhound <<'SQL' > "$OUT"
SELECT 'pg_stat_database' AS section;
SELECT datname, blks_read, blks_hit, tup_returned, tup_fetched, temp_files, temp_bytes
FROM pg_stat_database WHERE datname = current_database();
SELECT 'pg_stat_wal' AS section;
SELECT * FROM pg_stat_wal;
SELECT 'pg_stat_io' AS section;
SELECT backend_type, object, context, reads, read_time, writes, write_time
FROM pg_stat_io WHERE backend_type = 'client backend' OR object = 'relation'
ORDER BY reads DESC NULLS LAST LIMIT 20;
SQL
echo "Wrote $OUT"
