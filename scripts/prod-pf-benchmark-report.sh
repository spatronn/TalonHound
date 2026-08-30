#!/usr/bin/env bash
set -euo pipefail
cd /opt/TalonHound

echo "=== benchmark delta (manual) ==="
python3 <<'PY'
r0,r1,w0,w1,sec=11146530816,22728622080,4435357696,5954351104,3600
hr=3600/sec
dr,dw=max(r1-r0,0),max(w1-w0,0)
print(f"interval_sec={sec}")
print(f"read_GB_h={dr/1e9*hr:.3f}")
print(f"write_GB_h={dw/1e9*hr:.3f}")
print(f"rios_delta=1221816-789562={1221816-789562}")
print(f"wios_delta=33682-16665={33682-16665}")
PY

echo "=== feed state ==="
docker compose exec -T db psql -U talonhound -d talonhound <<'SQL'
SELECT id, name, last_refresh_mode, last_refresh_ms, last_changed_count,
       reconciliation_slice, COALESCE(reconciliation_cursor,'') AS cursor
FROM published_feeds WHERE id IN (11,12,14,15);
SELECT feed_id, window_name, generation_id, chunk_count, status, item_count
FROM published_feed_chunk_generations WHERE feed_id=11 ORDER BY created_at DESC LIMIT 1;
SQL

echo "=== refresh logs (backend, last 70m) ==="
docker compose logs backend --since=70m 2>/dev/null | grep 'published feed' | tail -30 || true

echo "=== reconciliation logs ==="
docker compose logs backend --since=70m 2>/dev/null | grep reconciliation | tail -15 || true
