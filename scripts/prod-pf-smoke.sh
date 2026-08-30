#!/usr/bin/env bash
set -euo pipefail
cd /opt/TalonHound

echo "=== reconciliation columns ==="
docker compose exec -T db psql -U talonhound -d talonhound <<'SQL'
SELECT column_name FROM information_schema.columns
WHERE table_name='published_feeds'
  AND column_name IN ('reconciliation_slice','reconciliation_cursor')
ORDER BY 1;
SQL

echo "=== health ==="
curl -sf http://127.0.0.1:3000/healthz && echo " healthz OK" || echo " healthz FAIL"
curl -sf http://127.0.0.1:3000/readyz && echo " readyz OK" || echo " readyz FAIL"

echo "=== public feeds (Domain TXT head) ==="
curl -sfI "http://127.0.0.1:3000/api/public/feeds/domain/latest.txt" | head -5

echo "=== ETag 304 ==="
ETAG=$(curl -sfI "http://127.0.0.1:3000/api/public/feeds/domain/latest.txt" | awk -F': ' '/^[Ee]tag:/ {print $2}' | tr -d '\r')
if [ -n "$ETAG" ]; then
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "If-None-Match: $ETAG" "http://127.0.0.1:3000/api/public/feeds/domain/latest.txt")
  echo "304 response: $CODE"
fi

echo "=== URL feed ==="
curl -sfI "http://127.0.0.1:3000/api/public/feeds/url/latest.txt" | head -3

echo "=== chunk manifest feed 11 ==="
docker compose exec -T db psql -U talonhound -d talonhound -c "SELECT feed_id, window_name, generation_id, chunk_count, status FROM published_feed_chunk_generations WHERE feed_id=11 ORDER BY created_at DESC LIMIT 1;"

echo "=== reconciliation state ==="
docker compose exec -T db psql -U talonhound -d talonhound -c "SELECT id, name, reconciliation_slice, COALESCE(reconciliation_cursor,'') AS cursor, last_refresh_mode FROM published_feeds WHERE id IN (11,12,14);"
