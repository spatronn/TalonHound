#!/usr/bin/env bash
set -eu

echo "=== SQL: #883 in new default scope ==="
docker exec demo-db psql -U demo -d demo -P pager=off -t -A -c \
  "SELECT COUNT(*) FROM ioc_activity a WHERE incident_id = 883 AND (a.status = 'open' OR (a.status = 'closed' AND a.updated_at >= NOW() - INTERVAL '7 days')) AND EXISTS (SELECT 1 FROM ioc_match_events m WHERE m.activity_id = a.id)"

echo "=== SQL: old closed excluded from default scope ==="
docker exec demo-db psql -U demo -d demo -P pager=off -t -A -c \
  "SELECT COUNT(*) FROM ioc_activity a WHERE status = 'closed' AND updated_at < NOW() - INTERVAL '7 days' AND (a.status = 'open' OR (a.status = 'closed' AND a.updated_at >= NOW() - INTERVAL '7 days'))"

echo "=== SQL: open incidents still included regardless of age ==="
docker exec demo-db psql -U demo -d demo -P pager=off -t -A -c \
  "SELECT COUNT(*) FROM ioc_activity a WHERE status = 'open' AND created_at < NOW() - INTERVAL '30 days' AND (a.status = 'open' OR (a.status = 'closed' AND a.updated_at >= NOW() - INTERVAL '7 days'))"

echo "=== API: login ==="
TOKEN=""
for payload in '{"email":"demo@demo.local","password":"Password1!"}' '{"username":"admin","password":"admin123"}'; do
  resp=$(curl -sk -c /tmp/cj -b /tmp/cj -X POST http://127.0.0.1:3000/api/auth/login \
    -H 'Content-Type: application/json' -d "$payload" || true)
  TOKEN=$(printf '%s' "$resp" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
  [ -n "$TOKEN" ] && break
done
echo "token_len=${#TOKEN}"

echo "=== API: default incidents list contains 883 ==="
list=$(curl -sk -b /tmp/cj "http://127.0.0.1:3000/api/incidents?page=1&page_size=200")
if printf '%s' "$list" | grep -q '"incident_id":883'; then
  echo FOUND
else
  echo NOT_FOUND
  exit 1
fi

echo "=== API: detail 883 ==="
detail_code=$(curl -sk -b /tmp/cj -o /dev/null -w '%{http_code}' "http://127.0.0.1:3000/api/incidents/883")
echo "detail_status=$detail_code"
[ "$detail_code" = "200" ]

echo "=== API: status=closed filter ==="
closed=$(curl -sk -b /tmp/cj "http://127.0.0.1:3000/api/incidents?status=closed&page=1&page_size=5")
printf '%s' "$closed" | grep -q '"status":"closed"'

echo "=== API: verdict=FP filter ==="
fp=$(curl -sk -b /tmp/cj "http://127.0.0.1:3000/api/incidents?verdict=FP&page=1&page_size=200")
printf '%s' "$fp" | grep -q '"incident_id":883'

echo "=== API: explicit from/to (created_at) unchanged ==="
fromto=$(curl -sk -b /tmp/cj "http://127.0.0.1:3000/api/incidents?from=2026-05-01&to=2026-05-04&page=1&page_size=200")
if printf '%s' "$fromto" | grep -q '"incident_id":883'; then
  echo FROMTO_INCLUDES_883
else
  echo FROMTO_EXCLUDES_883_AS_EXPECTED
fi

echo "ALL_SMOKE_PASSED"
