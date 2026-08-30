#!/usr/bin/env bash
set -euo pipefail
cd /opt/TalonHound

echo "=== product version (in-container) ==="
docker compose exec -T backend node --input-type=module <<'NODE'
import { getProductVersionInfo } from './lib/productVersion.js';
console.log(JSON.stringify(getProductVersionInfo(), null, 2));
NODE

echo "=== healthz ==="
docker compose exec -T backend node -e "fetch('http://127.0.0.1:3000/healthz').then(r=>r.json()).then(j=>console.log(JSON.stringify(j)))"

echo "=== readyz status ==="
docker compose exec -T backend node -e "fetch('http://127.0.0.1:3000/readyz').then(r=>r.json()).then(j=>console.log(j.status, j.checks))"

echo "=== containers ==="
docker compose ps

echo "=== production migrate idempotency ==="
docker compose run --rm --no-deps backend npm run migrate

echo "=== migration 045 state ==="
docker compose exec -T db psql -U talonhound -d talonhound -P pager=off -c "SELECT name FROM schema_migrations WHERE name LIKE '045%' ORDER BY name;"
