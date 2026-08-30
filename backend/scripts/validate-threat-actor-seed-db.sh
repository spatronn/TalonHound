#!/usr/bin/env bash
set -euo pipefail

DB_NAME="${DB_NAME:-talonhound_seed_test}"
PSQL=(docker compose exec -T db psql -U talonhound -d "$DB_NAME" -t -A)

echo "=== Threat actor seed validation: $DB_NAME ==="

total="$("${PSQL[@]}" -c 'SELECT COUNT(*) FROM threat_actors;')"
active="$("${PSQL[@]}" -c 'SELECT COUNT(*) FROM threat_actors WHERE active IS TRUE;')"
inactive="$("${PSQL[@]}" -c 'SELECT COUNT(*) FROM threat_actors WHERE active IS NOT TRUE;')"
dup_names="$("${PSQL[@]}" -c 'SELECT COUNT(*) FROM (SELECT lower(name) FROM threat_actors GROUP BY lower(name) HAVING COUNT(*) > 1) s;')"
dup_slugs="$("${PSQL[@]}" -c 'SELECT COUNT(*) FROM (SELECT slug FROM threat_actors GROUP BY slug HAVING COUNT(*) > 1) s;')"

echo "total=$total active=$active inactive=$inactive dup_names=$dup_names dup_slugs=$dup_slugs"

echo
echo "=== Key actors ==="
docker compose exec -T db psql -U talonhound -d "$DB_NAME" -c \
  "SELECT name, slug, active, COALESCE(cardinality(aliases), 0) AS alias_count
   FROM threat_actors
   WHERE slug IN ('unknown','apt28','apt29','lazarus','turla','apt41','sandworm','muddywater')
   ORDER BY slug;"

echo
echo "=== Lazarus rows (should be one) ==="
docker compose exec -T db psql -U talonhound -d "$DB_NAME" -c \
  "SELECT id, name, slug FROM threat_actors WHERE lower(name) LIKE '%lazarus%' ORDER BY name;"
