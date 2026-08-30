#!/usr/bin/env bash
set -euo pipefail

DB_NAME="${DB_NAME:-talonhound_seed_test}"

echo "=== Upgrade reconciliation validation: $DB_NAME ==="

docker compose exec -T db psql -U talonhound -d "$DB_NAME" <<'SQL'
INSERT INTO threat_actors (name, slug, aliases, description, active, created_by, updated_by)
VALUES (
  'Custom Analyst Actor',
  'custom-analyst-actor',
  ARRAY['Local Custom Alias'],
  'User-created actor for upgrade validation',
  TRUE,
  'analyst@example.com',
  'analyst@example.com'
)
ON CONFLICT DO NOTHING;

UPDATE threat_actors
SET aliases = array_append(COALESCE(aliases, ARRAY[]::text[]), 'Local APT28 Alias')
WHERE slug = 'apt28'
  AND NOT ('Local APT28 Alias' = ANY(COALESCE(aliases, ARRAY[]::text[])));
SQL

apt28_id_before="$(docker compose exec -T db psql -U talonhound -d "$DB_NAME" -t -A -c "SELECT id FROM threat_actors WHERE slug='apt28';")"
custom_id="$(docker compose exec -T db psql -U talonhound -d "$DB_NAME" -t -A -c "SELECT id FROM threat_actors WHERE slug='custom-analyst-actor';")"

echo "APT28 id before: $apt28_id_before"
echo "Custom actor id: $custom_id"

docker compose exec -T -e DB_NAME="$DB_NAME" backend npm run migrate 2>&1 | tail -12

apt28_id_after="$(docker compose exec -T db psql -U talonhound -d "$DB_NAME" -t -A -c "SELECT id FROM threat_actors WHERE slug='apt28';")"
custom_exists="$(docker compose exec -T db psql -U talonhound -d "$DB_NAME" -t -A -c "SELECT COUNT(*) FROM threat_actors WHERE id='$custom_id';")"
local_alias="$(docker compose exec -T db psql -U talonhound -d "$DB_NAME" -t -A -c "SELECT COUNT(*) FROM threat_actors WHERE slug='apt28' AND 'Local APT28 Alias' = ANY(COALESCE(aliases, ARRAY[]::text[]));")"
pawn_storm="$(docker compose exec -T db psql -U talonhound -d "$DB_NAME" -t -A -c "SELECT COUNT(*) FROM threat_actors WHERE slug='apt28' AND 'Pawn Storm' = ANY(COALESCE(aliases, ARRAY[]::text[]));")"

echo "APT28 id preserved: $([ "$apt28_id_before" = "$apt28_id_after" ] && echo yes || echo NO)"
echo "Custom actor preserved: $custom_exists"
echo "Local APT28 alias preserved: $local_alias"
echo "Bundled APT28 alias present: $pawn_storm"

docker compose exec -T -e DB_NAME="$DB_NAME" backend npm run migrate 2>&1 | tail -5
