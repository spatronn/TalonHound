#!/usr/bin/env bash
# Micro-benchmark USOM refreshGlobalIocStatus plan on production (read-only rollback).
set -euo pipefail
cd /opt/TalonHound
SAMPLE="${1:-5000}"

docker compose exec -T db psql -U talonhound -d talonhound <<SQL
BEGIN;
SET LOCAL statement_timeout = '120s';

DROP TABLE IF EXISTS usom_import_stage;
CREATE TEMP TABLE usom_import_stage (
  observable_type TEXT NOT NULL,
  observable TEXT NOT NULL,
  category TEXT NULL,
  note TEXT NULL,
  provider_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  provider_fingerprint TEXT NOT NULL,
  provider_record_timestamp TIMESTAMPTZ NULL,
  provider_record_id TEXT NULL,
  PRIMARY KEY (observable_type, observable)
) ON COMMIT DROP;

INSERT INTO usom_import_stage (observable_type, observable, provider_fingerprint)
SELECT observable_type, observable, 'bench-fp'
FROM (
  SELECT observable_type, observable
  FROM ioc_items
  WHERE observable_type IN ('domain', 'url', 'ip', 'ipv6')
  ORDER BY id DESC
  LIMIT ${SAMPLE}
) s;

CREATE TEMP TABLE usom_stage_canonical ON COMMIT DROP AS
SELECT DISTINCT ON (s.observable_type, s.observable)
       s.observable_type, s.observable, s.provider_fingerprint,
       i.id AS ioc_item_id, i.public_id
  FROM usom_import_stage s
  LEFT JOIN ioc_items i
    ON i.observable = s.observable AND i.observable_type = s.observable_type
 ORDER BY s.observable_type, s.observable, i.created_at ASC NULLS LAST, i.id ASC NULLS LAST;

SELECT 'stage_rows=' || COUNT(*)::text FROM usom_import_stage;
SELECT 'canonical_rows=' || COUNT(*)::text FROM usom_stage_canonical;

EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
WITH touched AS (
  SELECT observable_type, observable FROM usom_stage_canonical
),
membership_state AS (
  SELECT t.observable_type, t.observable,
         COUNT(m.id) FILTER (WHERE m.status = 'active' AND m.purged_at IS NULL) > 0 AS has_active_membership,
         MIN(m.expires_at) FILTER (
           WHERE m.status = 'active' AND m.purged_at IS NULL AND m.expires_at IS NOT NULL
         ) AS next_expires_at
  FROM touched t
  JOIN ioc_items i ON i.observable = t.observable AND i.observable_type = t.observable_type
  LEFT JOIN ioc_feed_memberships m
    ON m.ioc_item_id = i.id AND m.ioc_observable_type = i.observable_type
  GROUP BY t.observable_type, t.observable
)
SELECT COUNT(*) FROM membership_state;

ROLLBACK;
SQL

echo "=== watermark plan (domain) ==="
docker compose exec -T db psql -U talonhound -d talonhound <<'SQL'
EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
SELECT id AS max_id, COALESCE(last_seen_log, last_seen_at, created_at) AS max_ts
FROM ioc_domain
WHERE COALESCE(status, 'active') = 'active' AND observable_type = 'domain'
ORDER BY id DESC
LIMIT 1;
SQL
