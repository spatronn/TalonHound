-- Scale-oriented indexes for ~20M ioc_items and related queries.
-- Run after migrations 001–020. Safe to run on existing DB (IF NOT EXISTS).

-- 1) Geo cache: ASN filter on list (asn/country filter joins on this)
CREATE INDEX IF NOT EXISTS idx_ioc_ip_geo_cache_asn
ON ioc_ip_geo_cache (asn)
WHERE asn IS NOT NULL;

-- 2) IP-only observables: smaller index for geo refresh and IP lookups
CREATE INDEX IF NOT EXISTS idx_ioc_items_observable_where_ip
ON ioc_items (observable)
WHERE observable_type = 'ip';

-- 3) List default path: covering index for "ORDER BY created_at DESC LIMIT N"
--    (Index Only Scan possible; avoids heap fetch for list payload)
CREATE INDEX IF NOT EXISTS idx_ioc_items_created_at_desc_covering
ON ioc_items (created_at DESC)
INCLUDE (id, public_id, observable, observable_type, source_name, confidence, category);

-- 4) Filtered list: composite indexes for common filters (source / confidence)
--    Use with created_at range in app to avoid full scan at 20M.
CREATE INDEX IF NOT EXISTS idx_ioc_items_source_created_at_desc
ON ioc_items (source_name, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ioc_items_confidence_created_at_desc
ON ioc_items (confidence, created_at DESC);

-- 5) Planner statistics (better cardinality estimates for 20M rows)
ALTER TABLE ioc_items ALTER COLUMN observable SET STATISTICS 500;
ALTER TABLE ioc_items ALTER COLUMN source_name SET STATISTICS 500;
ALTER TABLE ioc_items ALTER COLUMN created_at SET STATISTICS 500;

-- Run ANALYZE after migration so planner picks new stats
ANALYZE ioc_items;
ANALYZE ioc_ip_geo_cache;
