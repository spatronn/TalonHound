-- PG supplement lookup for ioc-correlation (expired IOC fallback after CH miss).
-- Matches supplementLookupMapFromPostgres() predicate + DISTINCT ON sort (oldest created_at).
-- Partial index limits size to active/expired IOC rows used by correlation fallback.
-- Parent index propagates to ioc_items partitions (same pattern as 024/023).

CREATE INDEX IF NOT EXISTS idx_ioc_items_supplement_lookup
ON ioc_items (
  lower(observable),
  (CASE WHEN observable_type = 'hostname' THEN 'domain' ELSE observable_type END),
  created_at
)
WHERE COALESCE(status, 'active') IN ('active', 'expired');

ANALYZE ioc_items;
