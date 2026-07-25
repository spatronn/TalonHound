-- Action Center / IOC search-export retention indexes.
--
-- File artifacts already expire via expires_at (ready -> expired). Terminal metadata
-- rows (expired / failed / cancelled) are hard-deleted by the ioc-search-export worker
-- after IOC_EXPORT_METADATA_RETENTION_DAYS (default 7). This index keeps that sweep
-- cheap as the table grows. Also helps Action Center status filters.

CREATE INDEX IF NOT EXISTS idx_ioc_search_exports_metadata_cleanup
  ON ioc_search_exports (status, updated_at)
  WHERE status IN ('expired', 'failed', 'cancelled');

CREATE INDEX IF NOT EXISTS idx_ioc_search_exports_status_created
  ON ioc_search_exports (status, created_at DESC);

-- DEPLOYMENT / ROLLBACK
-- ---------------------
-- Forward: additive indexes only. Safe to apply online; no table rewrite, no data change.
-- The migrate runner wraps each file in a transaction; plain CREATE INDEX is fine here
-- (table remains modest; CONCURRENTLY is intentionally avoided so the transaction works).
--
-- Rollback:
--   DROP INDEX IF EXISTS idx_ioc_search_exports_metadata_cleanup;
--   DROP INDEX IF EXISTS idx_ioc_search_exports_status_created;
