-- 051_threat_report_catalog_keyset_index.sql
--
-- Keyset index for the read-only Threat Library report catalog
-- (lib/threatLibrary/reportCatalog.js, MCP threat_library_list_reports).
-- The catalog pages active reports by import time with an id tie-breaker:
-- ORDER BY created_at, id (either direction) and
-- WHERE (created_at, id) < / > (cursor). idx_threat_reports_created_at
-- (created_at DESC) has no id column, so equal timestamps needed a sort.
--
-- Additive only: one partial index, no data change.

CREATE INDEX IF NOT EXISTS idx_threat_reports_catalog_imported
    ON public.threat_reports (created_at, id)
    WHERE deleted_at IS NULL;
