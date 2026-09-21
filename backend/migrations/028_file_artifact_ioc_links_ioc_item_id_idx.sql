-- Page-scoped artifact alias expansion looks up links by ioc_item_id for a
-- small seed set (list page ids). The existing UNIQUE (observable_type, ioc_item_id)
-- cannot serve ioc_item_id-only predicates, so the planner seq-scanned
-- file_artifact_ioc_links (~1.2M rows) on every list request.
--
-- Idempotent: CREATE INDEX IF NOT EXISTS.

CREATE INDEX IF NOT EXISTS idx_file_artifact_ioc_links_ioc_item_id
  ON file_artifact_ioc_links (ioc_item_id);
