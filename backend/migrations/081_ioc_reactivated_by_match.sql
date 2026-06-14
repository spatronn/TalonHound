ALTER TABLE ioc_items
  ADD COLUMN IF NOT EXISTS reactivated_by_match_at TIMESTAMPTZ NULL;

CREATE INDEX IF NOT EXISTS idx_ioc_items_reactivated_by_match_at
  ON ioc_items (reactivated_by_match_at DESC)
  WHERE reactivated_by_match_at IS NOT NULL;
