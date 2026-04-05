-- Hot IOC list (match_count > 0): list + time-window filters + sort by last_seen_log
CREATE INDEX IF NOT EXISTS idx_ioc_items_match_count ON ioc_items (match_count);

CREATE INDEX IF NOT EXISTS idx_ioc_items_last_seen ON ioc_items (last_seen_log DESC NULLS LAST);

CREATE INDEX IF NOT EXISTS idx_ioc_items_hot_partial
  ON ioc_items (last_seen_log DESC NULLS LAST, match_count DESC)
  WHERE match_count > 0;

ANALYZE ioc_items;
