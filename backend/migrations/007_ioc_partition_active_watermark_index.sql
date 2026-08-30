-- Partial indexes for cheap published-feed IOC watermarks (max id + active count).
-- Supports ORDER BY id DESC LIMIT 1 and index-friendly active row counts per partition.

CREATE INDEX IF NOT EXISTS idx_ioc_domain_active_id
  ON ioc_domain (id DESC)
  WHERE (COALESCE(status, 'active') = 'active');

CREATE INDEX IF NOT EXISTS idx_ioc_url_active_id
  ON ioc_url (id DESC)
  WHERE (COALESCE(status, 'active') = 'active');

CREATE INDEX IF NOT EXISTS idx_ioc_ip_active_id
  ON ioc_ip (id DESC)
  WHERE (COALESCE(status, 'active') = 'active');

CREATE INDEX IF NOT EXISTS idx_ioc_ipv6_active_id
  ON ioc_ipv6 (id DESC)
  WHERE (COALESCE(status, 'active') = 'active');

CREATE INDEX IF NOT EXISTS idx_ioc_file_hash_active_id
  ON ioc_file_hash (id DESC)
  WHERE (COALESCE(status, 'active') = 'active');
