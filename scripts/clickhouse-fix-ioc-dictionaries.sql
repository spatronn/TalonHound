-- Apply on running ClickHouse to stop high network input from too-frequent PostgreSQL dictionary reloads.
-- Usage:
--   docker compose exec clickhouse clickhouse-client -u demo --password "$CLICKHOUSE_PASSWORD" --multiquery < /opt/demo-runbook/scripts/clickhouse-fix-ioc-dictionaries.sql

-- 1) Inspect current dictionaries
SELECT
  database,
  name,
  status,
  origin,
  type,
  key.names AS key_columns,
  loading_start_time,
  last_successful_update_time,
  bytes_allocated,
  query_count,
  hit_rate
FROM system.dictionaries
WHERE database = 'default' AND name IN ('ioc_domain_dict', 'ioc_ip_dict');

-- 2) Production-safe lifetime to reduce PostgreSQL polling/reloads
ALTER DICTIONARY default.ioc_domain_dict MODIFY LIFETIME(MIN 300 MAX 600);
ALTER DICTIONARY default.ioc_ip_dict MODIFY LIFETIME(MIN 300 MAX 600);

-- 3) Reload once after applying new lifetime
SYSTEM RELOAD DICTIONARY default.ioc_domain_dict;
SYSTEM RELOAD DICTIONARY default.ioc_ip_dict;

-- 4) Verify effective config and update times
SELECT
  database,
  name,
  lifetime_min,
  lifetime_max,
  loading_start_time,
  last_successful_update_time,
  loading_duration
FROM system.dictionaries
WHERE database = 'default' AND name IN ('ioc_domain_dict', 'ioc_ip_dict');
