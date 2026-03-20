-- 1) Active CPU-heavy queries now
SELECT
  query_id,
  user,
  elapsed,
  read_rows,
  formatReadableSize(read_bytes) AS read_bytes,
  memory_usage,
  thread_ids,
  query
FROM system.processes
ORDER BY elapsed DESC
LIMIT 20;

-- 2) Last 30m expensive queries
SELECT
  event_time,
  query_duration_ms,
  read_rows,
  formatReadableSize(read_bytes) AS read_bytes,
  result_rows,
  memory_usage,
  query
FROM system.query_log
WHERE event_time >= now() - INTERVAL 30 MINUTE
  AND type = 'QueryFinish'
ORDER BY query_duration_ms DESC
LIMIT 50;

-- 3) Parts pressure (too many active parts can increase CPU)
SELECT
  table,
  countIf(active) AS active_parts,
  sumIf(rows, active) AS active_rows,
  formatReadableSize(sumIf(bytes_on_disk, active)) AS active_size
FROM system.parts
WHERE database = currentDatabase()
GROUP BY table
ORDER BY active_parts DESC;

-- 4) Runtime guardrails for demo user (persistent user-level settings)
ALTER USER demo SETTINGS
  max_threads = 6,
  max_execution_time = 30,
  max_bytes_before_external_group_by = 268435456,
  max_bytes_before_external_sort = 268435456;

-- 5) Verify user settings
SELECT
  name,
  value,
  changed
FROM system.settings
WHERE name IN ('max_threads', 'max_execution_time', 'max_bytes_before_external_group_by', 'max_bytes_before_external_sort')
ORDER BY name;
