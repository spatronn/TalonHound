-- CPU root-cause profiling pack for demo-clickhouse
-- Run with:
-- docker compose exec clickhouse clickhouse-client -u demo --password "$CLICKHOUSE_PASSWORD" --multiquery < /opt/demo-runbook/scripts/clickhouse-cpu-root-cause-profile.sql

-- 1) Live expensive queries
SELECT
  now() AS sampled_at,
  query_id,
  user,
  elapsed,
  read_rows,
  formatReadableSize(read_bytes) AS read_bytes,
  memory_usage,
  query
FROM system.processes
ORDER BY elapsed DESC
LIMIT 30;

-- 2) Query log by worker tag/query_id (last 30 min)
SELECT
  event_time,
  query_id,
  query_duration_ms,
  read_rows,
  formatReadableSize(read_bytes) AS read_bytes,
  result_rows,
  memory_usage,
  query
FROM system.query_log
WHERE event_time >= now() - INTERVAL 30 MINUTE
  AND type = 'QueryFinish'
  AND (
    query_id LIKE 'ioc-correlation:%'
    OR query_id LIKE 'ioc-retro:%'
    OR query LIKE '/* ioc-% */%'
  )
ORDER BY query_duration_ms DESC
LIMIT 100;

-- 3) Query thread breakdown (if enabled in config)
SELECT
  event_time,
  query_id,
  thread_id,
  ProfileEvents['UserTimeMicroseconds'] AS user_us,
  ProfileEvents['SystemTimeMicroseconds'] AS sys_us,
  read_rows,
  read_bytes
FROM system.query_thread_log
WHERE event_time >= now() - INTERVAL 30 MINUTE
  AND (
    query_id LIKE 'ioc-correlation:%'
    OR query_id LIKE 'ioc-retro:%'
  )
ORDER BY (user_us + sys_us) DESC
LIMIT 100;

-- 4) Part pressure / tiny-parts evidence
SELECT
  table,
  countIf(active) AS active_parts,
  sumIf(rows, active) AS active_rows,
  formatReadableSize(sumIf(bytes_on_disk, active)) AS active_size
FROM system.parts
WHERE database = currentDatabase()
GROUP BY table
ORDER BY active_parts DESC;

-- 5) Merge activity
SELECT
  table,
  elapsed,
  progress,
  num_parts,
  formatReadableSize(total_size_bytes_compressed) AS in_bytes,
  source_part_names,
  result_part_name
FROM system.merges
ORDER BY elapsed DESC
LIMIT 50;

-- 6) Mutation backlog
SELECT
  database,
  table,
  mutation_id,
  command,
  create_time,
  is_done,
  parts_to_do
FROM system.mutations
WHERE is_done = 0
ORDER BY create_time ASC
LIMIT 50;

-- 7) Part log (if enabled)
SELECT
  event_time,
  event_type,
  table,
  part_name,
  rows,
  formatReadableSize(bytes_compressed_on_disk) AS bytes
FROM system.part_log
WHERE event_time >= now() - INTERVAL 30 MINUTE
ORDER BY event_time DESC
LIMIT 200;

-- 8) Key metrics snapshot
SELECT metric, value
FROM system.metrics
WHERE metric IN (
  'Query',
  'Merge',
  'BackgroundMergesAndMutationsPoolTask',
  'BackgroundFetchesPoolTask',
  'BackgroundMovePoolTask',
  'IOThreadsActive',
  'CPUUsage'
)
ORDER BY metric;

-- 9) Key profile events counters (since server start)
SELECT
  event,
  value
FROM system.events
WHERE event IN (
  'SelectedRows',
  'SelectedBytes',
  'InsertedRows',
  'InsertedBytes',
  'MergedRows',
  'MergedUncompressedBytes',
  'Merge',
  'Query',
  'OSCPUVirtualTimeMicroseconds',
  'OSCPUWaitMicroseconds'
)
ORDER BY event;
