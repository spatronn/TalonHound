CREATE TABLE IF NOT EXISTS syslog_logs (
  ts DateTime,
  source String,
  host String,
  program String,
  severity String,
  facility String,
  message String,
  raw String
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, host)
TTL ts + INTERVAL 30 DAY;
