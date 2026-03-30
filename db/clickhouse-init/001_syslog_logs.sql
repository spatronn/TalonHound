CREATE TABLE IF NOT EXISTS syslog_logs (
  ts DateTime,
  ingest_time DateTime DEFAULT now(),
  source String,
  host String,
  program String,
  severity String,
  facility String,
  message String,
  raw String,
  parser_source LowCardinality(String) DEFAULT 'unknown',
  parsed_ip Nullable(String),
  parsed_query Nullable(String),
  parsed_ip_private Nullable(Bool),
  ioc_ip Nullable(String),
  ioc_query Nullable(String),
  merged_observables String DEFAULT '[]'
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, host)
TTL ts + INTERVAL 30 DAY;
