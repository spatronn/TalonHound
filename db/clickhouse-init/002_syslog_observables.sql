CREATE TABLE IF NOT EXISTS syslog_observables (
  ts DateTime,
  source LowCardinality(String),
  host LowCardinality(String),
  observable String,
  observable_type LowCardinality(String),
  raw_row_hash String
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (observable, observable_type, ts, raw_row_hash)
TTL ts + INTERVAL 30 DAY;
