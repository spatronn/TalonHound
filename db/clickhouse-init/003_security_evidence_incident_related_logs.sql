CREATE DATABASE IF NOT EXISTS security_evidence;

CREATE TABLE IF NOT EXISTS security_evidence.incident_related_logs (
  activity_id UUID,
  incident_id UInt64,
  match_event_id UInt64,
  evidence_hash String,
  log_ts DateTime64(3, 'UTC'),
  created_at DateTime64(3, 'UTC') DEFAULT now64(3),
  matched_ioc String,
  observable_type LowCardinality(String),
  log_host String,
  observed_host String,
  parser_source LowCardinality(String),
  source_type LowCardinality(String),
  raw_message_hash String,
  raw_message_sample String
)
ENGINE = ReplacingMergeTree(created_at)
PARTITION BY toYYYYMM(log_ts)
ORDER BY (activity_id, match_event_id, evidence_hash, log_ts);
