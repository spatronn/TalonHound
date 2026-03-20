-- Optional one-time migration for faster JOIN predicates by type+observable.
-- Safe swap with backup.

CREATE TABLE IF NOT EXISTS default.ioc_lookup_v2 (
  observable String,
  observable_type LowCardinality(String),
  confidence Int32,
  source_name String,
  updated_at DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (observable_type, observable)
SETTINGS index_granularity = 8192;

INSERT INTO default.ioc_lookup_v2
SELECT observable, observable_type, confidence, source_name, updated_at
FROM default.ioc_lookup;

RENAME TABLE
  default.ioc_lookup TO default.ioc_lookup_backup,
  default.ioc_lookup_v2 TO default.ioc_lookup;

-- Verify row counts
SELECT
  (SELECT count() FROM default.ioc_lookup) AS new_count,
  (SELECT count() FROM default.ioc_lookup_backup) AS backup_count;
