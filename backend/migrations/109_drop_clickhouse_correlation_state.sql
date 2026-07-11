-- Drop ClickHouse correlation engine sync state tables (no longer needed after CH removal)
DROP TABLE IF EXISTS ioc_correlation_ioc_state;
DROP TABLE IF EXISTS ioc_correlation_state;
