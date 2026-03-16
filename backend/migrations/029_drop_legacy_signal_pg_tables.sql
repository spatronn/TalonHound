-- Legacy PostgreSQL log storage tables removed after ClickHouse migration.
DROP TABLE IF EXISTS signal_events CASCADE;
DROP TABLE IF EXISTS signal_sources CASCADE;
