-- Migration 110: Drop analytics, incidents, and risk tables removed in the platform refactor.
-- These tables are no longer written to or queried by any backend code.
-- Drop order respects FK constraints (child tables before parents).
BEGIN;

DROP TABLE IF EXISTS ioc_match_event_related_logs;
DROP TABLE IF EXISTS incident_ai_insights;
DROP TABLE IF EXISTS ioc_match_events;
DROP TABLE IF EXISTS ioc_activity;
DROP TABLE IF EXISTS risk_snapshots;
DROP TABLE IF EXISTS environment_ai_insights;
DROP TABLE IF EXISTS signal_events;
DROP TABLE IF EXISTS signal_sources;
DROP TABLE IF EXISTS ioc_match_count_snapshot;

COMMIT;
