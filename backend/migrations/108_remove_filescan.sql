-- Remove Filescan.io enrichment provider (product decision: provider removed entirely).
-- Drops dedicated cache table and removes provider config row.
-- Audit log rows in audit_logs referencing filescan actions are retained (historical).

DROP TABLE IF EXISTS ioc_filescan_enrichment CASCADE;

DELETE FROM threat_intel_provider_configs WHERE provider = 'filescan';
