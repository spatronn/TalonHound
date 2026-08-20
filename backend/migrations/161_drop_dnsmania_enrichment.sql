-- Remove the DNSMania passive-DNS enrichment provider from TalonHound.
--
-- WHY: DNSMania is no longer a TalonHound enrichment provider. Its integration
--   (service, route, registry entry, health evidence, UI) is removed; this
--   migration removes the DNSMania footprint left in the database so an upgraded
--   install carries no orphan/stale DNSMania rows.
--
-- WHAT:
--   1. Drop the DNSMania result cache table (created by migration 112).
--   2. Delete the stale provider-health row DNSMania wrote to
--      threat_intel_provider_configs (best-effort runtime health signal).
--   3. Delete DNSMania usage-telemetry rows from enrichment_usage_daily.
--
-- NOT TOUCHED: audit_log rows recording historical enrichment.dnsmania.* actions
--   are immutable event history and are intentionally preserved.
--
-- IDEMPOTENT: DROP TABLE IF EXISTS + DELETE ... WHERE make re-running a no-op.
-- FRESH INSTALL: migration 112 creates the table, then this drops it; the DELETEs
--   simply match zero rows. No FK references these rows, so delete order is free.

SET LOCAL lock_timeout = '120s';

DO $$
DECLARE
  cfg_rows bigint := 0;
  usage_rows bigint := 0;
BEGIN
  DELETE FROM threat_intel_provider_configs WHERE provider = 'dnsmania';
  GET DIAGNOSTICS cfg_rows = ROW_COUNT;

  DELETE FROM enrichment_usage_daily WHERE provider_key = 'dnsmania';
  GET DIAGNOSTICS usage_rows = ROW_COUNT;

  RAISE NOTICE 'dnsmania removal: % provider-config row(s), % usage row(s) deleted', cfg_rows, usage_rows;
END $$;

DROP TABLE IF EXISTS ioc_dnsmania_enrichment;
