-- Enrichment usage analytics: daily per-provider / per-IOC-type aggregate.
--
-- Purpose: make paid/quota-limited enrichment provider consumption (especially
-- VirusTotal) visible without scanning ioc_items / ioc_enrichments / audit_logs on
-- every dashboard load. Enrichment entry points do one concurrency-safe upsert per
-- logical request into this pre-aggregated table; the Enrichment Usage page reads
-- only from here.
--
-- Grain: (bucket_date, provider_key, ioc_type). ioc_type is normalized to a small
-- fixed set (ip|domain|url|hash|other) so the dimension stays bounded.
--
-- Expected row growth: bounded and tiny. At most
--   (enrichment providers ~5) x (ioc types <=5) rows per day  => <= ~25 rows/day,
--   ~9k rows/year worst case. The PRIMARY KEY (bucket_date leading) is the only
--   index required for the range + provider + type queries the API issues.
--
-- Collection starts at deploy time. No historical backfill is performed (cache-hit
-- vs external-call cannot be reconstructed reliably from existing tables), so dates
-- before the first row genuinely mean "telemetry not collected yet", which the API
-- reports via the earliest bucket_date rather than as real zero usage.
--
-- Counters (all non-overlapping, see lib/enrichmentUsageTelemetry.js):
--   request_count        logical enrichment requests initiated for the provider
--   external_call_count  real outbound provider attempts (primary consumption metric)
--   cache_hit_count      requests satisfied without an external provider lookup
--   success_count        logical requests that completed successfully
--   failure_count        logical requests that failed
--   rate_limit_count     external calls explicitly rate limited (e.g. HTTP 429)
--   total_external_response_time_ms / external_response_count
--                        provider-call latency accumulator (external calls only;
--                        cache latency is never mixed in). avg = total / count.
-- unique_ioc_count is intentionally omitted: it cannot be derived from additive
-- counters, and a per-target table would add write amplification. Documented as a
-- known limitation.

SET LOCAL statement_timeout = 0;
SET LOCAL lock_timeout = '120s';

CREATE TABLE IF NOT EXISTS enrichment_usage_daily (
  bucket_date  DATE NOT NULL,
  provider_key TEXT NOT NULL,
  ioc_type     TEXT NOT NULL,
  request_count                   BIGINT NOT NULL DEFAULT 0,
  external_call_count             BIGINT NOT NULL DEFAULT 0,
  cache_hit_count                 BIGINT NOT NULL DEFAULT 0,
  success_count                   BIGINT NOT NULL DEFAULT 0,
  failure_count                   BIGINT NOT NULL DEFAULT 0,
  rate_limit_count                BIGINT NOT NULL DEFAULT 0,
  total_external_response_time_ms BIGINT NOT NULL DEFAULT 0,
  external_response_count         BIGINT NOT NULL DEFAULT 0,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT enrichment_usage_daily_pkey PRIMARY KEY (bucket_date, provider_key, ioc_type)
);

-- ROLLBACK:
--   DROP TABLE IF EXISTS enrichment_usage_daily;
