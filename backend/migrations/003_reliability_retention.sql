-- Reliability retention helpers (HP-7).
-- App-level cleanup lives in backend/lib/operationalHistoryRetention.js.
-- integration_runs / integration_queue_jobs reuse existing created_at / status indexes.
-- ioc_ip_geo_cache only had asn/country indexes; add updated_at for TTL deletes.

CREATE INDEX IF NOT EXISTS idx_ioc_ip_geo_cache_updated_at
  ON public.ioc_ip_geo_cache USING btree (updated_at);
