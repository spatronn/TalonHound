-- 049_threat_library_ai_inference_scheduler.sql
--
-- Threat Library AI inference scheduling, job ownership and attempt history.
--
-- 1. threat_library_ai_capacity_leases: the shared inference-capacity
--    controller (lib/threatLibrary/ai/inferenceScheduler.js). One row per
--    waiting or holding AI request, FIFO by id per provider endpoint. Rows are
--    short-lived leases with an expiry, so a crashed process frees its slot
--    without manual cleanup. No PostgreSQL connection is held during inference.
--    A slot whose cancelled request may still be executing on the provider is
--    quarantined (quarantined_at): it stays occupied until a probe confirms
--    the provider is idle (verify_after paces probes) or its worst-case bound
--    expires.
-- 2. threat_library_ai_settings: per-endpoint AI request capacity, the
--    cumulative capacity-wait budget, a per-request execution limit and the
--    bounded automatic retry count. NULL keeps the provider default.
-- 3. threat_library_jobs: owner_token / heartbeat_at fence a job to one live
--    worker; not_before delays a bounded automatic retry.
-- 4. threat_library_analysis_chunks.attempt_history keeps a bounded record of
--    earlier attempts instead of overwriting failure diagnostics on success.
--
-- Additive only: no existing row is rewritten, no column is dropped.
-- Rollback: the previous release ignores every object added here.

CREATE TABLE IF NOT EXISTS public.threat_library_ai_capacity_leases (
    id bigserial PRIMARY KEY,
    resource_key text NOT NULL,
    token uuid NOT NULL,
    state text NOT NULL DEFAULT 'waiting'
      CHECK (state = ANY (ARRAY['waiting'::text, 'holding'::text])),
    purpose text,
    owner text,
    report_id bigint,
    lease_expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    acquired_at timestamptz,
    quarantined_at timestamptz,
    verify_after timestamptz,
    CONSTRAINT uq_tl_ai_capacity_leases_token UNIQUE (token)
);

ALTER TABLE public.threat_library_ai_capacity_leases
  ADD COLUMN IF NOT EXISTS quarantined_at timestamptz,
  ADD COLUMN IF NOT EXISTS verify_after timestamptz;

CREATE INDEX IF NOT EXISTS idx_tl_ai_capacity_leases_resource
  ON public.threat_library_ai_capacity_leases (resource_key, state, id);

ALTER TABLE public.threat_library_ai_settings
  ADD COLUMN IF NOT EXISTS max_concurrent_ai_requests integer,
  ADD COLUMN IF NOT EXISTS capacity_wait_timeout_ms integer,
  ADD COLUMN IF NOT EXISTS provider_execution_timeout_ms integer,
  ADD COLUMN IF NOT EXISTS auto_retry_max_attempts integer;

ALTER TABLE public.threat_library_ai_settings
  DROP CONSTRAINT IF EXISTS chk_tl_ai_max_concurrent_requests;
ALTER TABLE public.threat_library_ai_settings
  ADD CONSTRAINT chk_tl_ai_max_concurrent_requests
    CHECK (max_concurrent_ai_requests IS NULL OR (max_concurrent_ai_requests >= 1 AND max_concurrent_ai_requests <= 8));

ALTER TABLE public.threat_library_ai_settings
  DROP CONSTRAINT IF EXISTS chk_tl_ai_capacity_wait_timeout;
ALTER TABLE public.threat_library_ai_settings
  ADD CONSTRAINT chk_tl_ai_capacity_wait_timeout
    CHECK (capacity_wait_timeout_ms IS NULL OR (capacity_wait_timeout_ms >= 10000 AND capacity_wait_timeout_ms <= 14400000));

ALTER TABLE public.threat_library_ai_settings
  DROP CONSTRAINT IF EXISTS chk_tl_ai_provider_execution_timeout;
ALTER TABLE public.threat_library_ai_settings
  ADD CONSTRAINT chk_tl_ai_provider_execution_timeout
    CHECK (provider_execution_timeout_ms IS NULL OR (provider_execution_timeout_ms >= 30000 AND provider_execution_timeout_ms <= 7200000));

ALTER TABLE public.threat_library_ai_settings
  DROP CONSTRAINT IF EXISTS chk_tl_ai_auto_retry_max_attempts;
ALTER TABLE public.threat_library_ai_settings
  ADD CONSTRAINT chk_tl_ai_auto_retry_max_attempts
    CHECK (auto_retry_max_attempts IS NULL OR (auto_retry_max_attempts >= 0 AND auto_retry_max_attempts <= 5));

ALTER TABLE public.threat_library_jobs
  ADD COLUMN IF NOT EXISTS owner_token uuid,
  ADD COLUMN IF NOT EXISTS heartbeat_at timestamptz,
  ADD COLUMN IF NOT EXISTS not_before timestamptz;

ALTER TABLE public.threat_library_analysis_chunks
  ADD COLUMN IF NOT EXISTS attempt_history jsonb NOT NULL DEFAULT '[]'::jsonb;
