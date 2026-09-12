-- Threat Library: long-running AI timeout model, analysis checkpoints, cancel support.
-- Additive only.

ALTER TABLE public.threat_library_ai_settings
  ADD COLUMN IF NOT EXISTS connection_timeout_ms integer,
  ADD COLUMN IF NOT EXISTS first_token_timeout_ms integer,
  ADD COLUMN IF NOT EXISTS inactivity_timeout_ms integer,
  ADD COLUMN IF NOT EXISTS total_analysis_timeout_ms integer;

-- Backfill from legacy single timeout_ms where new columns are null.
UPDATE public.threat_library_ai_settings
SET
  connection_timeout_ms = COALESCE(connection_timeout_ms, 30000),
  first_token_timeout_ms = COALESCE(
    first_token_timeout_ms,
    CASE
      WHEN provider = 'ollama' THEN GREATEST(COALESCE(timeout_ms, 60000), 300000)
      ELSE GREATEST(COALESCE(timeout_ms, 60000), 120000)
    END
  ),
  inactivity_timeout_ms = COALESCE(
    inactivity_timeout_ms,
    CASE
      WHEN provider = 'ollama' THEN GREATEST(COALESCE(timeout_ms, 60000), 300000)
      ELSE GREATEST(COALESCE(timeout_ms, 60000), 180000)
    END
  ),
  total_analysis_timeout_ms = COALESCE(
    total_analysis_timeout_ms,
    CASE
      WHEN provider = 'ollama' THEN 1800000
      ELSE 900000
    END
  )
WHERE id = 1;

ALTER TABLE public.threat_library_ai_settings
  DROP CONSTRAINT IF EXISTS threat_library_ai_settings_timeout_ms_check;

ALTER TABLE public.threat_library_ai_settings
  ADD CONSTRAINT threat_library_ai_settings_timeout_ms_check
    CHECK (timeout_ms IS NULL OR (timeout_ms >= 1000 AND timeout_ms <= 3600000));

ALTER TABLE public.threat_library_ai_settings
  DROP CONSTRAINT IF EXISTS chk_tl_ai_connection_timeout;
ALTER TABLE public.threat_library_ai_settings
  ADD CONSTRAINT chk_tl_ai_connection_timeout
    CHECK (connection_timeout_ms IS NULL OR (connection_timeout_ms >= 1000 AND connection_timeout_ms <= 120000));

ALTER TABLE public.threat_library_ai_settings
  DROP CONSTRAINT IF EXISTS chk_tl_ai_first_token_timeout;
ALTER TABLE public.threat_library_ai_settings
  ADD CONSTRAINT chk_tl_ai_first_token_timeout
    CHECK (first_token_timeout_ms IS NULL OR (first_token_timeout_ms >= 5000 AND first_token_timeout_ms <= 1800000));

ALTER TABLE public.threat_library_ai_settings
  DROP CONSTRAINT IF EXISTS chk_tl_ai_inactivity_timeout;
ALTER TABLE public.threat_library_ai_settings
  ADD CONSTRAINT chk_tl_ai_inactivity_timeout
    CHECK (inactivity_timeout_ms IS NULL OR (inactivity_timeout_ms >= 5000 AND inactivity_timeout_ms <= 1800000));

ALTER TABLE public.threat_library_ai_settings
  DROP CONSTRAINT IF EXISTS chk_tl_ai_total_timeout;
ALTER TABLE public.threat_library_ai_settings
  ADD CONSTRAINT chk_tl_ai_total_timeout
    CHECK (total_analysis_timeout_ms IS NULL OR (total_analysis_timeout_ms >= 60000 AND total_analysis_timeout_ms <= 7200000));

ALTER TABLE public.threat_reports
  ADD COLUMN IF NOT EXISTS analysis_progress jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS failure_code text,
  ADD COLUMN IF NOT EXISTS analysis_run_id uuid,
  ADD COLUMN IF NOT EXISTS cancel_requested_at timestamptz;

CREATE TABLE IF NOT EXISTS public.threat_library_analysis_chunks (
    id bigserial PRIMARY KEY,
    report_id bigint NOT NULL REFERENCES public.threat_reports(id) ON DELETE CASCADE,
    analysis_run_id uuid NOT NULL,
    chunk_index integer NOT NULL,
    chunk_key text NOT NULL,
    status text NOT NULL DEFAULT 'pending'
      CHECK (status = ANY (ARRAY[
        'pending'::text, 'running'::text, 'completed'::text, 'failed'::text, 'skipped'::text
      ])),
    block_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    result jsonb,
    error_code text,
    error_message text,
    attempt_count integer NOT NULL DEFAULT 0,
    started_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_tl_analysis_chunks UNIQUE (report_id, analysis_run_id, chunk_key)
);

CREATE INDEX IF NOT EXISTS idx_tl_analysis_chunks_report_run
  ON public.threat_library_analysis_chunks (report_id, analysis_run_id, chunk_index);

ALTER TABLE public.threat_library_jobs
  DROP CONSTRAINT IF EXISTS threat_library_jobs_status_check;

ALTER TABLE public.threat_library_jobs
  ADD CONSTRAINT threat_library_jobs_status_check
    CHECK (status = ANY (ARRAY[
      'queued'::text, 'running'::text, 'completed'::text, 'failed'::text, 'cancelled'::text
    ]));
