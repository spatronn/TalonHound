-- Threat Library: configurable maximum concurrent AI report analyses.
-- Additive only. Default 2 matches the historical threat-library-worker
-- BullMQ concurrency default (THREAT_LIBRARY_WORKER_CONCURRENCY), so existing
-- installations keep the same throughput until an administrator changes the
-- AI Settings value. Range 1–4 matches the worker process ceiling.

ALTER TABLE public.threat_library_ai_settings
  ADD COLUMN IF NOT EXISTS max_concurrent_report_analyses integer NOT NULL DEFAULT 2;

ALTER TABLE public.threat_library_ai_settings
  DROP CONSTRAINT IF EXISTS threat_library_ai_settings_max_concurrent_report_analyses_check;

ALTER TABLE public.threat_library_ai_settings
  ADD CONSTRAINT threat_library_ai_settings_max_concurrent_report_analyses_check
    CHECK (max_concurrent_report_analyses >= 1 AND max_concurrent_report_analyses <= 4);
