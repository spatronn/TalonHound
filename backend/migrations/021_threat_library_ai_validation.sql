-- Threat Library: AI validation diagnostics + semantic schema versioning.
-- Additive only.

ALTER TABLE public.threat_library_analysis_chunks
  ADD COLUMN IF NOT EXISTS schema_version text,
  ADD COLUMN IF NOT EXISTS validation_details jsonb NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS raw_output_sample text,
  ADD COLUMN IF NOT EXISTS rejected_items jsonb NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE public.threat_reports
  ADD COLUMN IF NOT EXISTS failure_details jsonb NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE public.threat_library_ai_settings
  ADD COLUMN IF NOT EXISTS last_probe_at timestamptz,
  ADD COLUMN IF NOT EXISTS last_probe_ok boolean,
  ADD COLUMN IF NOT EXISTS last_probe_detail jsonb NOT NULL DEFAULT '{}'::jsonb;
