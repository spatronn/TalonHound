-- Threat Library: candidate evidence / provenance model (tl-candidates-v3).
-- Additive only. Evidence JSON carries source_assertion, occurrences, parsed URL
-- metadata (host/port), ai_needed and policy decisions so review + THIB export
-- can show why a candidate exists without re-running extraction.

ALTER TABLE public.threat_report_candidates
  ADD COLUMN IF NOT EXISTS is_ioc boolean NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS source_assertion text,
  ADD COLUMN IF NOT EXISTS evidence jsonb NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS idx_threat_report_candidates_assertion
  ON public.threat_report_candidates (report_id, source_assertion);

-- Per-call timing captured with each checkpointed chunk (diagnostics for slow local providers).
ALTER TABLE public.threat_library_analysis_chunks
  ADD COLUMN IF NOT EXISTS timing jsonb NOT NULL DEFAULT '[]'::jsonb;
