-- Threat Library: provenance of a report's effective TLP.
-- Additive only. `tlp` stays the single effective value every consumer
-- (UI, THIB export, API) reads; `tlp_source` records how it was obtained so
-- a manual edit is never overwritten by reprocessing.

ALTER TABLE public.threat_reports
  ADD COLUMN IF NOT EXISTS tlp_source text NOT NULL DEFAULT 'default'
    CHECK (tlp_source = ANY (ARRAY['explicit'::text, 'default'::text, 'manual'::text]));

COMMENT ON COLUMN public.threat_reports.tlp_source IS
  'How `tlp` was obtained: explicit = marking found in the source document; default = safe fallback for the source type; manual = set by a user (durable, survives reprocessing).';
