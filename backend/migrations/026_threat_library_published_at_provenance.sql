-- Threat Library: provenance + precision of a report's publication date.
-- Additive only. `published_at` stays the single value every consumer (UI,
-- API, MCP, THIB, threat-context ordering) reads; the new columns record how
-- it was obtained so reprocessing never downgrades it and so a calendar-day
-- value (the source stated no time) is never rendered with an invented time.

ALTER TABLE public.threat_reports
  ADD COLUMN IF NOT EXISTS published_at_source text
    CHECK (published_at_source IS NULL OR published_at_source = ANY (ARRAY[
      'manual'::text, 'thib'::text, 'json_ld'::text, 'og_article'::text, 'meta'::text,
      'html_time'::text, 'visible_date'::text, 'pdf_visible_date'::text, 'ai'::text
    ])),
  ADD COLUMN IF NOT EXISTS published_at_precision text
    CHECK (published_at_precision IS NULL OR published_at_precision = ANY (ARRAY['date'::text, 'datetime'::text])),
  ADD COLUMN IF NOT EXISTS published_at_raw text;

COMMENT ON COLUMN public.threat_reports.published_at IS
  'When the ORIGINAL source/report was published (never the import time = created_at, never a campaign/activity date). NULL = unknown.';
COMMENT ON COLUMN public.threat_reports.published_at_source IS
  'How published_at was obtained: manual/thib = asserted by a user / sharing party (durable); json_ld > og_article > meta > html_time > visible_date | pdf_visible_date = deterministic extraction (ranked); ai = model hint verified against document text.';
COMMENT ON COLUMN public.threat_reports.published_at_precision IS
  'date = the source stated a calendar day only (published_at holds 00:00:00 UTC of that day; render without a time); datetime = a real instant with an explicit UTC offset.';
COMMENT ON COLUMN public.threat_reports.published_at_raw IS
  'Exact string published_at was parsed from (audit / re-derivation).';
