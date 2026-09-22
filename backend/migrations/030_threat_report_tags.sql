-- 030_threat_report_tags.sql
--
-- Analyst-managed tags on a Threat Library report (campaign / threat context).
--
-- Report tags reuse the global `tags` catalog (same vocabulary, normalization and
-- admin enable/disable as IOC tags). They are NOT copied into ioc_tags: an IOC's
-- inherited ("Threat Library context") tags are derived at read time from
--   threat_report_tags → threat_reports (active) → threat_report_candidates
--   (IOC-eligible, matched_ioc_id) → ioc_items
-- so adding/removing a report tag, deleting a report or rejecting a candidate
-- changes every associated IOC immediately, direct ioc_tags rows are never
-- touched, and repeated processing cannot accumulate duplicate inheritance.
--
-- Report classifications are deliberately NOT inherited by IOCs.
--
-- Additive only: new table, no rewrite of existing data. No backfill — no
-- report-level tags existed before this migration.

CREATE TABLE IF NOT EXISTS public.threat_report_tags (
    report_id bigint NOT NULL REFERENCES public.threat_reports(id) ON DELETE CASCADE,
    tag_id bigint NOT NULL REFERENCES public.tags(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (report_id, tag_id)
);

-- Tag search (tag equals "x" → reports carrying x). The PK covers report → tags.
CREATE INDEX IF NOT EXISTS idx_threat_report_tags_tag
    ON public.threat_report_tags (tag_id);
