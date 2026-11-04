-- 053_threat_library_source_discovery_ledger.sql
--
-- Source-discovery ledger: what discovery examined for a report (accepted and
-- rejected links) and how each linked source was resolved. Append-only, like the
-- extraction ledger of 052. Reports imported before this migration have no rows
-- and read as "not recorded", never as "no package".

CREATE TABLE IF NOT EXISTS public.threat_report_source_discovery_runs (
    id bigserial PRIMARY KEY,
    public_id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    report_id bigint NOT NULL REFERENCES public.threat_reports(id) ON DELETE CASCADE,
    discovery_version text NOT NULL,
    status text NOT NULL
        CHECK (status = ANY (ARRAY['completed'::text, 'partial'::text, 'failed'::text, 'skipped_finalized'::text])),
    references_examined integer NOT NULL DEFAULT 0,
    references_accepted integer NOT NULL DEFAULT 0,
    references_rejected integer NOT NULL DEFAULT 0,
    references_not_recorded integer NOT NULL DEFAULT 0,
    sources_inserted integer NOT NULL DEFAULT 0,
    error_detail text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_threat_report_source_discovery_runs_report
  ON public.threat_report_source_discovery_runs (report_id, id DESC);

CREATE TABLE IF NOT EXISTS public.threat_report_source_references (
    id bigserial PRIMARY KEY,
    discovery_run_id bigint NOT NULL REFERENCES public.threat_report_source_discovery_runs(id) ON DELETE CASCADE,
    report_id bigint NOT NULL REFERENCES public.threat_reports(id) ON DELETE CASCADE,
    url text NOT NULL,
    canonical_url text,
    discovery_method text NOT NULL
        CHECK (discovery_method = ANY (ARRAY['html_anchor'::text, 'document_link'::text, 'text_url'::text])),
    publisher_host text,
    source_type text,
    link_text text,
    heading_text text,
    surrounding_text text,
    score integer NOT NULL DEFAULT 0,
    matched_cues jsonb NOT NULL DEFAULT '[]'::jsonb,
    decision text NOT NULL CHECK (decision = ANY (ARRAY['accepted'::text, 'rejected'::text])),
    rejection_reason text,
    source_public_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT threat_report_source_references_rejection_reason
      CHECK (decision <> 'rejected' OR rejection_reason IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_threat_report_source_references_run
  ON public.threat_report_source_references (discovery_run_id);
CREATE INDEX IF NOT EXISTS idx_threat_report_source_references_report
  ON public.threat_report_source_references (report_id);

CREATE TABLE IF NOT EXISTS public.threat_report_source_resolution_events (
    id bigserial PRIMARY KEY,
    report_id bigint NOT NULL REFERENCES public.threat_reports(id) ON DELETE CASCADE,
    source_public_id uuid NOT NULL,
    url text NOT NULL,
    event_type text NOT NULL
        CHECK (event_type = ANY (ARRAY['inspection'::text, 'extraction'::text, 'dismissal'::text])),
    outcome text NOT NULL,
    error_code text,
    detail text,
    content_hash text,
    repo_revision text,
    evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
    files jsonb NOT NULL DEFAULT '[]'::jsonb,
    actor_public_id uuid,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_threat_report_source_resolution_events_report
  ON public.threat_report_source_resolution_events (report_id, id DESC);

COMMENT ON TABLE public.threat_report_source_discovery_runs IS
  'One row per IOC Source discovery pass. Append-only. A report without rows predates the ledger.';
COMMENT ON TABLE public.threat_report_source_references IS
  'Every relevant external reference a discovery pass examined, with its decision and evidence. Append-only.';
COMMENT ON TABLE public.threat_report_source_resolution_events IS
  'Inspection, extraction and dismissal outcomes of a linked IOC Source. Append-only.';

ALTER TABLE public.threat_report_ioc_sources
  ADD COLUMN IF NOT EXISTS dismissal_reason text;

COMMENT ON COLUMN public.threat_report_ioc_sources.dismissal_reason IS
  'The analyst''s stated evidence for dismissing this source. NULL on dismissals made before the column existed.';

DROP TRIGGER IF EXISTS threat_report_source_discovery_runs_immutable ON public.threat_report_source_discovery_runs;
CREATE TRIGGER threat_report_source_discovery_runs_immutable
    BEFORE UPDATE OR DELETE ON public.threat_report_source_discovery_runs
    FOR EACH ROW EXECUTE FUNCTION public.threat_library_reject_ledger_mutation();

DROP TRIGGER IF EXISTS threat_report_source_references_immutable ON public.threat_report_source_references;
CREATE TRIGGER threat_report_source_references_immutable
    BEFORE UPDATE OR DELETE ON public.threat_report_source_references
    FOR EACH ROW EXECUTE FUNCTION public.threat_library_reject_ledger_mutation();

DROP TRIGGER IF EXISTS threat_report_source_resolution_events_immutable ON public.threat_report_source_resolution_events;
CREATE TRIGGER threat_report_source_resolution_events_immutable
    BEFORE UPDATE OR DELETE ON public.threat_report_source_resolution_events
    FOR EACH ROW EXECUTE FUNCTION public.threat_library_reject_ledger_mutation();
