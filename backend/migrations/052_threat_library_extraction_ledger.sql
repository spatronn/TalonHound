-- 052_threat_library_extraction_ledger.sql
--
-- Immutable extraction history for Threat Library reports.
--
-- threat_report_candidates holds the CURRENT, mutable review set. These tables
-- hold what each completed extraction produced, so a first-pass result can be
-- compared with the current state by exact identity. No document content is
-- duplicated: a run stores hashes plus bounded evidence excerpts.
--
-- Additive only: no existing table, row or membership is changed.
--
-- A report that existed before this ledger never receives a first-pass record.
-- scripts/threat-library-legacy-baseline.js labels its earliest available state
-- as run_type = 'legacy_baseline', is_first_pass = FALSE.

CREATE TABLE IF NOT EXISTS public.threat_report_extraction_runs (
    id BIGSERIAL PRIMARY KEY,
    public_id UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    report_id BIGINT NOT NULL REFERENCES public.threat_reports(id) ON DELETE CASCADE,
    -- Plain value, no FK: a SET NULL / cascade from the job row would have to
    -- rewrite an immutable run.
    job_id BIGINT,
    run_type TEXT NOT NULL CHECK (run_type IN ('initial', 'retry', 'refresh', 'rerun_ai', 'legacy_baseline')),
    is_first_pass BOOLEAN NOT NULL DEFAULT FALSE,
    operational_status TEXT NOT NULL DEFAULT 'completed' CHECK (operational_status IN ('completed', 'degraded')),
    contract_bundle JSONB NOT NULL DEFAULT '{}'::jsonb,
    contract_fingerprint TEXT NOT NULL,
    document_hash TEXT,
    source_sha256 TEXT,
    ai_provenance JSONB NOT NULL DEFAULT '{}'::jsonb,
    counts JSONB NOT NULL DEFAULT '{}'::jsonb,
    diagnostics JSONB NOT NULL DEFAULT '{}'::jsonb,
    idempotency_key TEXT NOT NULL,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT threat_report_extraction_runs_first_pass_type
        CHECK (NOT is_first_pass OR run_type IN ('initial', 'retry')),
    CONSTRAINT uq_threat_report_extraction_runs_idempotency UNIQUE (report_id, idempotency_key)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_report_extraction_runs_first_pass
    ON public.threat_report_extraction_runs (report_id)
    WHERE is_first_pass;

CREATE INDEX IF NOT EXISTS idx_threat_report_extraction_runs_report
    ON public.threat_report_extraction_runs (report_id, id DESC);

CREATE TABLE IF NOT EXISTS public.threat_report_extraction_run_candidates (
    run_id BIGINT NOT NULL REFERENCES public.threat_report_extraction_runs(id) ON DELETE CASCADE,
    candidate_type TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    original_value TEXT,
    is_member BOOLEAN NOT NULL DEFAULT FALSE,
    is_linked_member BOOLEAN NOT NULL DEFAULT FALSE,
    membership_outcome TEXT,
    reason_code TEXT,
    rule_id TEXT,
    assessment TEXT,
    role TEXT,
    source_assertion TEXT,
    review_status TEXT,
    matched_ioc_id BIGINT,
    has_original_document_occurrence BOOLEAN NOT NULL DEFAULT TRUE,
    decision JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (run_id, candidate_type, normalized_value)
);

CREATE TABLE IF NOT EXISTS public.threat_report_observable_dispositions (
    id BIGSERIAL PRIMARY KEY,
    run_id BIGINT NOT NULL REFERENCES public.threat_report_extraction_runs(id) ON DELETE CASCADE,
    source_kind TEXT NOT NULL DEFAULT 'document' CHECK (source_kind IN ('document', 'linked_source')),
    observable_type TEXT NOT NULL,
    raw_value TEXT,
    normalized_value TEXT,
    disposition TEXT NOT NULL CHECK (disposition IN ('accepted', 'rejected', 'context_only', 'needs_review', 'invalid', 'unsupported')),
    reason_code TEXT NOT NULL,
    rule_id TEXT,
    block_id TEXT,
    section_path JSONB NOT NULL DEFAULT '[]'::jsonb,
    table_index INTEGER,
    row_index INTEGER,
    column_index INTEGER,
    char_start INTEGER,
    char_end INTEGER,
    excerpt TEXT
);

CREATE INDEX IF NOT EXISTS idx_threat_report_observable_dispositions_run
    ON public.threat_report_observable_dispositions (run_id, disposition);

-- What normalization left out of the canonical document. Holds counts and a
-- bounded list of observable-shaped tokens, never the discarded markup itself.
CREATE TABLE IF NOT EXISTS public.threat_report_dropped_regions (
    id BIGSERIAL PRIMARY KEY,
    run_id BIGINT NOT NULL REFERENCES public.threat_report_extraction_runs(id) ON DELETE CASCADE,
    region_kind TEXT NOT NULL,
    reason TEXT NOT NULL,
    locator TEXT,
    text_chars INTEGER NOT NULL DEFAULT 0,
    observable_count INTEGER NOT NULL DEFAULT 0,
    observable_types JSONB NOT NULL DEFAULT '{}'::jsonb,
    sample_observables JSONB NOT NULL DEFAULT '[]'::jsonb,
    significant BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_threat_report_dropped_regions_run
    ON public.threat_report_dropped_regions (run_id);

-- Immutability. UPDATE is always refused. DELETE is refused unless it is the
-- FK cascade of deleting the report itself (pg_trigger_depth() > 1 inside the
-- referential-action trigger).
CREATE OR REPLACE FUNCTION public.threat_library_reject_ledger_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' AND pg_trigger_depth() > 1 THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'threat library extraction ledger is append-only (% on %)', TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$;

DROP TRIGGER IF EXISTS threat_report_extraction_runs_immutable ON public.threat_report_extraction_runs;
CREATE TRIGGER threat_report_extraction_runs_immutable
    BEFORE UPDATE OR DELETE ON public.threat_report_extraction_runs
    FOR EACH ROW EXECUTE FUNCTION public.threat_library_reject_ledger_mutation();

DROP TRIGGER IF EXISTS threat_report_extraction_run_candidates_immutable ON public.threat_report_extraction_run_candidates;
CREATE TRIGGER threat_report_extraction_run_candidates_immutable
    BEFORE UPDATE OR DELETE ON public.threat_report_extraction_run_candidates
    FOR EACH ROW EXECUTE FUNCTION public.threat_library_reject_ledger_mutation();

DROP TRIGGER IF EXISTS threat_report_observable_dispositions_immutable ON public.threat_report_observable_dispositions;
CREATE TRIGGER threat_report_observable_dispositions_immutable
    BEFORE UPDATE OR DELETE ON public.threat_report_observable_dispositions
    FOR EACH ROW EXECUTE FUNCTION public.threat_library_reject_ledger_mutation();

DROP TRIGGER IF EXISTS threat_report_dropped_regions_immutable ON public.threat_report_dropped_regions;
CREATE TRIGGER threat_report_dropped_regions_immutable
    BEFORE UPDATE OR DELETE ON public.threat_report_dropped_regions
    FOR EACH ROW EXECUTE FUNCTION public.threat_library_reject_ledger_mutation();
