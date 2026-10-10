-- 041_threat_report_ioc_sources.sql
--
-- Additional IOC Sources: multiple external IOC datasets associated with one
-- Threat Library report, with separate discovery / inspection / approval /
-- extraction lifecycle. Original-document MODE A membership is unchanged;
-- linked-source provenance is stored in junction rows and a candidate flag.

-- ---------------------------------------------------------------------------
-- Candidate provenance flag (existing rows = original document)
-- ---------------------------------------------------------------------------
ALTER TABLE public.threat_report_candidates
  ADD COLUMN IF NOT EXISTS has_original_document_occurrence boolean NOT NULL DEFAULT true;

COMMENT ON COLUMN public.threat_report_candidates.has_original_document_occurrence IS
  'True when the identity occurs in the original report document. Linked-only identities are false. Overlap with a linked source keeps this true.';

CREATE INDEX IF NOT EXISTS idx_threat_report_candidates_original_occ
  ON public.threat_report_candidates (report_id)
  WHERE has_original_document_occurrence = true;

-- ---------------------------------------------------------------------------
-- External / manual IOC sources for a report
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.threat_report_ioc_sources (
    id bigserial PRIMARY KEY,
    public_id uuid NOT NULL DEFAULT gen_random_uuid(),
    report_id bigint NOT NULL REFERENCES public.threat_reports(id) ON DELETE CASCADE,
    original_url text NOT NULL,
    canonical_url text NOT NULL,
    source_type text NOT NULL DEFAULT 'unknown'
        CHECK (source_type = ANY (ARRAY[
            'html'::text, 'txt'::text, 'csv'::text, 'json'::text, 'pdf'::text,
            'github_dir'::text, 'github_file'::text, 'unknown'::text
        ])),
    discovery_method text NOT NULL DEFAULT 'manual'
        CHECK (discovery_method = ANY (ARRAY['auto'::text, 'manual'::text])),
    discovery_evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
    lifecycle_status text NOT NULL DEFAULT 'discovered'
        CHECK (lifecycle_status = ANY (ARRAY[
            'discovered'::text, 'inspecting'::text, 'inspected'::text,
            'attached'::text, 'extracting'::text, 'extracted'::text,
            'dismissed'::text, 'blocked'::text, 'unsupported'::text,
            'failed'::text, 'stale'::text
        ])),
    inspection_status text NOT NULL DEFAULT 'pending'
        CHECK (inspection_status = ANY (ARRAY[
            'pending'::text, 'running'::text, 'succeeded'::text, 'failed'::text, 'skipped'::text
        ])),
    extraction_status text NOT NULL DEFAULT 'pending'
        CHECK (extraction_status = ANY (ARRAY[
            'pending'::text, 'running'::text, 'succeeded'::text, 'failed'::text, 'skipped'::text
        ])),
    content_hash text,
    repo_revision text,
    last_fetched_at timestamptz,
    preview jsonb NOT NULL DEFAULT '{}'::jsonb,
    error_code text,
    error_detail text,
    approved_by uuid REFERENCES public.users(public_id) ON DELETE SET NULL,
    approved_at timestamptz,
    dismissed_by uuid REFERENCES public.users(public_id) ON DELETE SET NULL,
    dismissed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_threat_report_ioc_sources_report_canonical
      UNIQUE (report_id, canonical_url)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_report_ioc_sources_public_id
  ON public.threat_report_ioc_sources (public_id);
CREATE INDEX IF NOT EXISTS idx_threat_report_ioc_sources_report
  ON public.threat_report_ioc_sources (report_id, lifecycle_status);

COMMENT ON TABLE public.threat_report_ioc_sources IS
  'Discovered or manually added external IOC datasets for a Threat Library report. Approval attaches and authorizes extraction; it does not approve IOCs into inventory.';

-- ---------------------------------------------------------------------------
-- File-level rows (GitHub directories and multi-file packs)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.threat_report_ioc_source_files (
    id bigserial PRIMARY KEY,
    public_id uuid NOT NULL DEFAULT gen_random_uuid(),
    source_id bigint NOT NULL REFERENCES public.threat_report_ioc_sources(id) ON DELETE CASCADE,
    path text NOT NULL,
    download_url text,
    size_bytes bigint
        CHECK (size_bytes IS NULL OR size_bytes >= 0),
    content_sha text,
    content_type text,
    selected boolean NOT NULL DEFAULT true,
    parse_status text NOT NULL DEFAULT 'pending'
        CHECK (parse_status = ANY (ARRAY[
            'pending'::text, 'ok'::text, 'unsupported'::text, 'failed'::text, 'skipped'::text
        ])),
    estimated_raw_count integer,
    estimated_unique_count integer,
    type_breakdown jsonb NOT NULL DEFAULT '{}'::jsonb,
    error_detail text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_threat_report_ioc_source_files_path UNIQUE (source_id, path)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_report_ioc_source_files_public_id
  ON public.threat_report_ioc_source_files (public_id);
CREATE INDEX IF NOT EXISTS idx_threat_report_ioc_source_files_source
  ON public.threat_report_ioc_source_files (source_id);

-- ---------------------------------------------------------------------------
-- Candidate ↔ source provenance (one identity, many sources)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.threat_report_candidate_source_links (
    id bigserial PRIMARY KEY,
    candidate_id bigint NOT NULL REFERENCES public.threat_report_candidates(id) ON DELETE CASCADE,
    source_id bigint NOT NULL REFERENCES public.threat_report_ioc_sources(id) ON DELETE CASCADE,
    source_file_id bigint REFERENCES public.threat_report_ioc_source_files(id) ON DELETE SET NULL,
    source_assertion text,
    evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_threat_report_candidate_source_links UNIQUE (candidate_id, source_id)
);

CREATE INDEX IF NOT EXISTS idx_threat_report_candidate_source_links_source
  ON public.threat_report_candidate_source_links (source_id);
CREATE INDEX IF NOT EXISTS idx_threat_report_candidate_source_links_candidate
  ON public.threat_report_candidate_source_links (candidate_id);

-- ---------------------------------------------------------------------------
-- Job modes: inspect / extract linked IOC sources
-- ---------------------------------------------------------------------------
ALTER TABLE public.threat_library_jobs
  DROP CONSTRAINT IF EXISTS threat_library_jobs_job_type_check;

ALTER TABLE public.threat_library_jobs
  ADD CONSTRAINT threat_library_jobs_job_type_check
  CHECK (job_type = ANY (ARRAY[
    'analyze'::text,
    'thib_import'::text,
    'retry'::text,
    'refresh_extraction'::text,
    'rerun_ai'::text,
    'inspect_ioc_source'::text,
    'extract_ioc_source'::text
  ]));

-- Optional payload for source-scoped jobs (source public_id / file selection)
ALTER TABLE public.threat_library_jobs
  ADD COLUMN IF NOT EXISTS job_payload jsonb NOT NULL DEFAULT '{}'::jsonb;
