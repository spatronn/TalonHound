-- Threat Library: reports, artifacts, candidates, entities, relationships, AI settings.
-- Additive only. Does not alter or replace canonical ioc_items storage.

-- ---------------------------------------------------------------------------
-- AI provider settings (singleton row id = 1). Secrets never returned to clients.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.threat_library_ai_settings (
    id smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    enabled boolean NOT NULL DEFAULT false,
    provider text NOT NULL DEFAULT 'openai_compatible'
        CHECK (provider = ANY (ARRAY['openai'::text, 'anthropic'::text, 'ollama'::text, 'openai_compatible'::text])),
    base_url text,
    model text,
    api_key text,
    timeout_ms integer NOT NULL DEFAULT 60000
        CHECK (timeout_ms >= 1000 AND timeout_ms <= 600000),
    max_input_chars integer NOT NULL DEFAULT 120000
        CHECK (max_input_chars >= 1000 AND max_input_chars <= 2000000),
    privacy_ack_at timestamptz,
    privacy_ack_by uuid REFERENCES public.users(public_id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by uuid REFERENCES public.users(public_id) ON DELETE SET NULL
);

INSERT INTO public.threat_library_ai_settings (id)
VALUES (1)
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Reports
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.threat_reports (
    id bigserial PRIMARY KEY,
    public_id uuid NOT NULL DEFAULT gen_random_uuid(),
    portable_id text,
    bundle_id text,
    title text NOT NULL DEFAULT 'Untitled report',
    source_type text NOT NULL
        CHECK (source_type = ANY (ARRAY['url'::text, 'pdf'::text, 'thib'::text])),
    source_name text,
    source_url text,
    source_file_name text,
    source_sha256 text,
    published_at timestamptz,
    language text,
    tlp text NOT NULL DEFAULT 'clear'
        CHECK (tlp = ANY (ARRAY['clear'::text, 'green'::text, 'amber'::text, 'amber_strict'::text, 'red'::text])),
    confidence numeric(4,3)
        CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
    report_type text,
    summary text,
    import_status text NOT NULL DEFAULT 'draft'
        CHECK (import_status = ANY (ARRAY[
            'draft'::text, 'processing'::text, 'review_required'::text,
            'ready'::text, 'imported'::text, 'failed'::text, 'already_imported'::text
        ])),
    analysis_status text NOT NULL DEFAULT 'pending'
        CHECK (analysis_status = ANY (ARRAY[
            'pending'::text, 'fetching'::text, 'extracting'::text, 'analyzing'::text,
            'matching'::text, 'review_required'::text, 'ready'::text, 'failed'::text, 'skipped'::text
        ])),
    failure_stage text,
    failure_reason text,
    candidate_summary jsonb NOT NULL DEFAULT '{}'::jsonb,
    canonical_document jsonb,
    ai_result jsonb,
    thib_spec_version text,
    created_by uuid REFERENCES public.users(public_id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    finalized_at timestamptz,
    deleted_at timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_reports_public_id
    ON public.threat_reports (public_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_reports_bundle_id_active
    ON public.threat_reports (bundle_id)
    WHERE bundle_id IS NOT NULL AND deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_reports_portable_id_active
    ON public.threat_reports (portable_id)
    WHERE portable_id IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_threat_reports_created_at
    ON public.threat_reports (created_at DESC)
    WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_threat_reports_status
    ON public.threat_reports (import_status, analysis_status)
    WHERE deleted_at IS NULL;

-- ---------------------------------------------------------------------------
-- Artifacts / canonical source material
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.threat_report_artifacts (
    id bigserial PRIMARY KEY,
    public_id uuid NOT NULL DEFAULT gen_random_uuid(),
    report_id bigint NOT NULL REFERENCES public.threat_reports(id) ON DELETE CASCADE,
    artifact_type text NOT NULL
        CHECK (artifact_type = ANY (ARRAY[
            'url_fetch'::text, 'pdf_upload'::text, 'thib_upload'::text, 'canonical_document'::text
        ])),
    file_name text,
    mime_type text,
    size_bytes bigint
        CHECK (size_bytes IS NULL OR size_bytes >= 0),
    sha256 text,
    storage_key text,
    source_metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    text_excerpt text,
    requires_ocr boolean NOT NULL DEFAULT false,
    fetched_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_report_artifacts_public_id
    ON public.threat_report_artifacts (public_id);
CREATE INDEX IF NOT EXISTS idx_threat_report_artifacts_report
    ON public.threat_report_artifacts (report_id);

-- ---------------------------------------------------------------------------
-- IOC candidates (NOT automatic IOCs)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.threat_report_candidates (
    id bigserial PRIMARY KEY,
    public_id uuid NOT NULL DEFAULT gen_random_uuid(),
    report_id bigint NOT NULL REFERENCES public.threat_reports(id) ON DELETE CASCADE,
    portable_id text,
    candidate_type text NOT NULL,
    original_value text NOT NULL,
    normalized_value text NOT NULL,
    assessment text NOT NULL DEFAULT 'unknown'
        CHECK (assessment = ANY (ARRAY[
            'malicious'::text, 'suspicious'::text, 'context_only'::text, 'unknown'::text, 'invalid'::text
        ])),
    role text NOT NULL DEFAULT 'unknown',
    confidence numeric(4,3)
        CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
    evidence_text text,
    section text,
    block_id text,
    page_number integer,
    review_status text NOT NULL DEFAULT 'pending'
        CHECK (review_status = ANY (ARRAY[
            'pending'::text, 'approved'::text, 'context_only'::text,
            'ignored'::text, 'created_ioc'::text, 'rejected'::text
        ])),
    match_state text NOT NULL DEFAULT 'new'
        CHECK (match_state = ANY (ARRAY[
            'existing'::text, 'new'::text, 'context_only'::text, 'needs_review'::text, 'invalid'::text
        ])),
    matched_ioc_id bigint,
    matched_ioc_observable_type text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_threat_report_candidates_report_norm UNIQUE (report_id, candidate_type, normalized_value)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_report_candidates_public_id
    ON public.threat_report_candidates (public_id);
CREATE INDEX IF NOT EXISTS idx_threat_report_candidates_report
    ON public.threat_report_candidates (report_id);
CREATE INDEX IF NOT EXISTS idx_threat_report_candidates_matched_ioc
    ON public.threat_report_candidates (matched_ioc_id)
    WHERE matched_ioc_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_threat_report_candidates_review
    ON public.threat_report_candidates (report_id, review_status, match_state);

-- ---------------------------------------------------------------------------
-- Threat entities (TalonHound-owned catalog, distinct from admin threat_actors seed)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.threat_entities (
    id bigserial PRIMARY KEY,
    public_id uuid NOT NULL DEFAULT gen_random_uuid(),
    portable_id text,
    entity_type text NOT NULL
        CHECK (entity_type = ANY (ARRAY[
            'threat_actor'::text, 'malware'::text, 'campaign'::text, 'tool'::text,
            'vulnerability'::text, 'infrastructure'::text, 'organization'::text,
            'attack_pattern'::text
        ])),
    name text NOT NULL,
    normalized_name text NOT NULL,
    description text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_entities_public_id
    ON public.threat_entities (public_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_entities_type_norm
    ON public.threat_entities (entity_type, normalized_name);
CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_entities_portable_id
    ON public.threat_entities (portable_id)
    WHERE portable_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS public.threat_entity_aliases (
    id bigserial PRIMARY KEY,
    entity_id bigint NOT NULL REFERENCES public.threat_entities(id) ON DELETE CASCADE,
    alias text NOT NULL,
    normalized_alias text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_threat_entity_aliases UNIQUE (entity_id, normalized_alias)
);

CREATE TABLE IF NOT EXISTS public.threat_report_entities (
    id bigserial PRIMARY KEY,
    report_id bigint NOT NULL REFERENCES public.threat_reports(id) ON DELETE CASCADE,
    entity_id bigint NOT NULL REFERENCES public.threat_entities(id) ON DELETE CASCADE,
    confidence numeric(4,3),
    evidence_text text,
    block_id text,
    section text,
    page_number integer,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_threat_report_entities UNIQUE (report_id, entity_id)
);

CREATE INDEX IF NOT EXISTS idx_threat_report_entities_report
    ON public.threat_report_entities (report_id);
CREATE INDEX IF NOT EXISTS idx_threat_report_entities_entity
    ON public.threat_report_entities (entity_id);

-- ---------------------------------------------------------------------------
-- Generic intelligence claims / relationships
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.threat_relationships (
    id bigserial PRIMARY KEY,
    public_id uuid NOT NULL DEFAULT gen_random_uuid(),
    portable_id text,
    report_id bigint NOT NULL REFERENCES public.threat_reports(id) ON DELETE CASCADE,
    subject_kind text NOT NULL
        CHECK (subject_kind = ANY (ARRAY['entity'::text, 'candidate'::text, 'ioc'::text])),
    subject_entity_id bigint REFERENCES public.threat_entities(id) ON DELETE CASCADE,
    subject_candidate_id bigint REFERENCES public.threat_report_candidates(id) ON DELETE CASCADE,
    subject_ioc_id bigint,
    subject_portable_ref text,
    relationship_type text NOT NULL,
    object_kind text NOT NULL
        CHECK (object_kind = ANY (ARRAY['entity'::text, 'candidate'::text, 'ioc'::text])),
    object_entity_id bigint REFERENCES public.threat_entities(id) ON DELETE CASCADE,
    object_candidate_id bigint REFERENCES public.threat_report_candidates(id) ON DELETE CASCADE,
    object_ioc_id bigint,
    object_portable_ref text,
    role text,
    confidence numeric(4,3),
    evidence_text text,
    section text,
    page_number integer,
    block_id text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_relationships_public_id
    ON public.threat_relationships (public_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_relationships_portable
    ON public.threat_relationships (portable_id)
    WHERE portable_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_threat_relationships_report
    ON public.threat_relationships (report_id);
CREATE INDEX IF NOT EXISTS idx_threat_relationships_subject_ioc
    ON public.threat_relationships (subject_ioc_id)
    WHERE subject_ioc_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_threat_relationships_object_ioc
    ON public.threat_relationships (object_ioc_id)
    WHERE object_ioc_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Async processing jobs (BullMQ-backed)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.threat_library_jobs (
    id bigserial PRIMARY KEY,
    public_id uuid NOT NULL DEFAULT gen_random_uuid(),
    report_id bigint NOT NULL REFERENCES public.threat_reports(id) ON DELETE CASCADE,
    job_type text NOT NULL DEFAULT 'analyze'
        CHECK (job_type = ANY (ARRAY['analyze'::text, 'thib_import'::text, 'retry'::text])),
    status text NOT NULL DEFAULT 'queued'
        CHECK (status = ANY (ARRAY[
            'queued'::text, 'running'::text, 'completed'::text, 'failed'::text, 'cancelled'::text
        ])),
    stage text,
    progress jsonb NOT NULL DEFAULT '{}'::jsonb,
    error_message text,
    bullmq_job_id text,
    requested_by uuid REFERENCES public.users(public_id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_library_jobs_public_id
    ON public.threat_library_jobs (public_id);
CREATE INDEX IF NOT EXISTS idx_threat_library_jobs_report
    ON public.threat_library_jobs (report_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_library_jobs_status
    ON public.threat_library_jobs (status)
    WHERE status IN ('queued', 'running');

-- ---------------------------------------------------------------------------
-- System IOC source for Threat Library–approved creates (not selectable in Add IOC UI
-- unless product later exposes it; createManualIoc still accepts by id).
-- ---------------------------------------------------------------------------
INSERT INTO public.ioc_sources (
    name, display_name, description, source_type,
    default_confidence, default_expire_policy, default_expire_days, active, color
)
SELECT
    'Threat_Library',
    'Threat Library',
    'System source for IOCs explicitly approved from Threat Library report analysis. Not auto-created from candidates.',
    'external_report',
    'medium',
    'never',
    NULL,
    true,
    '#0f766e'
WHERE NOT EXISTS (
    SELECT 1 FROM public.ioc_sources WHERE name = 'Threat_Library'
);
