-- 037_enrichment_jobs.sql
--
-- Explicit, auditable enrichment jobs for automated triggers (MCP enrich_ioc /
-- bulk_enrich_iocs, lib/enrichmentOrchestrator.js). A job is one request; each
-- (IOC, provider) pair is one item with its own state so `providers = all` is
-- never all-or-nothing. Provider results themselves keep living in the existing
-- provider stores (ioc_enrichments, ioc_ip_enrichment, ...): this table only
-- tracks who asked for what, when, and how each provider operation ended.
--
-- Active items (queued/running) are indexed by (provider, target_value) so
-- concurrent identical requests coalesce onto the in-flight operation instead of
-- spending provider quota twice.

CREATE TABLE IF NOT EXISTS public.enrichment_jobs (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    origin text NOT NULL DEFAULT 'mcp',
    requested_by_user_id bigint,
    api_key_id bigint,
    requested_providers jsonb NOT NULL DEFAULT '[]'::jsonb,
    force_refresh boolean NOT NULL DEFAULT false,
    status text NOT NULL DEFAULT 'queued',
    runner_instance text,
    request_id text,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    updated_at timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT enrichment_jobs_status_check CHECK (status = ANY (ARRAY[
      'queued'::text, 'running'::text, 'completed'::text,
      'partially_completed'::text, 'failed'::text
    ]))
);

CREATE TABLE IF NOT EXISTS public.enrichment_job_items (
    id bigserial NOT NULL PRIMARY KEY,
    job_id uuid NOT NULL REFERENCES public.enrichment_jobs(id) ON DELETE CASCADE,
    ioc_id bigint NOT NULL,
    ioc_public_id uuid,
    observable text,
    observable_type text,
    provider text NOT NULL,
    target_scope text,
    target_type text,
    target_value text,
    force_refresh boolean NOT NULL DEFAULT false,
    status text NOT NULL,
    result text,
    error_code text,
    message text,
    coalesced_into_item_id bigint,
    last_enriched_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    updated_at timestamp with time zone NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS enrichment_job_items_job_idx
    ON public.enrichment_job_items (job_id, id);

CREATE INDEX IF NOT EXISTS enrichment_job_items_active_target_idx
    ON public.enrichment_job_items (provider, target_value)
    WHERE status = ANY (ARRAY['queued'::text, 'running'::text]);

CREATE INDEX IF NOT EXISTS enrichment_jobs_api_key_active_idx
    ON public.enrichment_jobs (api_key_id)
    WHERE status = ANY (ARRAY['queued'::text, 'running'::text]);

CREATE INDEX IF NOT EXISTS enrichment_jobs_created_at_idx
    ON public.enrichment_jobs (created_at);
