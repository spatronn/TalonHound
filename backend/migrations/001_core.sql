-- TalonHound canonical database baseline (v0.1.0-beta.1)
-- Replaces private-development migrations 001-165 with a single public baseline.
-- Migration identity: 001_core.sql (full filename stored in schema_migrations).
-- Do NOT edit after public release; add forward migrations as 002_*.sql, 003_*.sql, ...
-- schema_migrations is created/owned by backend/migrate.js -- not included here.

BEGIN;

-- Replace docker init stub tables with canonical definitions from baseline.
DROP TABLE IF EXISTS public.integration_checkpoints CASCADE;
DROP TABLE IF EXISTS public.integration_runs CASCADE;
DROP TABLE IF EXISTS public.user_preferences CASCADE;

-- ===== SCHEMA =====
--
--


-- Dumped from database version 16.14
-- Dumped by pg_dump version 16.14


--
-- Name: pg_stat_statements; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_stat_statements WITH SCHEMA public;


--
-- Name: EXTENSION pg_stat_statements; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pg_stat_statements IS 'track planning and execution statistics of all SQL statements executed';


--
-- Name: pg_trgm; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;


--
-- Name: EXTENSION pg_trgm; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pg_trgm IS 'text similarity measurement and index searching based on trigrams';


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: app_user_role; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.app_user_role AS ENUM (
    'admin',
    'readonly',
    'analyst'
);


--
-- Name: app_user_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.app_user_status AS ENUM (
    'active',
    'passive'
);


--
-- Name: tag_type; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.tag_type AS ENUM (
    'threat',
    'actor',
    'technique',
    'context'
);


--
-- Name: pf_bump_tags_catalog_watermark(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.pf_bump_tags_catalog_watermark() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  INSERT INTO published_feed_global_watermarks (key, watermark)
  VALUES ('tags_catalog', NOW())
  ON CONFLICT (key) DO UPDATE SET watermark = EXCLUDED.watermark;
  RETURN NULL;
END;
$$;


--
-- Name: pf_record_ioc_item_delete(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.pf_record_ioc_item_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  art UUID;
BEGIN
  -- Capture artifact link before cascade removes file_artifact_ioc_links.
  SELECT fal.artifact_id
    INTO art
    FROM file_artifact_ioc_links fal
   WHERE fal.ioc_item_id = OLD.id
     AND fal.ioc_observable_type = OLD.observable_type
   ORDER BY fal.is_canonical_ioc DESC NULLS LAST, fal.artifact_id
   LIMIT 1;

  INSERT INTO published_feed_ioc_deletes (
    ioc_item_id, observable, observable_type, artifact_id, deleted_at
  ) VALUES (
    OLD.id, OLD.observable, OLD.observable_type, art, NOW()
  );
  RETURN OLD;
END;
$$;


--
-- Name: pf_touch_ioc_items_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.pf_touch_ioc_items_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  NEW.updated_at := NOW();
  RETURN NEW;
END;
$$;


--
-- Name: pf_touch_ioc_on_tag_change(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.pf_touch_ioc_on_tag_change() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    UPDATE ioc_items
       SET updated_at = NOW()
     WHERE id = OLD.ioc_id
       AND observable_type = OLD.ioc_observable_type;
    RETURN OLD;
  END IF;
  UPDATE ioc_items
     SET updated_at = NOW()
   WHERE id = NEW.ioc_id
     AND observable_type = NEW.ioc_observable_type;
  RETURN NEW;
END;
$$;


--
-- Name: published_feeds_bridge_ioc_types(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.published_feeds_bridge_ioc_types() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF NEW.ioc_types IS NULL AND NEW.ioc_type IS NOT NULL THEN
    NEW.ioc_types := to_jsonb(ARRAY[lower(NEW.ioc_type)]);
  ELSIF TG_OP = 'UPDATE'
    AND OLD.ioc_type IS DISTINCT FROM NEW.ioc_type
    AND OLD.ioc_types IS NOT DISTINCT FROM NEW.ioc_types
    AND NEW.ioc_type IS NOT NULL THEN
    -- Legacy UPDATE touched only ioc_type; keep ioc_types in sync.
    NEW.ioc_types := to_jsonb(ARRAY[lower(NEW.ioc_type)]);
  END IF;
  RETURN NEW;
END;
$$;




--
-- Name: audit_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_logs (
    id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    actor_user_id uuid,
    actor_username text,
    actor_email text,
    actor_role text,
    action text NOT NULL,
    entity_type text NOT NULL,
    entity_id text,
    entity_display text,
    severity text DEFAULT 'info'::text NOT NULL,
    status text DEFAULT 'success'::text NOT NULL,
    ip_address inet,
    user_agent text,
    request_id text,
    source text DEFAULT 'web'::text NOT NULL,
    before_data jsonb,
    after_data jsonb,
    metadata jsonb,
    subject_ioc_id bigint,
    subject_ioc_type text,
    subject_ioc_value text,
    target_type text,
    target_value text
);


--
-- Name: audit_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.audit_logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: audit_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.audit_logs_id_seq OWNED BY public.audit_logs.id;


--
-- Name: auth_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auth_sessions (
    id bigint NOT NULL,
    session_id uuid NOT NULL,
    user_id bigint NOT NULL,
    refresh_token_hash text NOT NULL,
    prev_refresh_token_hash text,
    rotated_at timestamp with time zone DEFAULT now() NOT NULL,
    auth_version_at_issue integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_activity_at timestamp with time zone DEFAULT now() NOT NULL,
    idle_expires_at timestamp with time zone NOT NULL,
    absolute_expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    revoked_reason text,
    user_agent text
);


--
-- Name: TABLE auth_sessions; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.auth_sessions IS 'Server-side interactive browser sessions: short access token + rotating refresh, idle + absolute enforcement. Stores only a hash of the refresh secret.';


--
-- Name: COLUMN auth_sessions.last_activity_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.auth_sessions.last_activity_at IS 'Advanced only by the explicit user-activity heartbeat; background polling/refresh must NOT touch it.';


--
-- Name: COLUMN auth_sessions.absolute_expires_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.auth_sessions.absolute_expires_at IS 'Hard session lifetime from original login. Refresh never extends this.';


--
-- Name: auth_sessions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.auth_sessions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: auth_sessions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.auth_sessions_id_seq OWNED BY public.auth_sessions.id;


--
-- Name: custom_threat_feed_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.custom_threat_feed_runs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    feed_id uuid NOT NULL,
    integration_feed_id uuid NOT NULL,
    queue_job_id text,
    status text DEFAULT 'running'::text NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    finished_at timestamp with time zone,
    duration_ms integer,
    fetched_bytes integer,
    http_status integer,
    total_rows integer DEFAULT 0 NOT NULL,
    valid_rows integer DEFAULT 0 NOT NULL,
    invalid_rows integer DEFAULT 0 NOT NULL,
    inserted integer DEFAULT 0 NOT NULL,
    updated integer DEFAULT 0 NOT NULL,
    refreshed integer DEFAULT 0 NOT NULL,
    expired_missing integer DEFAULT 0 NOT NULL,
    duplicate_rows integer DEFAULT 0 NOT NULL,
    error_message text,
    invalid_samples jsonb,
    triggered_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT custom_threat_feed_runs_status_check CHECK ((status = ANY (ARRAY['running'::text, 'success'::text, 'partial_success'::text, 'failed'::text])))
);


--
-- Name: custom_threat_feeds; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.custom_threat_feeds (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    feed_id uuid NOT NULL,
    url text NOT NULL,
    url_host text NOT NULL,
    format text DEFAULT 'auto'::text NOT NULL,
    ioc_type_mode text DEFAULT 'auto'::text NOT NULL,
    fixed_ioc_type text,
    timeout_ms integer DEFAULT 30000 NOT NULL,
    description text,
    deactivated_at timestamp with time zone,
    created_by uuid,
    created_by_username text,
    updated_by uuid,
    updated_by_username text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT custom_threat_feeds_fixed_ioc_type_check CHECK (((fixed_ioc_type IS NULL) OR (fixed_ioc_type = ANY (ARRAY['domain'::text, 'ip'::text, 'url'::text, 'file_hash'::text])))),
    CONSTRAINT custom_threat_feeds_format_check CHECK ((format = ANY (ARRAY['auto'::text, 'txt'::text, 'csv'::text]))),
    CONSTRAINT custom_threat_feeds_ioc_type_mode_check CHECK ((ioc_type_mode = ANY (ARRAY['auto'::text, 'fixed'::text]))),
    CONSTRAINT custom_threat_feeds_timeout_ms_check CHECK (((timeout_ms >= 1000) AND (timeout_ms <= 300000)))
);


--
-- Name: enrichment_provider_health; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.enrichment_provider_health (
    provider text NOT NULL,
    status text DEFAULT 'unknown'::text NOT NULL,
    last_check_at timestamp with time zone,
    last_success_at timestamp with time zone,
    last_failure_at timestamp with time zone,
    check_source text,
    error_category text,
    evidence text,
    consecutive_failures integer DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT enrichment_provider_health_status_chk CHECK ((status = ANY (ARRAY['healthy'::text, 'degraded'::text, 'unhealthy'::text, 'unknown'::text])))
);


--
-- Name: enrichment_usage_daily; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.enrichment_usage_daily (
    bucket_date date NOT NULL,
    provider_key text NOT NULL,
    ioc_type text NOT NULL,
    request_count bigint DEFAULT 0 NOT NULL,
    external_call_count bigint DEFAULT 0 NOT NULL,
    cache_hit_count bigint DEFAULT 0 NOT NULL,
    success_count bigint DEFAULT 0 NOT NULL,
    failure_count bigint DEFAULT 0 NOT NULL,
    rate_limit_count bigint DEFAULT 0 NOT NULL,
    total_external_response_time_ms bigint DEFAULT 0 NOT NULL,
    external_response_count bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: file_artifact_hashes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.file_artifact_hashes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    artifact_id uuid NOT NULL,
    hash_type text NOT NULL,
    normalized_hash_value text NOT NULL,
    is_primary boolean DEFAULT false NOT NULL,
    first_seen_at timestamp with time zone,
    last_seen_at timestamp with time zone,
    verification_source text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT file_artifact_hashes_hash_type_check CHECK ((hash_type = ANY (ARRAY['md5'::text, 'sha1'::text, 'sha256'::text]))),
    CONSTRAINT file_artifact_hashes_value_format CHECK ((((hash_type = 'md5'::text) AND (normalized_hash_value ~ '^[a-f0-9]{32}$'::text)) OR ((hash_type = 'sha1'::text) AND (normalized_hash_value ~ '^[a-f0-9]{40}$'::text)) OR ((hash_type = 'sha256'::text) AND (normalized_hash_value ~ '^[a-f0-9]{64}$'::text))))
);


--
-- Name: TABLE file_artifact_hashes; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.file_artifact_hashes IS 'Exact cryptographic hashes that identify a file_artifact. IMPHASH/TLSH/SSDEEP are not stored here.';


--
-- Name: file_artifact_ioc_links; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.file_artifact_ioc_links (
    id bigint NOT NULL,
    artifact_id uuid NOT NULL,
    ioc_item_id bigint NOT NULL,
    ioc_observable_type text NOT NULL,
    ioc_public_id uuid NOT NULL,
    linked_hash_id uuid,
    is_canonical_ioc boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE file_artifact_ioc_links; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.file_artifact_ioc_links IS 'Maps legacy ioc_items rows to file_artifacts without rewriting dependent FK tables.';


--
-- Name: file_artifact_ioc_links_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.file_artifact_ioc_links_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: file_artifact_ioc_links_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.file_artifact_ioc_links_id_seq OWNED BY public.file_artifact_ioc_links.id;


--
-- Name: file_artifact_merge_conflicts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.file_artifact_merge_conflicts (
    id bigint NOT NULL,
    conflicting_hash_type text NOT NULL,
    conflicting_hash_value text NOT NULL,
    candidate_artifact_ids uuid[] DEFAULT '{}'::uuid[] NOT NULL,
    evidence jsonb DEFAULT '{}'::jsonb NOT NULL,
    reason text NOT NULL,
    status text DEFAULT 'open'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    resolved_at timestamp with time zone,
    resolution_metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT file_artifact_merge_conflicts_conflicting_hash_type_check CHECK ((conflicting_hash_type = ANY (ARRAY['md5'::text, 'sha1'::text, 'sha256'::text]))),
    CONSTRAINT file_artifact_merge_conflicts_status_check CHECK ((status = ANY (ARRAY['open'::text, 'resolved'::text, 'ignored'::text])))
);


--
-- Name: TABLE file_artifact_merge_conflicts; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.file_artifact_merge_conflicts IS 'Records conflicting exact-hash mappings that block automatic merge (e.g. MD5 X → two SHA256s).';


--
-- Name: file_artifact_merge_conflicts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.file_artifact_merge_conflicts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: file_artifact_merge_conflicts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.file_artifact_merge_conflicts_id_seq OWNED BY public.file_artifact_merge_conflicts.id;


--
-- Name: file_artifact_non_identity_attrs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.file_artifact_non_identity_attrs (
    id bigint NOT NULL,
    artifact_id uuid NOT NULL,
    attr_type text NOT NULL,
    attr_value text NOT NULL,
    source_name text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT file_artifact_non_identity_attrs_attr_type_check CHECK ((attr_type = ANY (ARRAY['imphash'::text, 'tlsh'::text, 'ssdeep'::text])))
);


--
-- Name: TABLE file_artifact_non_identity_attrs; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.file_artifact_non_identity_attrs IS 'Structural/similarity attributes. Never used alone as automatic merge evidence.';


--
-- Name: file_artifact_non_identity_attrs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.file_artifact_non_identity_attrs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: file_artifact_non_identity_attrs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.file_artifact_non_identity_attrs_id_seq OWNED BY public.file_artifact_non_identity_attrs.id;


--
-- Name: file_artifact_source_observations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.file_artifact_source_observations (
    id bigint NOT NULL,
    artifact_id uuid NOT NULL,
    source_name text NOT NULL,
    feed_id uuid,
    source_membership_id bigint,
    source_record_id text,
    observed_hash_id uuid,
    observed_hash_type text NOT NULL,
    observed_hash_value text NOT NULL,
    observation_type text NOT NULL,
    relation_method text NOT NULL,
    confidence text,
    first_seen_in_source timestamp with time zone,
    last_seen_in_source timestamp with time zone,
    last_changed_in_source timestamp with time zone,
    raw_ref jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT file_artifact_source_observations_observation_type_check CHECK ((observation_type = ANY (ARRAY['direct_source_observation'::text, 'provider_hash_mapping'::text, 'enrichment_derived'::text, 'manual_verified'::text, 'migration_backfill'::text]))),
    CONSTRAINT file_artifact_source_observations_observed_hash_type_check CHECK ((observed_hash_type = ANY (ARRAY['md5'::text, 'sha1'::text, 'sha256'::text]))),
    CONSTRAINT file_artifact_source_observations_relation_method_check CHECK ((relation_method = ANY (ARRAY['same_source_record'::text, 'provider_exact_hash_set'::text, 'enrichment_result'::text, 'manual_merge'::text, 'migration_seed'::text])))
);


--
-- Name: TABLE file_artifact_source_observations; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.file_artifact_source_observations IS 'Preserves which hash each source actually provided. Never attribute unobserved hashes to a source.';


--
-- Name: file_artifact_source_observations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.file_artifact_source_observations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: file_artifact_source_observations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.file_artifact_source_observations_id_seq OWNED BY public.file_artifact_source_observations.id;


--
-- Name: file_artifacts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.file_artifacts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    primary_hash_id uuid,
    status text DEFAULT 'active'::text NOT NULL,
    merged_into_artifact_id uuid,
    file_name text,
    file_type text,
    mime_type text,
    size_bytes bigint,
    first_seen_at timestamp with time zone,
    last_seen_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT file_artifacts_merged_requires_target CHECK ((((status = 'merged'::text) AND (merged_into_artifact_id IS NOT NULL)) OR ((status = 'active'::text) AND (merged_into_artifact_id IS NULL)))),
    CONSTRAINT file_artifacts_status_check CHECK ((status = ANY (ARRAY['active'::text, 'merged'::text])))
);


--
-- Name: TABLE file_artifacts; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.file_artifacts IS 'Logical file identity. Exact hashes (md5/sha1/sha256) are identifiers; IOC rows link via file_artifact_ioc_links.';


--
-- Name: integration_checkpoints; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_checkpoints (
    source_name text NOT NULL,
    last_cursor text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: integration_feed_expiration_type_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_feed_expiration_type_policies (
    id bigint NOT NULL,
    feed_id uuid NOT NULL,
    ioc_type text NOT NULL,
    mode text NOT NULL,
    ttl_days integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT integration_feed_expiration_type_policies_mode_check CHECK ((mode = ANY (ARRAY['inherit'::text, 'no_expire'::text, 'fixed_ttl'::text]))),
    CONSTRAINT integration_feed_expiration_type_policies_ttl_check CHECK (((mode <> 'fixed_ttl'::text) OR ((ttl_days IS NOT NULL) AND (ttl_days > 0))))
);


--
-- Name: integration_feed_expiration_type_policies_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.integration_feed_expiration_type_policies_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: integration_feed_expiration_type_policies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.integration_feed_expiration_type_policies_id_seq OWNED BY public.integration_feed_expiration_type_policies.id;


--
-- Name: integration_feeds; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_feeds (
    key text NOT NULL,
    name text NOT NULL,
    source_url text NOT NULL,
    schedule_cron text NOT NULL,
    trust_level text DEFAULT 'not_categorized'::text NOT NULL,
    active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    integration_id uuid NOT NULL,
    feed_update_mode text DEFAULT 'incremental'::text NOT NULL,
    credentials jsonb DEFAULT '{}'::jsonb NOT NULL,
    default_confidence text,
    feed_kind text DEFAULT 'built_in'::text NOT NULL,
    archived_at timestamp with time zone,
    archived_by uuid,
    archived_by_username text,
    color text,
    CONSTRAINT chk_integration_feeds_color_hex CHECK (((color IS NULL) OR (color ~ '^#[0-9a-f]{6}$'::text))),
    CONSTRAINT integration_feeds_feed_kind_check CHECK ((feed_kind = ANY (ARRAY['built_in'::text, 'custom'::text]))),
    CONSTRAINT integration_feeds_feed_update_mode_check CHECK ((feed_update_mode = ANY (ARRAY['incremental'::text, 'snapshot'::text]))),
    CONSTRAINT integration_feeds_trust_level_check CHECK ((trust_level = ANY (ARRAY['guvenilir'::text, 'orta'::text, 'not_categorized'::text])))
);


--
-- Name: COLUMN integration_feeds.color; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.integration_feeds.color IS 'Managed badge color as #rrggbb (lowercase). NULL = frontend fallback.';


--
-- Name: integration_queue_jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_queue_jobs (
    job_id text NOT NULL,
    integration_key text NOT NULL,
    job_name text NOT NULL,
    status text NOT NULL,
    triggered_by text,
    queued_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    records_processed integer DEFAULT 0 NOT NULL,
    error_message text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    records_inserted integer DEFAULT 0 NOT NULL,
    records_updated integer DEFAULT 0 NOT NULL,
    records_duplicate integer DEFAULT 0 NOT NULL,
    records_skipped integer DEFAULT 0 NOT NULL,
    records_suppressed integer DEFAULT 0 NOT NULL,
    records_failed integer DEFAULT 0 NOT NULL,
    heartbeat_at timestamp with time zone,
    worker_id text,
    worker_hostname text,
    failure_type text,
    records_unchanged integer DEFAULT 0 NOT NULL,
    records_reactivated integer DEFAULT 0 NOT NULL,
    records_removed integer DEFAULT 0 NOT NULL,
    result_code text,
    result_summary text,
    result_details jsonb,
    run_mode text,
    CONSTRAINT integration_queue_jobs_status_check CHECK ((status = ANY (ARRAY['queued'::text, 'running'::text, 'success'::text, 'failed'::text, 'skipped'::text])))
);


--
-- Name: COLUMN integration_queue_jobs.records_unchanged; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.integration_queue_jobs.records_unchanged IS 'Rows seen again with identical content. Written once at job completion.';


--
-- Name: COLUMN integration_queue_jobs.records_reactivated; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.integration_queue_jobs.records_reactivated IS 'Previously inactive memberships that returned. Written once at job completion.';


--
-- Name: COLUMN integration_queue_jobs.records_removed; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.integration_queue_jobs.records_removed IS 'Memberships marked missing/inactive by full reconciliation. Written once at completion.';


--
-- Name: COLUMN integration_queue_jobs.result_code; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.integration_queue_jobs.result_code IS 'Canonical job result code (e.g. COMPLETED_WITH_CHANGES). NULL = legacy/no snapshot.';


--
-- Name: COLUMN integration_queue_jobs.result_summary; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.integration_queue_jobs.result_summary IS 'Human-readable result summary for Job Queue Result column. NULL = legacy/no snapshot.';


--
-- Name: COLUMN integration_queue_jobs.result_details; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.integration_queue_jobs.result_details IS 'Immutable whitelist JSON snapshot of run metrics. NULL = legacy/no snapshot.';


--
-- Name: COLUMN integration_queue_jobs.run_mode; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.integration_queue_jobs.run_mode IS 'Run mode when applicable (incremental, full_reconciliation). NULL when not set.';


--
-- Name: integration_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_runs (
    id bigint NOT NULL,
    job_type text NOT NULL,
    status text NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    finished_at timestamp with time zone,
    records_processed integer DEFAULT 0 NOT NULL,
    error_message text,
    triggered_by text DEFAULT 'scheduler'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    records_inserted integer DEFAULT 0 NOT NULL,
    records_updated integer DEFAULT 0 NOT NULL,
    records_duplicate integer DEFAULT 0 NOT NULL,
    records_skipped integer DEFAULT 0 NOT NULL,
    records_suppressed integer DEFAULT 0 NOT NULL,
    records_failed integer DEFAULT 0 NOT NULL,
    run_details jsonb,
    run_mode text,
    records_unchanged integer DEFAULT 0 NOT NULL,
    records_reactivated integer DEFAULT 0 NOT NULL,
    records_removed integer DEFAULT 0 NOT NULL,
    CONSTRAINT integration_runs_status_check CHECK ((status = ANY (ARRAY['running'::text, 'success'::text, 'failed'::text, 'skipped_unchanged'::text])))
);


--
-- Name: COLUMN integration_runs.records_duplicate; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.integration_runs.records_duplicate IS 'DEPRECATED alias of records_unchanged, retained for API backward compatibility. Use records_unchanged.';


--
-- Name: COLUMN integration_runs.run_details; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.integration_runs.run_details IS 'Provider-specific JSON metrics such as page totals, retries and lookup refresh outcomes.';


--
-- Name: COLUMN integration_runs.run_mode; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.integration_runs.run_mode IS 'Execution mode such as incremental, full_reconciliation, or dry_run.';


--
-- Name: COLUMN integration_runs.records_unchanged; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.integration_runs.records_unchanged IS 'Rows seen again with identical canonical content fingerprint. No physical UPDATE was issued for these.';


--
-- Name: COLUMN integration_runs.records_reactivated; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.integration_runs.records_reactivated IS 'Previously inactive/expired/missing memberships that returned in a successful run.';


--
-- Name: COLUMN integration_runs.records_removed; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.integration_runs.records_removed IS 'Memberships marked missing/inactive by a successful FULL snapshot reconciliation only.';


--
-- Name: integration_runs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.integration_runs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: integration_runs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.integration_runs_id_seq OWNED BY public.integration_runs.id;


--
-- Name: integration_source_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_source_state (
    source_name text NOT NULL,
    content_hash text,
    items_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: ioc_abuseipdb_enrichment; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_abuseipdb_enrichment (
    id bigint NOT NULL,
    ip text NOT NULL,
    provider_status text,
    max_age_days integer DEFAULT 90 NOT NULL,
    verbose_enabled boolean DEFAULT false NOT NULL,
    normalized_summary jsonb DEFAULT '{}'::jsonb NOT NULL,
    raw_json jsonb,
    error_message text,
    last_enriched_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: ioc_abuseipdb_enrichment_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ioc_abuseipdb_enrichment_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ioc_abuseipdb_enrichment_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ioc_abuseipdb_enrichment_id_seq OWNED BY public.ioc_abuseipdb_enrichment.id;


--
-- Name: ioc_activity_incident_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ioc_activity_incident_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ioc_analyst_intelligence; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_analyst_intelligence (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    ioc_id bigint NOT NULL,
    ioc_observable_type text NOT NULL,
    title text NOT NULL,
    url text,
    source_name text,
    reference_type text DEFAULT 'other'::text NOT NULL,
    tlp text DEFAULT 'clear'::text NOT NULL,
    confidence text DEFAULT 'unknown'::text NOT NULL,
    assessment_impact text DEFAULT 'context_only'::text NOT NULL,
    note text,
    created_by uuid,
    created_by_username text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_by uuid,
    updated_by_username text,
    updated_at timestamp with time zone,
    deleted_by uuid,
    deleted_by_username text,
    deleted_at timestamp with time zone,
    CONSTRAINT ioc_analyst_intelligence_assessment_impact_chk CHECK ((assessment_impact = ANY (ARRAY['supports_malicious'::text, 'supports_benign'::text, 'context_only'::text, 'needs_review'::text]))),
    CONSTRAINT ioc_analyst_intelligence_confidence_chk CHECK ((confidence = ANY (ARRAY['unknown'::text, 'low'::text, 'medium'::text, 'high'::text]))),
    CONSTRAINT ioc_analyst_intelligence_note_len_chk CHECK (((note IS NULL) OR (char_length(note) <= 4000))),
    CONSTRAINT ioc_analyst_intelligence_reference_type_chk CHECK ((reference_type = ANY (ARRAY['social'::text, 'free_ti'::text, 'vendor_report'::text, 'sandbox'::text, 'blog'::text, 'internal_note'::text, 'other'::text]))),
    CONSTRAINT ioc_analyst_intelligence_source_name_len_chk CHECK (((source_name IS NULL) OR (char_length(source_name) <= 120))),
    CONSTRAINT ioc_analyst_intelligence_title_len_chk CHECK (((char_length(title) >= 1) AND (char_length(title) <= 200))),
    CONSTRAINT ioc_analyst_intelligence_tlp_chk CHECK ((tlp = ANY (ARRAY['clear'::text, 'green'::text, 'amber'::text, 'red'::text])))
);


--
-- Name: ioc_bulk_query_job_targets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_bulk_query_job_targets (
    job_id uuid NOT NULL,
    ioc_item_id bigint NOT NULL
);


--
-- Name: ioc_bulk_query_jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_bulk_query_jobs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    action text NOT NULL,
    original_query text NOT NULL,
    normalized_query text NOT NULL,
    normalized_ast jsonb NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    status text DEFAULT 'queued'::text NOT NULL,
    match_count bigint,
    succeeded bigint DEFAULT 0 NOT NULL,
    skipped bigint DEFAULT 0 NOT NULL,
    failed bigint DEFAULT 0 NOT NULL,
    progress integer DEFAULT 0 NOT NULL,
    error_sample jsonb,
    requested_by_id bigint,
    requested_by_email text NOT NULL,
    requested_by_public_id text,
    requested_by_role text,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    snapshot_cutoff timestamp with time zone,
    expires_at timestamp with time zone,
    failure_reason text,
    cancel_requested boolean DEFAULT false NOT NULL,
    cancelled_at timestamp with time zone,
    job_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ioc_bulk_query_jobs_action_check CHECK ((action = ANY (ARRAY['tag'::text, 'classification'::text, 'suppress'::text, 'expire'::text]))),
    CONSTRAINT ioc_bulk_query_jobs_progress_check CHECK (((progress >= 0) AND (progress <= 100))),
    CONSTRAINT ioc_bulk_query_jobs_status_check CHECK ((status = ANY (ARRAY['queued'::text, 'processing'::text, 'completed'::text, 'failed'::text, 'cancelled'::text, 'expired'::text])))
);


--
-- Name: ioc_deep_search_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_deep_search_results (
    deep_search_id uuid NOT NULL,
    "position" bigint NOT NULL,
    ioc_item_id bigint NOT NULL,
    ioc_observable_type text NOT NULL,
    public_id uuid NOT NULL,
    observable text NOT NULL,
    status text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    first_seen_at timestamp with time zone,
    artifact_id uuid
);


--
-- Name: ioc_deep_searches; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_deep_searches (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    original_query text NOT NULL,
    normalized_query text NOT NULL,
    normalized_ast jsonb NOT NULL,
    query_fingerprint text NOT NULL,
    classification_reason text,
    origin text DEFAULT 'classified'::text NOT NULL,
    status text DEFAULT 'queued'::text NOT NULL,
    requested_by_id bigint,
    requested_by_email text NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    snapshot_cutoff timestamp with time zone,
    match_count bigint,
    duration_ms bigint,
    progress integer DEFAULT 0 NOT NULL,
    expires_at timestamp with time zone,
    failure_reason text,
    cancel_requested boolean DEFAULT false NOT NULL,
    cancelled_at timestamp with time zone,
    job_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ioc_deep_searches_origin_check CHECK ((origin = ANY (ARRAY['classified'::text, 'timeout_fallback'::text]))),
    CONSTRAINT ioc_deep_searches_progress_check CHECK (((progress >= 0) AND (progress <= 100))),
    CONSTRAINT ioc_deep_searches_status_check CHECK ((status = ANY (ARRAY['queued'::text, 'running'::text, 'completed'::text, 'failed'::text, 'expired'::text, 'cancelled'::text])))
);


--
-- Name: ioc_items; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_items (
    id bigint NOT NULL,
    observable text NOT NULL,
    observable_type text NOT NULL,
    source_name text NOT NULL,
    source_url text,
    confidence text DEFAULT 'medium'::text NOT NULL,
    category text,
    note text,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    public_id uuid DEFAULT gen_random_uuid() NOT NULL,
    first_seen_log timestamp with time zone,
    last_seen_log timestamp with time zone,
    status text DEFAULT 'active'::text NOT NULL,
    expires_at timestamp with time zone,
    expired_at timestamp with time zone,
    expiration_reason text,
    manual_status_override boolean DEFAULT false NOT NULL,
    manual_status text,
    manual_expires_at timestamp with time zone,
    manual_override_reason text,
    manual_override_by_user_id uuid,
    manual_override_at timestamp with time zone,
    source_confidence text,
    feed_default_confidence text,
    analyst_confidence_override text,
    analyst_confidence_override_reason text,
    analyst_confidence_overridden_by uuid,
    analyst_confidence_overridden_at timestamp with time zone,
    ioc_source_id bigint,
    confidence_source text,
    confidence_source_name text,
    threat_classification text DEFAULT 'unknown'::text NOT NULL,
    reactivated_by_match_at timestamp with time zone,
    threat_actor_id uuid,
    provider_fingerprint text,
    created_origin text,
    created_by_user_id uuid,
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT ioc_items_created_origin_check CHECK (((created_origin IS NULL) OR (created_origin = ANY (ARRAY['manual_add'::text, 'api'::text])))),
    CONSTRAINT ioc_items_manual_status_check CHECK (((manual_status IS NULL) OR (manual_status = ANY (ARRAY['active'::text, 'expired'::text])))),
    CONSTRAINT ioc_items_status_check CHECK ((status = ANY (ARRAY['active'::text, 'expired'::text, 'disabled'::text, 'suppressed'::text])))
)
PARTITION BY LIST (observable_type);
ALTER TABLE ONLY public.ioc_items ALTER COLUMN observable SET STATISTICS 500;
ALTER TABLE ONLY public.ioc_items ALTER COLUMN source_name SET STATISTICS 500;
ALTER TABLE ONLY public.ioc_items ALTER COLUMN created_at SET STATISTICS 500;


--
-- Name: COLUMN ioc_items.confidence_source; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.ioc_items.confidence_source IS 'Provenance of confidence: manual_entry, ioc_source_default, feed_default, feed_entry, analyst_override, unknown';


--
-- Name: ioc_items_id_seq1; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ioc_items_id_seq1
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ioc_items_id_seq1; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ioc_items_id_seq1 OWNED BY public.ioc_items.id;


--
-- Name: ioc_domain; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_domain (
    id bigint DEFAULT nextval('public.ioc_items_id_seq1'::regclass) NOT NULL,
    observable text NOT NULL,
    observable_type text NOT NULL,
    source_name text NOT NULL,
    source_url text,
    confidence text DEFAULT 'medium'::text NOT NULL,
    category text,
    note text,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    public_id uuid DEFAULT gen_random_uuid() NOT NULL,
    first_seen_log timestamp with time zone,
    last_seen_log timestamp with time zone,
    status text DEFAULT 'active'::text NOT NULL,
    expires_at timestamp with time zone,
    expired_at timestamp with time zone,
    expiration_reason text,
    manual_status_override boolean DEFAULT false NOT NULL,
    manual_status text,
    manual_expires_at timestamp with time zone,
    manual_override_reason text,
    manual_override_by_user_id uuid,
    manual_override_at timestamp with time zone,
    source_confidence text,
    feed_default_confidence text,
    analyst_confidence_override text,
    analyst_confidence_override_reason text,
    analyst_confidence_overridden_by uuid,
    analyst_confidence_overridden_at timestamp with time zone,
    ioc_source_id bigint,
    confidence_source text,
    confidence_source_name text,
    threat_classification text DEFAULT 'unknown'::text NOT NULL,
    reactivated_by_match_at timestamp with time zone,
    threat_actor_id uuid,
    provider_fingerprint text,
    created_origin text,
    created_by_user_id uuid,
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT ioc_items_created_origin_check CHECK (((created_origin IS NULL) OR (created_origin = ANY (ARRAY['manual_add'::text, 'api'::text])))),
    CONSTRAINT ioc_items_manual_status_check CHECK (((manual_status IS NULL) OR (manual_status = ANY (ARRAY['active'::text, 'expired'::text])))),
    CONSTRAINT ioc_items_status_check CHECK ((status = ANY (ARRAY['active'::text, 'expired'::text, 'disabled'::text, 'suppressed'::text])))
);
ALTER TABLE ONLY public.ioc_domain ALTER COLUMN observable SET STATISTICS 500;
ALTER TABLE ONLY public.ioc_domain ALTER COLUMN source_name SET STATISTICS 500;
ALTER TABLE ONLY public.ioc_domain ALTER COLUMN created_at SET STATISTICS 500;


--
-- Name: ioc_domain_enrichment; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_domain_enrichment (
    id bigint NOT NULL,
    observable_value text NOT NULL,
    root_domain text NOT NULL,
    ioc_type text,
    rdap_status text,
    registrar text,
    registration_date timestamp with time zone,
    expiration_date timestamp with time zone,
    last_changed_date timestamp with time zone,
    domain_age_days integer,
    nameservers jsonb DEFAULT '[]'::jsonb NOT NULL,
    statuses jsonb DEFAULT '[]'::jsonb NOT NULL,
    derived_signals jsonb DEFAULT '{}'::jsonb NOT NULL,
    rdap_raw_json jsonb,
    error_message text,
    last_enriched_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_success_at timestamp with time zone,
    last_attempt_at timestamp with time zone,
    last_error text
);


--
-- Name: ioc_domain_enrichment_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ioc_domain_enrichment_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ioc_domain_enrichment_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ioc_domain_enrichment_id_seq OWNED BY public.ioc_domain_enrichment.id;


--
-- Name: ioc_enrichments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_enrichments (
    id bigint NOT NULL,
    ioc_id bigint,
    ioc_value text NOT NULL,
    ioc_type text NOT NULL,
    provider text DEFAULT 'virustotal'::text NOT NULL,
    status text NOT NULL,
    normalized_summary jsonb,
    raw_response jsonb,
    error_message text,
    fetched_at timestamp with time zone,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: ioc_enrichments_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ioc_enrichments_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ioc_enrichments_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ioc_enrichments_id_seq OWNED BY public.ioc_enrichments.id;


--
-- Name: ioc_feed_memberships; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_feed_memberships (
    id bigint NOT NULL,
    ioc_item_id bigint NOT NULL,
    ioc_observable_type text NOT NULL,
    feed_id uuid NOT NULL,
    first_seen_in_feed timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_in_feed timestamp with time zone DEFAULT now() NOT NULL,
    missing_since timestamp with time zone,
    policy_expires_at timestamp with time zone,
    expires_at timestamp with time zone,
    expired_at timestamp with time zone,
    status text DEFAULT 'active'::text NOT NULL,
    expiration_reason text,
    override_enabled boolean DEFAULT false NOT NULL,
    override_expires_at timestamp with time zone,
    override_status text,
    override_reason text,
    override_by_user_id uuid,
    override_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    explicit_confidence text,
    purged_at timestamp with time zone,
    purged_by uuid,
    purged_by_username text,
    purge_reason text,
    content_fingerprint text,
    last_changed_in_source timestamp with time zone,
    CONSTRAINT ioc_feed_memberships_override_status_check CHECK (((override_status IS NULL) OR (override_status = ANY (ARRAY['active'::text, 'expired'::text])))),
    CONSTRAINT ioc_feed_memberships_status_check CHECK ((status = ANY (ARRAY['active'::text, 'expired'::text, 'purged'::text])))
);


--
-- Name: COLUMN ioc_feed_memberships.last_seen_in_feed; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.ioc_feed_memberships.last_seen_in_feed IS 'LEGACY/TECHNICAL. Written only for last_seen_ttl expiration policies and internal recency sorting. Do NOT surface in API or UI; use last_changed_in_source instead.';


--
-- Name: COLUMN ioc_feed_memberships.content_fingerprint; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.ioc_feed_memberships.content_fingerprint IS 'Canonical sha256 of source-controlled normalized content. NULL = not yet adopted (treated as unchanged on first observation).';


--
-- Name: COLUMN ioc_feed_memberships.last_changed_in_source; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.ioc_feed_memberships.last_changed_in_source IS 'ANALYST-VISIBLE. Advances only on genuine source content change or reactivation. NULL falls back to first_seen_in_feed.';


--
-- Name: ioc_feed_memberships_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ioc_feed_memberships_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ioc_feed_memberships_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ioc_feed_memberships_id_seq OWNED BY public.ioc_feed_memberships.id;


--
-- Name: ioc_feed_source_evidence; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_feed_source_evidence (
    id bigint NOT NULL,
    ioc_item_id bigint NOT NULL,
    ioc_observable_type text NOT NULL,
    feed_id uuid NOT NULL,
    source_name text NOT NULL,
    source_url text,
    category text,
    note text,
    confidence text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    provider_metadata jsonb,
    provider_fingerprint text
);


--
-- Name: TABLE ioc_feed_source_evidence; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.ioc_feed_source_evidence IS 'Per-feed import metadata (note, category, source URL) for IOCs seen from multiple feeds.';


--
-- Name: COLUMN ioc_feed_source_evidence.provider_metadata; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.ioc_feed_source_evidence.provider_metadata IS 'Sanitized per-provider record metadata; provider timestamps do not control IOC lifecycle.';


--
-- Name: COLUMN ioc_feed_source_evidence.provider_fingerprint; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.ioc_feed_source_evidence.provider_fingerprint IS 'Provider-scoped semantic fingerprint used to avoid evidence updates for volatile-only metadata changes.';


--
-- Name: ioc_feed_source_evidence_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ioc_feed_source_evidence_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ioc_feed_source_evidence_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ioc_feed_source_evidence_id_seq OWNED BY public.ioc_feed_source_evidence.id;


--
-- Name: ioc_file_hash; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_file_hash (
    id bigint DEFAULT nextval('public.ioc_items_id_seq1'::regclass) NOT NULL,
    observable text NOT NULL,
    observable_type text NOT NULL,
    source_name text NOT NULL,
    source_url text,
    confidence text DEFAULT 'medium'::text NOT NULL,
    category text,
    note text,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    public_id uuid DEFAULT gen_random_uuid() NOT NULL,
    first_seen_log timestamp with time zone,
    last_seen_log timestamp with time zone,
    status text DEFAULT 'active'::text NOT NULL,
    expires_at timestamp with time zone,
    expired_at timestamp with time zone,
    expiration_reason text,
    manual_status_override boolean DEFAULT false NOT NULL,
    manual_status text,
    manual_expires_at timestamp with time zone,
    manual_override_reason text,
    manual_override_by_user_id uuid,
    manual_override_at timestamp with time zone,
    source_confidence text,
    feed_default_confidence text,
    analyst_confidence_override text,
    analyst_confidence_override_reason text,
    analyst_confidence_overridden_by uuid,
    analyst_confidence_overridden_at timestamp with time zone,
    ioc_source_id bigint,
    confidence_source text,
    confidence_source_name text,
    threat_classification text DEFAULT 'unknown'::text NOT NULL,
    reactivated_by_match_at timestamp with time zone,
    threat_actor_id uuid,
    provider_fingerprint text,
    created_origin text,
    created_by_user_id uuid,
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT ioc_items_created_origin_check CHECK (((created_origin IS NULL) OR (created_origin = ANY (ARRAY['manual_add'::text, 'api'::text])))),
    CONSTRAINT ioc_items_manual_status_check CHECK (((manual_status IS NULL) OR (manual_status = ANY (ARRAY['active'::text, 'expired'::text])))),
    CONSTRAINT ioc_items_status_check CHECK ((status = ANY (ARRAY['active'::text, 'expired'::text, 'disabled'::text, 'suppressed'::text])))
);
ALTER TABLE ONLY public.ioc_file_hash ALTER COLUMN observable SET STATISTICS 500;
ALTER TABLE ONLY public.ioc_file_hash ALTER COLUMN source_name SET STATISTICS 500;
ALTER TABLE ONLY public.ioc_file_hash ALTER COLUMN created_at SET STATISTICS 500;


--
-- Name: ioc_ip; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_ip (
    id bigint DEFAULT nextval('public.ioc_items_id_seq1'::regclass) NOT NULL,
    observable text NOT NULL,
    observable_type text NOT NULL,
    source_name text NOT NULL,
    source_url text,
    confidence text DEFAULT 'medium'::text NOT NULL,
    category text,
    note text,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    public_id uuid DEFAULT gen_random_uuid() NOT NULL,
    first_seen_log timestamp with time zone,
    last_seen_log timestamp with time zone,
    status text DEFAULT 'active'::text NOT NULL,
    expires_at timestamp with time zone,
    expired_at timestamp with time zone,
    expiration_reason text,
    manual_status_override boolean DEFAULT false NOT NULL,
    manual_status text,
    manual_expires_at timestamp with time zone,
    manual_override_reason text,
    manual_override_by_user_id uuid,
    manual_override_at timestamp with time zone,
    source_confidence text,
    feed_default_confidence text,
    analyst_confidence_override text,
    analyst_confidence_override_reason text,
    analyst_confidence_overridden_by uuid,
    analyst_confidence_overridden_at timestamp with time zone,
    ioc_source_id bigint,
    confidence_source text,
    confidence_source_name text,
    threat_classification text DEFAULT 'unknown'::text NOT NULL,
    reactivated_by_match_at timestamp with time zone,
    threat_actor_id uuid,
    provider_fingerprint text,
    created_origin text,
    created_by_user_id uuid,
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT ioc_items_created_origin_check CHECK (((created_origin IS NULL) OR (created_origin = ANY (ARRAY['manual_add'::text, 'api'::text])))),
    CONSTRAINT ioc_items_manual_status_check CHECK (((manual_status IS NULL) OR (manual_status = ANY (ARRAY['active'::text, 'expired'::text])))),
    CONSTRAINT ioc_items_status_check CHECK ((status = ANY (ARRAY['active'::text, 'expired'::text, 'disabled'::text, 'suppressed'::text])))
);
ALTER TABLE ONLY public.ioc_ip ALTER COLUMN observable SET STATISTICS 500;
ALTER TABLE ONLY public.ioc_ip ALTER COLUMN source_name SET STATISTICS 500;
ALTER TABLE ONLY public.ioc_ip ALTER COLUMN created_at SET STATISTICS 500;


--
-- Name: ioc_ip_enrichment; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_ip_enrichment (
    id bigint NOT NULL,
    ip text NOT NULL,
    provider text DEFAULT 'ipinfo_lite'::text NOT NULL,
    provider_status text,
    asn text,
    as_name text,
    as_domain text,
    country_code text,
    country text,
    continent_code text,
    continent text,
    derived_signals jsonb DEFAULT '{}'::jsonb NOT NULL,
    raw_json jsonb,
    error_message text,
    last_enriched_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    normalized_ip text
);


--
-- Name: ioc_ip_enrichment_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ioc_ip_enrichment_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ioc_ip_enrichment_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ioc_ip_enrichment_id_seq OWNED BY public.ioc_ip_enrichment.id;


--
-- Name: ioc_ip_geo_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_ip_geo_cache (
    ip inet NOT NULL,
    country_code text,
    asn bigint,
    as_name text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: ioc_ipv6; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_ipv6 (
    id bigint DEFAULT nextval('public.ioc_items_id_seq1'::regclass) NOT NULL,
    observable text NOT NULL,
    observable_type text NOT NULL,
    source_name text NOT NULL,
    source_url text,
    confidence text DEFAULT 'medium'::text NOT NULL,
    category text,
    note text,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    public_id uuid DEFAULT gen_random_uuid() NOT NULL,
    first_seen_log timestamp with time zone,
    last_seen_log timestamp with time zone,
    status text DEFAULT 'active'::text NOT NULL,
    expires_at timestamp with time zone,
    expired_at timestamp with time zone,
    expiration_reason text,
    manual_status_override boolean DEFAULT false NOT NULL,
    manual_status text,
    manual_expires_at timestamp with time zone,
    manual_override_reason text,
    manual_override_by_user_id uuid,
    manual_override_at timestamp with time zone,
    source_confidence text,
    feed_default_confidence text,
    analyst_confidence_override text,
    analyst_confidence_override_reason text,
    analyst_confidence_overridden_by uuid,
    analyst_confidence_overridden_at timestamp with time zone,
    ioc_source_id bigint,
    confidence_source text,
    confidence_source_name text,
    threat_classification text DEFAULT 'unknown'::text NOT NULL,
    reactivated_by_match_at timestamp with time zone,
    threat_actor_id uuid,
    provider_fingerprint text,
    created_origin text,
    created_by_user_id uuid,
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT ioc_items_created_origin_check CHECK (((created_origin IS NULL) OR (created_origin = ANY (ARRAY['manual_add'::text, 'api'::text])))),
    CONSTRAINT ioc_items_manual_status_check CHECK (((manual_status IS NULL) OR (manual_status = ANY (ARRAY['active'::text, 'expired'::text])))),
    CONSTRAINT ioc_items_status_check CHECK ((status = ANY (ARRAY['active'::text, 'expired'::text, 'disabled'::text, 'suppressed'::text])))
);


--
-- Name: ioc_items_other; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_items_other (
    id bigint DEFAULT nextval('public.ioc_items_id_seq1'::regclass) NOT NULL,
    observable text NOT NULL,
    observable_type text NOT NULL,
    source_name text NOT NULL,
    source_url text,
    confidence text DEFAULT 'medium'::text NOT NULL,
    category text,
    note text,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    public_id uuid DEFAULT gen_random_uuid() NOT NULL,
    first_seen_log timestamp with time zone,
    last_seen_log timestamp with time zone,
    status text DEFAULT 'active'::text NOT NULL,
    expires_at timestamp with time zone,
    expired_at timestamp with time zone,
    expiration_reason text,
    manual_status_override boolean DEFAULT false NOT NULL,
    manual_status text,
    manual_expires_at timestamp with time zone,
    manual_override_reason text,
    manual_override_by_user_id uuid,
    manual_override_at timestamp with time zone,
    source_confidence text,
    feed_default_confidence text,
    analyst_confidence_override text,
    analyst_confidence_override_reason text,
    analyst_confidence_overridden_by uuid,
    analyst_confidence_overridden_at timestamp with time zone,
    ioc_source_id bigint,
    confidence_source text,
    confidence_source_name text,
    threat_classification text DEFAULT 'unknown'::text NOT NULL,
    reactivated_by_match_at timestamp with time zone,
    threat_actor_id uuid,
    provider_fingerprint text,
    created_origin text,
    created_by_user_id uuid,
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT ioc_items_created_origin_check CHECK (((created_origin IS NULL) OR (created_origin = ANY (ARRAY['manual_add'::text, 'api'::text])))),
    CONSTRAINT ioc_items_manual_status_check CHECK (((manual_status IS NULL) OR (manual_status = ANY (ARRAY['active'::text, 'expired'::text])))),
    CONSTRAINT ioc_items_status_check CHECK ((status = ANY (ARRAY['active'::text, 'expired'::text, 'disabled'::text, 'suppressed'::text])))
);
ALTER TABLE ONLY public.ioc_items_other ALTER COLUMN observable SET STATISTICS 500;
ALTER TABLE ONLY public.ioc_items_other ALTER COLUMN source_name SET STATISTICS 500;
ALTER TABLE ONLY public.ioc_items_other ALTER COLUMN created_at SET STATISTICS 500;


--
-- Name: ioc_list_stats_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_list_stats_snapshots (
    id bigint NOT NULL,
    snapshot_key text NOT NULL,
    payload jsonb NOT NULL,
    calculated_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: ioc_list_stats_snapshots_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ioc_list_stats_snapshots_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ioc_list_stats_snapshots_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ioc_list_stats_snapshots_id_seq OWNED BY public.ioc_list_stats_snapshots.id;


--
-- Name: ioc_manual_source_memberships; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_manual_source_memberships (
    id bigint NOT NULL,
    ioc_item_id bigint NOT NULL,
    ioc_observable_type text NOT NULL,
    ioc_source_id bigint,
    source_name text NOT NULL,
    status text DEFAULT 'moved'::text NOT NULL,
    confidence text,
    confidence_source text,
    confidence_source_name text,
    manual_expires_at timestamp with time zone,
    moved_to_source_id bigint,
    moved_at timestamp with time zone,
    moved_by uuid,
    move_reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    first_seen_at timestamp with time zone,
    last_seen_at timestamp with time zone,
    CONSTRAINT ioc_manual_source_memberships_status_check CHECK ((status = ANY (ARRAY['active'::text, 'moved'::text, 'superseded'::text, 'inactive'::text, 'removed'::text])))
);


--
-- Name: ioc_manual_source_memberships_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ioc_manual_source_memberships_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ioc_manual_source_memberships_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ioc_manual_source_memberships_id_seq OWNED BY public.ioc_manual_source_memberships.id;


--
-- Name: ioc_observables; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_observables (
    id bigint NOT NULL,
    ioc_public_id uuid NOT NULL,
    observable_type text NOT NULL,
    observable_value text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_observable_type CHECK ((observable_type = ANY (ARRAY['md5'::text, 'sha1'::text, 'sha256'::text, 'ssdeep'::text, 'imphash'::text, 'tlsh'::text, 'ip'::text, 'ipv6'::text, 'domain'::text, 'url'::text])))
);


--
-- Name: TABLE ioc_observables; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.ioc_observables IS 'Index of all observables per IOC for fast lookup; observable_value stored normalized (lowercase).';


--
-- Name: ioc_observables_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ioc_observables_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ioc_observables_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ioc_observables_id_seq OWNED BY public.ioc_observables.id;


--
-- Name: ioc_saved_searches; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_saved_searches (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    description text,
    original_query text NOT NULL,
    normalized_query text NOT NULL,
    normalized_ast jsonb NOT NULL,
    owner_id bigint NOT NULL,
    owner_username text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: ioc_search_exports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_search_exports (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    original_query text NOT NULL,
    normalized_query text NOT NULL,
    normalized_ast jsonb NOT NULL,
    format text DEFAULT 'csv'::text NOT NULL,
    selected_columns text[] NOT NULL,
    scope text DEFAULT 'all'::text NOT NULL,
    status text DEFAULT 'queued'::text NOT NULL,
    requested_by_id bigint,
    requested_by_email text NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    snapshot_cutoff timestamp with time zone,
    record_count bigint,
    file_size bigint,
    storage_path text,
    progress integer DEFAULT 0 NOT NULL,
    expires_at timestamp with time zone,
    failure_reason text,
    cancel_requested boolean DEFAULT false NOT NULL,
    cancelled_at timestamp with time zone,
    retry_count integer DEFAULT 0 NOT NULL,
    job_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ioc_search_exports_format_check CHECK ((format = ANY (ARRAY['csv'::text, 'csv_gz'::text]))),
    CONSTRAINT ioc_search_exports_progress_check CHECK (((progress >= 0) AND (progress <= 100))),
    CONSTRAINT ioc_search_exports_scope_check CHECK ((scope = ANY (ARRAY['all'::text, 'preview'::text]))),
    CONSTRAINT ioc_search_exports_status_check CHECK ((status = ANY (ARRAY['queued'::text, 'processing'::text, 'ready'::text, 'failed'::text, 'expired'::text, 'cancelled'::text])))
);


--
-- Name: ioc_source_expiration_type_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_source_expiration_type_policies (
    id bigint NOT NULL,
    source_id bigint NOT NULL,
    ioc_type text NOT NULL,
    mode text NOT NULL,
    ttl_days integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ioc_source_expiration_type_policies_check CHECK (((mode <> 'fixed_ttl'::text) OR ((ttl_days IS NOT NULL) AND (ttl_days > 0)))),
    CONSTRAINT ioc_source_expiration_type_policies_ioc_type_check CHECK ((ioc_type = ANY (ARRAY['domain'::text, 'ip'::text, 'url'::text, 'file_hash'::text]))),
    CONSTRAINT ioc_source_expiration_type_policies_mode_check CHECK ((mode = ANY (ARRAY['inherit'::text, 'no_expire'::text, 'fixed_ttl'::text])))
);


--
-- Name: ioc_source_expiration_type_policies_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ioc_source_expiration_type_policies_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ioc_source_expiration_type_policies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ioc_source_expiration_type_policies_id_seq OWNED BY public.ioc_source_expiration_type_policies.id;


--
-- Name: ioc_source_tag_overrides; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_source_tag_overrides (
    id bigint NOT NULL,
    ioc_id bigint NOT NULL,
    ioc_observable_type text NOT NULL,
    tag_value text NOT NULL,
    tag_normalized text NOT NULL,
    source_name text NOT NULL,
    action text DEFAULT 'hidden'::text NOT NULL,
    created_by bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    restored_at timestamp with time zone,
    restored_by bigint,
    CONSTRAINT ioc_source_tag_overrides_action_check CHECK ((action = 'hidden'::text))
);


--
-- Name: ioc_source_tag_overrides_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ioc_source_tag_overrides_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ioc_source_tag_overrides_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ioc_source_tag_overrides_id_seq OWNED BY public.ioc_source_tag_overrides.id;


--
-- Name: ioc_sources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_sources (
    id bigint NOT NULL,
    name text NOT NULL,
    display_name text,
    description text,
    source_type text DEFAULT 'manual'::text NOT NULL,
    default_confidence text,
    default_expire_policy text,
    default_expire_days integer,
    active boolean DEFAULT true NOT NULL,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    default_threat_classification text,
    archived_at timestamp with time zone,
    archived_by uuid,
    color text,
    CONSTRAINT chk_ioc_sources_color_hex CHECK (((color IS NULL) OR (color ~ '^#[0-9a-f]{6}$'::text))),
    CONSTRAINT chk_ioc_sources_name_format CHECK ((name ~ '^[A-Za-z0-9_-]{3,64}$'::text)),
    CONSTRAINT ioc_sources_default_confidence_check CHECK (((default_confidence IS NULL) OR (default_confidence = ANY (ARRAY['low'::text, 'medium'::text, 'high'::text])))),
    CONSTRAINT ioc_sources_default_expire_days_check CHECK (((default_expire_days IS NULL) OR ((default_expire_days > 0) AND (default_expire_days <= 3650)))),
    CONSTRAINT ioc_sources_default_expire_policy_check CHECK (((default_expire_policy IS NULL) OR (default_expire_policy = ANY (ARRAY['never'::text, 'expire_after_days'::text, 'custom_date'::text])))),
    CONSTRAINT ioc_sources_source_type_check CHECK ((source_type = ANY (ARRAY['manual'::text, 'internal_hunting'::text, 'external_report'::text, 'feed'::text, 'test'::text])))
);


--
-- Name: COLUMN ioc_sources.color; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.ioc_sources.color IS 'Managed badge color as #rrggbb (lowercase). NULL = frontend fallback.';


--
-- Name: ioc_sources_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ioc_sources_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ioc_sources_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ioc_sources_id_seq OWNED BY public.ioc_sources.id;


--
-- Name: ioc_spamhaus_drop_enrichment; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_spamhaus_drop_enrichment (
    id bigint NOT NULL,
    lookup_ip text NOT NULL,
    lookup_type text DEFAULT 'ip'::text NOT NULL,
    observable_value text,
    ioc_type text,
    provider_status text NOT NULL,
    listed boolean,
    matched_cidr text,
    list_type text,
    sblid text,
    rir text,
    dataset_status text,
    last_sync_at timestamp with time zone,
    error_code text,
    error_message text,
    raw_json jsonb,
    enriched_at timestamp with time zone,
    last_attempt_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ioc_spamhaus_drop_enrichment_lookup_type_check CHECK ((lookup_type = 'ip'::text)),
    CONSTRAINT ioc_spamhaus_drop_enrichment_provider_status_check CHECK ((provider_status = ANY (ARRAY['listed'::text, 'not_listed'::text, 'failed'::text])))
);


--
-- Name: ioc_spamhaus_drop_enrichment_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ioc_spamhaus_drop_enrichment_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ioc_spamhaus_drop_enrichment_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ioc_spamhaus_drop_enrichment_id_seq OWNED BY public.ioc_spamhaus_drop_enrichment.id;


--
-- Name: ioc_suppressions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_suppressions (
    id bigint NOT NULL,
    ioc_value text NOT NULL,
    ioc_type text NOT NULL,
    scope text DEFAULT 'global'::text NOT NULL,
    source_name text,
    reason text NOT NULL,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    active boolean DEFAULT true NOT NULL,
    deleted_at timestamp with time zone,
    deleted_by text
);


--
-- Name: ioc_suppressions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ioc_suppressions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ioc_suppressions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ioc_suppressions_id_seq OWNED BY public.ioc_suppressions.id;


--
-- Name: ioc_tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_tags (
    ioc_id bigint NOT NULL,
    ioc_observable_type text NOT NULL,
    tag_id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by bigint,
    origin text DEFAULT 'manual'::text NOT NULL,
    source_name text,
    source_key text DEFAULT ''::text NOT NULL,
    CONSTRAINT ioc_tags_origin_chk CHECK ((origin = ANY (ARRAY['manual'::text, 'integration'::text]))),
    CONSTRAINT ioc_tags_origin_source_chk CHECK ((((origin = 'manual'::text) AND (source_name IS NULL) AND (source_key = ''::text)) OR ((origin = 'integration'::text) AND (source_name IS NOT NULL) AND (btrim(source_name) <> ''::text) AND (source_key = lower(source_name)))))
);


--
-- Name: ioc_threat_actors; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_threat_actors (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    ioc_id bigint NOT NULL,
    ioc_observable_type text NOT NULL,
    threat_actor_id uuid NOT NULL,
    source_type text DEFAULT 'analyst'::text NOT NULL,
    source_name text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by text,
    updated_by text
);


--
-- Name: ioc_threat_classification_overrides; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_threat_classification_overrides (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    ioc_id bigint NOT NULL,
    ioc_observable_type text NOT NULL,
    classification_slug text NOT NULL,
    action text NOT NULL,
    source_name text,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    cleared_at timestamp with time zone,
    cleared_by text,
    CONSTRAINT ioc_threat_classification_overrides_action_check CHECK ((action = ANY (ARRAY['add'::text, 'suppress'::text])))
);


--
-- Name: ioc_threat_classifications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_threat_classifications (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    ioc_id bigint NOT NULL,
    ioc_observable_type text NOT NULL,
    classification_slug text NOT NULL,
    source_type text DEFAULT 'analyst'::text NOT NULL,
    source_name text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by text,
    updated_by text
);


--
-- Name: ioc_url; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_url (
    id bigint DEFAULT nextval('public.ioc_items_id_seq1'::regclass) NOT NULL,
    observable text NOT NULL,
    observable_type text NOT NULL,
    source_name text NOT NULL,
    source_url text,
    confidence text DEFAULT 'medium'::text NOT NULL,
    category text,
    note text,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    public_id uuid DEFAULT gen_random_uuid() NOT NULL,
    first_seen_log timestamp with time zone,
    last_seen_log timestamp with time zone,
    status text DEFAULT 'active'::text NOT NULL,
    expires_at timestamp with time zone,
    expired_at timestamp with time zone,
    expiration_reason text,
    manual_status_override boolean DEFAULT false NOT NULL,
    manual_status text,
    manual_expires_at timestamp with time zone,
    manual_override_reason text,
    manual_override_by_user_id uuid,
    manual_override_at timestamp with time zone,
    source_confidence text,
    feed_default_confidence text,
    analyst_confidence_override text,
    analyst_confidence_override_reason text,
    analyst_confidence_overridden_by uuid,
    analyst_confidence_overridden_at timestamp with time zone,
    ioc_source_id bigint,
    confidence_source text,
    confidence_source_name text,
    threat_classification text DEFAULT 'unknown'::text NOT NULL,
    reactivated_by_match_at timestamp with time zone,
    threat_actor_id uuid,
    provider_fingerprint text,
    created_origin text,
    created_by_user_id uuid,
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT ioc_items_created_origin_check CHECK (((created_origin IS NULL) OR (created_origin = ANY (ARRAY['manual_add'::text, 'api'::text])))),
    CONSTRAINT ioc_items_manual_status_check CHECK (((manual_status IS NULL) OR (manual_status = ANY (ARRAY['active'::text, 'expired'::text])))),
    CONSTRAINT ioc_items_status_check CHECK ((status = ANY (ARRAY['active'::text, 'expired'::text, 'disabled'::text, 'suppressed'::text])))
);
ALTER TABLE ONLY public.ioc_url ALTER COLUMN observable SET STATISTICS 500;
ALTER TABLE ONLY public.ioc_url ALTER COLUMN source_name SET STATISTICS 500;
ALTER TABLE ONLY public.ioc_url ALTER COLUMN created_at SET STATISTICS 500;


--
-- Name: malwarebazaar_coverage_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.malwarebazaar_coverage_state (
    feed_key text NOT NULL,
    source_name text NOT NULL,
    status text DEFAULT 'current'::text NOT NULL,
    last_successful_recent_at timestamp with time zone,
    last_recent_oldest_first_seen timestamp with time zone,
    last_recent_newest_first_seen timestamp with time zone,
    covered_through timestamp with time zone,
    gap_from timestamp with time zone,
    gap_to timestamp with time zone,
    recovery_watermark_first_seen timestamp with time zone,
    recovery_scan_lines bigint DEFAULT 0 NOT NULL,
    recovery_dump_identity text,
    last_recovered_through timestamp with time zone,
    last_error text,
    details jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT malwarebazaar_coverage_state_status_check CHECK ((status = ANY (ARRAY['current'::text, 'stale'::text, 'retention_risk'::text, 'gap_pending'::text, 'recovery_running'::text, 'recovery_failed'::text, 'recovered'::text])))
);


--
-- Name: TABLE malwarebazaar_coverage_state; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.malwarebazaar_coverage_state IS 'MalwareBazaar recent.csv continuity cursor and bounded historical recovery watermark. Independent of integration_source_state content hash.';


--
-- Name: published_feed_access_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.published_feed_access_keys (
    id bigint NOT NULL,
    feed_id bigint,
    name text NOT NULL,
    token_hash text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    last_used_at timestamp with time zone,
    last_used_ip text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    key_type text DEFAULT 'feed_access'::text NOT NULL,
    key_prefix text,
    last_four text,
    secret_ciphertext bytea,
    secret_nonce bytea,
    secret_tag bytea,
    expires_at timestamp with time zone,
    created_by text,
    deleted_at timestamp with time zone,
    deleted_by text,
    scopes jsonb DEFAULT '[]'::jsonb NOT NULL,
    CONSTRAINT chk_pf_access_keys_key_type CHECK ((key_type = ANY (ARRAY['feed_access'::text, 'published_feed'::text, 'ioc_management'::text, 'ioc_read'::text]))),
    CONSTRAINT chk_pf_access_keys_scopes CHECK (((jsonb_typeof(scopes) = 'array'::text) AND (jsonb_array_length(scopes) >= 1) AND (scopes <@ '["published_feeds:read", "ioc:create", "ioc:update", "ioc:read", "ioc:export"]'::jsonb)))
);


--
-- Name: published_feed_access_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.published_feed_access_keys_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: published_feed_access_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.published_feed_access_keys_id_seq OWNED BY public.published_feed_access_keys.id;


--
-- Name: published_feed_active_generations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.published_feed_active_generations (
    feed_id bigint NOT NULL,
    snapshot_window text NOT NULL,
    ioc_type_key text NOT NULL,
    generation_id text NOT NULL,
    activated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: published_feed_chunks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.published_feed_chunks (
    id bigint NOT NULL,
    feed_id bigint NOT NULL,
    snapshot_window text NOT NULL,
    chunk_algo_version integer NOT NULL,
    chunk_count integer NOT NULL,
    chunk_key integer NOT NULL,
    format text NOT NULL,
    serializer_version integer NOT NULL,
    content_hash text NOT NULL,
    byte_length bigint NOT NULL,
    item_count bigint NOT NULL,
    storage_path text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_pf_chunks_format CHECK ((format = ANY (ARRAY['txt'::text, 'json'::text, 'stix'::text]))),
    CONSTRAINT chk_pf_chunks_key CHECK (((chunk_key >= 0) AND (chunk_key < chunk_count)))
);


--
-- Name: published_feed_chunks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.published_feed_chunks_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: published_feed_chunks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.published_feed_chunks_id_seq OWNED BY public.published_feed_chunks.id;


--
-- Name: published_feed_generation_chunks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.published_feed_generation_chunks (
    generation_id text NOT NULL,
    format text NOT NULL,
    chunk_key integer NOT NULL,
    chunk_id bigint NOT NULL,
    ordinal integer NOT NULL,
    CONSTRAINT chk_pf_generation_chunks_format CHECK ((format = ANY (ARRAY['txt'::text, 'json'::text, 'stix'::text])))
);


--
-- Name: published_feed_generation_formats; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.published_feed_generation_formats (
    generation_id text NOT NULL,
    format text NOT NULL,
    serializer_version integer NOT NULL,
    header_bytes text DEFAULT ''::text NOT NULL,
    footer_bytes text DEFAULT ''::text NOT NULL,
    separator_bytes text DEFAULT ''::text NOT NULL,
    item_count bigint NOT NULL,
    byte_length bigint NOT NULL,
    strong_etag text NOT NULL,
    recency_head_path text,
    recency_head_hash text,
    recency_head_item_count integer,
    recency_head_byte_length bigint,
    CONSTRAINT chk_pf_generation_formats_format CHECK ((format = ANY (ARRAY['txt'::text, 'json'::text, 'stix'::text])))
);


--
-- Name: published_feed_generations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.published_feed_generations (
    id text NOT NULL,
    feed_id bigint NOT NULL,
    snapshot_window text NOT NULL,
    ioc_type_key text NOT NULL,
    parent_generation_id text,
    state text NOT NULL,
    candidate_cutoff timestamp with time zone NOT NULL,
    generated_at timestamp with time zone NOT NULL,
    activated_at timestamp with time zone,
    superseded_at timestamp with time zone,
    item_count bigint NOT NULL,
    chunk_count integer NOT NULL,
    chunk_algo_version integer NOT NULL,
    formats jsonb NOT NULL,
    config_hash text NOT NULL,
    full_rebuild_reason text,
    generation_metrics jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_pf_generations_formats CHECK (((jsonb_typeof(formats) = 'array'::text) AND (jsonb_array_length(formats) > 0))),
    CONSTRAINT chk_pf_generations_state CHECK ((state = ANY (ARRAY['building'::text, 'ready'::text, 'active'::text, 'superseded'::text, 'failed'::text])))
);


--
-- Name: published_feed_global_watermarks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.published_feed_global_watermarks (
    key text NOT NULL,
    watermark timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: published_feed_ioc_deletes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.published_feed_ioc_deletes (
    id bigint NOT NULL,
    ioc_item_id bigint NOT NULL,
    observable text NOT NULL,
    observable_type text NOT NULL,
    artifact_id uuid,
    deleted_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: published_feed_ioc_deletes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.published_feed_ioc_deletes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: published_feed_ioc_deletes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.published_feed_ioc_deletes_id_seq OWNED BY public.published_feed_ioc_deletes.id;


--
-- Name: published_feed_items; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.published_feed_items (
    feed_id bigint NOT NULL,
    snapshot_window text NOT NULL,
    identity_key text NOT NULL,
    ioc_item_id bigint NOT NULL,
    observable text NOT NULL,
    observable_type text NOT NULL,
    recency_ts timestamp with time zone,
    confidence text,
    category text,
    confidence_rank smallint DEFAULT 0 NOT NULL,
    txt_value text NOT NULL,
    item_json jsonb,
    content_fingerprint text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    partition_identity text,
    chunk_key integer
);


--
-- Name: published_feed_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.published_feed_snapshots (
    id bigint NOT NULL,
    feed_id bigint NOT NULL,
    generated_at timestamp with time zone DEFAULT now() NOT NULL,
    item_count integer DEFAULT 0 NOT NULL,
    content_hash text,
    content text,
    status text DEFAULT 'success'::text NOT NULL,
    error_message text,
    params jsonb,
    storage_path text,
    file_size bigint,
    artifact_format text,
    generation_id text,
    CONSTRAINT chk_pf_snapshots_content_or_artifact CHECK (((status <> 'success'::text) OR (content IS NOT NULL) OR (storage_path IS NOT NULL)))
);


--
-- Name: published_feed_snapshots_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.published_feed_snapshots_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: published_feed_snapshots_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.published_feed_snapshots_id_seq OWNED BY public.published_feed_snapshots.id;


--
-- Name: published_feeds; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.published_feeds (
    id bigint NOT NULL,
    name text NOT NULL,
    description text,
    enabled boolean DEFAULT true NOT NULL,
    ioc_type text,
    min_confidence integer,
    include_sources jsonb,
    include_tags jsonb,
    exclude_tags jsonb,
    exclude_false_positive boolean DEFAULT true NOT NULL,
    exclude_expired boolean DEFAULT true NOT NULL,
    verdict_filter jsonb,
    time_window text DEFAULT 'all'::text NOT NULL,
    max_items integer,
    refresh_interval_minutes integer DEFAULT 15 NOT NULL,
    last_generated_at timestamp with time zone,
    last_status text,
    last_error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    include_feed_keys jsonb,
    slug text NOT NULL,
    ioc_types jsonb NOT NULL,
    filter_mode text DEFAULT 'basic'::text NOT NULL,
    advanced_query text,
    include_source_metadata boolean DEFAULT true NOT NULL,
    include_classification boolean DEFAULT true NOT NULL,
    include_enrichment boolean DEFAULT false NOT NULL,
    projection_status text DEFAULT 'absent'::text NOT NULL,
    projection_cutoff timestamp with time zone,
    projection_built_at timestamp with time zone,
    last_refresh_checked_at timestamp with time zone,
    last_refresh_mode text,
    last_refresh_ms integer,
    last_changed_count integer,
    formats jsonb DEFAULT '["txt"]'::jsonb NOT NULL,
    chunk_count integer,
    chunk_algo_version integer,
    chunk_backfill_status text DEFAULT 'absent'::text NOT NULL,
    projection_pending_cutoff timestamp with time zone,
    CONSTRAINT chk_published_feeds_chunk_backfill_status CHECK ((chunk_backfill_status = ANY (ARRAY['absent'::text, 'backfilling'::text, 'ready'::text, 'failed'::text, 'stale'::text]))),
    CONSTRAINT chk_published_feeds_chunk_count CHECK (((chunk_count IS NULL) OR ((chunk_count >= 64) AND (chunk_count <= 512) AND ((chunk_count & (chunk_count - 1)) = 0)))),
    CONSTRAINT chk_published_feeds_filter_mode CHECK ((filter_mode = ANY (ARRAY['basic'::text, 'query'::text]))),
    CONSTRAINT chk_published_feeds_formats CHECK (((jsonb_typeof(formats) = 'array'::text) AND (jsonb_array_length(formats) >= 1) AND (jsonb_array_length(formats) <= 3) AND (formats <@ '["txt", "json", "stix"]'::jsonb) AND ((jsonb_array_length(formats) = 1) OR ((jsonb_array_length(formats) = 2) AND ((formats ->> 0) IS DISTINCT FROM (formats ->> 1))) OR ((jsonb_array_length(formats) = 3) AND ((formats ->> 0) IS DISTINCT FROM (formats ->> 1)) AND ((formats ->> 0) IS DISTINCT FROM (formats ->> 2)) AND ((formats ->> 1) IS DISTINCT FROM (formats ->> 2)))))),
    CONSTRAINT chk_published_feeds_ioc_type CHECK ((ioc_type = ANY (ARRAY['ip'::text, 'domain'::text, 'url'::text, 'hash'::text]))),
    CONSTRAINT chk_published_feeds_ioc_types CHECK (((jsonb_typeof(ioc_types) = 'array'::text) AND (jsonb_array_length(ioc_types) >= 1) AND (jsonb_array_length(ioc_types) <= 4) AND (ioc_types <@ '["domain", "hash", "ip", "url"]'::jsonb))),
    CONSTRAINT chk_published_feeds_projection_status CHECK ((projection_status = ANY (ARRAY['absent'::text, 'bootstrapping'::text, 'ready'::text, 'failed'::text, 'stale'::text]))),
    CONSTRAINT chk_published_feeds_query_requires_text CHECK (((filter_mode <> 'query'::text) OR ((advanced_query IS NOT NULL) AND (length(btrim(advanced_query)) > 0)))),
    CONSTRAINT chk_published_feeds_refresh_interval CHECK ((refresh_interval_minutes >= 5)),
    CONSTRAINT chk_published_feeds_time_window CHECK ((time_window = ANY (ARRAY['1d'::text, '3d'::text, '7d'::text, 'all'::text])))
);


--
-- Name: published_feeds_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.published_feeds_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: published_feeds_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.published_feeds_id_seq OWNED BY public.published_feeds.id;


--
-- Name: spamhaus_drop_entries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.spamhaus_drop_entries (
    id bigint NOT NULL,
    list_type text NOT NULL,
    cidr cidr NOT NULL,
    sblid text,
    rir text,
    raw_json jsonb,
    synced_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: spamhaus_drop_entries_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.spamhaus_drop_entries_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: spamhaus_drop_entries_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.spamhaus_drop_entries_id_seq OWNED BY public.spamhaus_drop_entries.id;


--
-- Name: spamhaus_drop_sync_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.spamhaus_drop_sync_state (
    list_type text NOT NULL,
    last_success_at timestamp with time zone,
    last_attempt_at timestamp with time zone,
    next_run_at timestamp with time zone,
    status text DEFAULT 'never_synced'::text NOT NULL,
    entry_count integer DEFAULT 0 NOT NULL,
    added_count integer,
    removed_count integer,
    source_url text,
    dataset_sha256 text,
    error_message text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: system_backups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.system_backups (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    backup_id text NOT NULL,
    trigger_type text DEFAULT 'manual'::text NOT NULL,
    status text DEFAULT 'queued'::text NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    duration_ms bigint,
    archive_path text,
    archive_filename text,
    archive_size_bytes bigint,
    checksum_sha256 text,
    encrypted boolean DEFAULT false NOT NULL,
    database_size_bytes bigint,
    files_size_bytes bigint DEFAULT 0,
    error_code text,
    error_message text,
    verified_at timestamp with time zone,
    verify_status text,
    verify_error text,
    manifest jsonb,
    job_id text,
    created_by_id bigint,
    created_by_email text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT system_backups_status_check CHECK ((status = ANY (ARRAY['queued'::text, 'running'::text, 'verifying'::text, 'completed'::text, 'failed'::text, 'deleted'::text, 'interrupted'::text]))),
    CONSTRAINT system_backups_trigger_type_check CHECK ((trigger_type = ANY (ARRAY['manual'::text, 'scheduled'::text, 'safety'::text]))),
    CONSTRAINT system_backups_verify_status_check CHECK (((verify_status IS NULL) OR (verify_status = ANY (ARRAY['pending'::text, 'passed'::text, 'failed'::text]))))
);


--
-- Name: system_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.system_settings (
    id smallint DEFAULT 1 NOT NULL,
    active_system_timezone text,
    pending_system_timezone text,
    initial_setup_completed boolean DEFAULT false NOT NULL,
    timezone_restart_required boolean DEFAULT false NOT NULL,
    timezone_configuration_required boolean DEFAULT false NOT NULL,
    timezone_config_version integer DEFAULT 0 NOT NULL,
    active_timezone_config_version integer DEFAULT 0 NOT NULL,
    adoption_source text,
    initial_setup_completed_at timestamp with time zone,
    timezone_change_requested_at timestamp with time zone,
    timezone_change_requested_by text,
    timezone_promoted_at timestamp with time zone,
    timezone_updated_at timestamp with time zone,
    timezone_updated_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    default_admin_bootstrapped boolean DEFAULT false NOT NULL,
    audit_log_retention_days integer DEFAULT 365,
    audit_log_retention_updated_at timestamp with time zone,
    audit_log_retention_updated_by text,
    audit_log_retention_last_run_at timestamp with time zone,
    CONSTRAINT system_settings_audit_log_retention_days_check CHECK (((audit_log_retention_days IS NULL) OR (audit_log_retention_days >= 1))),
    CONSTRAINT system_settings_id_check CHECK ((id = 1))
);


--
-- Name: TABLE system_settings; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.system_settings IS 'Singleton system configuration. active_system_timezone is the live IANA zone; pending awaits restart promotion.';


--
-- Name: COLUMN system_settings.active_system_timezone; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.system_settings.active_system_timezone IS 'Live IANA timezone used by API, UI, schedulers, workers, and logs until a pending change is promoted.';


--
-- Name: COLUMN system_settings.pending_system_timezone; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.system_settings.pending_system_timezone IS 'IANA timezone waiting for successful restart/rollout promotion. Not used for runtime formatting.';


--
-- Name: COLUMN system_settings.timezone_configuration_required; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.system_settings.timezone_configuration_required IS 'True for existing installs that need an admin-selected timezone (no silent UTC).';


--
-- Name: COLUMN system_settings.default_admin_bootstrapped; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.system_settings.default_admin_bootstrapped IS 'True after first-install default admin bootstrap has run (or skipped because users already existed). Prevents silent re-create after admin deletion.';


--
-- Name: COLUMN system_settings.audit_log_retention_days; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.system_settings.audit_log_retention_days IS 'Audit log retention window in days. NULL = Keep forever (no automatic deletion). Rows older than the cutoff are deleted by the bounded daily cleanup job.';


--
-- Name: COLUMN system_settings.audit_log_retention_last_run_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.system_settings.audit_log_retention_last_run_at IS 'Last time the audit log retention cleanup job completed a run (observability + daily gate).';


--
-- Name: tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tags (
    id bigint NOT NULL,
    name text NOT NULL,
    type public.tag_type NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    slug text NOT NULL,
    description text,
    color text,
    category text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_origin text DEFAULT 'manual'::text NOT NULL,
    CONSTRAINT tags_created_origin_chk CHECK ((created_origin = ANY (ARRAY['manual'::text, 'integration'::text]))),
    CONSTRAINT tags_name_lower_chk CHECK ((name = lower(name)))
);


--
-- Name: tags_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.tags_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: tags_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.tags_id_seq OWNED BY public.tags.id;


--
-- Name: threat_actors; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.threat_actors (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    slug text NOT NULL,
    aliases text[],
    description text,
    active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by text,
    updated_by text
);


--
-- Name: threat_classifications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.threat_classifications (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    slug text NOT NULL,
    description text,
    active boolean DEFAULT true NOT NULL,
    sort_order integer DEFAULT 100 NOT NULL,
    system_default boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by text,
    updated_by text
);


--
-- Name: threat_feed_expiration_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.threat_feed_expiration_policies (
    id bigint NOT NULL,
    feed_id uuid NOT NULL,
    observable_type text DEFAULT 'all'::text NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    expiration_mode text DEFAULT 'never'::text NOT NULL,
    ttl_days integer,
    grace_days integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT threat_feed_expiration_policies_expiration_mode_check CHECK ((expiration_mode = ANY (ARRAY['never'::text, 'fixed_ttl'::text, 'missing_from_feed_ttl'::text])))
);


--
-- Name: threat_feed_expiration_policies_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.threat_feed_expiration_policies_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: threat_feed_expiration_policies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.threat_feed_expiration_policies_id_seq OWNED BY public.threat_feed_expiration_policies.id;


--
-- Name: threat_intel_provider_configs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.threat_intel_provider_configs (
    id bigint NOT NULL,
    provider text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    api_key text,
    ttl_hours integer DEFAULT 24 NOT NULL,
    timeout_ms integer DEFAULT 12000 NOT NULL,
    last_test_at timestamp with time zone,
    last_success_at timestamp with time zone,
    last_error_at timestamp with time zone,
    last_error_message text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    config jsonb DEFAULT '{}'::jsonb NOT NULL
);


--
-- Name: threat_intel_provider_configs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.threat_intel_provider_configs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: threat_intel_provider_configs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.threat_intel_provider_configs_id_seq OWNED BY public.threat_intel_provider_configs.id;


--
-- Name: user_preferences; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_preferences (
    email text NOT NULL,
    timezone text DEFAULT 'UTC'::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id bigint NOT NULL,
    username text NOT NULL,
    password_hash text NOT NULL,
    first_name text DEFAULT ''::text NOT NULL,
    last_name text DEFAULT ''::text NOT NULL,
    role public.app_user_role DEFAULT 'readonly'::public.app_user_role NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    status public.app_user_status DEFAULT 'active'::public.app_user_status NOT NULL,
    public_id uuid DEFAULT gen_random_uuid() NOT NULL,
    must_change_password boolean DEFAULT false NOT NULL,
    is_system_admin boolean DEFAULT false NOT NULL,
    auth_version integer DEFAULT 1 NOT NULL
);


--
-- Name: COLUMN users.must_change_password; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.users.must_change_password IS 'When true, authenticated user may only read session info, change password, or logout.';


--
-- Name: COLUMN users.is_system_admin; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.users.is_system_admin IS 'When true, this is the protected system administrator account (admin@talonhound.local): it cannot be deleted, deactivated, renamed, or demoted below admin. Reconciliation/creation is handled by backend bootstrap, never by this migration.';


--
-- Name: COLUMN users.auth_version; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.users.auth_version IS 'Incremented on password change/reset, logout-all, disable/delete security events. JWTs carry matching av claim.';


--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.users_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: usom_import_cursors; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.usom_import_cursors (
    feed_id uuid NOT NULL,
    ioc_type text NOT NULL,
    cursor_timestamp timestamp with time zone NOT NULL,
    cursor_provider_id text NOT NULL,
    last_incremental_started_at timestamp with time zone,
    last_incremental_completed_at timestamp with time zone,
    cursor_version integer DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT usom_import_cursors_ioc_type_check CHECK ((ioc_type = ANY (ARRAY['domain'::text, 'url'::text, 'ip'::text, 'ip6'::text, 'ip6net'::text])))
);


--
-- Name: TABLE usom_import_cursors; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.usom_import_cursors IS 'Per-USOM-feed/type successful high-water marks. Rows are created only after a complete successful fetch.';


--
-- Name: usom_import_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.usom_import_state (
    feed_id uuid NOT NULL,
    full_snapshot_hash text,
    full_type_highwaters jsonb DEFAULT '{}'::jsonb NOT NULL,
    last_full_reconciliation_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE usom_import_state; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.usom_import_state IS 'USOM reconciliation state. Snapshot hash is an optimization and never replaces seen-row merging.';


--
-- Name: ioc_domain; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_items ATTACH PARTITION public.ioc_domain FOR VALUES IN ('domain');


--
-- Name: ioc_file_hash; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_items ATTACH PARTITION public.ioc_file_hash FOR VALUES IN ('md5', 'sha1', 'sha256', 'ssdeep', 'imphash', 'tlsh');


--
-- Name: ioc_ip; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_items ATTACH PARTITION public.ioc_ip FOR VALUES IN ('ip');


--
-- Name: ioc_ipv6; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_items ATTACH PARTITION public.ioc_ipv6 FOR VALUES IN ('ipv6');


--
-- Name: ioc_items_other; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_items ATTACH PARTITION public.ioc_items_other DEFAULT;


--
-- Name: ioc_url; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_items ATTACH PARTITION public.ioc_url FOR VALUES IN ('url');


--
-- Name: audit_logs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_logs ALTER COLUMN id SET DEFAULT nextval('public.audit_logs_id_seq'::regclass);


--
-- Name: auth_sessions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_sessions ALTER COLUMN id SET DEFAULT nextval('public.auth_sessions_id_seq'::regclass);


--
-- Name: file_artifact_ioc_links id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_artifact_ioc_links ALTER COLUMN id SET DEFAULT nextval('public.file_artifact_ioc_links_id_seq'::regclass);


--
-- Name: file_artifact_merge_conflicts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_artifact_merge_conflicts ALTER COLUMN id SET DEFAULT nextval('public.file_artifact_merge_conflicts_id_seq'::regclass);


--
-- Name: file_artifact_non_identity_attrs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_artifact_non_identity_attrs ALTER COLUMN id SET DEFAULT nextval('public.file_artifact_non_identity_attrs_id_seq'::regclass);


--
-- Name: file_artifact_source_observations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_artifact_source_observations ALTER COLUMN id SET DEFAULT nextval('public.file_artifact_source_observations_id_seq'::regclass);


--
-- Name: integration_feed_expiration_type_policies id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_feed_expiration_type_policies ALTER COLUMN id SET DEFAULT nextval('public.integration_feed_expiration_type_policies_id_seq'::regclass);


--
-- Name: integration_runs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_runs ALTER COLUMN id SET DEFAULT nextval('public.integration_runs_id_seq'::regclass);


--
-- Name: ioc_abuseipdb_enrichment id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_abuseipdb_enrichment ALTER COLUMN id SET DEFAULT nextval('public.ioc_abuseipdb_enrichment_id_seq'::regclass);


--
-- Name: ioc_domain_enrichment id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_domain_enrichment ALTER COLUMN id SET DEFAULT nextval('public.ioc_domain_enrichment_id_seq'::regclass);


--
-- Name: ioc_enrichments id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_enrichments ALTER COLUMN id SET DEFAULT nextval('public.ioc_enrichments_id_seq'::regclass);


--
-- Name: ioc_feed_memberships id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_feed_memberships ALTER COLUMN id SET DEFAULT nextval('public.ioc_feed_memberships_id_seq'::regclass);


--
-- Name: ioc_feed_source_evidence id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_feed_source_evidence ALTER COLUMN id SET DEFAULT nextval('public.ioc_feed_source_evidence_id_seq'::regclass);


--
-- Name: ioc_ip_enrichment id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_ip_enrichment ALTER COLUMN id SET DEFAULT nextval('public.ioc_ip_enrichment_id_seq'::regclass);


--
-- Name: ioc_items id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_items ALTER COLUMN id SET DEFAULT nextval('public.ioc_items_id_seq1'::regclass);


--
-- Name: ioc_list_stats_snapshots id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_list_stats_snapshots ALTER COLUMN id SET DEFAULT nextval('public.ioc_list_stats_snapshots_id_seq'::regclass);


--
-- Name: ioc_manual_source_memberships id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_manual_source_memberships ALTER COLUMN id SET DEFAULT nextval('public.ioc_manual_source_memberships_id_seq'::regclass);


--
-- Name: ioc_observables id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_observables ALTER COLUMN id SET DEFAULT nextval('public.ioc_observables_id_seq'::regclass);


--
-- Name: ioc_source_expiration_type_policies id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_source_expiration_type_policies ALTER COLUMN id SET DEFAULT nextval('public.ioc_source_expiration_type_policies_id_seq'::regclass);


--
-- Name: ioc_source_tag_overrides id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_source_tag_overrides ALTER COLUMN id SET DEFAULT nextval('public.ioc_source_tag_overrides_id_seq'::regclass);


--
-- Name: ioc_sources id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_sources ALTER COLUMN id SET DEFAULT nextval('public.ioc_sources_id_seq'::regclass);


--
-- Name: ioc_spamhaus_drop_enrichment id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_spamhaus_drop_enrichment ALTER COLUMN id SET DEFAULT nextval('public.ioc_spamhaus_drop_enrichment_id_seq'::regclass);


--
-- Name: ioc_suppressions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_suppressions ALTER COLUMN id SET DEFAULT nextval('public.ioc_suppressions_id_seq'::regclass);


--
-- Name: published_feed_access_keys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_access_keys ALTER COLUMN id SET DEFAULT nextval('public.published_feed_access_keys_id_seq'::regclass);


--
-- Name: published_feed_chunks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_chunks ALTER COLUMN id SET DEFAULT nextval('public.published_feed_chunks_id_seq'::regclass);


--
-- Name: published_feed_ioc_deletes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_ioc_deletes ALTER COLUMN id SET DEFAULT nextval('public.published_feed_ioc_deletes_id_seq'::regclass);


--
-- Name: published_feed_snapshots id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_snapshots ALTER COLUMN id SET DEFAULT nextval('public.published_feed_snapshots_id_seq'::regclass);


--
-- Name: published_feeds id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feeds ALTER COLUMN id SET DEFAULT nextval('public.published_feeds_id_seq'::regclass);


--
-- Name: spamhaus_drop_entries id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spamhaus_drop_entries ALTER COLUMN id SET DEFAULT nextval('public.spamhaus_drop_entries_id_seq'::regclass);


--
-- Name: tags id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tags ALTER COLUMN id SET DEFAULT nextval('public.tags_id_seq'::regclass);


--
-- Name: threat_feed_expiration_policies id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_feed_expiration_policies ALTER COLUMN id SET DEFAULT nextval('public.threat_feed_expiration_policies_id_seq'::regclass);


--
-- Name: threat_intel_provider_configs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_intel_provider_configs ALTER COLUMN id SET DEFAULT nextval('public.threat_intel_provider_configs_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Name: audit_logs audit_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id);


--
-- Name: auth_sessions auth_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_sessions
    ADD CONSTRAINT auth_sessions_pkey PRIMARY KEY (id);


--
-- Name: auth_sessions auth_sessions_session_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_sessions
    ADD CONSTRAINT auth_sessions_session_id_key UNIQUE (session_id);


--
-- Name: custom_threat_feed_runs custom_threat_feed_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_threat_feed_runs
    ADD CONSTRAINT custom_threat_feed_runs_pkey PRIMARY KEY (id);


--
-- Name: custom_threat_feeds custom_threat_feeds_feed_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_threat_feeds
    ADD CONSTRAINT custom_threat_feeds_feed_id_key UNIQUE (feed_id);


--
-- Name: custom_threat_feeds custom_threat_feeds_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_threat_feeds
    ADD CONSTRAINT custom_threat_feeds_pkey PRIMARY KEY (id);


--
-- Name: enrichment_provider_health enrichment_provider_health_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrichment_provider_health
    ADD CONSTRAINT enrichment_provider_health_pkey PRIMARY KEY (provider);


--
-- Name: enrichment_usage_daily enrichment_usage_daily_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrichment_usage_daily
    ADD CONSTRAINT enrichment_usage_daily_pkey PRIMARY KEY (bucket_date, provider_key, ioc_type);


--
-- Name: file_artifact_hashes file_artifact_hashes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_artifact_hashes
    ADD CONSTRAINT file_artifact_hashes_pkey PRIMARY KEY (id);


--
-- Name: file_artifact_ioc_links file_artifact_ioc_links_ioc_observable_type_ioc_item_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_artifact_ioc_links
    ADD CONSTRAINT file_artifact_ioc_links_ioc_observable_type_ioc_item_id_key UNIQUE (ioc_observable_type, ioc_item_id);


--
-- Name: file_artifact_ioc_links file_artifact_ioc_links_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_artifact_ioc_links
    ADD CONSTRAINT file_artifact_ioc_links_pkey PRIMARY KEY (id);


--
-- Name: file_artifact_merge_conflicts file_artifact_merge_conflicts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_artifact_merge_conflicts
    ADD CONSTRAINT file_artifact_merge_conflicts_pkey PRIMARY KEY (id);


--
-- Name: file_artifact_non_identity_attrs file_artifact_non_identity_at_artifact_id_attr_type_attr_va_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_artifact_non_identity_attrs
    ADD CONSTRAINT file_artifact_non_identity_at_artifact_id_attr_type_attr_va_key UNIQUE (artifact_id, attr_type, attr_value);


--
-- Name: file_artifact_non_identity_attrs file_artifact_non_identity_attrs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_artifact_non_identity_attrs
    ADD CONSTRAINT file_artifact_non_identity_attrs_pkey PRIMARY KEY (id);


--
-- Name: file_artifact_source_observations file_artifact_source_observations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_artifact_source_observations
    ADD CONSTRAINT file_artifact_source_observations_pkey PRIMARY KEY (id);


--
-- Name: file_artifacts file_artifacts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_artifacts
    ADD CONSTRAINT file_artifacts_pkey PRIMARY KEY (id);


--
-- Name: integration_checkpoints integration_checkpoints_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_checkpoints
    ADD CONSTRAINT integration_checkpoints_pkey PRIMARY KEY (source_name);


--
-- Name: integration_feed_expiration_type_policies integration_feed_expiration_type_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_feed_expiration_type_policies
    ADD CONSTRAINT integration_feed_expiration_type_policies_pkey PRIMARY KEY (id);


--
-- Name: integration_feed_expiration_type_policies integration_feed_expiration_type_policies_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_feed_expiration_type_policies
    ADD CONSTRAINT integration_feed_expiration_type_policies_unique UNIQUE (feed_id, ioc_type);


--
-- Name: integration_feeds integration_feeds_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_feeds
    ADD CONSTRAINT integration_feeds_pkey PRIMARY KEY (key);


--
-- Name: integration_queue_jobs integration_queue_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_queue_jobs
    ADD CONSTRAINT integration_queue_jobs_pkey PRIMARY KEY (job_id);


--
-- Name: integration_runs integration_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_runs
    ADD CONSTRAINT integration_runs_pkey PRIMARY KEY (id);


--
-- Name: integration_source_state integration_source_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_source_state
    ADD CONSTRAINT integration_source_state_pkey PRIMARY KEY (source_name);


--
-- Name: ioc_abuseipdb_enrichment ioc_abuseipdb_enrichment_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_abuseipdb_enrichment
    ADD CONSTRAINT ioc_abuseipdb_enrichment_pkey PRIMARY KEY (id);


--
-- Name: ioc_analyst_intelligence ioc_analyst_intelligence_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_analyst_intelligence
    ADD CONSTRAINT ioc_analyst_intelligence_pkey PRIMARY KEY (id);


--
-- Name: ioc_bulk_query_job_targets ioc_bulk_query_job_targets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_bulk_query_job_targets
    ADD CONSTRAINT ioc_bulk_query_job_targets_pkey PRIMARY KEY (job_id, ioc_item_id);


--
-- Name: ioc_bulk_query_jobs ioc_bulk_query_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_bulk_query_jobs
    ADD CONSTRAINT ioc_bulk_query_jobs_pkey PRIMARY KEY (id);


--
-- Name: ioc_deep_search_results ioc_deep_search_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_deep_search_results
    ADD CONSTRAINT ioc_deep_search_results_pkey PRIMARY KEY (deep_search_id, "position");


--
-- Name: ioc_deep_searches ioc_deep_searches_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_deep_searches
    ADD CONSTRAINT ioc_deep_searches_pkey PRIMARY KEY (id);


--
-- Name: ioc_domain_enrichment ioc_domain_enrichment_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_domain_enrichment
    ADD CONSTRAINT ioc_domain_enrichment_pkey PRIMARY KEY (id);


--
-- Name: ioc_items ioc_items_pkey1; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_items
    ADD CONSTRAINT ioc_items_pkey1 PRIMARY KEY (observable_type, id);


--
-- Name: ioc_domain ioc_domain_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_domain
    ADD CONSTRAINT ioc_domain_pkey PRIMARY KEY (observable_type, id);


--
-- Name: ioc_enrichments ioc_enrichments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_enrichments
    ADD CONSTRAINT ioc_enrichments_pkey PRIMARY KEY (id);


--
-- Name: ioc_feed_memberships ioc_feed_memberships_ioc_item_id_ioc_observable_type_feed_i_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_feed_memberships
    ADD CONSTRAINT ioc_feed_memberships_ioc_item_id_ioc_observable_type_feed_i_key UNIQUE (ioc_item_id, ioc_observable_type, feed_id);


--
-- Name: ioc_feed_memberships ioc_feed_memberships_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_feed_memberships
    ADD CONSTRAINT ioc_feed_memberships_pkey PRIMARY KEY (id);


--
-- Name: ioc_feed_source_evidence ioc_feed_source_evidence_ioc_item_id_ioc_observable_type_fe_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_feed_source_evidence
    ADD CONSTRAINT ioc_feed_source_evidence_ioc_item_id_ioc_observable_type_fe_key UNIQUE (ioc_item_id, ioc_observable_type, feed_id);


--
-- Name: ioc_feed_source_evidence ioc_feed_source_evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_feed_source_evidence
    ADD CONSTRAINT ioc_feed_source_evidence_pkey PRIMARY KEY (id);


--
-- Name: ioc_file_hash ioc_file_hash_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_file_hash
    ADD CONSTRAINT ioc_file_hash_pkey PRIMARY KEY (observable_type, id);


--
-- Name: ioc_ip_enrichment ioc_ip_enrichment_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_ip_enrichment
    ADD CONSTRAINT ioc_ip_enrichment_pkey PRIMARY KEY (id);


--
-- Name: ioc_ip_geo_cache ioc_ip_geo_cache_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_ip_geo_cache
    ADD CONSTRAINT ioc_ip_geo_cache_pkey PRIMARY KEY (ip);


--
-- Name: ioc_ip ioc_ip_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_ip
    ADD CONSTRAINT ioc_ip_pkey PRIMARY KEY (observable_type, id);


--
-- Name: ioc_ipv6 ioc_ipv6_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_ipv6
    ADD CONSTRAINT ioc_ipv6_pkey PRIMARY KEY (observable_type, id);


--
-- Name: ioc_items_other ioc_items_other_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_items_other
    ADD CONSTRAINT ioc_items_other_pkey PRIMARY KEY (observable_type, id);


--
-- Name: ioc_list_stats_snapshots ioc_list_stats_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_list_stats_snapshots
    ADD CONSTRAINT ioc_list_stats_snapshots_pkey PRIMARY KEY (id);


--
-- Name: ioc_list_stats_snapshots ioc_list_stats_snapshots_snapshot_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_list_stats_snapshots
    ADD CONSTRAINT ioc_list_stats_snapshots_snapshot_key_key UNIQUE (snapshot_key);


--
-- Name: ioc_manual_source_memberships ioc_manual_source_memberships_ioc_item_id_ioc_observable_ty_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_manual_source_memberships
    ADD CONSTRAINT ioc_manual_source_memberships_ioc_item_id_ioc_observable_ty_key UNIQUE (ioc_item_id, ioc_observable_type, ioc_source_id);


--
-- Name: ioc_manual_source_memberships ioc_manual_source_memberships_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_manual_source_memberships
    ADD CONSTRAINT ioc_manual_source_memberships_pkey PRIMARY KEY (id);


--
-- Name: ioc_observables ioc_observables_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_observables
    ADD CONSTRAINT ioc_observables_pkey PRIMARY KEY (id);


--
-- Name: ioc_saved_searches ioc_saved_searches_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_saved_searches
    ADD CONSTRAINT ioc_saved_searches_pkey PRIMARY KEY (id);


--
-- Name: ioc_search_exports ioc_search_exports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_search_exports
    ADD CONSTRAINT ioc_search_exports_pkey PRIMARY KEY (id);


--
-- Name: ioc_source_expiration_type_policies ioc_source_expiration_type_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_source_expiration_type_policies
    ADD CONSTRAINT ioc_source_expiration_type_policies_pkey PRIMARY KEY (id);


--
-- Name: ioc_source_expiration_type_policies ioc_source_expiration_type_policies_source_id_ioc_type_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_source_expiration_type_policies
    ADD CONSTRAINT ioc_source_expiration_type_policies_source_id_ioc_type_key UNIQUE (source_id, ioc_type);


--
-- Name: ioc_source_tag_overrides ioc_source_tag_overrides_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_source_tag_overrides
    ADD CONSTRAINT ioc_source_tag_overrides_pkey PRIMARY KEY (id);


--
-- Name: ioc_sources ioc_sources_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_sources
    ADD CONSTRAINT ioc_sources_pkey PRIMARY KEY (id);


--
-- Name: ioc_spamhaus_drop_enrichment ioc_spamhaus_drop_enrichment_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_spamhaus_drop_enrichment
    ADD CONSTRAINT ioc_spamhaus_drop_enrichment_pkey PRIMARY KEY (id);


--
-- Name: ioc_suppressions ioc_suppressions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_suppressions
    ADD CONSTRAINT ioc_suppressions_pkey PRIMARY KEY (id);


--
-- Name: ioc_threat_actors ioc_threat_actors_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_threat_actors
    ADD CONSTRAINT ioc_threat_actors_pkey PRIMARY KEY (id);


--
-- Name: ioc_threat_classification_overrides ioc_threat_classification_overrides_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_threat_classification_overrides
    ADD CONSTRAINT ioc_threat_classification_overrides_pkey PRIMARY KEY (id);


--
-- Name: ioc_threat_classifications ioc_threat_classifications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_threat_classifications
    ADD CONSTRAINT ioc_threat_classifications_pkey PRIMARY KEY (id);


--
-- Name: ioc_url ioc_url_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_url
    ADD CONSTRAINT ioc_url_pkey PRIMARY KEY (observable_type, id);


--
-- Name: malwarebazaar_coverage_state malwarebazaar_coverage_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.malwarebazaar_coverage_state
    ADD CONSTRAINT malwarebazaar_coverage_state_pkey PRIMARY KEY (feed_key);


--
-- Name: published_feed_access_keys published_feed_access_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_access_keys
    ADD CONSTRAINT published_feed_access_keys_pkey PRIMARY KEY (id);


--
-- Name: published_feed_active_generations published_feed_active_generations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_active_generations
    ADD CONSTRAINT published_feed_active_generations_pkey PRIMARY KEY (feed_id, snapshot_window, ioc_type_key);


--
-- Name: published_feed_chunks published_feed_chunks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_chunks
    ADD CONSTRAINT published_feed_chunks_pkey PRIMARY KEY (id);


--
-- Name: published_feed_generation_chunks published_feed_generation_chunks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_generation_chunks
    ADD CONSTRAINT published_feed_generation_chunks_pkey PRIMARY KEY (generation_id, format, chunk_key);


--
-- Name: published_feed_generation_formats published_feed_generation_formats_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_generation_formats
    ADD CONSTRAINT published_feed_generation_formats_pkey PRIMARY KEY (generation_id, format);


--
-- Name: published_feed_generations published_feed_generations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_generations
    ADD CONSTRAINT published_feed_generations_pkey PRIMARY KEY (id);


--
-- Name: published_feed_global_watermarks published_feed_global_watermarks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_global_watermarks
    ADD CONSTRAINT published_feed_global_watermarks_pkey PRIMARY KEY (key);


--
-- Name: published_feed_ioc_deletes published_feed_ioc_deletes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_ioc_deletes
    ADD CONSTRAINT published_feed_ioc_deletes_pkey PRIMARY KEY (id);


--
-- Name: published_feed_items published_feed_items_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_items
    ADD CONSTRAINT published_feed_items_pkey PRIMARY KEY (feed_id, snapshot_window, identity_key);


--
-- Name: published_feed_snapshots published_feed_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_snapshots
    ADD CONSTRAINT published_feed_snapshots_pkey PRIMARY KEY (id);


--
-- Name: published_feeds published_feeds_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feeds
    ADD CONSTRAINT published_feeds_pkey PRIMARY KEY (id);


--
-- Name: spamhaus_drop_entries spamhaus_drop_entries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spamhaus_drop_entries
    ADD CONSTRAINT spamhaus_drop_entries_pkey PRIMARY KEY (id);


--
-- Name: spamhaus_drop_sync_state spamhaus_drop_sync_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spamhaus_drop_sync_state
    ADD CONSTRAINT spamhaus_drop_sync_state_pkey PRIMARY KEY (list_type);


--
-- Name: system_backups system_backups_backup_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_backups
    ADD CONSTRAINT system_backups_backup_id_key UNIQUE (backup_id);


--
-- Name: system_backups system_backups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_backups
    ADD CONSTRAINT system_backups_pkey PRIMARY KEY (id);


--
-- Name: system_settings system_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_settings
    ADD CONSTRAINT system_settings_pkey PRIMARY KEY (id);


--
-- Name: tags tags_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tags
    ADD CONSTRAINT tags_pkey PRIMARY KEY (id);


--
-- Name: threat_actors threat_actors_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_actors
    ADD CONSTRAINT threat_actors_pkey PRIMARY KEY (id);


--
-- Name: threat_actors threat_actors_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_actors
    ADD CONSTRAINT threat_actors_slug_key UNIQUE (slug);


--
-- Name: threat_classifications threat_classifications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_classifications
    ADD CONSTRAINT threat_classifications_pkey PRIMARY KEY (id);


--
-- Name: threat_classifications threat_classifications_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_classifications
    ADD CONSTRAINT threat_classifications_slug_key UNIQUE (slug);


--
-- Name: threat_feed_expiration_policies threat_feed_expiration_policies_feed_id_observable_type_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_feed_expiration_policies
    ADD CONSTRAINT threat_feed_expiration_policies_feed_id_observable_type_key UNIQUE (feed_id, observable_type);


--
-- Name: threat_feed_expiration_policies threat_feed_expiration_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_feed_expiration_policies
    ADD CONSTRAINT threat_feed_expiration_policies_pkey PRIMARY KEY (id);


--
-- Name: threat_intel_provider_configs threat_intel_provider_configs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_intel_provider_configs
    ADD CONSTRAINT threat_intel_provider_configs_pkey PRIMARY KEY (id);


--
-- Name: threat_intel_provider_configs threat_intel_provider_configs_provider_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_intel_provider_configs
    ADD CONSTRAINT threat_intel_provider_configs_provider_key UNIQUE (provider);


--
-- Name: ioc_sources uq_ioc_sources_name; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_sources
    ADD CONSTRAINT uq_ioc_sources_name UNIQUE (name);


--
-- Name: ioc_threat_actors uq_ioc_threat_actors_ioc_actor; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_threat_actors
    ADD CONSTRAINT uq_ioc_threat_actors_ioc_actor UNIQUE (ioc_id, ioc_observable_type, threat_actor_id);


--
-- Name: ioc_threat_classifications uq_ioc_threat_classifications_ioc_slug; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_threat_classifications
    ADD CONSTRAINT uq_ioc_threat_classifications_ioc_slug UNIQUE (ioc_id, ioc_observable_type, classification_slug);


--
-- Name: published_feed_active_generations uq_pf_active_generation; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_active_generations
    ADD CONSTRAINT uq_pf_active_generation UNIQUE (generation_id);


--
-- Name: published_feed_chunks uq_pf_chunks_content; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_chunks
    ADD CONSTRAINT uq_pf_chunks_content UNIQUE (feed_id, snapshot_window, chunk_algo_version, chunk_count, chunk_key, format, serializer_version, content_hash);


--
-- Name: published_feed_chunks uq_pf_chunks_storage_path; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_chunks
    ADD CONSTRAINT uq_pf_chunks_storage_path UNIQUE (storage_path);


--
-- Name: published_feed_generation_chunks uq_pf_generation_chunks_ordinal; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_generation_chunks
    ADD CONSTRAINT uq_pf_generation_chunks_ordinal UNIQUE (generation_id, format, ordinal);


--
-- Name: published_feed_access_keys uq_published_feed_access_keys_token_hash; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_access_keys
    ADD CONSTRAINT uq_published_feed_access_keys_token_hash UNIQUE (token_hash);


--
-- Name: user_preferences user_preferences_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_preferences
    ADD CONSTRAINT user_preferences_pkey PRIMARY KEY (email);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users users_username_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);


--
-- Name: usom_import_cursors usom_import_cursors_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usom_import_cursors
    ADD CONSTRAINT usom_import_cursors_pkey PRIMARY KEY (feed_id, ioc_type);


--
-- Name: usom_import_state usom_import_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usom_import_state
    ADD CONSTRAINT usom_import_state_pkey PRIMARY KEY (feed_id);


--
-- Name: audit_logs_action_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_logs_action_idx ON public.audit_logs USING btree (action);


--
-- Name: audit_logs_actor_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_logs_actor_user_id_idx ON public.audit_logs USING btree (actor_user_id);


--
-- Name: audit_logs_created_at_desc_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_logs_created_at_desc_idx ON public.audit_logs USING btree (created_at DESC);


--
-- Name: audit_logs_enrichment_subject_ioc_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_logs_enrichment_subject_ioc_idx ON public.audit_logs USING btree (entity_type, subject_ioc_id, created_at DESC) WHERE ((entity_type = 'enrichment'::text) AND (subject_ioc_id IS NOT NULL));


--
-- Name: audit_logs_entity_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_logs_entity_id_idx ON public.audit_logs USING btree (entity_id);


--
-- Name: audit_logs_entity_type_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_logs_entity_type_idx ON public.audit_logs USING btree (entity_type);


--
-- Name: audit_logs_metadata_gin_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_logs_metadata_gin_idx ON public.audit_logs USING gin (metadata);


--
-- Name: audit_logs_severity_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_logs_severity_idx ON public.audit_logs USING btree (severity);


--
-- Name: audit_logs_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_logs_status_idx ON public.audit_logs USING btree (status);


--
-- Name: audit_logs_subject_ioc_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_logs_subject_ioc_id_idx ON public.audit_logs USING btree (subject_ioc_id) WHERE (subject_ioc_id IS NOT NULL);


--
-- Name: auth_sessions_absolute_expires_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX auth_sessions_absolute_expires_idx ON public.auth_sessions USING btree (absolute_expires_at);


--
-- Name: auth_sessions_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX auth_sessions_user_id_idx ON public.auth_sessions USING btree (user_id);


--
-- Name: idx_custom_threat_feed_runs_feed_started; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_custom_threat_feed_runs_feed_started ON public.custom_threat_feed_runs USING btree (feed_id, started_at DESC);


--
-- Name: idx_custom_threat_feed_runs_integration_feed; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_custom_threat_feed_runs_integration_feed ON public.custom_threat_feed_runs USING btree (integration_feed_id, started_at DESC);


--
-- Name: idx_fa_non_identity_attrs_imphash_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_fa_non_identity_attrs_imphash_value ON public.file_artifact_non_identity_attrs USING btree (attr_value) WHERE (attr_type = 'imphash'::text);


--
-- Name: idx_fa_non_identity_attrs_ssdeep_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_fa_non_identity_attrs_ssdeep_value ON public.file_artifact_non_identity_attrs USING btree (attr_value) WHERE (attr_type = 'ssdeep'::text);


--
-- Name: idx_fa_non_identity_attrs_tlsh_lower_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_fa_non_identity_attrs_tlsh_lower_value ON public.file_artifact_non_identity_attrs USING btree (lower(attr_value)) WHERE (attr_type = 'tlsh'::text);


--
-- Name: idx_file_artifact_hashes_artifact; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_file_artifact_hashes_artifact ON public.file_artifact_hashes USING btree (artifact_id);


--
-- Name: idx_file_artifact_ioc_links_artifact; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_file_artifact_ioc_links_artifact ON public.file_artifact_ioc_links USING btree (artifact_id);


--
-- Name: idx_file_artifact_ioc_links_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_file_artifact_ioc_links_public_id ON public.file_artifact_ioc_links USING btree (ioc_public_id);


--
-- Name: idx_file_artifact_merge_conflicts_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_file_artifact_merge_conflicts_hash ON public.file_artifact_merge_conflicts USING btree (conflicting_hash_type, conflicting_hash_value);


--
-- Name: idx_file_artifact_merge_conflicts_open; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_file_artifact_merge_conflicts_open ON public.file_artifact_merge_conflicts USING btree (created_at) WHERE (status = 'open'::text);


--
-- Name: idx_file_artifact_non_identity_attrs_artifact; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_file_artifact_non_identity_attrs_artifact ON public.file_artifact_non_identity_attrs USING btree (artifact_id);


--
-- Name: idx_file_artifact_source_observations_artifact; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_file_artifact_source_observations_artifact ON public.file_artifact_source_observations USING btree (artifact_id);


--
-- Name: idx_file_artifact_source_observations_feed; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_file_artifact_source_observations_feed ON public.file_artifact_source_observations USING btree (feed_id) WHERE (feed_id IS NOT NULL);


--
-- Name: idx_file_artifact_source_observations_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_file_artifact_source_observations_lookup ON public.file_artifact_source_observations USING btree (artifact_id, source_name, observed_hash_type, observed_hash_value, observation_type);


--
-- Name: idx_file_artifacts_merged_into; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_file_artifacts_merged_into ON public.file_artifacts USING btree (merged_into_artifact_id) WHERE (merged_into_artifact_id IS NOT NULL);


--
-- Name: idx_file_artifacts_status_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_file_artifacts_status_active ON public.file_artifacts USING btree (created_at) WHERE (status = 'active'::text);


--
-- Name: idx_integration_feed_expiration_type_policies_feed; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_feed_expiration_type_policies_feed ON public.integration_feed_expiration_type_policies USING btree (feed_id);


--
-- Name: idx_integration_feeds_archived; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_feeds_archived ON public.integration_feeds USING btree (archived_at) WHERE (archived_at IS NOT NULL);


--
-- Name: idx_integration_feeds_custom_name_unique_ci; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_integration_feeds_custom_name_unique_ci ON public.integration_feeds USING btree (lower(TRIM(BOTH FROM name))) WHERE ((feed_kind = 'custom'::text) AND (archived_at IS NULL));


--
-- Name: idx_integration_queue_jobs_heartbeat_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_queue_jobs_heartbeat_at ON public.integration_queue_jobs USING btree (heartbeat_at) WHERE (status = 'running'::text);


--
-- Name: idx_integration_queue_jobs_key_latest; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_queue_jobs_key_latest ON public.integration_queue_jobs USING btree (integration_key, COALESCE(started_at, queued_at) DESC);


--
-- Name: idx_integration_queue_jobs_queued_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_queue_jobs_queued_at ON public.integration_queue_jobs USING btree (queued_at DESC);


--
-- Name: idx_integration_queue_jobs_queued_at_desc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_queue_jobs_queued_at_desc ON public.integration_queue_jobs USING btree (queued_at DESC);


--
-- Name: idx_integration_queue_jobs_running_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_queue_jobs_running_source ON public.integration_queue_jobs USING btree (integration_key, status) WHERE (status = 'running'::text);


--
-- Name: idx_integration_queue_jobs_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_queue_jobs_status ON public.integration_queue_jobs USING btree (status);


--
-- Name: idx_integration_runs_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_runs_created_at ON public.integration_runs USING btree (created_at DESC);


--
-- Name: idx_integration_runs_job_type_started_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_runs_job_type_started_at ON public.integration_runs USING btree (job_type, started_at DESC);


--
-- Name: idx_integration_runs_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_runs_status ON public.integration_runs USING btree (status);


--
-- Name: idx_ioc_analyst_intelligence_created_at_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_analyst_intelligence_created_at_active ON public.ioc_analyst_intelligence USING btree (created_at DESC) WHERE (deleted_at IS NULL);


--
-- Name: idx_ioc_analyst_intelligence_impact_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_analyst_intelligence_impact_active ON public.ioc_analyst_intelligence USING btree (assessment_impact) WHERE (deleted_at IS NULL);


--
-- Name: idx_ioc_analyst_intelligence_ioc_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_analyst_intelligence_ioc_active ON public.ioc_analyst_intelligence USING btree (ioc_id, ioc_observable_type) WHERE (deleted_at IS NULL);


--
-- Name: idx_ioc_bulk_query_job_targets_job; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_bulk_query_job_targets_job ON public.ioc_bulk_query_job_targets USING btree (job_id, ioc_item_id);


--
-- Name: idx_ioc_bulk_query_jobs_requester_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_bulk_query_jobs_requester_created ON public.ioc_bulk_query_jobs USING btree (requested_by_id, created_at DESC);


--
-- Name: idx_ioc_bulk_query_jobs_status_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_bulk_query_jobs_status_created ON public.ioc_bulk_query_jobs USING btree (status, created_at DESC);


--
-- Name: idx_ioc_deep_search_results_keyset; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_deep_search_results_keyset ON public.ioc_deep_search_results USING btree (deep_search_id, created_at DESC, ioc_item_id DESC);


--
-- Name: idx_ioc_deep_searches_dedup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_deep_searches_dedup ON public.ioc_deep_searches USING btree (requested_by_email, query_fingerprint) WHERE (status = ANY (ARRAY['queued'::text, 'running'::text]));


--
-- Name: idx_ioc_deep_searches_expiry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_deep_searches_expiry ON public.ioc_deep_searches USING btree (expires_at) WHERE ((status = 'completed'::text) AND (expires_at IS NOT NULL));


--
-- Name: idx_ioc_deep_searches_metadata_cleanup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_deep_searches_metadata_cleanup ON public.ioc_deep_searches USING btree (status, updated_at) WHERE (status = ANY (ARRAY['expired'::text, 'failed'::text, 'cancelled'::text]));


--
-- Name: idx_ioc_deep_searches_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_deep_searches_owner ON public.ioc_deep_searches USING btree (requested_by_email, created_at DESC);


--
-- Name: idx_ioc_deep_searches_status_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_deep_searches_status_created ON public.ioc_deep_searches USING btree (status, created_at DESC);


--
-- Name: idx_ioc_feed_memberships_active_last_seen; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_feed_memberships_active_last_seen ON public.ioc_feed_memberships USING btree (last_seen_in_feed DESC NULLS LAST) WHERE ((status = 'active'::text) AND (purged_at IS NULL));


--
-- Name: idx_ioc_feed_memberships_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_feed_memberships_expires_at ON public.ioc_feed_memberships USING btree (expires_at) WHERE ((status = 'active'::text) AND (expires_at IS NOT NULL));


--
-- Name: idx_ioc_feed_memberships_feed_purged; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_feed_memberships_feed_purged ON public.ioc_feed_memberships USING btree (feed_id, status) WHERE (status = 'purged'::text);


--
-- Name: idx_ioc_feed_memberships_feed_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_feed_memberships_feed_status ON public.ioc_feed_memberships USING btree (feed_id, status);


--
-- Name: idx_ioc_feed_memberships_ioc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_feed_memberships_ioc ON public.ioc_feed_memberships USING btree (ioc_item_id, ioc_observable_type);


--
-- Name: idx_ioc_feed_memberships_override_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_feed_memberships_override_enabled ON public.ioc_feed_memberships USING btree (override_enabled) WHERE (override_enabled = true);


--
-- Name: idx_ioc_feed_memberships_policy_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_feed_memberships_policy_expires_at ON public.ioc_feed_memberships USING btree (policy_expires_at);


--
-- Name: idx_ioc_feed_source_evidence_item; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_feed_source_evidence_item ON public.ioc_feed_source_evidence USING btree (ioc_item_id, ioc_observable_type);


--
-- Name: idx_ioc_ip_geo_cache_asn; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_ip_geo_cache_asn ON public.ioc_ip_geo_cache USING btree (asn) WHERE (asn IS NOT NULL);


--
-- Name: idx_ioc_ip_geo_cache_country_code; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_ip_geo_cache_country_code ON public.ioc_ip_geo_cache USING btree (country_code);


--
-- Name: idx_ioc_ip_observable; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_ip_observable ON public.ioc_ip USING btree (observable);


--
-- Name: idx_ioc_items_analyst_confidence_override; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_analyst_confidence_override ON ONLY public.ioc_items USING btree (analyst_confidence_override) WHERE (analyst_confidence_override IS NOT NULL);


--
-- Name: idx_ioc_items_api_recent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_api_recent ON ONLY public.ioc_items USING btree (created_at DESC) WHERE (created_origin = 'api'::text);


--
-- Name: idx_ioc_items_confidence; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_confidence ON ONLY public.ioc_items USING btree (confidence);


--
-- Name: idx_ioc_items_confidence_created_at_desc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_confidence_created_at_desc ON ONLY public.ioc_items USING btree (confidence, created_at DESC);


--
-- Name: idx_ioc_items_confidence_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_confidence_source ON ONLY public.ioc_items USING btree (confidence_source) WHERE (confidence_source IS NOT NULL);


--
-- Name: idx_ioc_items_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_created_at ON ONLY public.ioc_items USING btree (created_at DESC);


--
-- Name: idx_ioc_items_created_at_desc_covering; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_created_at_desc_covering ON ONLY public.ioc_items USING btree (created_at DESC) INCLUDE (id, public_id, observable, observable_type, source_name, confidence, category);


--
-- Name: idx_ioc_items_dedup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_dedup ON ONLY public.ioc_items USING btree (observable, observable_type, source_name, confidence, COALESCE(category, ''::text), COALESCE(source_url, ''::text));


--
-- Name: idx_ioc_items_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_expires_at ON ONLY public.ioc_items USING btree (expires_at) WHERE ((status = 'active'::text) AND (expires_at IS NOT NULL));


--
-- Name: idx_ioc_items_imphash_from_note; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_imphash_from_note ON ONLY public.ioc_items USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'imphash='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: idx_ioc_items_ioc_source_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_ioc_source_id ON ONLY public.ioc_items USING btree (ioc_source_id) WHERE (ioc_source_id IS NOT NULL);


--
-- Name: idx_ioc_items_last_seen; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_last_seen ON ONLY public.ioc_items USING btree (last_seen_log DESC NULLS LAST);


--
-- Name: idx_ioc_items_manual_recent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_manual_recent ON ONLY public.ioc_items USING btree (created_at DESC) WHERE (created_origin = 'manual_add'::text);


--
-- Name: idx_ioc_items_md5_from_note; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_md5_from_note ON ONLY public.ioc_items USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'md5='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: idx_ioc_items_md5_lower_observable; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_md5_lower_observable ON ONLY public.ioc_items USING btree (lower(observable)) WHERE (observable_type = 'md5'::text);


--
-- Name: idx_ioc_items_observable_trgm; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_observable_trgm ON ONLY public.ioc_items USING gin (observable public.gin_trgm_ops);


--
-- Name: idx_ioc_items_observable_type_observable; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_observable_type_observable ON ONLY public.ioc_items USING btree (observable_type, observable);


--
-- Name: idx_ioc_items_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_public_id ON ONLY public.ioc_items USING btree (public_id);


--
-- Name: idx_ioc_items_reactivated_by_match_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_reactivated_by_match_at ON ONLY public.ioc_items USING btree (reactivated_by_match_at DESC) WHERE (reactivated_by_match_at IS NOT NULL);


--
-- Name: idx_ioc_items_sha1_from_note; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_sha1_from_note ON ONLY public.ioc_items USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'sha1='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: idx_ioc_items_sha1_lower_observable; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_sha1_lower_observable ON ONLY public.ioc_items USING btree (lower(observable)) WHERE (observable_type = 'sha1'::text);


--
-- Name: idx_ioc_items_sha256_from_note; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_sha256_from_note ON ONLY public.ioc_items USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'sha256='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: idx_ioc_items_sha256_lower_observable; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_sha256_lower_observable ON ONLY public.ioc_items USING btree (lower(observable)) WHERE (observable_type = 'sha256'::text);


--
-- Name: idx_ioc_items_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_source ON ONLY public.ioc_items USING btree (source_name);


--
-- Name: idx_ioc_items_source_created_at_desc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_source_created_at_desc ON ONLY public.ioc_items USING btree (source_name, created_at DESC);


--
-- Name: idx_ioc_items_source_trgm; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_source_trgm ON ONLY public.ioc_items USING gin (source_name public.gin_trgm_ops);


--
-- Name: idx_ioc_items_ssdeep_from_note; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_ssdeep_from_note ON ONLY public.ioc_items USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'ssdeep='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: idx_ioc_items_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_status ON ONLY public.ioc_items USING btree (status);


--
-- Name: idx_ioc_items_supplement_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_supplement_lookup ON ONLY public.ioc_items USING btree (lower(observable), (
CASE
    WHEN (observable_type = 'hostname'::text) THEN 'domain'::text
    ELSE observable_type
END), created_at) WHERE (COALESCE(status, 'active'::text) = ANY (ARRAY['active'::text, 'expired'::text]));


--
-- Name: idx_ioc_items_threat_actor_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_threat_actor_id ON ONLY public.ioc_items USING btree (threat_actor_id) WHERE (threat_actor_id IS NOT NULL);


--
-- Name: idx_ioc_items_threat_classification; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_threat_classification ON ONLY public.ioc_items USING btree (threat_classification);


--
-- Name: idx_ioc_items_threat_classification_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_threat_classification_active ON ONLY public.ioc_items USING btree (threat_classification) WHERE (threat_classification <> 'unknown'::text);


--
-- Name: idx_ioc_items_tlsh_from_note; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_items_tlsh_from_note ON ONLY public.ioc_items USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'tlsh='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: idx_ioc_list_stats_snapshots_key_calculated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_list_stats_snapshots_key_calculated ON public.ioc_list_stats_snapshots USING btree (snapshot_key, calculated_at DESC);


--
-- Name: idx_ioc_manual_source_memberships_ioc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_manual_source_memberships_ioc ON public.ioc_manual_source_memberships USING btree (ioc_item_id, ioc_observable_type);


--
-- Name: idx_ioc_manual_source_memberships_moved_to; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_manual_source_memberships_moved_to ON public.ioc_manual_source_memberships USING btree (moved_to_source_id) WHERE (moved_to_source_id IS NOT NULL);


--
-- Name: idx_ioc_manual_source_memberships_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_manual_source_memberships_source ON public.ioc_manual_source_memberships USING btree (ioc_source_id);


--
-- Name: idx_ioc_observables_type_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_observables_type_value ON public.ioc_observables USING btree (observable_type, observable_value);


--
-- Name: idx_ioc_observables_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_observables_value ON public.ioc_observables USING btree (observable_value);


--
-- Name: idx_ioc_saved_searches_owner_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_ioc_saved_searches_owner_name ON public.ioc_saved_searches USING btree (owner_id, lower(name));


--
-- Name: idx_ioc_saved_searches_owner_updated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_saved_searches_owner_updated ON public.ioc_saved_searches USING btree (owner_id, updated_at DESC);


--
-- Name: idx_ioc_search_exports_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_search_exports_active ON public.ioc_search_exports USING btree (requested_by_email) WHERE (status = ANY (ARRAY['queued'::text, 'processing'::text]));


--
-- Name: idx_ioc_search_exports_expiry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_search_exports_expiry ON public.ioc_search_exports USING btree (expires_at) WHERE ((status = 'ready'::text) AND (expires_at IS NOT NULL));


--
-- Name: idx_ioc_search_exports_metadata_cleanup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_search_exports_metadata_cleanup ON public.ioc_search_exports USING btree (status, updated_at) WHERE (status = ANY (ARRAY['expired'::text, 'failed'::text, 'cancelled'::text]));


--
-- Name: idx_ioc_search_exports_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_search_exports_owner ON public.ioc_search_exports USING btree (requested_by_email, created_at DESC);


--
-- Name: idx_ioc_search_exports_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_search_exports_status ON public.ioc_search_exports USING btree (status);


--
-- Name: idx_ioc_search_exports_status_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_search_exports_status_created ON public.ioc_search_exports USING btree (status, created_at DESC);


--
-- Name: idx_ioc_source_tag_overrides_ioc_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_source_tag_overrides_ioc_active ON public.ioc_source_tag_overrides USING btree (ioc_id) WHERE (restored_at IS NULL);


--
-- Name: idx_ioc_sources_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_sources_active ON public.ioc_sources USING btree (active) WHERE (active = true);


--
-- Name: idx_ioc_sources_archived_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_sources_archived_at ON public.ioc_sources USING btree (archived_at) WHERE (archived_at IS NOT NULL);


--
-- Name: idx_ioc_suppressions_active_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_suppressions_active_expires ON public.ioc_suppressions USING btree (active, expires_at);


--
-- Name: idx_ioc_suppressions_ioc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_suppressions_ioc ON public.ioc_suppressions USING btree (ioc_value, ioc_type);


--
-- Name: idx_ioc_suppressions_not_deleted; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_suppressions_not_deleted ON public.ioc_suppressions USING btree (id) WHERE (deleted_at IS NULL);


--
-- Name: idx_ioc_suppressions_scope_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_suppressions_scope_source ON public.ioc_suppressions USING btree (scope, source_name);


--
-- Name: idx_ioc_tags_ioc_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_tags_ioc_id ON public.ioc_tags USING btree (ioc_id);


--
-- Name: idx_ioc_tags_tag_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_tags_tag_id ON public.ioc_tags USING btree (tag_id);


--
-- Name: idx_ioc_tc_overrides_ioc_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_tc_overrides_ioc_active ON public.ioc_threat_classification_overrides USING btree (ioc_id, ioc_observable_type) WHERE (cleared_at IS NULL);


--
-- Name: idx_ioc_tc_overrides_slug; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_tc_overrides_slug ON public.ioc_threat_classification_overrides USING btree (classification_slug) WHERE (cleared_at IS NULL);


--
-- Name: idx_ioc_threat_actors_actor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_threat_actors_actor ON public.ioc_threat_actors USING btree (threat_actor_id);


--
-- Name: idx_ioc_threat_actors_ioc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_threat_actors_ioc ON public.ioc_threat_actors USING btree (ioc_id, ioc_observable_type);


--
-- Name: idx_ioc_threat_classifications_ioc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_threat_classifications_ioc ON public.ioc_threat_classifications USING btree (ioc_id, ioc_observable_type);


--
-- Name: idx_ioc_threat_classifications_slug; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_threat_classifications_slug ON public.ioc_threat_classifications USING btree (classification_slug);


--
-- Name: idx_malwarebazaar_coverage_state_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_malwarebazaar_coverage_state_status ON public.malwarebazaar_coverage_state USING btree (status);


--
-- Name: idx_pf_access_keys_scopes_gin; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pf_access_keys_scopes_gin ON public.published_feed_access_keys USING gin (scopes);


--
-- Name: idx_pf_access_keys_type_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pf_access_keys_type_active ON public.published_feed_access_keys USING btree (key_type) WHERE (revoked_at IS NULL);


--
-- Name: idx_pf_access_keys_type_not_deleted; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pf_access_keys_type_not_deleted ON public.published_feed_access_keys USING btree (key_type) WHERE (deleted_at IS NULL);


--
-- Name: idx_pf_chunks_feed_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pf_chunks_feed_created ON public.published_feed_chunks USING btree (feed_id, created_at);


--
-- Name: idx_pf_generation_chunks_chunk; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pf_generation_chunks_chunk ON public.published_feed_generation_chunks USING btree (chunk_id);


--
-- Name: idx_pf_generations_feed_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pf_generations_feed_state ON public.published_feed_generations USING btree (feed_id, snapshot_window, ioc_type_key, state, created_at DESC);


--
-- Name: idx_pf_ioc_deletes_deleted_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pf_ioc_deletes_deleted_at ON public.published_feed_ioc_deletes USING btree (deleted_at);


--
-- Name: idx_pf_ioc_deletes_ioc_item_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pf_ioc_deletes_ioc_item_id ON public.published_feed_ioc_deletes USING btree (ioc_item_id);


--
-- Name: idx_pf_items_feed_ioc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pf_items_feed_ioc ON public.published_feed_items USING btree (feed_id, ioc_item_id);


--
-- Name: idx_pf_items_feed_window_order; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pf_items_feed_window_order ON public.published_feed_items USING btree (feed_id, snapshot_window, recency_ts DESC NULLS LAST, confidence_rank DESC, observable);


--
-- Name: idx_pf_snapshots_params_format_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pf_snapshots_params_format_lookup ON public.published_feed_snapshots USING btree (feed_id, ((params ->> 'ioc_type'::text)), ((params ->> 'window'::text)), artifact_format, generated_at DESC) WHERE (status = 'success'::text);


--
-- Name: idx_pf_snapshots_storage_path; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pf_snapshots_storage_path ON public.published_feed_snapshots USING btree (feed_id) WHERE (storage_path IS NOT NULL);


--
-- Name: idx_published_feed_access_keys_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_published_feed_access_keys_enabled ON public.published_feed_access_keys USING btree (enabled) WHERE (revoked_at IS NULL);


--
-- Name: idx_published_feed_access_keys_feed_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_published_feed_access_keys_feed_id ON public.published_feed_access_keys USING btree (feed_id);


--
-- Name: idx_published_feed_snapshots_feed_generated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_published_feed_snapshots_feed_generated ON public.published_feed_snapshots USING btree (feed_id, generated_at DESC);


--
-- Name: idx_published_feeds_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_published_feeds_enabled ON public.published_feeds USING btree (enabled);


--
-- Name: idx_published_feeds_ioc_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_published_feeds_ioc_type ON public.published_feeds USING btree (ioc_type);


--
-- Name: idx_published_feeds_ioc_types; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_published_feeds_ioc_types ON public.published_feeds USING gin (ioc_types);


--
-- Name: idx_spamhaus_drop_entries_cidr; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_spamhaus_drop_entries_cidr ON public.spamhaus_drop_entries USING gist (cidr inet_ops);


--
-- Name: idx_system_backups_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_system_backups_active ON public.system_backups USING btree (status) WHERE (status = ANY (ARRAY['queued'::text, 'running'::text, 'verifying'::text]));


--
-- Name: idx_system_backups_completed_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_system_backups_completed_created ON public.system_backups USING btree (created_at DESC) WHERE (status = 'completed'::text);


--
-- Name: idx_system_backups_status_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_system_backups_status_created ON public.system_backups USING btree (status, created_at DESC);


--
-- Name: idx_tags_enabled_type_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tags_enabled_type_name ON public.tags USING btree (enabled, type, name);


--
-- Name: idx_threat_actors_active_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_threat_actors_active_name ON public.threat_actors USING btree (active, name);


--
-- Name: idx_threat_classifications_active_sort; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_threat_classifications_active_sort ON public.threat_classifications USING btree (active, sort_order, name);


--
-- Name: idx_threat_classifications_slug; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_threat_classifications_slug ON public.threat_classifications USING btree (slug);


--
-- Name: idx_threat_feed_expiration_policies_feed; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_threat_feed_expiration_policies_feed ON public.threat_feed_expiration_policies USING btree (feed_id);


--
-- Name: idx_users_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_users_public_id ON public.users USING btree (public_id);


--
-- Name: idx_users_role; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_role ON public.users USING btree (role);


--
-- Name: idx_users_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_status ON public.users USING btree (status);


--
-- Name: ioc_abuseipdb_enrichment_ip_uniq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ioc_abuseipdb_enrichment_ip_uniq ON public.ioc_abuseipdb_enrichment USING btree (ip);


--
-- Name: ioc_abuseipdb_enrichment_last_enriched_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_abuseipdb_enrichment_last_enriched_at_idx ON public.ioc_abuseipdb_enrichment USING btree (last_enriched_at);


--
-- Name: ioc_domain_analyst_confidence_override_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_analyst_confidence_override_idx ON public.ioc_domain USING btree (analyst_confidence_override) WHERE (analyst_confidence_override IS NOT NULL);


--
-- Name: ioc_domain_confidence_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_confidence_created_at_idx ON public.ioc_domain USING btree (confidence, created_at DESC);


--
-- Name: ioc_domain_confidence_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_confidence_idx ON public.ioc_domain USING btree (confidence);


--
-- Name: ioc_domain_confidence_source_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_confidence_source_idx ON public.ioc_domain USING btree (confidence_source) WHERE (confidence_source IS NOT NULL);


--
-- Name: ioc_domain_created_at_id_public_id_observable_observable_ty_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_created_at_id_public_id_observable_observable_ty_idx ON public.ioc_domain USING btree (created_at DESC) INCLUDE (id, public_id, observable, observable_type, source_name, confidence, category);


--
-- Name: ioc_domain_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_created_at_idx ON public.ioc_domain USING btree (created_at DESC);


--
-- Name: ioc_domain_created_at_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_created_at_idx1 ON public.ioc_domain USING btree (created_at DESC) WHERE (created_origin = 'manual_add'::text);


--
-- Name: ioc_domain_created_at_idx2; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_created_at_idx2 ON public.ioc_domain USING btree (created_at DESC) WHERE (created_origin = 'api'::text);


--
-- Name: ioc_domain_enrichment_last_enriched_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_enrichment_last_enriched_at_idx ON public.ioc_domain_enrichment USING btree (last_enriched_at);


--
-- Name: ioc_domain_enrichment_last_success_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_enrichment_last_success_at_idx ON public.ioc_domain_enrichment USING btree (last_success_at);


--
-- Name: ioc_domain_enrichment_root_domain_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_enrichment_root_domain_idx ON public.ioc_domain_enrichment USING btree (root_domain);


--
-- Name: ioc_domain_enrichment_root_domain_uniq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ioc_domain_enrichment_root_domain_uniq ON public.ioc_domain_enrichment USING btree (root_domain);


--
-- Name: ioc_domain_enrichment_updated_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_enrichment_updated_at_idx ON public.ioc_domain_enrichment USING btree (updated_at);


--
-- Name: ioc_domain_expires_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_expires_at_idx ON public.ioc_domain USING btree (expires_at) WHERE ((status = 'active'::text) AND (expires_at IS NOT NULL));


--
-- Name: ioc_domain_ioc_source_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_ioc_source_id_idx ON public.ioc_domain USING btree (ioc_source_id) WHERE (ioc_source_id IS NOT NULL);


--
-- Name: ioc_domain_last_seen_log_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_last_seen_log_idx ON public.ioc_domain USING btree (last_seen_log DESC NULLS LAST);


--
-- Name: ioc_domain_lower_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_lower_idx ON public.ioc_domain USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'md5='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_domain_lower_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_lower_idx1 ON public.ioc_domain USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'sha1='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_domain_lower_idx2; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_lower_idx2 ON public.ioc_domain USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'sha256='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_domain_lower_idx3; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_lower_idx3 ON public.ioc_domain USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'ssdeep='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_domain_lower_idx4; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_lower_idx4 ON public.ioc_domain USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'imphash='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_domain_lower_idx5; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_lower_idx5 ON public.ioc_domain USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'tlsh='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_domain_lower_idx6; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_lower_idx6 ON public.ioc_domain USING btree (lower(observable)) WHERE (observable_type = 'sha256'::text);


--
-- Name: ioc_domain_lower_idx7; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_lower_idx7 ON public.ioc_domain USING btree (lower(observable)) WHERE (observable_type = 'sha1'::text);


--
-- Name: ioc_domain_lower_idx8; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_lower_idx8 ON public.ioc_domain USING btree (lower(observable)) WHERE (observable_type = 'md5'::text);


--
-- Name: ioc_domain_lower_observable_type_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_lower_observable_type_created_at_idx ON public.ioc_domain USING btree (lower(observable), (
CASE
    WHEN (observable_type = 'hostname'::text) THEN 'domain'::text
    ELSE observable_type
END), created_at) WHERE (COALESCE(status, 'active'::text) = ANY (ARRAY['active'::text, 'expired'::text]));


--
-- Name: ioc_domain_observable_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_observable_idx ON public.ioc_domain USING gin (observable public.gin_trgm_ops);


--
-- Name: ioc_domain_observable_observable_type_source_name_confidenc_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_observable_observable_type_source_name_confidenc_idx ON public.ioc_domain USING btree (observable, observable_type, source_name, confidence, COALESCE(category, ''::text), COALESCE(source_url, ''::text));


--
-- Name: ioc_domain_observable_type_observable_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_observable_type_observable_idx ON public.ioc_domain USING btree (observable_type, observable);


--
-- Name: ioc_items_provider_fingerprint_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_provider_fingerprint_idx ON ONLY public.ioc_items USING btree (provider_fingerprint) WHERE (provider_fingerprint IS NOT NULL);


--
-- Name: ioc_domain_provider_fingerprint_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_provider_fingerprint_idx ON public.ioc_domain USING btree (provider_fingerprint) WHERE (provider_fingerprint IS NOT NULL);


--
-- Name: ioc_domain_public_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_public_id_idx ON public.ioc_domain USING btree (public_id);


--
-- Name: ioc_domain_reactivated_by_match_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_reactivated_by_match_at_idx ON public.ioc_domain USING btree (reactivated_by_match_at DESC) WHERE (reactivated_by_match_at IS NOT NULL);


--
-- Name: ioc_domain_source_name_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_source_name_created_at_idx ON public.ioc_domain USING btree (source_name, created_at DESC);


--
-- Name: ioc_domain_source_name_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_source_name_idx ON public.ioc_domain USING btree (source_name);


--
-- Name: ioc_domain_source_name_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_source_name_idx1 ON public.ioc_domain USING gin (source_name public.gin_trgm_ops);


--
-- Name: ioc_domain_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_status_idx ON public.ioc_domain USING btree (status);


--
-- Name: ioc_domain_threat_actor_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_threat_actor_id_idx ON public.ioc_domain USING btree (threat_actor_id) WHERE (threat_actor_id IS NOT NULL);


--
-- Name: ioc_domain_threat_classification_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_threat_classification_idx ON public.ioc_domain USING btree (threat_classification);


--
-- Name: ioc_domain_threat_classification_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_domain_threat_classification_idx1 ON public.ioc_domain USING btree (threat_classification) WHERE (threat_classification <> 'unknown'::text);


--
-- Name: ioc_enrichments_expires_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_enrichments_expires_at_idx ON public.ioc_enrichments USING btree (expires_at);


--
-- Name: ioc_enrichments_ioc_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_enrichments_ioc_id_idx ON public.ioc_enrichments USING btree (ioc_id);


--
-- Name: ioc_enrichments_provider_value_type_uniq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ioc_enrichments_provider_value_type_uniq ON public.ioc_enrichments USING btree (provider, ioc_value, ioc_type);


--
-- Name: ioc_file_hash_analyst_confidence_override_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_analyst_confidence_override_idx ON public.ioc_file_hash USING btree (analyst_confidence_override) WHERE (analyst_confidence_override IS NOT NULL);


--
-- Name: ioc_file_hash_confidence_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_confidence_created_at_idx ON public.ioc_file_hash USING btree (confidence, created_at DESC);


--
-- Name: ioc_file_hash_confidence_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_confidence_idx ON public.ioc_file_hash USING btree (confidence);


--
-- Name: ioc_file_hash_confidence_source_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_confidence_source_idx ON public.ioc_file_hash USING btree (confidence_source) WHERE (confidence_source IS NOT NULL);


--
-- Name: ioc_file_hash_created_at_id_public_id_observable_observable_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_created_at_id_public_id_observable_observable_idx ON public.ioc_file_hash USING btree (created_at DESC) INCLUDE (id, public_id, observable, observable_type, source_name, confidence, category);


--
-- Name: ioc_file_hash_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_created_at_idx ON public.ioc_file_hash USING btree (created_at DESC);


--
-- Name: ioc_file_hash_created_at_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_created_at_idx1 ON public.ioc_file_hash USING btree (created_at DESC) WHERE (created_origin = 'manual_add'::text);


--
-- Name: ioc_file_hash_created_at_idx2; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_created_at_idx2 ON public.ioc_file_hash USING btree (created_at DESC) WHERE (created_origin = 'api'::text);


--
-- Name: ioc_file_hash_expires_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_expires_at_idx ON public.ioc_file_hash USING btree (expires_at) WHERE ((status = 'active'::text) AND (expires_at IS NOT NULL));


--
-- Name: ioc_file_hash_ioc_source_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_ioc_source_id_idx ON public.ioc_file_hash USING btree (ioc_source_id) WHERE (ioc_source_id IS NOT NULL);


--
-- Name: ioc_file_hash_last_seen_log_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_last_seen_log_idx ON public.ioc_file_hash USING btree (last_seen_log DESC NULLS LAST);


--
-- Name: ioc_file_hash_lower_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_lower_idx ON public.ioc_file_hash USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'md5='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_file_hash_lower_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_lower_idx1 ON public.ioc_file_hash USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'sha1='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_file_hash_lower_idx2; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_lower_idx2 ON public.ioc_file_hash USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'sha256='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_file_hash_lower_idx3; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_lower_idx3 ON public.ioc_file_hash USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'ssdeep='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_file_hash_lower_idx4; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_lower_idx4 ON public.ioc_file_hash USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'imphash='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_file_hash_lower_idx5; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_lower_idx5 ON public.ioc_file_hash USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'tlsh='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_file_hash_lower_idx6; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_lower_idx6 ON public.ioc_file_hash USING btree (lower(observable)) WHERE (observable_type = 'sha256'::text);


--
-- Name: ioc_file_hash_lower_idx7; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_lower_idx7 ON public.ioc_file_hash USING btree (lower(observable)) WHERE (observable_type = 'sha1'::text);


--
-- Name: ioc_file_hash_lower_idx8; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_lower_idx8 ON public.ioc_file_hash USING btree (lower(observable)) WHERE (observable_type = 'md5'::text);


--
-- Name: ioc_file_hash_lower_observable_type_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_lower_observable_type_created_at_idx ON public.ioc_file_hash USING btree (lower(observable), (
CASE
    WHEN (observable_type = 'hostname'::text) THEN 'domain'::text
    ELSE observable_type
END), created_at) WHERE (COALESCE(status, 'active'::text) = ANY (ARRAY['active'::text, 'expired'::text]));


--
-- Name: ioc_file_hash_observable_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_observable_idx ON public.ioc_file_hash USING gin (observable public.gin_trgm_ops);


--
-- Name: ioc_file_hash_observable_observable_type_source_name_confid_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_observable_observable_type_source_name_confid_idx ON public.ioc_file_hash USING btree (observable, observable_type, source_name, confidence, COALESCE(category, ''::text), COALESCE(source_url, ''::text));


--
-- Name: ioc_file_hash_observable_type_observable_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_observable_type_observable_idx ON public.ioc_file_hash USING btree (observable_type, observable);


--
-- Name: ioc_file_hash_provider_fingerprint_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_provider_fingerprint_idx ON public.ioc_file_hash USING btree (provider_fingerprint) WHERE (provider_fingerprint IS NOT NULL);


--
-- Name: ioc_file_hash_public_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_public_id_idx ON public.ioc_file_hash USING btree (public_id);


--
-- Name: ioc_file_hash_reactivated_by_match_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_reactivated_by_match_at_idx ON public.ioc_file_hash USING btree (reactivated_by_match_at DESC) WHERE (reactivated_by_match_at IS NOT NULL);


--
-- Name: ioc_file_hash_source_name_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_source_name_created_at_idx ON public.ioc_file_hash USING btree (source_name, created_at DESC);


--
-- Name: ioc_file_hash_source_name_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_source_name_idx ON public.ioc_file_hash USING btree (source_name);


--
-- Name: ioc_file_hash_source_name_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_source_name_idx1 ON public.ioc_file_hash USING gin (source_name public.gin_trgm_ops);


--
-- Name: ioc_file_hash_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_status_idx ON public.ioc_file_hash USING btree (status);


--
-- Name: ioc_file_hash_threat_actor_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_threat_actor_id_idx ON public.ioc_file_hash USING btree (threat_actor_id) WHERE (threat_actor_id IS NOT NULL);


--
-- Name: ioc_file_hash_threat_classification_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_threat_classification_idx ON public.ioc_file_hash USING btree (threat_classification);


--
-- Name: ioc_file_hash_threat_classification_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_file_hash_threat_classification_idx1 ON public.ioc_file_hash USING btree (threat_classification) WHERE (threat_classification <> 'unknown'::text);


--
-- Name: ioc_ip_analyst_confidence_override_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_analyst_confidence_override_idx ON public.ioc_ip USING btree (analyst_confidence_override) WHERE (analyst_confidence_override IS NOT NULL);


--
-- Name: ioc_ip_confidence_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_confidence_created_at_idx ON public.ioc_ip USING btree (confidence, created_at DESC);


--
-- Name: ioc_ip_confidence_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_confidence_idx ON public.ioc_ip USING btree (confidence);


--
-- Name: ioc_ip_confidence_source_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_confidence_source_idx ON public.ioc_ip USING btree (confidence_source) WHERE (confidence_source IS NOT NULL);


--
-- Name: ioc_ip_created_at_id_public_id_observable_observable_type_s_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_created_at_id_public_id_observable_observable_type_s_idx ON public.ioc_ip USING btree (created_at DESC) INCLUDE (id, public_id, observable, observable_type, source_name, confidence, category);


--
-- Name: ioc_ip_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_created_at_idx ON public.ioc_ip USING btree (created_at DESC);


--
-- Name: ioc_ip_created_at_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_created_at_idx1 ON public.ioc_ip USING btree (created_at DESC) WHERE (created_origin = 'manual_add'::text);


--
-- Name: ioc_ip_created_at_idx2; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_created_at_idx2 ON public.ioc_ip USING btree (created_at DESC) WHERE (created_origin = 'api'::text);


--
-- Name: ioc_ip_enrichment_asn_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_enrichment_asn_idx ON public.ioc_ip_enrichment USING btree (asn);


--
-- Name: ioc_ip_enrichment_country_code_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_enrichment_country_code_idx ON public.ioc_ip_enrichment USING btree (country_code);


--
-- Name: ioc_ip_enrichment_ip_uniq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ioc_ip_enrichment_ip_uniq ON public.ioc_ip_enrichment USING btree (ip);


--
-- Name: ioc_ip_enrichment_last_enriched_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_enrichment_last_enriched_at_idx ON public.ioc_ip_enrichment USING btree (last_enriched_at);


--
-- Name: ioc_ip_enrichment_normalized_ip_uniq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ioc_ip_enrichment_normalized_ip_uniq ON public.ioc_ip_enrichment USING btree (normalized_ip);


--
-- Name: ioc_ip_enrichment_provider_normalized_ip_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_enrichment_provider_normalized_ip_idx ON public.ioc_ip_enrichment USING btree (provider, normalized_ip);


--
-- Name: ioc_ip_expires_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_expires_at_idx ON public.ioc_ip USING btree (expires_at) WHERE ((status = 'active'::text) AND (expires_at IS NOT NULL));


--
-- Name: ioc_ip_ioc_source_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_ioc_source_id_idx ON public.ioc_ip USING btree (ioc_source_id) WHERE (ioc_source_id IS NOT NULL);


--
-- Name: ioc_ip_last_seen_log_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_last_seen_log_idx ON public.ioc_ip USING btree (last_seen_log DESC NULLS LAST);


--
-- Name: ioc_ip_lower_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_lower_idx ON public.ioc_ip USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'md5='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_ip_lower_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_lower_idx1 ON public.ioc_ip USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'sha1='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_ip_lower_idx2; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_lower_idx2 ON public.ioc_ip USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'sha256='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_ip_lower_idx3; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_lower_idx3 ON public.ioc_ip USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'ssdeep='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_ip_lower_idx4; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_lower_idx4 ON public.ioc_ip USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'imphash='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_ip_lower_idx5; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_lower_idx5 ON public.ioc_ip USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'tlsh='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_ip_lower_idx6; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_lower_idx6 ON public.ioc_ip USING btree (lower(observable)) WHERE (observable_type = 'sha256'::text);


--
-- Name: ioc_ip_lower_idx7; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_lower_idx7 ON public.ioc_ip USING btree (lower(observable)) WHERE (observable_type = 'sha1'::text);


--
-- Name: ioc_ip_lower_idx8; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_lower_idx8 ON public.ioc_ip USING btree (lower(observable)) WHERE (observable_type = 'md5'::text);


--
-- Name: ioc_ip_lower_observable_type_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_lower_observable_type_created_at_idx ON public.ioc_ip USING btree (lower(observable), (
CASE
    WHEN (observable_type = 'hostname'::text) THEN 'domain'::text
    ELSE observable_type
END), created_at) WHERE (COALESCE(status, 'active'::text) = ANY (ARRAY['active'::text, 'expired'::text]));


--
-- Name: ioc_ip_observable_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_observable_idx ON public.ioc_ip USING gin (observable public.gin_trgm_ops);


--
-- Name: ioc_ip_observable_observable_type_source_name_confidence_co_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_observable_observable_type_source_name_confidence_co_idx ON public.ioc_ip USING btree (observable, observable_type, source_name, confidence, COALESCE(category, ''::text), COALESCE(source_url, ''::text));


--
-- Name: ioc_ip_observable_type_observable_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_observable_type_observable_idx ON public.ioc_ip USING btree (observable_type, observable);


--
-- Name: ioc_ip_provider_fingerprint_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_provider_fingerprint_idx ON public.ioc_ip USING btree (provider_fingerprint) WHERE (provider_fingerprint IS NOT NULL);


--
-- Name: ioc_ip_public_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_public_id_idx ON public.ioc_ip USING btree (public_id);


--
-- Name: ioc_ip_reactivated_by_match_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_reactivated_by_match_at_idx ON public.ioc_ip USING btree (reactivated_by_match_at DESC) WHERE (reactivated_by_match_at IS NOT NULL);


--
-- Name: ioc_ip_source_name_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_source_name_created_at_idx ON public.ioc_ip USING btree (source_name, created_at DESC);


--
-- Name: ioc_ip_source_name_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_source_name_idx ON public.ioc_ip USING btree (source_name);


--
-- Name: ioc_ip_source_name_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_source_name_idx1 ON public.ioc_ip USING gin (source_name public.gin_trgm_ops);


--
-- Name: ioc_ip_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_status_idx ON public.ioc_ip USING btree (status);


--
-- Name: ioc_ip_threat_actor_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_threat_actor_id_idx ON public.ioc_ip USING btree (threat_actor_id) WHERE (threat_actor_id IS NOT NULL);


--
-- Name: ioc_ip_threat_classification_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_threat_classification_idx ON public.ioc_ip USING btree (threat_classification);


--
-- Name: ioc_ip_threat_classification_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ip_threat_classification_idx1 ON public.ioc_ip USING btree (threat_classification) WHERE (threat_classification <> 'unknown'::text);


--
-- Name: ioc_ipv6_analyst_confidence_override_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_analyst_confidence_override_idx ON public.ioc_ipv6 USING btree (analyst_confidence_override) WHERE (analyst_confidence_override IS NOT NULL);


--
-- Name: ioc_ipv6_confidence_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_confidence_created_at_idx ON public.ioc_ipv6 USING btree (confidence, created_at DESC);


--
-- Name: ioc_ipv6_confidence_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_confidence_idx ON public.ioc_ipv6 USING btree (confidence);


--
-- Name: ioc_ipv6_confidence_source_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_confidence_source_idx ON public.ioc_ipv6 USING btree (confidence_source) WHERE (confidence_source IS NOT NULL);


--
-- Name: ioc_ipv6_created_at_id_public_id_observable_observable_type_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_created_at_id_public_id_observable_observable_type_idx ON public.ioc_ipv6 USING btree (created_at DESC) INCLUDE (id, public_id, observable, observable_type, source_name, confidence, category);


--
-- Name: ioc_ipv6_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_created_at_idx ON public.ioc_ipv6 USING btree (created_at DESC);


--
-- Name: ioc_ipv6_created_at_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_created_at_idx1 ON public.ioc_ipv6 USING btree (created_at DESC) WHERE (created_origin = 'manual_add'::text);


--
-- Name: ioc_ipv6_created_at_idx2; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_created_at_idx2 ON public.ioc_ipv6 USING btree (created_at DESC) WHERE (created_origin = 'api'::text);


--
-- Name: ioc_ipv6_expires_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_expires_at_idx ON public.ioc_ipv6 USING btree (expires_at) WHERE ((status = 'active'::text) AND (expires_at IS NOT NULL));


--
-- Name: ioc_ipv6_ioc_source_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_ioc_source_id_idx ON public.ioc_ipv6 USING btree (ioc_source_id) WHERE (ioc_source_id IS NOT NULL);


--
-- Name: ioc_ipv6_last_seen_log_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_last_seen_log_idx ON public.ioc_ipv6 USING btree (last_seen_log DESC NULLS LAST);


--
-- Name: ioc_ipv6_lower_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_lower_idx ON public.ioc_ipv6 USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'md5='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_ipv6_lower_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_lower_idx1 ON public.ioc_ipv6 USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'sha1='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_ipv6_lower_idx2; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_lower_idx2 ON public.ioc_ipv6 USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'sha256='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_ipv6_lower_idx3; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_lower_idx3 ON public.ioc_ipv6 USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'ssdeep='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_ipv6_lower_idx4; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_lower_idx4 ON public.ioc_ipv6 USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'imphash='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_ipv6_lower_idx5; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_lower_idx5 ON public.ioc_ipv6 USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'tlsh='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_ipv6_lower_idx6; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_lower_idx6 ON public.ioc_ipv6 USING btree (lower(observable)) WHERE (observable_type = 'sha256'::text);


--
-- Name: ioc_ipv6_lower_idx7; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_lower_idx7 ON public.ioc_ipv6 USING btree (lower(observable)) WHERE (observable_type = 'sha1'::text);


--
-- Name: ioc_ipv6_lower_idx8; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_lower_idx8 ON public.ioc_ipv6 USING btree (lower(observable)) WHERE (observable_type = 'md5'::text);


--
-- Name: ioc_ipv6_lower_observable_type_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_lower_observable_type_created_at_idx ON public.ioc_ipv6 USING btree (lower(observable), (
CASE
    WHEN (observable_type = 'hostname'::text) THEN 'domain'::text
    ELSE observable_type
END), created_at) WHERE (COALESCE(status, 'active'::text) = ANY (ARRAY['active'::text, 'expired'::text]));


--
-- Name: ioc_ipv6_observable_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_observable_idx ON public.ioc_ipv6 USING gin (observable public.gin_trgm_ops);


--
-- Name: ioc_ipv6_observable_observable_type_source_name_confidence__idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_observable_observable_type_source_name_confidence__idx ON public.ioc_ipv6 USING btree (observable, observable_type, source_name, confidence, COALESCE(category, ''::text), COALESCE(source_url, ''::text));


--
-- Name: ioc_ipv6_observable_type_observable_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_observable_type_observable_idx ON public.ioc_ipv6 USING btree (observable_type, observable);


--
-- Name: ioc_ipv6_provider_fingerprint_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_provider_fingerprint_idx ON public.ioc_ipv6 USING btree (provider_fingerprint) WHERE (provider_fingerprint IS NOT NULL);


--
-- Name: ioc_ipv6_public_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_public_id_idx ON public.ioc_ipv6 USING btree (public_id);


--
-- Name: ioc_ipv6_reactivated_by_match_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_reactivated_by_match_at_idx ON public.ioc_ipv6 USING btree (reactivated_by_match_at DESC) WHERE (reactivated_by_match_at IS NOT NULL);


--
-- Name: ioc_ipv6_source_name_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_source_name_created_at_idx ON public.ioc_ipv6 USING btree (source_name, created_at DESC);


--
-- Name: ioc_ipv6_source_name_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_source_name_idx ON public.ioc_ipv6 USING btree (source_name);


--
-- Name: ioc_ipv6_source_name_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_source_name_idx1 ON public.ioc_ipv6 USING gin (source_name public.gin_trgm_ops);


--
-- Name: ioc_ipv6_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_status_idx ON public.ioc_ipv6 USING btree (status);


--
-- Name: ioc_ipv6_threat_actor_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_threat_actor_id_idx ON public.ioc_ipv6 USING btree (threat_actor_id) WHERE (threat_actor_id IS NOT NULL);


--
-- Name: ioc_ipv6_threat_classification_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_threat_classification_idx ON public.ioc_ipv6 USING btree (threat_classification);


--
-- Name: ioc_ipv6_threat_classification_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_ipv6_threat_classification_idx1 ON public.ioc_ipv6 USING btree (threat_classification) WHERE (threat_classification <> 'unknown'::text);


--
-- Name: ioc_items_other_analyst_confidence_override_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_analyst_confidence_override_idx ON public.ioc_items_other USING btree (analyst_confidence_override) WHERE (analyst_confidence_override IS NOT NULL);


--
-- Name: ioc_items_other_confidence_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_confidence_created_at_idx ON public.ioc_items_other USING btree (confidence, created_at DESC);


--
-- Name: ioc_items_other_confidence_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_confidence_idx ON public.ioc_items_other USING btree (confidence);


--
-- Name: ioc_items_other_confidence_source_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_confidence_source_idx ON public.ioc_items_other USING btree (confidence_source) WHERE (confidence_source IS NOT NULL);


--
-- Name: ioc_items_other_created_at_id_public_id_observable_observab_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_created_at_id_public_id_observable_observab_idx ON public.ioc_items_other USING btree (created_at DESC) INCLUDE (id, public_id, observable, observable_type, source_name, confidence, category);


--
-- Name: ioc_items_other_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_created_at_idx ON public.ioc_items_other USING btree (created_at DESC);


--
-- Name: ioc_items_other_created_at_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_created_at_idx1 ON public.ioc_items_other USING btree (created_at DESC) WHERE (created_origin = 'manual_add'::text);


--
-- Name: ioc_items_other_created_at_idx2; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_created_at_idx2 ON public.ioc_items_other USING btree (created_at DESC) WHERE (created_origin = 'api'::text);


--
-- Name: ioc_items_other_expires_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_expires_at_idx ON public.ioc_items_other USING btree (expires_at) WHERE ((status = 'active'::text) AND (expires_at IS NOT NULL));


--
-- Name: ioc_items_other_ioc_source_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_ioc_source_id_idx ON public.ioc_items_other USING btree (ioc_source_id) WHERE (ioc_source_id IS NOT NULL);


--
-- Name: ioc_items_other_last_seen_log_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_last_seen_log_idx ON public.ioc_items_other USING btree (last_seen_log DESC NULLS LAST);


--
-- Name: ioc_items_other_lower_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_lower_idx ON public.ioc_items_other USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'md5='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_items_other_lower_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_lower_idx1 ON public.ioc_items_other USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'sha1='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_items_other_lower_idx2; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_lower_idx2 ON public.ioc_items_other USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'sha256='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_items_other_lower_idx3; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_lower_idx3 ON public.ioc_items_other USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'ssdeep='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_items_other_lower_idx4; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_lower_idx4 ON public.ioc_items_other USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'imphash='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_items_other_lower_idx5; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_lower_idx5 ON public.ioc_items_other USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'tlsh='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_items_other_lower_idx6; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_lower_idx6 ON public.ioc_items_other USING btree (lower(observable)) WHERE (observable_type = 'sha256'::text);


--
-- Name: ioc_items_other_lower_idx7; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_lower_idx7 ON public.ioc_items_other USING btree (lower(observable)) WHERE (observable_type = 'sha1'::text);


--
-- Name: ioc_items_other_lower_idx8; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_lower_idx8 ON public.ioc_items_other USING btree (lower(observable)) WHERE (observable_type = 'md5'::text);


--
-- Name: ioc_items_other_lower_observable_type_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_lower_observable_type_created_at_idx ON public.ioc_items_other USING btree (lower(observable), (
CASE
    WHEN (observable_type = 'hostname'::text) THEN 'domain'::text
    ELSE observable_type
END), created_at) WHERE (COALESCE(status, 'active'::text) = ANY (ARRAY['active'::text, 'expired'::text]));


--
-- Name: ioc_items_other_observable_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_observable_idx ON public.ioc_items_other USING gin (observable public.gin_trgm_ops);


--
-- Name: ioc_items_other_observable_observable_type_source_name_conf_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_observable_observable_type_source_name_conf_idx ON public.ioc_items_other USING btree (observable, observable_type, source_name, confidence, COALESCE(category, ''::text), COALESCE(source_url, ''::text));


--
-- Name: ioc_items_other_observable_type_observable_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_observable_type_observable_idx ON public.ioc_items_other USING btree (observable_type, observable);


--
-- Name: ioc_items_other_provider_fingerprint_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_provider_fingerprint_idx ON public.ioc_items_other USING btree (provider_fingerprint) WHERE (provider_fingerprint IS NOT NULL);


--
-- Name: ioc_items_other_public_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_public_id_idx ON public.ioc_items_other USING btree (public_id);


--
-- Name: ioc_items_other_reactivated_by_match_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_reactivated_by_match_at_idx ON public.ioc_items_other USING btree (reactivated_by_match_at DESC) WHERE (reactivated_by_match_at IS NOT NULL);


--
-- Name: ioc_items_other_source_name_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_source_name_created_at_idx ON public.ioc_items_other USING btree (source_name, created_at DESC);


--
-- Name: ioc_items_other_source_name_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_source_name_idx ON public.ioc_items_other USING btree (source_name);


--
-- Name: ioc_items_other_source_name_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_source_name_idx1 ON public.ioc_items_other USING gin (source_name public.gin_trgm_ops);


--
-- Name: ioc_items_other_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_status_idx ON public.ioc_items_other USING btree (status);


--
-- Name: ioc_items_other_threat_actor_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_threat_actor_id_idx ON public.ioc_items_other USING btree (threat_actor_id) WHERE (threat_actor_id IS NOT NULL);


--
-- Name: ioc_items_other_threat_classification_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_threat_classification_idx ON public.ioc_items_other USING btree (threat_classification);


--
-- Name: ioc_items_other_threat_classification_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_items_other_threat_classification_idx1 ON public.ioc_items_other USING btree (threat_classification) WHERE (threat_classification <> 'unknown'::text);


--
-- Name: ioc_source_expiration_type_policies_source_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_source_expiration_type_policies_source_id_idx ON public.ioc_source_expiration_type_policies USING btree (source_id);


--
-- Name: ioc_spamhaus_drop_enrichment_last_attempt_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_spamhaus_drop_enrichment_last_attempt_at_idx ON public.ioc_spamhaus_drop_enrichment USING btree (last_attempt_at DESC NULLS LAST);


--
-- Name: ioc_spamhaus_drop_enrichment_lookup_ip_uniq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ioc_spamhaus_drop_enrichment_lookup_ip_uniq ON public.ioc_spamhaus_drop_enrichment USING btree (lookup_ip);


--
-- Name: ioc_url_analyst_confidence_override_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_analyst_confidence_override_idx ON public.ioc_url USING btree (analyst_confidence_override) WHERE (analyst_confidence_override IS NOT NULL);


--
-- Name: ioc_url_confidence_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_confidence_created_at_idx ON public.ioc_url USING btree (confidence, created_at DESC);


--
-- Name: ioc_url_confidence_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_confidence_idx ON public.ioc_url USING btree (confidence);


--
-- Name: ioc_url_confidence_source_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_confidence_source_idx ON public.ioc_url USING btree (confidence_source) WHERE (confidence_source IS NOT NULL);


--
-- Name: ioc_url_created_at_id_public_id_observable_observable_type__idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_created_at_id_public_id_observable_observable_type__idx ON public.ioc_url USING btree (created_at DESC) INCLUDE (id, public_id, observable, observable_type, source_name, confidence, category);


--
-- Name: ioc_url_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_created_at_idx ON public.ioc_url USING btree (created_at DESC);


--
-- Name: ioc_url_created_at_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_created_at_idx1 ON public.ioc_url USING btree (created_at DESC) WHERE (created_origin = 'manual_add'::text);


--
-- Name: ioc_url_created_at_idx2; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_created_at_idx2 ON public.ioc_url USING btree (created_at DESC) WHERE (created_origin = 'api'::text);


--
-- Name: ioc_url_expires_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_expires_at_idx ON public.ioc_url USING btree (expires_at) WHERE ((status = 'active'::text) AND (expires_at IS NOT NULL));


--
-- Name: ioc_url_ioc_source_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_ioc_source_id_idx ON public.ioc_url USING btree (ioc_source_id) WHERE (ioc_source_id IS NOT NULL);


--
-- Name: ioc_url_last_seen_log_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_last_seen_log_idx ON public.ioc_url USING btree (last_seen_log DESC NULLS LAST);


--
-- Name: ioc_url_lower_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_lower_idx ON public.ioc_url USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'md5='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_url_lower_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_lower_idx1 ON public.ioc_url USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'sha1='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_url_lower_idx2; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_lower_idx2 ON public.ioc_url USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'sha256='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_url_lower_idx3; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_lower_idx3 ON public.ioc_url USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'ssdeep='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_url_lower_idx4; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_lower_idx4 ON public.ioc_url USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'imphash='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_url_lower_idx5; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_lower_idx5 ON public.ioc_url USING btree (lower(NULLIF(split_part(split_part(replace(COALESCE(note, ''::text), ' '::text, ''::text), 'tlsh='::text, 2), '|'::text, 1), ''::text)));


--
-- Name: ioc_url_lower_idx6; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_lower_idx6 ON public.ioc_url USING btree (lower(observable)) WHERE (observable_type = 'sha256'::text);


--
-- Name: ioc_url_lower_idx7; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_lower_idx7 ON public.ioc_url USING btree (lower(observable)) WHERE (observable_type = 'sha1'::text);


--
-- Name: ioc_url_lower_idx8; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_lower_idx8 ON public.ioc_url USING btree (lower(observable)) WHERE (observable_type = 'md5'::text);


--
-- Name: ioc_url_lower_observable_type_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_lower_observable_type_created_at_idx ON public.ioc_url USING btree (lower(observable), (
CASE
    WHEN (observable_type = 'hostname'::text) THEN 'domain'::text
    ELSE observable_type
END), created_at) WHERE (COALESCE(status, 'active'::text) = ANY (ARRAY['active'::text, 'expired'::text]));


--
-- Name: ioc_url_observable_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_observable_idx ON public.ioc_url USING gin (observable public.gin_trgm_ops);


--
-- Name: ioc_url_observable_observable_type_source_name_confidence_c_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_observable_observable_type_source_name_confidence_c_idx ON public.ioc_url USING btree (observable, observable_type, source_name, confidence, COALESCE(category, ''::text), COALESCE(source_url, ''::text));


--
-- Name: ioc_url_observable_type_observable_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_observable_type_observable_idx ON public.ioc_url USING btree (observable_type, observable);


--
-- Name: ioc_url_provider_fingerprint_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_provider_fingerprint_idx ON public.ioc_url USING btree (provider_fingerprint) WHERE (provider_fingerprint IS NOT NULL);


--
-- Name: ioc_url_public_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_public_id_idx ON public.ioc_url USING btree (public_id);


--
-- Name: ioc_url_reactivated_by_match_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_reactivated_by_match_at_idx ON public.ioc_url USING btree (reactivated_by_match_at DESC) WHERE (reactivated_by_match_at IS NOT NULL);


--
-- Name: ioc_url_source_name_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_source_name_created_at_idx ON public.ioc_url USING btree (source_name, created_at DESC);


--
-- Name: ioc_url_source_name_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_source_name_idx ON public.ioc_url USING btree (source_name);


--
-- Name: ioc_url_source_name_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_source_name_idx1 ON public.ioc_url USING gin (source_name public.gin_trgm_ops);


--
-- Name: ioc_url_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_status_idx ON public.ioc_url USING btree (status);


--
-- Name: ioc_url_threat_actor_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_threat_actor_id_idx ON public.ioc_url USING btree (threat_actor_id) WHERE (threat_actor_id IS NOT NULL);


--
-- Name: ioc_url_threat_classification_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_threat_classification_idx ON public.ioc_url USING btree (threat_classification);


--
-- Name: ioc_url_threat_classification_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ioc_url_threat_classification_idx1 ON public.ioc_url USING btree (threat_classification) WHERE (threat_classification <> 'unknown'::text);


--
-- Name: uq_file_artifact_hashes_artifact_type; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_file_artifact_hashes_artifact_type ON public.file_artifact_hashes USING btree (artifact_id, hash_type);


--
-- Name: uq_file_artifact_hashes_one_primary; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_file_artifact_hashes_one_primary ON public.file_artifact_hashes USING btree (artifact_id) WHERE (is_primary = true);


--
-- Name: uq_file_artifact_hashes_type_value; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_file_artifact_hashes_type_value ON public.file_artifact_hashes USING btree (hash_type, normalized_hash_value);


--
-- Name: uq_file_artifact_ioc_links_one_canonical; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_file_artifact_ioc_links_one_canonical ON public.file_artifact_ioc_links USING btree (artifact_id) WHERE (is_canonical_ioc = true);


--
-- Name: uq_integration_feeds_integration_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_integration_feeds_integration_id ON public.integration_feeds USING btree (integration_id);


--
-- Name: uq_ioc_observables_ioc_type_value; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_ioc_observables_ioc_type_value ON public.ioc_observables USING btree (ioc_public_id, observable_type, observable_value);


--
-- Name: uq_ioc_source_tag_override_active; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_ioc_source_tag_override_active ON public.ioc_source_tag_overrides USING btree (ioc_id, tag_normalized, lower(source_name)) WHERE (restored_at IS NULL);


--
-- Name: uq_ioc_suppressions_active_scope; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_ioc_suppressions_active_scope ON public.ioc_suppressions USING btree (lower(ioc_value), lower(ioc_type), scope, COALESCE(lower(source_name), ''::text)) WHERE (deleted_at IS NULL);


--
-- Name: uq_ioc_suppressions_one_active_value_type; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_ioc_suppressions_one_active_value_type ON public.ioc_suppressions USING btree (lower(ioc_value), lower(ioc_type)) WHERE ((active = true) AND (deleted_at IS NULL));


--
-- Name: uq_ioc_tags_assignment; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_ioc_tags_assignment ON public.ioc_tags USING btree (ioc_id, tag_id, origin, source_key);


--
-- Name: uq_ioc_tc_override_active; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_ioc_tc_override_active ON public.ioc_threat_classification_overrides USING btree (ioc_id, ioc_observable_type, classification_slug, action, lower(COALESCE(source_name, ''::text))) WHERE (cleared_at IS NULL);


--
-- Name: uq_pf_generations_active; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_pf_generations_active ON public.published_feed_generations USING btree (feed_id, snapshot_window, ioc_type_key) WHERE (state = 'active'::text);


--
-- Name: uq_published_feeds_slug; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_published_feeds_slug ON public.published_feeds USING btree (slug);


--
-- Name: uq_spamhaus_drop_entries_list_cidr; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_spamhaus_drop_entries_list_cidr ON public.spamhaus_drop_entries USING btree (list_type, cidr);


--
-- Name: uq_tags_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_tags_name ON public.tags USING btree (name);


--
-- Name: uq_tags_slug; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_tags_slug ON public.tags USING btree (slug);


--
-- Name: uq_users_single_system_admin; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_users_single_system_admin ON public.users USING btree (is_system_admin) WHERE is_system_admin;


--
-- Name: ioc_domain_analyst_confidence_override_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_analyst_confidence_override ATTACH PARTITION public.ioc_domain_analyst_confidence_override_idx;


--
-- Name: ioc_domain_confidence_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_confidence_created_at_desc ATTACH PARTITION public.ioc_domain_confidence_created_at_idx;


--
-- Name: ioc_domain_confidence_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_confidence ATTACH PARTITION public.ioc_domain_confidence_idx;


--
-- Name: ioc_domain_confidence_source_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_confidence_source ATTACH PARTITION public.ioc_domain_confidence_source_idx;


--
-- Name: ioc_domain_created_at_id_public_id_observable_observable_ty_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_created_at_desc_covering ATTACH PARTITION public.ioc_domain_created_at_id_public_id_observable_observable_ty_idx;


--
-- Name: ioc_domain_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_created_at ATTACH PARTITION public.ioc_domain_created_at_idx;


--
-- Name: ioc_domain_created_at_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_manual_recent ATTACH PARTITION public.ioc_domain_created_at_idx1;


--
-- Name: ioc_domain_created_at_idx2; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_api_recent ATTACH PARTITION public.ioc_domain_created_at_idx2;


--
-- Name: ioc_domain_expires_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_expires_at ATTACH PARTITION public.ioc_domain_expires_at_idx;


--
-- Name: ioc_domain_ioc_source_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_ioc_source_id ATTACH PARTITION public.ioc_domain_ioc_source_id_idx;


--
-- Name: ioc_domain_last_seen_log_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_last_seen ATTACH PARTITION public.ioc_domain_last_seen_log_idx;


--
-- Name: ioc_domain_lower_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_md5_from_note ATTACH PARTITION public.ioc_domain_lower_idx;


--
-- Name: ioc_domain_lower_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_sha1_from_note ATTACH PARTITION public.ioc_domain_lower_idx1;


--
-- Name: ioc_domain_lower_idx2; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_sha256_from_note ATTACH PARTITION public.ioc_domain_lower_idx2;


--
-- Name: ioc_domain_lower_idx3; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_ssdeep_from_note ATTACH PARTITION public.ioc_domain_lower_idx3;


--
-- Name: ioc_domain_lower_idx4; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_imphash_from_note ATTACH PARTITION public.ioc_domain_lower_idx4;


--
-- Name: ioc_domain_lower_idx5; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_tlsh_from_note ATTACH PARTITION public.ioc_domain_lower_idx5;


--
-- Name: ioc_domain_lower_idx6; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_sha256_lower_observable ATTACH PARTITION public.ioc_domain_lower_idx6;


--
-- Name: ioc_domain_lower_idx7; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_sha1_lower_observable ATTACH PARTITION public.ioc_domain_lower_idx7;


--
-- Name: ioc_domain_lower_idx8; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_md5_lower_observable ATTACH PARTITION public.ioc_domain_lower_idx8;


--
-- Name: ioc_domain_lower_observable_type_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_supplement_lookup ATTACH PARTITION public.ioc_domain_lower_observable_type_created_at_idx;


--
-- Name: ioc_domain_observable_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_observable_trgm ATTACH PARTITION public.ioc_domain_observable_idx;


--
-- Name: ioc_domain_observable_observable_type_source_name_confidenc_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_dedup ATTACH PARTITION public.ioc_domain_observable_observable_type_source_name_confidenc_idx;


--
-- Name: ioc_domain_observable_type_observable_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_observable_type_observable ATTACH PARTITION public.ioc_domain_observable_type_observable_idx;


--
-- Name: ioc_domain_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.ioc_items_pkey1 ATTACH PARTITION public.ioc_domain_pkey;


--
-- Name: ioc_domain_provider_fingerprint_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.ioc_items_provider_fingerprint_idx ATTACH PARTITION public.ioc_domain_provider_fingerprint_idx;


--
-- Name: ioc_domain_public_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_public_id ATTACH PARTITION public.ioc_domain_public_id_idx;


--
-- Name: ioc_domain_reactivated_by_match_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_reactivated_by_match_at ATTACH PARTITION public.ioc_domain_reactivated_by_match_at_idx;


--
-- Name: ioc_domain_source_name_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_source_created_at_desc ATTACH PARTITION public.ioc_domain_source_name_created_at_idx;


--
-- Name: ioc_domain_source_name_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_source ATTACH PARTITION public.ioc_domain_source_name_idx;


--
-- Name: ioc_domain_source_name_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_source_trgm ATTACH PARTITION public.ioc_domain_source_name_idx1;


--
-- Name: ioc_domain_status_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_status ATTACH PARTITION public.ioc_domain_status_idx;


--
-- Name: ioc_domain_threat_actor_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_threat_actor_id ATTACH PARTITION public.ioc_domain_threat_actor_id_idx;


--
-- Name: ioc_domain_threat_classification_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_threat_classification ATTACH PARTITION public.ioc_domain_threat_classification_idx;


--
-- Name: ioc_domain_threat_classification_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_threat_classification_active ATTACH PARTITION public.ioc_domain_threat_classification_idx1;


--
-- Name: ioc_file_hash_analyst_confidence_override_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_analyst_confidence_override ATTACH PARTITION public.ioc_file_hash_analyst_confidence_override_idx;


--
-- Name: ioc_file_hash_confidence_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_confidence_created_at_desc ATTACH PARTITION public.ioc_file_hash_confidence_created_at_idx;


--
-- Name: ioc_file_hash_confidence_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_confidence ATTACH PARTITION public.ioc_file_hash_confidence_idx;


--
-- Name: ioc_file_hash_confidence_source_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_confidence_source ATTACH PARTITION public.ioc_file_hash_confidence_source_idx;


--
-- Name: ioc_file_hash_created_at_id_public_id_observable_observable_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_created_at_desc_covering ATTACH PARTITION public.ioc_file_hash_created_at_id_public_id_observable_observable_idx;


--
-- Name: ioc_file_hash_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_created_at ATTACH PARTITION public.ioc_file_hash_created_at_idx;


--
-- Name: ioc_file_hash_created_at_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_manual_recent ATTACH PARTITION public.ioc_file_hash_created_at_idx1;


--
-- Name: ioc_file_hash_created_at_idx2; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_api_recent ATTACH PARTITION public.ioc_file_hash_created_at_idx2;


--
-- Name: ioc_file_hash_expires_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_expires_at ATTACH PARTITION public.ioc_file_hash_expires_at_idx;


--
-- Name: ioc_file_hash_ioc_source_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_ioc_source_id ATTACH PARTITION public.ioc_file_hash_ioc_source_id_idx;


--
-- Name: ioc_file_hash_last_seen_log_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_last_seen ATTACH PARTITION public.ioc_file_hash_last_seen_log_idx;


--
-- Name: ioc_file_hash_lower_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_md5_from_note ATTACH PARTITION public.ioc_file_hash_lower_idx;


--
-- Name: ioc_file_hash_lower_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_sha1_from_note ATTACH PARTITION public.ioc_file_hash_lower_idx1;


--
-- Name: ioc_file_hash_lower_idx2; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_sha256_from_note ATTACH PARTITION public.ioc_file_hash_lower_idx2;


--
-- Name: ioc_file_hash_lower_idx3; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_ssdeep_from_note ATTACH PARTITION public.ioc_file_hash_lower_idx3;


--
-- Name: ioc_file_hash_lower_idx4; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_imphash_from_note ATTACH PARTITION public.ioc_file_hash_lower_idx4;


--
-- Name: ioc_file_hash_lower_idx5; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_tlsh_from_note ATTACH PARTITION public.ioc_file_hash_lower_idx5;


--
-- Name: ioc_file_hash_lower_idx6; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_sha256_lower_observable ATTACH PARTITION public.ioc_file_hash_lower_idx6;


--
-- Name: ioc_file_hash_lower_idx7; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_sha1_lower_observable ATTACH PARTITION public.ioc_file_hash_lower_idx7;


--
-- Name: ioc_file_hash_lower_idx8; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_md5_lower_observable ATTACH PARTITION public.ioc_file_hash_lower_idx8;


--
-- Name: ioc_file_hash_lower_observable_type_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_supplement_lookup ATTACH PARTITION public.ioc_file_hash_lower_observable_type_created_at_idx;


--
-- Name: ioc_file_hash_observable_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_observable_trgm ATTACH PARTITION public.ioc_file_hash_observable_idx;


--
-- Name: ioc_file_hash_observable_observable_type_source_name_confid_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_dedup ATTACH PARTITION public.ioc_file_hash_observable_observable_type_source_name_confid_idx;


--
-- Name: ioc_file_hash_observable_type_observable_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_observable_type_observable ATTACH PARTITION public.ioc_file_hash_observable_type_observable_idx;


--
-- Name: ioc_file_hash_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.ioc_items_pkey1 ATTACH PARTITION public.ioc_file_hash_pkey;


--
-- Name: ioc_file_hash_provider_fingerprint_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.ioc_items_provider_fingerprint_idx ATTACH PARTITION public.ioc_file_hash_provider_fingerprint_idx;


--
-- Name: ioc_file_hash_public_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_public_id ATTACH PARTITION public.ioc_file_hash_public_id_idx;


--
-- Name: ioc_file_hash_reactivated_by_match_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_reactivated_by_match_at ATTACH PARTITION public.ioc_file_hash_reactivated_by_match_at_idx;


--
-- Name: ioc_file_hash_source_name_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_source_created_at_desc ATTACH PARTITION public.ioc_file_hash_source_name_created_at_idx;


--
-- Name: ioc_file_hash_source_name_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_source ATTACH PARTITION public.ioc_file_hash_source_name_idx;


--
-- Name: ioc_file_hash_source_name_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_source_trgm ATTACH PARTITION public.ioc_file_hash_source_name_idx1;


--
-- Name: ioc_file_hash_status_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_status ATTACH PARTITION public.ioc_file_hash_status_idx;


--
-- Name: ioc_file_hash_threat_actor_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_threat_actor_id ATTACH PARTITION public.ioc_file_hash_threat_actor_id_idx;


--
-- Name: ioc_file_hash_threat_classification_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_threat_classification ATTACH PARTITION public.ioc_file_hash_threat_classification_idx;


--
-- Name: ioc_file_hash_threat_classification_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_threat_classification_active ATTACH PARTITION public.ioc_file_hash_threat_classification_idx1;


--
-- Name: ioc_ip_analyst_confidence_override_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_analyst_confidence_override ATTACH PARTITION public.ioc_ip_analyst_confidence_override_idx;


--
-- Name: ioc_ip_confidence_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_confidence_created_at_desc ATTACH PARTITION public.ioc_ip_confidence_created_at_idx;


--
-- Name: ioc_ip_confidence_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_confidence ATTACH PARTITION public.ioc_ip_confidence_idx;


--
-- Name: ioc_ip_confidence_source_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_confidence_source ATTACH PARTITION public.ioc_ip_confidence_source_idx;


--
-- Name: ioc_ip_created_at_id_public_id_observable_observable_type_s_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_created_at_desc_covering ATTACH PARTITION public.ioc_ip_created_at_id_public_id_observable_observable_type_s_idx;


--
-- Name: ioc_ip_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_created_at ATTACH PARTITION public.ioc_ip_created_at_idx;


--
-- Name: ioc_ip_created_at_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_manual_recent ATTACH PARTITION public.ioc_ip_created_at_idx1;


--
-- Name: ioc_ip_created_at_idx2; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_api_recent ATTACH PARTITION public.ioc_ip_created_at_idx2;


--
-- Name: ioc_ip_expires_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_expires_at ATTACH PARTITION public.ioc_ip_expires_at_idx;


--
-- Name: ioc_ip_ioc_source_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_ioc_source_id ATTACH PARTITION public.ioc_ip_ioc_source_id_idx;


--
-- Name: ioc_ip_last_seen_log_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_last_seen ATTACH PARTITION public.ioc_ip_last_seen_log_idx;


--
-- Name: ioc_ip_lower_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_md5_from_note ATTACH PARTITION public.ioc_ip_lower_idx;


--
-- Name: ioc_ip_lower_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_sha1_from_note ATTACH PARTITION public.ioc_ip_lower_idx1;


--
-- Name: ioc_ip_lower_idx2; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_sha256_from_note ATTACH PARTITION public.ioc_ip_lower_idx2;


--
-- Name: ioc_ip_lower_idx3; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_ssdeep_from_note ATTACH PARTITION public.ioc_ip_lower_idx3;


--
-- Name: ioc_ip_lower_idx4; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_imphash_from_note ATTACH PARTITION public.ioc_ip_lower_idx4;


--
-- Name: ioc_ip_lower_idx5; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_tlsh_from_note ATTACH PARTITION public.ioc_ip_lower_idx5;


--
-- Name: ioc_ip_lower_idx6; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_sha256_lower_observable ATTACH PARTITION public.ioc_ip_lower_idx6;


--
-- Name: ioc_ip_lower_idx7; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_sha1_lower_observable ATTACH PARTITION public.ioc_ip_lower_idx7;


--
-- Name: ioc_ip_lower_idx8; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_md5_lower_observable ATTACH PARTITION public.ioc_ip_lower_idx8;


--
-- Name: ioc_ip_lower_observable_type_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_supplement_lookup ATTACH PARTITION public.ioc_ip_lower_observable_type_created_at_idx;


--
-- Name: ioc_ip_observable_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_observable_trgm ATTACH PARTITION public.ioc_ip_observable_idx;


--
-- Name: ioc_ip_observable_observable_type_source_name_confidence_co_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_dedup ATTACH PARTITION public.ioc_ip_observable_observable_type_source_name_confidence_co_idx;


--
-- Name: ioc_ip_observable_type_observable_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_observable_type_observable ATTACH PARTITION public.ioc_ip_observable_type_observable_idx;


--
-- Name: ioc_ip_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.ioc_items_pkey1 ATTACH PARTITION public.ioc_ip_pkey;


--
-- Name: ioc_ip_provider_fingerprint_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.ioc_items_provider_fingerprint_idx ATTACH PARTITION public.ioc_ip_provider_fingerprint_idx;


--
-- Name: ioc_ip_public_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_public_id ATTACH PARTITION public.ioc_ip_public_id_idx;


--
-- Name: ioc_ip_reactivated_by_match_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_reactivated_by_match_at ATTACH PARTITION public.ioc_ip_reactivated_by_match_at_idx;


--
-- Name: ioc_ip_source_name_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_source_created_at_desc ATTACH PARTITION public.ioc_ip_source_name_created_at_idx;


--
-- Name: ioc_ip_source_name_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_source ATTACH PARTITION public.ioc_ip_source_name_idx;


--
-- Name: ioc_ip_source_name_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_source_trgm ATTACH PARTITION public.ioc_ip_source_name_idx1;


--
-- Name: ioc_ip_status_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_status ATTACH PARTITION public.ioc_ip_status_idx;


--
-- Name: ioc_ip_threat_actor_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_threat_actor_id ATTACH PARTITION public.ioc_ip_threat_actor_id_idx;


--
-- Name: ioc_ip_threat_classification_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_threat_classification ATTACH PARTITION public.ioc_ip_threat_classification_idx;


--
-- Name: ioc_ip_threat_classification_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_threat_classification_active ATTACH PARTITION public.ioc_ip_threat_classification_idx1;


--
-- Name: ioc_ipv6_analyst_confidence_override_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_analyst_confidence_override ATTACH PARTITION public.ioc_ipv6_analyst_confidence_override_idx;


--
-- Name: ioc_ipv6_confidence_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_confidence_created_at_desc ATTACH PARTITION public.ioc_ipv6_confidence_created_at_idx;


--
-- Name: ioc_ipv6_confidence_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_confidence ATTACH PARTITION public.ioc_ipv6_confidence_idx;


--
-- Name: ioc_ipv6_confidence_source_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_confidence_source ATTACH PARTITION public.ioc_ipv6_confidence_source_idx;


--
-- Name: ioc_ipv6_created_at_id_public_id_observable_observable_type_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_created_at_desc_covering ATTACH PARTITION public.ioc_ipv6_created_at_id_public_id_observable_observable_type_idx;


--
-- Name: ioc_ipv6_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_created_at ATTACH PARTITION public.ioc_ipv6_created_at_idx;


--
-- Name: ioc_ipv6_created_at_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_manual_recent ATTACH PARTITION public.ioc_ipv6_created_at_idx1;


--
-- Name: ioc_ipv6_created_at_idx2; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_api_recent ATTACH PARTITION public.ioc_ipv6_created_at_idx2;


--
-- Name: ioc_ipv6_expires_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_expires_at ATTACH PARTITION public.ioc_ipv6_expires_at_idx;


--
-- Name: ioc_ipv6_ioc_source_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_ioc_source_id ATTACH PARTITION public.ioc_ipv6_ioc_source_id_idx;


--
-- Name: ioc_ipv6_last_seen_log_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_last_seen ATTACH PARTITION public.ioc_ipv6_last_seen_log_idx;


--
-- Name: ioc_ipv6_lower_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_md5_from_note ATTACH PARTITION public.ioc_ipv6_lower_idx;


--
-- Name: ioc_ipv6_lower_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_sha1_from_note ATTACH PARTITION public.ioc_ipv6_lower_idx1;


--
-- Name: ioc_ipv6_lower_idx2; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_sha256_from_note ATTACH PARTITION public.ioc_ipv6_lower_idx2;


--
-- Name: ioc_ipv6_lower_idx3; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_ssdeep_from_note ATTACH PARTITION public.ioc_ipv6_lower_idx3;


--
-- Name: ioc_ipv6_lower_idx4; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_imphash_from_note ATTACH PARTITION public.ioc_ipv6_lower_idx4;


--
-- Name: ioc_ipv6_lower_idx5; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_tlsh_from_note ATTACH PARTITION public.ioc_ipv6_lower_idx5;


--
-- Name: ioc_ipv6_lower_idx6; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_sha256_lower_observable ATTACH PARTITION public.ioc_ipv6_lower_idx6;


--
-- Name: ioc_ipv6_lower_idx7; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_sha1_lower_observable ATTACH PARTITION public.ioc_ipv6_lower_idx7;


--
-- Name: ioc_ipv6_lower_idx8; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_md5_lower_observable ATTACH PARTITION public.ioc_ipv6_lower_idx8;


--
-- Name: ioc_ipv6_lower_observable_type_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_supplement_lookup ATTACH PARTITION public.ioc_ipv6_lower_observable_type_created_at_idx;


--
-- Name: ioc_ipv6_observable_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_observable_trgm ATTACH PARTITION public.ioc_ipv6_observable_idx;


--
-- Name: ioc_ipv6_observable_observable_type_source_name_confidence__idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_dedup ATTACH PARTITION public.ioc_ipv6_observable_observable_type_source_name_confidence__idx;


--
-- Name: ioc_ipv6_observable_type_observable_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_observable_type_observable ATTACH PARTITION public.ioc_ipv6_observable_type_observable_idx;


--
-- Name: ioc_ipv6_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.ioc_items_pkey1 ATTACH PARTITION public.ioc_ipv6_pkey;


--
-- Name: ioc_ipv6_provider_fingerprint_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.ioc_items_provider_fingerprint_idx ATTACH PARTITION public.ioc_ipv6_provider_fingerprint_idx;


--
-- Name: ioc_ipv6_public_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_public_id ATTACH PARTITION public.ioc_ipv6_public_id_idx;


--
-- Name: ioc_ipv6_reactivated_by_match_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_reactivated_by_match_at ATTACH PARTITION public.ioc_ipv6_reactivated_by_match_at_idx;


--
-- Name: ioc_ipv6_source_name_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_source_created_at_desc ATTACH PARTITION public.ioc_ipv6_source_name_created_at_idx;


--
-- Name: ioc_ipv6_source_name_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_source ATTACH PARTITION public.ioc_ipv6_source_name_idx;


--
-- Name: ioc_ipv6_source_name_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_source_trgm ATTACH PARTITION public.ioc_ipv6_source_name_idx1;


--
-- Name: ioc_ipv6_status_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_status ATTACH PARTITION public.ioc_ipv6_status_idx;


--
-- Name: ioc_ipv6_threat_actor_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_threat_actor_id ATTACH PARTITION public.ioc_ipv6_threat_actor_id_idx;


--
-- Name: ioc_ipv6_threat_classification_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_threat_classification ATTACH PARTITION public.ioc_ipv6_threat_classification_idx;


--
-- Name: ioc_ipv6_threat_classification_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_threat_classification_active ATTACH PARTITION public.ioc_ipv6_threat_classification_idx1;


--
-- Name: ioc_items_other_analyst_confidence_override_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_analyst_confidence_override ATTACH PARTITION public.ioc_items_other_analyst_confidence_override_idx;


--
-- Name: ioc_items_other_confidence_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_confidence_created_at_desc ATTACH PARTITION public.ioc_items_other_confidence_created_at_idx;


--
-- Name: ioc_items_other_confidence_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_confidence ATTACH PARTITION public.ioc_items_other_confidence_idx;


--
-- Name: ioc_items_other_confidence_source_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_confidence_source ATTACH PARTITION public.ioc_items_other_confidence_source_idx;


--
-- Name: ioc_items_other_created_at_id_public_id_observable_observab_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_created_at_desc_covering ATTACH PARTITION public.ioc_items_other_created_at_id_public_id_observable_observab_idx;


--
-- Name: ioc_items_other_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_created_at ATTACH PARTITION public.ioc_items_other_created_at_idx;


--
-- Name: ioc_items_other_created_at_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_manual_recent ATTACH PARTITION public.ioc_items_other_created_at_idx1;


--
-- Name: ioc_items_other_created_at_idx2; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_api_recent ATTACH PARTITION public.ioc_items_other_created_at_idx2;


--
-- Name: ioc_items_other_expires_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_expires_at ATTACH PARTITION public.ioc_items_other_expires_at_idx;


--
-- Name: ioc_items_other_ioc_source_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_ioc_source_id ATTACH PARTITION public.ioc_items_other_ioc_source_id_idx;


--
-- Name: ioc_items_other_last_seen_log_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_last_seen ATTACH PARTITION public.ioc_items_other_last_seen_log_idx;


--
-- Name: ioc_items_other_lower_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_md5_from_note ATTACH PARTITION public.ioc_items_other_lower_idx;


--
-- Name: ioc_items_other_lower_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_sha1_from_note ATTACH PARTITION public.ioc_items_other_lower_idx1;


--
-- Name: ioc_items_other_lower_idx2; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_sha256_from_note ATTACH PARTITION public.ioc_items_other_lower_idx2;


--
-- Name: ioc_items_other_lower_idx3; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_ssdeep_from_note ATTACH PARTITION public.ioc_items_other_lower_idx3;


--
-- Name: ioc_items_other_lower_idx4; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_imphash_from_note ATTACH PARTITION public.ioc_items_other_lower_idx4;


--
-- Name: ioc_items_other_lower_idx5; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_tlsh_from_note ATTACH PARTITION public.ioc_items_other_lower_idx5;


--
-- Name: ioc_items_other_lower_idx6; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_sha256_lower_observable ATTACH PARTITION public.ioc_items_other_lower_idx6;


--
-- Name: ioc_items_other_lower_idx7; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_sha1_lower_observable ATTACH PARTITION public.ioc_items_other_lower_idx7;


--
-- Name: ioc_items_other_lower_idx8; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_md5_lower_observable ATTACH PARTITION public.ioc_items_other_lower_idx8;


--
-- Name: ioc_items_other_lower_observable_type_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_supplement_lookup ATTACH PARTITION public.ioc_items_other_lower_observable_type_created_at_idx;


--
-- Name: ioc_items_other_observable_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_observable_trgm ATTACH PARTITION public.ioc_items_other_observable_idx;


--
-- Name: ioc_items_other_observable_observable_type_source_name_conf_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_dedup ATTACH PARTITION public.ioc_items_other_observable_observable_type_source_name_conf_idx;


--
-- Name: ioc_items_other_observable_type_observable_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_observable_type_observable ATTACH PARTITION public.ioc_items_other_observable_type_observable_idx;


--
-- Name: ioc_items_other_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.ioc_items_pkey1 ATTACH PARTITION public.ioc_items_other_pkey;


--
-- Name: ioc_items_other_provider_fingerprint_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.ioc_items_provider_fingerprint_idx ATTACH PARTITION public.ioc_items_other_provider_fingerprint_idx;


--
-- Name: ioc_items_other_public_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_public_id ATTACH PARTITION public.ioc_items_other_public_id_idx;


--
-- Name: ioc_items_other_reactivated_by_match_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_reactivated_by_match_at ATTACH PARTITION public.ioc_items_other_reactivated_by_match_at_idx;


--
-- Name: ioc_items_other_source_name_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_source_created_at_desc ATTACH PARTITION public.ioc_items_other_source_name_created_at_idx;


--
-- Name: ioc_items_other_source_name_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_source ATTACH PARTITION public.ioc_items_other_source_name_idx;


--
-- Name: ioc_items_other_source_name_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_source_trgm ATTACH PARTITION public.ioc_items_other_source_name_idx1;


--
-- Name: ioc_items_other_status_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_status ATTACH PARTITION public.ioc_items_other_status_idx;


--
-- Name: ioc_items_other_threat_actor_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_threat_actor_id ATTACH PARTITION public.ioc_items_other_threat_actor_id_idx;


--
-- Name: ioc_items_other_threat_classification_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_threat_classification ATTACH PARTITION public.ioc_items_other_threat_classification_idx;


--
-- Name: ioc_items_other_threat_classification_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_threat_classification_active ATTACH PARTITION public.ioc_items_other_threat_classification_idx1;


--
-- Name: ioc_url_analyst_confidence_override_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_analyst_confidence_override ATTACH PARTITION public.ioc_url_analyst_confidence_override_idx;


--
-- Name: ioc_url_confidence_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_confidence_created_at_desc ATTACH PARTITION public.ioc_url_confidence_created_at_idx;


--
-- Name: ioc_url_confidence_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_confidence ATTACH PARTITION public.ioc_url_confidence_idx;


--
-- Name: ioc_url_confidence_source_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_confidence_source ATTACH PARTITION public.ioc_url_confidence_source_idx;


--
-- Name: ioc_url_created_at_id_public_id_observable_observable_type__idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_created_at_desc_covering ATTACH PARTITION public.ioc_url_created_at_id_public_id_observable_observable_type__idx;


--
-- Name: ioc_url_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_created_at ATTACH PARTITION public.ioc_url_created_at_idx;


--
-- Name: ioc_url_created_at_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_manual_recent ATTACH PARTITION public.ioc_url_created_at_idx1;


--
-- Name: ioc_url_created_at_idx2; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_api_recent ATTACH PARTITION public.ioc_url_created_at_idx2;


--
-- Name: ioc_url_expires_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_expires_at ATTACH PARTITION public.ioc_url_expires_at_idx;


--
-- Name: ioc_url_ioc_source_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_ioc_source_id ATTACH PARTITION public.ioc_url_ioc_source_id_idx;


--
-- Name: ioc_url_last_seen_log_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_last_seen ATTACH PARTITION public.ioc_url_last_seen_log_idx;


--
-- Name: ioc_url_lower_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_md5_from_note ATTACH PARTITION public.ioc_url_lower_idx;


--
-- Name: ioc_url_lower_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_sha1_from_note ATTACH PARTITION public.ioc_url_lower_idx1;


--
-- Name: ioc_url_lower_idx2; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_sha256_from_note ATTACH PARTITION public.ioc_url_lower_idx2;


--
-- Name: ioc_url_lower_idx3; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_ssdeep_from_note ATTACH PARTITION public.ioc_url_lower_idx3;


--
-- Name: ioc_url_lower_idx4; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_imphash_from_note ATTACH PARTITION public.ioc_url_lower_idx4;


--
-- Name: ioc_url_lower_idx5; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_tlsh_from_note ATTACH PARTITION public.ioc_url_lower_idx5;


--
-- Name: ioc_url_lower_idx6; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_sha256_lower_observable ATTACH PARTITION public.ioc_url_lower_idx6;


--
-- Name: ioc_url_lower_idx7; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_sha1_lower_observable ATTACH PARTITION public.ioc_url_lower_idx7;


--
-- Name: ioc_url_lower_idx8; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_md5_lower_observable ATTACH PARTITION public.ioc_url_lower_idx8;


--
-- Name: ioc_url_lower_observable_type_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_supplement_lookup ATTACH PARTITION public.ioc_url_lower_observable_type_created_at_idx;


--
-- Name: ioc_url_observable_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_observable_trgm ATTACH PARTITION public.ioc_url_observable_idx;


--
-- Name: ioc_url_observable_observable_type_source_name_confidence_c_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_dedup ATTACH PARTITION public.ioc_url_observable_observable_type_source_name_confidence_c_idx;


--
-- Name: ioc_url_observable_type_observable_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_observable_type_observable ATTACH PARTITION public.ioc_url_observable_type_observable_idx;


--
-- Name: ioc_url_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.ioc_items_pkey1 ATTACH PARTITION public.ioc_url_pkey;


--
-- Name: ioc_url_provider_fingerprint_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.ioc_items_provider_fingerprint_idx ATTACH PARTITION public.ioc_url_provider_fingerprint_idx;


--
-- Name: ioc_url_public_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_public_id ATTACH PARTITION public.ioc_url_public_id_idx;


--
-- Name: ioc_url_reactivated_by_match_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_reactivated_by_match_at ATTACH PARTITION public.ioc_url_reactivated_by_match_at_idx;


--
-- Name: ioc_url_source_name_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_source_created_at_desc ATTACH PARTITION public.ioc_url_source_name_created_at_idx;


--
-- Name: ioc_url_source_name_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_source ATTACH PARTITION public.ioc_url_source_name_idx;


--
-- Name: ioc_url_source_name_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_source_trgm ATTACH PARTITION public.ioc_url_source_name_idx1;


--
-- Name: ioc_url_status_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_status ATTACH PARTITION public.ioc_url_status_idx;


--
-- Name: ioc_url_threat_actor_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_threat_actor_id ATTACH PARTITION public.ioc_url_threat_actor_id_idx;


--
-- Name: ioc_url_threat_classification_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_threat_classification ATTACH PARTITION public.ioc_url_threat_classification_idx;


--
-- Name: ioc_url_threat_classification_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.idx_ioc_items_threat_classification_active ATTACH PARTITION public.ioc_url_threat_classification_idx1;


--
-- Name: tags trg_pf_bump_tags_catalog; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_pf_bump_tags_catalog AFTER UPDATE OF name, enabled ON public.tags FOR EACH STATEMENT EXECUTE FUNCTION public.pf_bump_tags_catalog_watermark();


--
-- Name: ioc_items trg_pf_record_ioc_item_delete; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_pf_record_ioc_item_delete BEFORE DELETE ON public.ioc_items FOR EACH ROW EXECUTE FUNCTION public.pf_record_ioc_item_delete();


--
-- Name: ioc_items trg_pf_touch_ioc_items_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_pf_touch_ioc_items_updated_at BEFORE UPDATE ON public.ioc_items FOR EACH ROW EXECUTE FUNCTION public.pf_touch_ioc_items_updated_at();


--
-- Name: ioc_tags trg_pf_touch_ioc_on_tag_del; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_pf_touch_ioc_on_tag_del AFTER DELETE ON public.ioc_tags FOR EACH ROW EXECUTE FUNCTION public.pf_touch_ioc_on_tag_change();


--
-- Name: ioc_tags trg_pf_touch_ioc_on_tag_ins; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_pf_touch_ioc_on_tag_ins AFTER INSERT ON public.ioc_tags FOR EACH ROW EXECUTE FUNCTION public.pf_touch_ioc_on_tag_change();


--
-- Name: published_feeds trg_published_feeds_bridge_ioc_types; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_published_feeds_bridge_ioc_types BEFORE INSERT OR UPDATE ON public.published_feeds FOR EACH ROW EXECUTE FUNCTION public.published_feeds_bridge_ioc_types();


--
-- Name: auth_sessions auth_sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_sessions
    ADD CONSTRAINT auth_sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: custom_threat_feed_runs custom_threat_feed_runs_feed_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_threat_feed_runs
    ADD CONSTRAINT custom_threat_feed_runs_feed_id_fkey FOREIGN KEY (feed_id) REFERENCES public.custom_threat_feeds(id) ON DELETE CASCADE;


--
-- Name: custom_threat_feed_runs custom_threat_feed_runs_integration_feed_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_threat_feed_runs
    ADD CONSTRAINT custom_threat_feed_runs_integration_feed_id_fkey FOREIGN KEY (integration_feed_id) REFERENCES public.integration_feeds(integration_id) ON DELETE CASCADE;


--
-- Name: custom_threat_feeds custom_threat_feeds_feed_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_threat_feeds
    ADD CONSTRAINT custom_threat_feeds_feed_id_fkey FOREIGN KEY (feed_id) REFERENCES public.integration_feeds(integration_id) ON DELETE CASCADE;


--
-- Name: file_artifact_hashes file_artifact_hashes_artifact_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_artifact_hashes
    ADD CONSTRAINT file_artifact_hashes_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES public.file_artifacts(id) ON DELETE CASCADE;


--
-- Name: file_artifact_ioc_links file_artifact_ioc_links_artifact_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_artifact_ioc_links
    ADD CONSTRAINT file_artifact_ioc_links_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES public.file_artifacts(id) ON DELETE CASCADE;


--
-- Name: file_artifact_ioc_links file_artifact_ioc_links_ioc_observable_type_ioc_item_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_artifact_ioc_links
    ADD CONSTRAINT file_artifact_ioc_links_ioc_observable_type_ioc_item_id_fkey FOREIGN KEY (ioc_observable_type, ioc_item_id) REFERENCES public.ioc_items(observable_type, id) ON DELETE CASCADE;


--
-- Name: file_artifact_ioc_links file_artifact_ioc_links_linked_hash_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_artifact_ioc_links
    ADD CONSTRAINT file_artifact_ioc_links_linked_hash_id_fkey FOREIGN KEY (linked_hash_id) REFERENCES public.file_artifact_hashes(id) ON DELETE SET NULL;


--
-- Name: file_artifact_non_identity_attrs file_artifact_non_identity_attrs_artifact_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_artifact_non_identity_attrs
    ADD CONSTRAINT file_artifact_non_identity_attrs_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES public.file_artifacts(id) ON DELETE CASCADE;


--
-- Name: file_artifact_source_observations file_artifact_source_observations_artifact_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_artifact_source_observations
    ADD CONSTRAINT file_artifact_source_observations_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES public.file_artifacts(id) ON DELETE CASCADE;


--
-- Name: file_artifact_source_observations file_artifact_source_observations_observed_hash_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_artifact_source_observations
    ADD CONSTRAINT file_artifact_source_observations_observed_hash_id_fkey FOREIGN KEY (observed_hash_id) REFERENCES public.file_artifact_hashes(id) ON DELETE SET NULL;


--
-- Name: file_artifacts file_artifacts_merged_into_artifact_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_artifacts
    ADD CONSTRAINT file_artifacts_merged_into_artifact_id_fkey FOREIGN KEY (merged_into_artifact_id) REFERENCES public.file_artifacts(id);


--
-- Name: file_artifacts file_artifacts_primary_hash_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_artifacts
    ADD CONSTRAINT file_artifacts_primary_hash_id_fkey FOREIGN KEY (primary_hash_id) REFERENCES public.file_artifact_hashes(id) ON DELETE SET NULL;


--
-- Name: ioc_threat_actors fk_ioc_threat_actors_ioc; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_threat_actors
    ADD CONSTRAINT fk_ioc_threat_actors_ioc FOREIGN KEY (ioc_observable_type, ioc_id) REFERENCES public.ioc_items(observable_type, id) ON DELETE CASCADE;


--
-- Name: ioc_threat_classification_overrides fk_ioc_threat_classification_overrides_ioc; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_threat_classification_overrides
    ADD CONSTRAINT fk_ioc_threat_classification_overrides_ioc FOREIGN KEY (ioc_observable_type, ioc_id) REFERENCES public.ioc_items(observable_type, id) ON DELETE CASCADE;


--
-- Name: integration_feed_expiration_type_policies integration_feed_expiration_type_policies_feed_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_feed_expiration_type_policies
    ADD CONSTRAINT integration_feed_expiration_type_policies_feed_id_fkey FOREIGN KEY (feed_id) REFERENCES public.integration_feeds(integration_id) ON DELETE CASCADE;


--
-- Name: ioc_bulk_query_job_targets ioc_bulk_query_job_targets_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_bulk_query_job_targets
    ADD CONSTRAINT ioc_bulk_query_job_targets_job_id_fkey FOREIGN KEY (job_id) REFERENCES public.ioc_bulk_query_jobs(id) ON DELETE CASCADE;


--
-- Name: ioc_bulk_query_jobs ioc_bulk_query_jobs_requested_by_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_bulk_query_jobs
    ADD CONSTRAINT ioc_bulk_query_jobs_requested_by_id_fkey FOREIGN KEY (requested_by_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: ioc_deep_searches ioc_deep_searches_requested_by_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_deep_searches
    ADD CONSTRAINT ioc_deep_searches_requested_by_id_fkey FOREIGN KEY (requested_by_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: ioc_feed_memberships ioc_feed_memberships_feed_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_feed_memberships
    ADD CONSTRAINT ioc_feed_memberships_feed_id_fkey FOREIGN KEY (feed_id) REFERENCES public.integration_feeds(integration_id) ON DELETE CASCADE;


--
-- Name: ioc_feed_source_evidence ioc_feed_source_evidence_feed_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_feed_source_evidence
    ADD CONSTRAINT ioc_feed_source_evidence_feed_id_fkey FOREIGN KEY (feed_id) REFERENCES public.integration_feeds(integration_id) ON DELETE CASCADE;


--
-- Name: ioc_items ioc_items_ioc_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE public.ioc_items
    ADD CONSTRAINT ioc_items_ioc_source_id_fkey FOREIGN KEY (ioc_source_id) REFERENCES public.ioc_sources(id) ON DELETE SET NULL;


--
-- Name: ioc_items ioc_items_threat_actor_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE public.ioc_items
    ADD CONSTRAINT ioc_items_threat_actor_id_fkey FOREIGN KEY (threat_actor_id) REFERENCES public.threat_actors(id);


--
-- Name: ioc_manual_source_memberships ioc_manual_source_memberships_ioc_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_manual_source_memberships
    ADD CONSTRAINT ioc_manual_source_memberships_ioc_source_id_fkey FOREIGN KEY (ioc_source_id) REFERENCES public.ioc_sources(id) ON DELETE SET NULL;


--
-- Name: ioc_manual_source_memberships ioc_manual_source_memberships_moved_to_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_manual_source_memberships
    ADD CONSTRAINT ioc_manual_source_memberships_moved_to_source_id_fkey FOREIGN KEY (moved_to_source_id) REFERENCES public.ioc_sources(id) ON DELETE SET NULL;


--
-- Name: ioc_saved_searches ioc_saved_searches_owner_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_saved_searches
    ADD CONSTRAINT ioc_saved_searches_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: ioc_search_exports ioc_search_exports_requested_by_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_search_exports
    ADD CONSTRAINT ioc_search_exports_requested_by_id_fkey FOREIGN KEY (requested_by_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: ioc_source_expiration_type_policies ioc_source_expiration_type_policies_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_source_expiration_type_policies
    ADD CONSTRAINT ioc_source_expiration_type_policies_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.ioc_sources(id) ON DELETE CASCADE;


--
-- Name: ioc_source_tag_overrides ioc_source_tag_overrides_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_source_tag_overrides
    ADD CONSTRAINT ioc_source_tag_overrides_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: ioc_source_tag_overrides ioc_source_tag_overrides_restored_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_source_tag_overrides
    ADD CONSTRAINT ioc_source_tag_overrides_restored_by_fkey FOREIGN KEY (restored_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: ioc_tags ioc_tags_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_tags
    ADD CONSTRAINT ioc_tags_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: ioc_tags ioc_tags_tag_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_tags
    ADD CONSTRAINT ioc_tags_tag_id_fkey FOREIGN KEY (tag_id) REFERENCES public.tags(id) ON DELETE CASCADE;


--
-- Name: ioc_threat_actors ioc_threat_actors_threat_actor_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_threat_actors
    ADD CONSTRAINT ioc_threat_actors_threat_actor_id_fkey FOREIGN KEY (threat_actor_id) REFERENCES public.threat_actors(id);


--
-- Name: published_feed_access_keys published_feed_access_keys_feed_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_access_keys
    ADD CONSTRAINT published_feed_access_keys_feed_id_fkey FOREIGN KEY (feed_id) REFERENCES public.published_feeds(id) ON DELETE CASCADE;


--
-- Name: published_feed_active_generations published_feed_active_generations_feed_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_active_generations
    ADD CONSTRAINT published_feed_active_generations_feed_id_fkey FOREIGN KEY (feed_id) REFERENCES public.published_feeds(id) ON DELETE CASCADE;


--
-- Name: published_feed_active_generations published_feed_active_generations_generation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_active_generations
    ADD CONSTRAINT published_feed_active_generations_generation_id_fkey FOREIGN KEY (generation_id) REFERENCES public.published_feed_generations(id) ON DELETE RESTRICT;


--
-- Name: published_feed_chunks published_feed_chunks_feed_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_chunks
    ADD CONSTRAINT published_feed_chunks_feed_id_fkey FOREIGN KEY (feed_id) REFERENCES public.published_feeds(id) ON DELETE CASCADE;


--
-- Name: published_feed_generation_chunks published_feed_generation_chunks_chunk_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_generation_chunks
    ADD CONSTRAINT published_feed_generation_chunks_chunk_id_fkey FOREIGN KEY (chunk_id) REFERENCES public.published_feed_chunks(id) ON DELETE RESTRICT;


--
-- Name: published_feed_generation_chunks published_feed_generation_chunks_generation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_generation_chunks
    ADD CONSTRAINT published_feed_generation_chunks_generation_id_fkey FOREIGN KEY (generation_id) REFERENCES public.published_feed_generations(id) ON DELETE CASCADE;


--
-- Name: published_feed_generation_formats published_feed_generation_formats_generation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_generation_formats
    ADD CONSTRAINT published_feed_generation_formats_generation_id_fkey FOREIGN KEY (generation_id) REFERENCES public.published_feed_generations(id) ON DELETE CASCADE;


--
-- Name: published_feed_generations published_feed_generations_feed_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_generations
    ADD CONSTRAINT published_feed_generations_feed_id_fkey FOREIGN KEY (feed_id) REFERENCES public.published_feeds(id) ON DELETE CASCADE;


--
-- Name: published_feed_generations published_feed_generations_parent_generation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_generations
    ADD CONSTRAINT published_feed_generations_parent_generation_id_fkey FOREIGN KEY (parent_generation_id) REFERENCES public.published_feed_generations(id) ON DELETE SET NULL;


--
-- Name: published_feed_items published_feed_items_feed_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_items
    ADD CONSTRAINT published_feed_items_feed_id_fkey FOREIGN KEY (feed_id) REFERENCES public.published_feeds(id) ON DELETE CASCADE;


--
-- Name: published_feed_snapshots published_feed_snapshots_feed_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.published_feed_snapshots
    ADD CONSTRAINT published_feed_snapshots_feed_id_fkey FOREIGN KEY (feed_id) REFERENCES public.published_feeds(id) ON DELETE CASCADE;


--
-- Name: system_backups system_backups_created_by_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_backups
    ADD CONSTRAINT system_backups_created_by_id_fkey FOREIGN KEY (created_by_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: threat_feed_expiration_policies threat_feed_expiration_policies_feed_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_feed_expiration_policies
    ADD CONSTRAINT threat_feed_expiration_policies_feed_id_fkey FOREIGN KEY (feed_id) REFERENCES public.integration_feeds(integration_id) ON DELETE CASCADE;


--
-- Name: usom_import_cursors usom_import_cursors_feed_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usom_import_cursors
    ADD CONSTRAINT usom_import_cursors_feed_id_fkey FOREIGN KEY (feed_id) REFERENCES public.integration_feeds(integration_id) ON DELETE CASCADE;


--
-- Name: usom_import_state usom_import_state_feed_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usom_import_state
    ADD CONSTRAINT usom_import_state_feed_id_fkey FOREIGN KEY (feed_id) REFERENCES public.integration_feeds(integration_id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--



-- ===== CANONICAL SEED DATA =====
--
-- PostgreSQL database dump
--


-- Dumped from database version 16.14
-- Dumped by pg_dump version 16.14


--
-- Data for Name: integration_feeds; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.integration_feeds (key, name, source_url, schedule_cron, trust_level, active, created_at, updated_at, integration_id, feed_update_mode, credentials, default_confidence, feed_kind, archived_at, archived_by, archived_by_username, color) VALUES ('usom-trcert', 'Siber Güvenlik Başkanlığı / USOM', 'https://siberguvenlik.gov.tr/api/address/index', '0 * * * *', 'guvenilir', true, '2026-08-23 15:28:59.183922+00', '2026-08-23 15:28:59.187938+00', 'f7f1e4ab-529b-4596-99ac-42470312ded7', 'snapshot', '{}', 'high', 'built_in', NULL, NULL, NULL, '#7c3aed');
INSERT INTO public.integration_feeds (key, name, source_url, schedule_cron, trust_level, active, created_at, updated_at, integration_id, feed_update_mode, credentials, default_confidence, feed_kind, archived_at, archived_by, archived_by_username, color) VALUES ('malwarebazaar-abusech', 'MalwareBazaar abuse.ch', 'https://mb-api.abuse.ch/v2/files/exports/***/recent.csv', '*/5 * * * *', 'guvenilir', true, '2026-08-23 15:28:59.216417+00', '2026-08-23 15:28:59.418341+00', '66dc94d0-5e49-4702-a302-0d7344b1e772', 'incremental', '{}', 'high', 'built_in', NULL, NULL, NULL, '#16a34a');
INSERT INTO public.integration_feeds (key, name, source_url, schedule_cron, trust_level, active, created_at, updated_at, integration_id, feed_update_mode, credentials, default_confidence, feed_kind, archived_at, archived_by, archived_by_username, color) VALUES ('urlhaus-abusech', 'URLhaus abuse.ch', 'https://urlhaus-api.abuse.ch/v2/files/exports/***/recent.csv', '*/5 * * * *', 'guvenilir', true, '2026-08-23 15:28:59.205983+00', '2026-08-23 15:28:59.415748+00', '5b3dcd56-430f-4e77-9c37-0c8ffd894599', 'incremental', '{}', 'high', 'built_in', NULL, NULL, NULL, '#0d9488');
INSERT INTO public.integration_feeds (key, name, source_url, schedule_cron, trust_level, active, created_at, updated_at, integration_id, feed_update_mode, credentials, default_confidence, feed_kind, archived_at, archived_by, archived_by_username, color) VALUES ('threatfox-abusech', 'ThreatFox abuse.ch', 'https://threatfox-api.abuse.ch/api/v1/', '0 * * * *', 'guvenilir', true, '2026-08-23 15:28:59.21564+00', '2026-08-23 15:28:59.426155+00', '9f04b9f4-fc5b-4195-8802-0c99ac14b721', 'incremental', '{}', 'high', 'built_in', NULL, NULL, NULL, '#15803d');
INSERT INTO public.integration_feeds (key, name, source_url, schedule_cron, trust_level, active, created_at, updated_at, integration_id, feed_update_mode, credentials, default_confidence, feed_kind, archived_at, archived_by, archived_by_username, color) VALUES ('et-blockrules', 'EmergingThreats Blockrules', 'http://rules.emergingthreats.net/blockrules/', '0 * * * *', 'not_categorized', true, '2026-08-23 15:28:59.181757+00', '2026-08-23 15:28:59.181757+00', 'b1316d76-3e50-489d-9809-efdb46b00f42', 'incremental', '{}', 'medium', 'built_in', NULL, NULL, NULL, '#b45309');
INSERT INTO public.integration_feeds (key, name, source_url, schedule_cron, trust_level, active, created_at, updated_at, integration_id, feed_update_mode, credentials, default_confidence, feed_kind, archived_at, archived_by, archived_by_username, color) VALUES ('alienvault-otx', 'AlienVault OTX', 'https://otx.alienvault.com/api/v1/pulses/subscribed', '0 * * * *', 'orta', true, '2026-08-23 15:28:59.533654+00', '2026-08-23 15:28:59.533654+00', '896dd4d9-c634-4c18-8ea5-85aeafb10240', 'incremental', '{}', 'medium', 'built_in', NULL, NULL, NULL, '#2563eb');


--
-- Data for Name: ioc_sources; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.ioc_sources (id, name, display_name, description, source_type, default_confidence, default_expire_policy, default_expire_days, active, created_by, created_at, updated_at, default_threat_classification, archived_at, archived_by, color) VALUES (1, 'API', 'API', 'System source for IOCs created through the TalonHound REST API. Not selectable in Add IOC.', 'internal_hunting', 'medium', 'never', NULL, true, NULL, '2026-08-23 15:28:59.702462+00', '2026-08-23 15:28:59.702462+00', NULL, NULL, NULL, NULL);


--
-- Data for Name: published_feed_global_watermarks; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.published_feed_global_watermarks (key, watermark) VALUES ('tags_catalog', '2026-08-23 15:28:59.711646+00');


--
-- Data for Name: spamhaus_drop_sync_state; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.spamhaus_drop_sync_state (list_type, last_success_at, last_attempt_at, next_run_at, status, entry_count, added_count, removed_count, source_url, dataset_sha256, error_message, updated_at) VALUES ('drop_v4', NULL, NULL, NULL, 'never_synced', 0, NULL, NULL, NULL, NULL, NULL, '2026-08-23 15:28:59.543853+00');
INSERT INTO public.spamhaus_drop_sync_state (list_type, last_success_at, last_attempt_at, next_run_at, status, entry_count, added_count, removed_count, source_url, dataset_sha256, error_message, updated_at) VALUES ('drop_v6', NULL, NULL, NULL, 'never_synced', 0, NULL, NULL, NULL, NULL, NULL, '2026-08-23 15:28:59.543853+00');


--
-- Data for Name: system_settings; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.system_settings (id, active_system_timezone, pending_system_timezone, initial_setup_completed, timezone_restart_required, timezone_configuration_required, timezone_config_version, active_timezone_config_version, adoption_source, initial_setup_completed_at, timezone_change_requested_at, timezone_change_requested_by, timezone_promoted_at, timezone_updated_at, timezone_updated_by, created_at, updated_at, default_admin_bootstrapped, audit_log_retention_days, audit_log_retention_updated_at, audit_log_retention_updated_by, audit_log_retention_last_run_at) VALUES (1, NULL, NULL, false, false, false, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '2026-08-23 15:28:59.63723+00', '2026-08-23 15:28:59.63723+00', false, 365, NULL, NULL, NULL);


--
-- Data for Name: tags; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.tags (id, name, type, enabled, created_at, slug, description, color, category, updated_at, created_origin) VALUES (5, 'clickfix', 'technique', true, '2026-08-23 15:28:59.351257+00', 'clickfix', NULL, NULL, 'behavior', '2026-08-23 15:28:59.376259+00', 'manual');
INSERT INTO public.tags (id, name, type, enabled, created_at, slug, description, color, category, updated_at, created_origin) VALUES (1, 'ransomware', 'threat', false, '2026-08-23 15:28:59.351257+00', 'ransomware', 'legacy-migrated-to-threat-classification', NULL, 'malware', '2026-08-23 15:28:59.454571+00', 'manual');
INSERT INTO public.tags (id, name, type, enabled, created_at, slug, description, color, category, updated_at, created_origin) VALUES (2, 'c2', 'threat', false, '2026-08-23 15:28:59.351257+00', 'c2', 'legacy-migrated-to-threat-classification', NULL, 'malware', '2026-08-23 15:28:59.454571+00', 'manual');
INSERT INTO public.tags (id, name, type, enabled, created_at, slug, description, color, category, updated_at, created_origin) VALUES (3, 'phishing', 'threat', false, '2026-08-23 15:28:59.351257+00', 'phishing', 'legacy-migrated-to-threat-classification', NULL, 'malware', '2026-08-23 15:28:59.454571+00', 'manual');
INSERT INTO public.tags (id, name, type, enabled, created_at, slug, description, color, category, updated_at, created_origin) VALUES (4, 'apt29', 'actor', false, '2026-08-23 15:28:59.351257+00', 'apt29', 'legacy-migrated-to-threat-actor', NULL, 'actor', '2026-08-23 15:28:59.454571+00', 'manual');


--
-- Data for Name: threat_actors; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.threat_actors (id, name, slug, aliases, description, active, created_at, updated_at, created_by, updated_by) VALUES ('92e08e97-5e84-4d29-920f-df0428d35dc7', 'APT29', 'apt29', '{"Cozy Bear","Midnight Blizzard",Nobelium}', 'Legacy tag migration seed', true, '2026-08-23 15:28:59.454571+00', '2026-08-23 15:28:59.454571+00', NULL, NULL);
INSERT INTO public.threat_actors (id, name, slug, aliases, description, active, created_at, updated_at, created_by, updated_by) VALUES ('8bd4f10c-0904-43cb-acdf-02aa0b0a81e6', 'APT28', 'apt28', '{"Fancy Bear",Sofacy}', 'Legacy tag migration seed', true, '2026-08-23 15:28:59.454571+00', '2026-08-23 15:28:59.454571+00', NULL, NULL);
INSERT INTO public.threat_actors (id, name, slug, aliases, description, active, created_at, updated_at, created_by, updated_by) VALUES ('364117ec-9e72-4531-956a-ba7f013f1b45', 'Lazarus', 'lazarus', '{"Lazarus Group","HIDDEN COBRA"}', 'Legacy tag migration seed', true, '2026-08-23 15:28:59.454571+00', '2026-08-23 15:28:59.454571+00', NULL, NULL);


--
-- Data for Name: threat_classifications; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.threat_classifications (id, name, slug, description, active, sort_order, system_default, created_at, updated_at, created_by, updated_by) VALUES ('8d6b91c4-86ad-4247-a986-9afe98fb1b43', 'Phishing', 'phishing', NULL, true, 10, true, '2026-08-23 15:28:59.477516+00', '2026-08-23 15:28:59.477516+00', NULL, NULL);
INSERT INTO public.threat_classifications (id, name, slug, description, active, sort_order, system_default, created_at, updated_at, created_by, updated_by) VALUES ('1d7f32a2-60b2-4429-9e3c-f9ed8bd08c32', 'Credential Theft', 'credential_theft', NULL, true, 20, true, '2026-08-23 15:28:59.477516+00', '2026-08-23 15:28:59.477516+00', NULL, NULL);
INSERT INTO public.threat_classifications (id, name, slug, description, active, sort_order, system_default, created_at, updated_at, created_by, updated_by) VALUES ('d228b87f-625f-4421-8bb2-0995d6f25133', 'Malware', 'malware', NULL, true, 30, true, '2026-08-23 15:28:59.477516+00', '2026-08-23 15:28:59.477516+00', NULL, NULL);
INSERT INTO public.threat_classifications (id, name, slug, description, active, sort_order, system_default, created_at, updated_at, created_by, updated_by) VALUES ('4a6170bc-b944-4117-9bb8-762bfc0be7ca', 'Ransomware', 'ransomware', NULL, true, 40, true, '2026-08-23 15:28:59.477516+00', '2026-08-23 15:28:59.477516+00', NULL, NULL);
INSERT INTO public.threat_classifications (id, name, slug, description, active, sort_order, system_default, created_at, updated_at, created_by, updated_by) VALUES ('16c102a0-89a4-4ba0-89c6-34e813d79082', 'Command and Control (C2)', 'command_and_control', NULL, true, 50, true, '2026-08-23 15:28:59.477516+00', '2026-08-23 15:28:59.477516+00', NULL, NULL);
INSERT INTO public.threat_classifications (id, name, slug, description, active, sort_order, system_default, created_at, updated_at, created_by, updated_by) VALUES ('120e65b7-3da5-467c-93ab-a3897a95ae4e', 'Botnet', 'botnet', NULL, true, 60, true, '2026-08-23 15:28:59.477516+00', '2026-08-23 15:28:59.477516+00', NULL, NULL);
INSERT INTO public.threat_classifications (id, name, slug, description, active, sort_order, system_default, created_at, updated_at, created_by, updated_by) VALUES ('10d77804-ea43-4d87-98c7-9d9dc57a263c', 'Exploit', 'exploit', NULL, true, 70, true, '2026-08-23 15:28:59.477516+00', '2026-08-23 15:28:59.477516+00', NULL, NULL);
INSERT INTO public.threat_classifications (id, name, slug, description, active, sort_order, system_default, created_at, updated_at, created_by, updated_by) VALUES ('4c168ff9-1165-4c88-9df2-f19f1034af8f', 'Scanner / Reconnaissance', 'scanner_recon', NULL, true, 80, true, '2026-08-23 15:28:59.477516+00', '2026-08-23 15:28:59.477516+00', NULL, NULL);
INSERT INTO public.threat_classifications (id, name, slug, description, active, sort_order, system_default, created_at, updated_at, created_by, updated_by) VALUES ('885cd03b-34a2-4803-8e24-f0e26197ea7b', 'Suspicious Infrastructure', 'suspicious_infrastructure', NULL, true, 90, true, '2026-08-23 15:28:59.477516+00', '2026-08-23 15:28:59.477516+00', NULL, NULL);
INSERT INTO public.threat_classifications (id, name, slug, description, active, sort_order, system_default, created_at, updated_at, created_by, updated_by) VALUES ('55fdc758-f016-4a81-8422-122b4f0f482a', 'Spam / Abuse', 'spam_abuse', NULL, true, 100, true, '2026-08-23 15:28:59.477516+00', '2026-08-23 15:28:59.477516+00', NULL, NULL);
INSERT INTO public.threat_classifications (id, name, slug, description, active, sort_order, system_default, created_at, updated_at, created_by, updated_by) VALUES ('5985cb2a-b06b-428b-b719-2fc43d9f1a0b', 'Dropper / Downloader', 'dropper_downloader', NULL, true, 110, true, '2026-08-23 15:28:59.477516+00', '2026-08-23 15:28:59.477516+00', NULL, NULL);
INSERT INTO public.threat_classifications (id, name, slug, description, active, sort_order, system_default, created_at, updated_at, created_by, updated_by) VALUES ('5345d47e-9e93-4610-8317-c0b3a28ed82b', 'Payload Hosting', 'payload_hosting', NULL, true, 120, true, '2026-08-23 15:28:59.477516+00', '2026-08-23 15:28:59.477516+00', NULL, NULL);
INSERT INTO public.threat_classifications (id, name, slug, description, active, sort_order, system_default, created_at, updated_at, created_by, updated_by) VALUES ('53aae112-f56f-4e79-8260-5ae6e1fc7888', 'Data Exfiltration', 'data_exfiltration', NULL, true, 130, true, '2026-08-23 15:28:59.477516+00', '2026-08-23 15:28:59.477516+00', NULL, NULL);
INSERT INTO public.threat_classifications (id, name, slug, description, active, sort_order, system_default, created_at, updated_at, created_by, updated_by) VALUES ('9a3a6a9b-2fd6-4e9e-9a92-bdbbc8b19775', 'Cryptomining', 'cryptomining', NULL, true, 140, true, '2026-08-23 15:28:59.477516+00', '2026-08-23 15:28:59.477516+00', NULL, NULL);
INSERT INTO public.threat_classifications (id, name, slug, description, active, sort_order, system_default, created_at, updated_at, created_by, updated_by) VALUES ('4560cda8-3532-4220-9520-9de778eec48f', 'Fraud / Scam', 'fraud_scam', NULL, true, 150, true, '2026-08-23 15:28:59.477516+00', '2026-08-23 15:28:59.477516+00', NULL, NULL);
INSERT INTO public.threat_classifications (id, name, slug, description, active, sort_order, system_default, created_at, updated_at, created_by, updated_by) VALUES ('87fe3fb7-5368-44a8-adee-084ee29beb61', 'Typosquatting / Impersonation', 'typosquatting_impersonation', NULL, true, 160, true, '2026-08-23 15:28:59.477516+00', '2026-08-23 15:28:59.477516+00', NULL, NULL);
INSERT INTO public.threat_classifications (id, name, slug, description, active, sort_order, system_default, created_at, updated_at, created_by, updated_by) VALUES ('a51cea8c-7bcb-4811-868f-1781d4cb1821', 'Benign / Test', 'benign_test', NULL, true, 170, true, '2026-08-23 15:28:59.477516+00', '2026-08-23 15:28:59.477516+00', NULL, NULL);
INSERT INTO public.threat_classifications (id, name, slug, description, active, sort_order, system_default, created_at, updated_at, created_by, updated_by) VALUES ('4ee39c50-9e95-4c2e-bfba-c177a4c771e7', 'Unknown', 'unknown', 'Default when classification is unset or unrecognized', true, 0, true, '2026-08-23 15:28:59.477516+00', '2026-08-23 15:28:59.477516+00', NULL, NULL);


--
-- Data for Name: threat_feed_expiration_policies; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.threat_feed_expiration_policies (id, feed_id, observable_type, enabled, expiration_mode, ttl_days, grace_days, created_at, updated_at) VALUES (1, 'f7f1e4ab-529b-4596-99ac-42470312ded7', 'all', false, 'never', NULL, NULL, '2026-08-23 15:28:59.385993+00', '2026-08-23 15:28:59.385993+00');
INSERT INTO public.threat_feed_expiration_policies (id, feed_id, observable_type, enabled, expiration_mode, ttl_days, grace_days, created_at, updated_at) VALUES (2, '5b3dcd56-430f-4e77-9c37-0c8ffd894599', 'all', false, 'never', NULL, NULL, '2026-08-23 15:28:59.385993+00', '2026-08-23 15:28:59.385993+00');
INSERT INTO public.threat_feed_expiration_policies (id, feed_id, observable_type, enabled, expiration_mode, ttl_days, grace_days, created_at, updated_at) VALUES (3, '9f04b9f4-fc5b-4195-8802-0c99ac14b721', 'all', false, 'never', NULL, NULL, '2026-08-23 15:28:59.385993+00', '2026-08-23 15:28:59.385993+00');
INSERT INTO public.threat_feed_expiration_policies (id, feed_id, observable_type, enabled, expiration_mode, ttl_days, grace_days, created_at, updated_at) VALUES (4, '66dc94d0-5e49-4702-a302-0d7344b1e772', 'all', false, 'never', NULL, NULL, '2026-08-23 15:28:59.385993+00', '2026-08-23 15:28:59.385993+00');
INSERT INTO public.threat_feed_expiration_policies (id, feed_id, observable_type, enabled, expiration_mode, ttl_days, grace_days, created_at, updated_at) VALUES (5, 'b1316d76-3e50-489d-9809-efdb46b00f42', 'all', false, 'never', NULL, NULL, '2026-08-23 15:28:59.385993+00', '2026-08-23 15:28:59.385993+00');
INSERT INTO public.threat_feed_expiration_policies (id, feed_id, observable_type, enabled, expiration_mode, ttl_days, grace_days, created_at, updated_at) VALUES (6, '896dd4d9-c634-4c18-8ea5-85aeafb10240', 'all', true, 'fixed_ttl', 30, NULL, '2026-08-23 15:28:59.533654+00', '2026-08-23 15:28:59.725262+00');


--
-- Data for Name: threat_intel_provider_configs; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.threat_intel_provider_configs (id, provider, enabled, api_key, ttl_hours, timeout_ms, last_test_at, last_success_at, last_error_at, last_error_message, created_at, updated_at, config) VALUES (1, 'virustotal', true, NULL, 24, 12000, NULL, NULL, NULL, NULL, '2026-08-23 15:28:59.36573+00', '2026-08-23 15:28:59.36573+00', '{}');
INSERT INTO public.threat_intel_provider_configs (id, provider, enabled, api_key, ttl_hours, timeout_ms, last_test_at, last_success_at, last_error_at, last_error_message, created_at, updated_at, config) VALUES (2, 'ipinfo_lite', false, NULL, 24, 6000, NULL, NULL, NULL, NULL, '2026-08-23 15:28:59.383113+00', '2026-08-23 15:28:59.383113+00', '{"base_url": "https://api.ipinfo.io/lite", "timeout_seconds": 6}');
INSERT INTO public.threat_intel_provider_configs (id, provider, enabled, api_key, ttl_hours, timeout_ms, last_test_at, last_success_at, last_error_at, last_error_message, created_at, updated_at, config) VALUES (3, 'abuseipdb', false, NULL, 24, 8000, NULL, NULL, NULL, NULL, '2026-08-23 15:28:59.495726+00', '2026-08-23 15:28:59.495726+00', '{"verbose": false, "max_age_days": 90}');
INSERT INTO public.threat_intel_provider_configs (id, provider, enabled, api_key, ttl_hours, timeout_ms, last_test_at, last_success_at, last_error_at, last_error_message, created_at, updated_at, config) VALUES (4, 'spamhaus_drop', false, NULL, 24, 30000, NULL, NULL, NULL, NULL, '2026-08-23 15:28:59.543853+00', '2026-08-23 15:28:59.543853+00', '{"sync_interval_hours": 24}');


--
-- Name: ioc_sources_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--



--
-- Name: tags_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--



--
-- Name: threat_feed_expiration_policies_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--



--
-- Name: threat_intel_provider_configs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--



--
-- PostgreSQL database dump complete
--



COMMIT;
