-- Source-aware IOC attribution for Threat Actors and Malware Families.
-- Additive only: preserves existing ioc_threat_actors analyst junction.

-- ---------------------------------------------------------------------------
-- Malware family catalog (parallel to threat_actors; empty until resolved/analyst-created)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.malware_families (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    slug text NOT NULL,
    aliases text[] DEFAULT '{}'::text[] NOT NULL,
    description text,
    active boolean DEFAULT true NOT NULL,
    catalog_sources text[] DEFAULT '{}'::text[] NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by text,
    updated_by text,
    CONSTRAINT malware_families_pkey PRIMARY KEY (id),
    CONSTRAINT malware_families_slug_key UNIQUE (slug)
);

CREATE INDEX IF NOT EXISTS idx_malware_families_active_name
    ON public.malware_families USING btree (active, name);

COMMENT ON TABLE public.malware_families IS
    'Canonical malware family catalog. Source-reported labels may remain unresolved without creating rows here.';

-- Analyst-managed IOC ↔ malware family associations
CREATE TABLE IF NOT EXISTS public.ioc_malware_families (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    ioc_id bigint NOT NULL,
    ioc_observable_type text NOT NULL,
    malware_family_id uuid NOT NULL,
    source_type text DEFAULT 'analyst'::text NOT NULL,
    source_name text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by text,
    updated_by text,
    CONSTRAINT ioc_malware_families_pkey PRIMARY KEY (id),
    CONSTRAINT uq_ioc_malware_families_ioc_family UNIQUE (ioc_id, ioc_observable_type, malware_family_id),
    CONSTRAINT fk_ioc_malware_families_ioc FOREIGN KEY (ioc_observable_type, ioc_id)
        REFERENCES public.ioc_items(observable_type, id) ON DELETE CASCADE,
    CONSTRAINT ioc_malware_families_malware_family_id_fkey FOREIGN KEY (malware_family_id)
        REFERENCES public.malware_families(id)
);

CREATE INDEX IF NOT EXISTS idx_ioc_malware_families_ioc
    ON public.ioc_malware_families USING btree (ioc_id, ioc_observable_type);
CREATE INDEX IF NOT EXISTS idx_ioc_malware_families_family
    ON public.ioc_malware_families USING btree (malware_family_id);

COMMENT ON TABLE public.ioc_malware_families IS
    'Analyst (or explicit) malware family associations for an IOC. Feed assertions live in ioc_source_attributions.';

-- ---------------------------------------------------------------------------
-- Per-source attribution assertions (Threat Actor + Malware Family)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.ioc_source_attributions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    ioc_id bigint NOT NULL,
    ioc_observable_type text NOT NULL,
    entity_kind text NOT NULL,
    source_label text NOT NULL,
    source_label_normalized text NOT NULL,
    entity_id uuid,
    resolution_status text DEFAULT 'unresolved'::text NOT NULL,
    feed_key text NOT NULL,
    source_name text NOT NULL,
    evidence_ref_type text NOT NULL,
    evidence_ref_id text NOT NULL,
    evidence_url text,
    evidence_title text,
    association_kind text DEFAULT 'associated_via_source_pulse'::text NOT NULL,
    assertion_status text DEFAULT 'current'::text NOT NULL,
    observed_at timestamp with time zone,
    first_ingested_at timestamp with time zone DEFAULT now() NOT NULL,
    last_ingested_at timestamp with time zone DEFAULT now() NOT NULL,
    withdrawn_at timestamp with time zone,
    is_backfill boolean DEFAULT false NOT NULL,
    provider_metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ioc_source_attributions_pkey PRIMARY KEY (id),
    CONSTRAINT ioc_source_attributions_entity_kind_check
        CHECK (entity_kind = ANY (ARRAY['threat_actor'::text, 'malware_family'::text])),
    CONSTRAINT ioc_source_attributions_resolution_check
        CHECK (resolution_status = ANY (ARRAY['resolved'::text, 'unresolved'::text, 'ambiguous'::text])),
    CONSTRAINT ioc_source_attributions_association_kind_check
        CHECK (association_kind = ANY (ARRAY[
            'associated_via_source_pulse'::text,
            'directly_attributed_to'::text,
            'malware_sample_of'::text
        ])),
    CONSTRAINT ioc_source_attributions_assertion_status_check
        CHECK (assertion_status = ANY (ARRAY['current'::text, 'withdrawn'::text, 'stale'::text])),
    CONSTRAINT uq_ioc_source_attributions_assertion UNIQUE (
        ioc_id, ioc_observable_type, entity_kind, feed_key,
        evidence_ref_type, evidence_ref_id, source_label_normalized
    ),
    CONSTRAINT fk_ioc_source_attributions_ioc FOREIGN KEY (ioc_observable_type, ioc_id)
        REFERENCES public.ioc_items(observable_type, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ioc_source_attributions_ioc
    ON public.ioc_source_attributions USING btree (ioc_id, ioc_observable_type);
CREATE INDEX IF NOT EXISTS idx_ioc_source_attributions_ioc_kind_status
    ON public.ioc_source_attributions USING btree (ioc_id, ioc_observable_type, entity_kind, assertion_status);
CREATE INDEX IF NOT EXISTS idx_ioc_source_attributions_evidence
    ON public.ioc_source_attributions USING btree (feed_key, evidence_ref_type, evidence_ref_id);
CREATE INDEX IF NOT EXISTS idx_ioc_source_attributions_entity
    ON public.ioc_source_attributions USING btree (entity_kind, entity_id)
    WHERE (entity_id IS NOT NULL);

COMMENT ON TABLE public.ioc_source_attributions IS
    'Independent source-reported attributions (e.g. OTX Pulse adversary / malware_families). Not analyst confirmation.';
COMMENT ON COLUMN public.ioc_source_attributions.association_kind IS
    'associated_via_source_pulse = inherited Pulse context; directly_attributed_to / malware_sample_of only when evidence supports it.';
COMMENT ON COLUMN public.ioc_source_attributions.assertion_status IS
    'current = supported by latest complete source observation; withdrawn = authoritative removal; stale = incomplete observability.';

-- Analyst suppressions for source-reported attributions (do not delete provenance)
CREATE TABLE IF NOT EXISTS public.ioc_attribution_overrides (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    ioc_id bigint NOT NULL,
    ioc_observable_type text NOT NULL,
    entity_kind text NOT NULL,
    entity_id uuid,
    source_label_normalized text,
    action text NOT NULL,
    feed_key text,
    evidence_ref_type text,
    evidence_ref_id text,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    cleared_at timestamp with time zone,
    cleared_by text,
    CONSTRAINT ioc_attribution_overrides_pkey PRIMARY KEY (id),
    CONSTRAINT ioc_attribution_overrides_entity_kind_check
        CHECK (entity_kind = ANY (ARRAY['threat_actor'::text, 'malware_family'::text])),
    CONSTRAINT ioc_attribution_overrides_action_check
        CHECK (action = ANY (ARRAY['suppress'::text])),
    CONSTRAINT fk_ioc_attribution_overrides_ioc FOREIGN KEY (ioc_observable_type, ioc_id)
        REFERENCES public.ioc_items(observable_type, id) ON DELETE CASCADE,
    CONSTRAINT ioc_attribution_overrides_match_check CHECK (
        (entity_id IS NOT NULL) OR (source_label_normalized IS NOT NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_ioc_attribution_overrides_active
    ON public.ioc_attribution_overrides (
        ioc_id, ioc_observable_type, entity_kind,
        COALESCE(entity_id::text, ''),
        COALESCE(source_label_normalized, ''),
        COALESCE(feed_key, ''),
        COALESCE(evidence_ref_type, ''),
        COALESCE(evidence_ref_id, '')
    )
    WHERE (cleared_at IS NULL);

CREATE INDEX IF NOT EXISTS idx_ioc_attribution_overrides_ioc
    ON public.ioc_attribution_overrides USING btree (ioc_id, ioc_observable_type)
    WHERE (cleared_at IS NULL);

COMMENT ON TABLE public.ioc_attribution_overrides IS
    'Analyst suppressions of source-reported attributions. Cleared rows remain for audit; active suppressions hide current display.';

-- Bounded OTX Pulse structured metadata cache (no indicator roster)
CREATE TABLE IF NOT EXISTS public.otx_pulse_snapshots (
    pulse_id text NOT NULL,
    pulse_name text,
    adversary text,
    malware_families text[] DEFAULT '{}'::text[] NOT NULL,
    tags text[] DEFAULT '{}'::text[] NOT NULL,
    tlp text,
    author_name text,
    pulse_created timestamp with time zone,
    pulse_modified timestamp with time zone,
    pulse_url text,
    first_fetched_at timestamp with time zone DEFAULT now() NOT NULL,
    last_fetched_at timestamp with time zone DEFAULT now() NOT NULL,
    is_backfill boolean DEFAULT false NOT NULL,
    CONSTRAINT otx_pulse_snapshots_pkey PRIMARY KEY (pulse_id)
);

CREATE INDEX IF NOT EXISTS idx_otx_pulse_snapshots_modified
    ON public.otx_pulse_snapshots USING btree (pulse_modified DESC NULLS LAST);

COMMENT ON TABLE public.otx_pulse_snapshots IS
    'Structured OTX Pulse metadata (adversary, malware_families, tags). Indicators are not stored here.';
