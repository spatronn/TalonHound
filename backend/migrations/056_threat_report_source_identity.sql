-- 056_threat_report_source_identity.sql
--
-- Logical article identity for Threat Library URL reports.
--
-- Before this migration a URL report's identity was only the canonical form of
-- the URL as SUBMITTED (031 source_url_canonical), checked before fetch. Two
-- URLs of one article (an HTTP redirect alias, a publisher canonical, a
-- WordPress post reached under another path) therefore produced independent
-- reports. The worker already knew the redirect target (url_fetch artifact
-- final_url) but never used it as identity.
--
-- threat_report_identity_keys: every identity key a report has proven
-- (submitted URL, delivered URL after redirects, corroborated publisher
-- canonical URL, WordPress post id — see lib/threatLibrary/sourceIdentity.js).
-- One key belongs to exactly one report (UNIQUE), so two imports of equivalent
-- URLs can never both claim it; the import route and the worker also take a
-- transaction-scoped advisory lock per key before reading.
--
-- threat_reports.superseded_by_report_id: explicit, non-destructive
-- supersession. A superseded report keeps every row it owns (candidates,
-- entities, relationships, tags, artifacts, jobs, audit) for provenance; it is
-- hidden from library listings and IOC threat context and its public id
-- resolves to the primary report. Nothing is merged or deleted.
--
-- threat_reports.source_identity: the evidence the worker recorded (accepted
-- keys, rejected signals with reasons, hreflang alternates) for audit and
-- reciprocal-translation checks.
--
-- Additive only. Historical keys are filled by migrate.js (submitted URLs) and
-- scripts/threat-library-source-identity.js backfill (stored source HTML).

CREATE TABLE IF NOT EXISTS public.threat_report_identity_keys (
    id bigserial PRIMARY KEY,
    report_id bigint NOT NULL REFERENCES public.threat_reports(id) ON DELETE CASCADE,
    identity_key text NOT NULL CHECK (identity_key ~ '^(url|wp):.+'),
    evidence text[] NOT NULL DEFAULT ARRAY[]::text[],
    source_values text[] NOT NULL DEFAULT ARRAY[]::text[],
    origin text NOT NULL DEFAULT 'import'
        CHECK (origin = ANY (ARRAY['import'::text, 'fetch'::text, 'backfill'::text, 'reconciliation'::text])),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_report_identity_keys_key
    ON public.threat_report_identity_keys (identity_key);
CREATE INDEX IF NOT EXISTS idx_threat_report_identity_keys_report
    ON public.threat_report_identity_keys (report_id);

COMMENT ON TABLE public.threat_report_identity_keys IS
    'Logical article identity keys of Threat Library reports (url:/wp:). One key, one report; resolution follows superseded_by_report_id.';

ALTER TABLE public.threat_reports
    ADD COLUMN IF NOT EXISTS superseded_by_report_id bigint REFERENCES public.threat_reports(id),
    ADD COLUMN IF NOT EXISTS superseded_at timestamptz,
    ADD COLUMN IF NOT EXISTS supersession jsonb,
    ADD COLUMN IF NOT EXISTS source_identity jsonb;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'threat_reports_superseded_not_self'
          AND conrelid = 'public.threat_reports'::regclass
    ) THEN
        ALTER TABLE public.threat_reports
            ADD CONSTRAINT threat_reports_superseded_not_self
            CHECK (superseded_by_report_id IS NULL OR superseded_by_report_id <> id);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'threat_reports_superseded_consistent'
          AND conrelid = 'public.threat_reports'::regclass
    ) THEN
        ALTER TABLE public.threat_reports
            ADD CONSTRAINT threat_reports_superseded_consistent
            CHECK ((superseded_by_report_id IS NULL) = (superseded_at IS NULL));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_threat_reports_superseded_by
    ON public.threat_reports (superseded_by_report_id)
    WHERE superseded_by_report_id IS NOT NULL;

COMMENT ON COLUMN public.threat_reports.superseded_by_report_id IS
    'Primary report of the same logical article. Superseded rows are retained for provenance and hidden from listings.';
COMMENT ON COLUMN public.threat_reports.source_identity IS
    'Source identity evidence recorded at fetch (lib/threatLibrary/sourceIdentity.js).';
