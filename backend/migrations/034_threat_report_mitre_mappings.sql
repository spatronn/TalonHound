-- 034_threat_report_mitre_mappings.sql
--
-- Report-level MITRE ATT&CK mappings produced by Threat Library AI analysis
-- (and optional analyst add/remove). Canonical identity is attack_id (Txxxx /
-- Txxxx.xxx). Technique names and tactics are resolved at read time from the
-- bundled ATT&CK catalog (backend/data/mitre-attack-reference.json), not stored
-- here.
--
-- Additive only: new table, no rewrite of existing reports or tags.
-- Re-analysis upserts by (report_id, attack_id) and never deletes other rows.

CREATE TABLE IF NOT EXISTS public.threat_report_mitre_mappings (
    report_id bigint NOT NULL REFERENCES public.threat_reports(id) ON DELETE CASCADE,
    attack_id text NOT NULL,
    confidence numeric,
    evidence_text text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (report_id, attack_id),
    CONSTRAINT threat_report_mitre_mappings_attack_id_check
      CHECK (attack_id ~ '^T[0-9]{4}(\.[0-9]{3})?$')
);

CREATE INDEX IF NOT EXISTS idx_threat_report_mitre_mappings_attack
    ON public.threat_report_mitre_mappings (attack_id);
