-- Threat classification taxonomy hardening: MITRE ATT&CK mapping layer.
-- Built-in descriptions and mappings are reconciled from backend/seeds/threat-classifications.json
-- during npm run migrate (idempotent).

CREATE TABLE IF NOT EXISTS public.threat_classification_mitre_mappings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    classification_id uuid NOT NULL,
    attack_id text NOT NULL,
    attack_name text NOT NULL,
    attack_type text NOT NULL,
    attack_url text NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT threat_classification_mitre_mappings_attack_type_check
      CHECK (attack_type = ANY (ARRAY['tactic'::text, 'technique'::text, 'sub-technique'::text])),
    CONSTRAINT threat_classification_mitre_mappings_pkey PRIMARY KEY (id),
    CONSTRAINT threat_classification_mitre_mappings_classification_id_fkey
      FOREIGN KEY (classification_id) REFERENCES public.threat_classifications(id) ON DELETE CASCADE,
    CONSTRAINT threat_classification_mitre_mappings_classification_attack_unique
      UNIQUE (classification_id, attack_id)
);

CREATE INDEX IF NOT EXISTS idx_tc_mitre_mappings_classification
  ON public.threat_classification_mitre_mappings (classification_id, sort_order ASC, attack_id ASC);
