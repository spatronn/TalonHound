-- Analyst-confirmed catalog identity for source-reported attributions.
-- Additive only: no existing row, label, Pulse reference or timestamp changes.
--
-- An analyst can link a source-reported Threat Actor / Malware Family label on
-- one IOC to a local catalog entity (IOC Details → Overview "+"). That sets
-- entity_id with resolution_method = 'analyst' on the IOC's assertions for the
-- label. It is an identity decision ("this label means that catalog entity"),
-- not analyst attribution: analyst attributions stay in ioc_threat_actors /
-- ioc_malware_families. Feed re-ingestion keeps analyst links (see
-- lib/iocSourceAttributions.upsertSourceAttribution).

ALTER TABLE public.ioc_source_attributions
  ADD COLUMN IF NOT EXISTS resolved_by text;

COMMENT ON COLUMN public.ioc_source_attributions.resolution_method IS
  'Catalog resolution rule that linked source_label to entity_id: attack_id | name | slug | alias (automatic), analyst (analyst-confirmed identity, kept by re-ingestion); NULL when unresolved.';
COMMENT ON COLUMN public.ioc_source_attributions.resolved_by IS
  'Analyst who linked this assertion to entity_id (resolution_method = analyst). NULL for automatic resolution.';
