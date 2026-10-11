-- Canonical resolution provenance + reverse-lookup indexes for source-reported
-- attributions (Malware Family → IOC discovery).
-- Additive only: no existing row, label, Pulse reference or timestamp changes.

-- How / when a source label was linked to a catalog identity (NULL = never
-- resolved, or resolved before this column existed). Set by feed ingestion and
-- by the controlled historical backfill; source observation timestamps
-- (observed_at, first_ingested_at, last_ingested_at) are never touched by it.
ALTER TABLE public.ioc_source_attributions
  ADD COLUMN IF NOT EXISTS resolution_method text,
  ADD COLUMN IF NOT EXISTS resolved_at timestamp with time zone;

COMMENT ON COLUMN public.ioc_source_attributions.resolution_method IS
  'Catalog resolution rule that linked source_label to entity_id: name | slug | alias (NULL when unresolved).';
COMMENT ON COLUMN public.ioc_source_attributions.resolved_at IS
  'When entity_id was last linked (ingestion or controlled backfill). Not a source observation time.';

-- Family → current source assertions → IOC (index-only friendly reverse lookup).
CREATE INDEX IF NOT EXISTS idx_ioc_source_attributions_entity_current
  ON public.ioc_source_attributions (entity_kind, entity_id, ioc_observable_type, ioc_id)
  WHERE entity_id IS NOT NULL AND assertion_status = 'current';

-- Source-label discovery (unresolved labels) and label-grouped backfill.
CREATE INDEX IF NOT EXISTS idx_ioc_source_attributions_kind_label
  ON public.ioc_source_attributions (entity_kind, source_label_normalized, assertion_status);
