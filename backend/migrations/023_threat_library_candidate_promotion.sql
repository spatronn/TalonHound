-- Threat Library: persist Create IOCs / promotion outcomes per candidate.
-- Additive only. Does not alter ioc_items types or explode CIDR ranges.

ALTER TABLE public.threat_report_candidates
  ADD COLUMN IF NOT EXISTS promotion_outcome text
    CHECK (
      promotion_outcome IS NULL
      OR promotion_outcome = ANY (ARRAY[
        'created'::text,
        'already_existing'::text,
        'unsupported'::text,
        'not_approved'::text,
        'not_applicable'::text,
        'failed'::text
      ])
    ),
  ADD COLUMN IF NOT EXISTS promotion_detail text,
  ADD COLUMN IF NOT EXISTS promoted_at timestamptz;

COMMENT ON COLUMN public.threat_report_candidates.promotion_outcome IS
  'Result of the last Create IOCs action. Independent of review_status (analyst decision) and match_state.';
