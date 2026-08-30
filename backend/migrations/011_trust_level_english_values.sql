-- Convert legacy Turkish trust_level machine values to English canonical values.
-- Safe for existing installs that still store guvenilir/orta, and for fresh installs
-- that already seed trusted/medium/not_categorized.

-- Refuse unexpected values rather than silently remapping them.
DO $$
DECLARE
  bad_count integer;
  bad_sample text;
BEGIN
  SELECT count(*), string_agg(DISTINCT trust_level, ', ' ORDER BY trust_level)
    INTO bad_count, bad_sample
  FROM public.integration_feeds
  WHERE trust_level NOT IN ('guvenilir', 'orta', 'not_categorized', 'trusted', 'medium');

  IF COALESCE(bad_count, 0) > 0 THEN
    RAISE EXCEPTION
      '011_trust_level_english_values: refusing to migrate; unexpected trust_level value(s): %',
      bad_sample;
  END IF;
END $$;

ALTER TABLE public.integration_feeds
  DROP CONSTRAINT IF EXISTS integration_feeds_trust_level_check;

UPDATE public.integration_feeds
SET trust_level = 'trusted',
    updated_at = NOW()
WHERE trust_level = 'guvenilir';

UPDATE public.integration_feeds
SET trust_level = 'medium',
    updated_at = NOW()
WHERE trust_level = 'orta';

DO $$
DECLARE
  bad_count integer;
  bad_sample text;
BEGIN
  SELECT count(*), string_agg(DISTINCT trust_level, ', ' ORDER BY trust_level)
    INTO bad_count, bad_sample
  FROM public.integration_feeds
  WHERE trust_level NOT IN ('trusted', 'medium', 'not_categorized');

  IF COALESCE(bad_count, 0) > 0 THEN
    RAISE EXCEPTION
      '011_trust_level_english_values: post-update invalid trust_level value(s): %',
      bad_sample;
  END IF;
END $$;

ALTER TABLE public.integration_feeds
  ADD CONSTRAINT integration_feeds_trust_level_check
  CHECK (trust_level = ANY (ARRAY['trusted'::text, 'medium'::text, 'not_categorized'::text]));
