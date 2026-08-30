-- Remap legacy import slug c2 -> command_and_control.
-- Historical URLhaus/ThreatFox imports wrote raw 'c2' before dictionary normalization.
-- Idempotent: safe when no c2 rows remain.

UPDATE public.ioc_items
SET threat_classification = 'command_and_control',
    updated_at = NOW()
WHERE threat_classification = 'c2';

UPDATE public.ioc_threat_classifications AS src
SET classification_slug = 'command_and_control',
    updated_at = NOW()
WHERE classification_slug = 'c2'
  AND NOT EXISTS (
    SELECT 1
    FROM public.ioc_threat_classifications x
    WHERE x.ioc_id = src.ioc_id
      AND x.ioc_observable_type = src.ioc_observable_type
      AND x.classification_slug = 'command_and_control'
  );

DELETE FROM public.ioc_threat_classifications
WHERE classification_slug = 'c2';

UPDATE public.ioc_threat_classification_overrides AS src
SET classification_slug = 'command_and_control'
WHERE classification_slug = 'c2'
  AND cleared_at IS NULL
  AND NOT EXISTS (
    SELECT 1
    FROM public.ioc_threat_classification_overrides x
    WHERE x.ioc_id = src.ioc_id
      AND x.ioc_observable_type = src.ioc_observable_type
      AND x.classification_slug = 'command_and_control'
      AND x.cleared_at IS NULL
  );

UPDATE public.ioc_threat_classification_overrides
SET cleared_at = NOW(),
    cleared_by = COALESCE(cleared_by, 'system-c2-normalize')
WHERE classification_slug = 'c2'
  AND cleared_at IS NULL;
