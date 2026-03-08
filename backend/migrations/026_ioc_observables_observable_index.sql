-- Exact match search on ioc_observables.observable (used by IOC list endpoint).
-- Only when table has "observable" column (004 schema); skip if 025 replaced with observable_value.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'ioc_observables' AND column_name = 'observable'
  ) THEN
    CREATE INDEX IF NOT EXISTS idx_ioc_observables_observable ON ioc_observables (observable);
  END IF;
END $$;
