-- Manageable source badge colors for Default Feeds (integration_feeds),
-- Custom Feeds (which are integration_feeds rows) and IOC Sources (ioc_sources).
-- Color is stored as a 7-char hex string (#rrggbb, lowercase). NULL means
-- "use the frontend fallback". Idempotent + production-safe.
SET LOCAL statement_timeout = 0;
SET LOCAL lock_timeout = '120s';

-- ---------------------------------------------------------------------------
-- 1) Columns + hex format guards
-- ---------------------------------------------------------------------------
ALTER TABLE integration_feeds
  ADD COLUMN IF NOT EXISTS color TEXT NULL;

ALTER TABLE ioc_sources
  ADD COLUMN IF NOT EXISTS color TEXT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_integration_feeds_color_hex'
  ) THEN
    ALTER TABLE integration_feeds
      ADD CONSTRAINT chk_integration_feeds_color_hex
      CHECK (color IS NULL OR color ~ '^#[0-9a-f]{6}$');
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_ioc_sources_color_hex'
  ) THEN
    ALTER TABLE ioc_sources
      ADD CONSTRAINT chk_ioc_sources_color_hex
      CHECK (color IS NULL OR color ~ '^#[0-9a-f]{6}$');
  END IF;
END $$;

COMMENT ON COLUMN integration_feeds.color IS 'Managed badge color as #rrggbb (lowercase). NULL = frontend fallback.';
COMMENT ON COLUMN ioc_sources.color IS 'Managed badge color as #rrggbb (lowercase). NULL = frontend fallback.';

-- ---------------------------------------------------------------------------
-- 2) Seed brand colors for known built-in feeds.
--    Preserves the "USOM purple / MalwareBazaar green" look as durable defaults.
--    Only fills rows whose color is still NULL, so operator overrides are kept.
-- ---------------------------------------------------------------------------
UPDATE integration_feeds SET color = seed.color
FROM (VALUES
  ('usom-trcert',            '#7c3aed'),  -- purple
  ('malwarebazaar-abusech',  '#16a34a'),  -- green
  ('urlhaus-abusech',        '#0d9488'),  -- teal-green (abuse.ch family)
  ('threatfox-abusech',      '#15803d'),  -- green (abuse.ch family)
  ('et-blockrules',          '#b45309'),  -- amber
  ('alienvault-otx',         '#2563eb')   -- blue
) AS seed(key, color)
WHERE integration_feeds.key = seed.key
  AND integration_feeds.color IS NULL;
