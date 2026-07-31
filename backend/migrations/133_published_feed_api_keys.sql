-- Published Feed API keys: revealable, type-scoped keys + standard slug pull URL.
--
-- Target flow: GET /api/published-feeds/{slug}?api_key={API_KEY}
--   * A single "published_feed" key type can pull ANY published feed (authorized by
--     key type + active state, not by manual feed<->key binding).
--   * Keys are revealable after creation: the secret is stored encrypted (AES-256-GCM)
--     in addition to its SHA-256 hash. Legacy feed-bound hash-only keys stay usable on
--     the legacy /public/feeds/:token endpoint but are marked non-revealable.

-- 1) Stable per-feed slug for the standard pull URL. ------------------------------------
ALTER TABLE published_feeds ADD COLUMN IF NOT EXISTS slug TEXT;

-- Backfill slugs from name (kebab-case). Empty/failed slugs fall back to feed-<id>.
UPDATE published_feeds
SET slug = NULLIF(btrim(regexp_replace(lower(coalesce(name, '')), '[^a-z0-9]+', '-', 'g'), '-'), '')
WHERE slug IS NULL OR btrim(slug) = '';

UPDATE published_feeds SET slug = 'feed-' || id
WHERE slug IS NULL OR btrim(slug) = '';

-- Deterministically de-duplicate collisions by suffixing the feed id.
UPDATE published_feeds pf
SET slug = pf.slug || '-' || pf.id
WHERE EXISTS (
  SELECT 1 FROM published_feeds o
  WHERE o.slug = pf.slug AND o.id < pf.id
);

ALTER TABLE published_feeds ALTER COLUMN slug SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_published_feeds_slug ON published_feeds (slug);

-- 2) Evolve access keys into typed, optionally-revealable API keys. ---------------------
ALTER TABLE published_feed_access_keys
  ADD COLUMN IF NOT EXISTS key_type TEXT NOT NULL DEFAULT 'feed_access',
  ADD COLUMN IF NOT EXISTS key_prefix TEXT,
  ADD COLUMN IF NOT EXISTS last_four TEXT,
  ADD COLUMN IF NOT EXISTS secret_ciphertext BYTEA,
  ADD COLUMN IF NOT EXISTS secret_nonce BYTEA,
  ADD COLUMN IF NOT EXISTS secret_tag BYTEA,
  ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS created_by TEXT;

-- Global "published_feed" keys are not bound to a single feed.
ALTER TABLE published_feed_access_keys ALTER COLUMN feed_id DROP NOT NULL;

-- Constrain the key type. Existing rows default to 'feed_access' (legacy, hash-only).
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_pf_access_keys_key_type'
  ) THEN
    ALTER TABLE published_feed_access_keys
      ADD CONSTRAINT chk_pf_access_keys_key_type
      CHECK (key_type IN ('feed_access', 'published_feed'));
  END IF;
END$$;

-- Active-key lookup by type for the /api/published-feeds/{slug} pull endpoint.
CREATE INDEX IF NOT EXISTS idx_pf_access_keys_type_active
  ON published_feed_access_keys (key_type)
  WHERE revoked_at IS NULL;
