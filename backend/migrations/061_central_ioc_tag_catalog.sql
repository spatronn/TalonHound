-- Central IOC tag catalog enhancements.
-- Note: `tags` is the master catalog; `ioc_tags` remains the IOC assignment junction table.

ALTER TABLE tags ADD COLUMN IF NOT EXISTS slug TEXT;
ALTER TABLE tags ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE tags ADD COLUMN IF NOT EXISTS color TEXT;
ALTER TABLE tags ADD COLUMN IF NOT EXISTS category TEXT;
ALTER TABLE tags ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

UPDATE tags
SET slug = name
WHERE slug IS NULL OR btrim(slug) = '';

UPDATE tags
SET category = CASE type::text
  WHEN 'threat' THEN 'malware'
  WHEN 'actor' THEN 'actor'
  WHEN 'technique' THEN 'behavior'
  WHEN 'context' THEN 'custom'
  ELSE 'custom'
END
WHERE category IS NULL OR btrim(category) = '';

ALTER TABLE tags ALTER COLUMN slug SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_tags_slug ON tags (slug);

INSERT INTO tags (name, type, enabled, slug, category)
VALUES
  ('ransomware', 'threat', TRUE, 'ransomware', 'malware'),
  ('c2', 'threat', TRUE, 'c2', 'malware'),
  ('phishing', 'threat', TRUE, 'phishing', 'malware'),
  ('apt29', 'actor', TRUE, 'apt29', 'actor'),
  ('clickfix', 'technique', TRUE, 'clickfix', 'behavior')
ON CONFLICT (name) DO UPDATE
SET
  enabled = TRUE,
  slug = EXCLUDED.slug,
  category = COALESCE(tags.category, EXCLUDED.category),
  updated_at = NOW();
