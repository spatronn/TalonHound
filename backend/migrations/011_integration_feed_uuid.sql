CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE integration_feeds
ADD COLUMN IF NOT EXISTS integration_id UUID;

UPDATE integration_feeds
SET integration_id = gen_random_uuid()
WHERE integration_id IS NULL;

ALTER TABLE integration_feeds
ALTER COLUMN integration_id SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_integration_feeds_integration_id
ON integration_feeds (integration_id);
