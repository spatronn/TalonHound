CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE ioc_items
ADD COLUMN IF NOT EXISTS public_id UUID;

UPDATE ioc_items
SET public_id = gen_random_uuid()
WHERE public_id IS NULL;

ALTER TABLE ioc_items
ALTER COLUMN public_id SET DEFAULT gen_random_uuid();

ALTER TABLE ioc_items
ALTER COLUMN public_id SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_ioc_items_public_id
ON ioc_items (public_id);
