-- Allow STIX 2.1 as a third Published Feed output format.
-- Existing txt/json values remain valid. No data rewrite.

SET LOCAL statement_timeout = '30s';
SET LOCAL lock_timeout = '15s';

ALTER TABLE published_feeds
  DROP CONSTRAINT IF EXISTS chk_published_feeds_formats;

ALTER TABLE published_feeds
  ADD CONSTRAINT chk_published_feeds_formats CHECK (
    jsonb_typeof(formats) = 'array'
    AND jsonb_array_length(formats) >= 1
    AND jsonb_array_length(formats) <= 3
    AND formats <@ '["txt","json","stix"]'::jsonb
    AND (
      jsonb_array_length(formats) = 1
      OR (
        jsonb_array_length(formats) = 2
        AND (formats->>0) IS DISTINCT FROM (formats->>1)
      )
      OR (
        jsonb_array_length(formats) = 3
        AND (formats->>0) IS DISTINCT FROM (formats->>1)
        AND (formats->>0) IS DISTINCT FROM (formats->>2)
        AND (formats->>1) IS DISTINCT FROM (formats->>2)
      )
    )
  );
