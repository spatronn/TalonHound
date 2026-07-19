ALTER TABLE ioc_ip_enrichment
  ADD COLUMN IF NOT EXISTS normalized_ip TEXT NULL;

DO $$
DECLARE
  record_row RECORD;
  canonical_ip TEXT;
BEGIN
  FOR record_row IN
    SELECT id, ip
    FROM ioc_ip_enrichment
    WHERE normalized_ip IS NULL
  LOOP
    BEGIN
      canonical_ip := host(record_row.ip::inet);
      UPDATE ioc_ip_enrichment
      SET normalized_ip = canonical_ip
      WHERE id = record_row.id;
    EXCEPTION
      WHEN invalid_text_representation THEN
        NULL;
    END;
  END LOOP;
END
$$;

WITH ranked AS (
  SELECT
    id,
    ROW_NUMBER() OVER (
      PARTITION BY normalized_ip
      ORDER BY
        (provider_status = 'success') DESC,
        last_enriched_at DESC NULLS LAST,
        updated_at DESC,
        id DESC
    ) AS duplicate_rank
  FROM ioc_ip_enrichment
  WHERE normalized_ip IS NOT NULL
)
DELETE FROM ioc_ip_enrichment target
USING ranked
WHERE target.id = ranked.id
  AND ranked.duplicate_rank > 1;

CREATE UNIQUE INDEX IF NOT EXISTS ioc_ip_enrichment_normalized_ip_uniq
  ON ioc_ip_enrichment (normalized_ip);

CREATE INDEX IF NOT EXISTS ioc_ip_enrichment_provider_normalized_ip_idx
  ON ioc_ip_enrichment (provider, normalized_ip);
