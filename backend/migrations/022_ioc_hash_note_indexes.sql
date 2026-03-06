-- Hash-prefixed IOC searches (md5:..., sha1:..., sha256:..., ssdeep:..., imphash:..., tlsh:...)
-- rely on extracting hash values from ioc_items.note in key=value format.

CREATE INDEX IF NOT EXISTS idx_ioc_items_md5_from_note
ON ioc_items ((LOWER(NULLIF(SPLIT_PART(SPLIT_PART(REPLACE(COALESCE(note, ''), ' ', ''), 'md5=', 2), '|', 1), ''))));

CREATE INDEX IF NOT EXISTS idx_ioc_items_sha1_from_note
ON ioc_items ((LOWER(NULLIF(SPLIT_PART(SPLIT_PART(REPLACE(COALESCE(note, ''), ' ', ''), 'sha1=', 2), '|', 1), ''))));

CREATE INDEX IF NOT EXISTS idx_ioc_items_sha256_from_note
ON ioc_items ((LOWER(NULLIF(SPLIT_PART(SPLIT_PART(REPLACE(COALESCE(note, ''), ' ', ''), 'sha256=', 2), '|', 1), ''))));

CREATE INDEX IF NOT EXISTS idx_ioc_items_ssdeep_from_note
ON ioc_items ((LOWER(NULLIF(SPLIT_PART(SPLIT_PART(REPLACE(COALESCE(note, ''), ' ', ''), 'ssdeep=', 2), '|', 1), ''))));

CREATE INDEX IF NOT EXISTS idx_ioc_items_imphash_from_note
ON ioc_items ((LOWER(NULLIF(SPLIT_PART(SPLIT_PART(REPLACE(COALESCE(note, ''), ' ', ''), 'imphash=', 2), '|', 1), ''))));

CREATE INDEX IF NOT EXISTS idx_ioc_items_tlsh_from_note
ON ioc_items ((LOWER(NULLIF(SPLIT_PART(SPLIT_PART(REPLACE(COALESCE(note, ''), ' ', ''), 'tlsh=', 2), '|', 1), ''))));

ANALYZE ioc_items;
