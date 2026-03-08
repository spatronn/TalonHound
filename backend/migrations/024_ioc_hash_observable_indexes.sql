-- Hash-prefixed IOC search: observable_type + LOWER(observable) path.
-- The list API uses LOWER(observable) = $hash, so (observable_type, observable)
-- is not used. These partial expression indexes make the observable path fast.
-- Note path already covered by 022 (idx_ioc_items_sha256_from_note etc.).

CREATE INDEX IF NOT EXISTS idx_ioc_items_sha256_lower_observable
ON ioc_items ((LOWER(observable)))
WHERE observable_type = 'sha256';

CREATE INDEX IF NOT EXISTS idx_ioc_items_sha1_lower_observable
ON ioc_items ((LOWER(observable)))
WHERE observable_type = 'sha1';

CREATE INDEX IF NOT EXISTS idx_ioc_items_md5_lower_observable
ON ioc_items ((LOWER(observable)))
WHERE observable_type = 'md5';

ANALYZE ioc_items;
