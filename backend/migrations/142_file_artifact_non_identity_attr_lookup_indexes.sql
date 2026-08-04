-- Exact value lookup for non-identity file-artifact attributes (imphash/tlsh/ssdeep)
-- from the IOC Search DSL (imphash/tlsh/ssdeep equals "<value>").
--
-- The existing indexes on file_artifact_non_identity_attrs are artifact-first
-- (PK on id, UNIQUE(artifact_id, attr_type, attr_value), idx(artifact_id)) — none can
-- serve a value-first lookup, so without these a search would sequential-scan ~2.8M
-- attribute rows (measured 200-500ms). Additive only; no data is modified.
--
-- PARTIAL, per attr type. A single (attr_type, attr_value) index would index every type
-- for every query and roughly double the on-disk entries (measured: two wide indexes
-- ~444MB vs three partial ~211MB on production). Each resolver predicate pins a literal
-- attr_type (queryBuilder.buildNonIdentityAttr), so the planner uses the matching partial:
--   imphash / ssdeep : compared on the raw column (imphash pre-lowercased by the parser;
--                      ssdeep is base64 and case-significant) -> partial on attr_value.
--   tlsh             : hex digest compared case-insensitively via LOWER(attr_value), so it
--                      needs the matching partial functional index on lower(attr_value).
--
-- DEPLOY NOTE: the migration runner (migrate.js) wraps each file in a single
-- transaction, and CREATE INDEX CONCURRENTLY cannot run inside a transaction — so these
-- are plain CREATE INDEX, which take a brief write lock while the index builds (a few
-- seconds at current volume). On a large existing install where that lock is
-- unacceptable, create the three indexes out-of-band first with
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS <same definition>;
-- then this migration's IF NOT EXISTS is a no-op (no lock). Fresh/small installs just
-- let the migration build them.

CREATE INDEX IF NOT EXISTS idx_fa_non_identity_attrs_imphash_value
  ON file_artifact_non_identity_attrs (attr_value)
  WHERE attr_type = 'imphash';

CREATE INDEX IF NOT EXISTS idx_fa_non_identity_attrs_ssdeep_value
  ON file_artifact_non_identity_attrs (attr_value)
  WHERE attr_type = 'ssdeep';

CREATE INDEX IF NOT EXISTS idx_fa_non_identity_attrs_tlsh_lower_value
  ON file_artifact_non_identity_attrs (LOWER(attr_value))
  WHERE attr_type = 'tlsh';

ANALYZE file_artifact_non_identity_attrs;
