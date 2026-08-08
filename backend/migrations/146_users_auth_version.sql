-- JWT-03: durable per-user auth version for server-side token invalidation.
-- Existing users receive auth_version = 1. Tokens without av (or mismatched av) fail closed.

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS auth_version INTEGER NOT NULL DEFAULT 1;

COMMENT ON COLUMN users.auth_version IS
  'Incremented on password change/reset, logout-all, disable/delete security events. JWTs carry matching av claim.';
