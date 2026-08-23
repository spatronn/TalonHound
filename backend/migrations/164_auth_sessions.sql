-- Bounded interactive browser sessions (security: enforce bounded browser sessions).
--
-- Previously TalonHound authentication was a single stateless JWT (default 24h) with
-- no refresh, no idle timeout and no absolute cap: an open browser stayed logged in
-- for the full token lifetime with nothing shorter to bound it. This table introduces
-- a minimal server-side session so we can enforce:
--   - a short access-token TTL with silent refresh (rotation),
--   - an idle timeout driven ONLY by genuine user activity (not background polling),
--   - an absolute lifetime from original login that refresh can never extend.
--
-- Only a cryptographic HASH of the refresh secret is stored — never the raw token.
-- Rows are short-lived operational state; the ioc-expiration maintenance worker
-- deletes revoked/expired rows after a bounded retention window.

CREATE TABLE IF NOT EXISTS auth_sessions (
  id                    BIGSERIAL PRIMARY KEY,
  -- Opaque public session id (also embedded as the `sid` claim in access JWTs).
  session_id            UUID NOT NULL UNIQUE,
  user_id               BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- SHA-256 hex of the refresh secret. Rotated on every successful refresh.
  refresh_token_hash    TEXT NOT NULL,
  -- Previous secret hash + rotation time. A brief grace window accepts the immediately
  -- prior secret so two browser tabs racing to refresh the same (shared-cookie) session
  -- do not trip replay detection and log the user out. Outside the window, presenting a
  -- rotated secret is treated as compromise.
  prev_refresh_token_hash TEXT,
  rotated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- users.auth_version snapshot at issue time; a security event that bumps it
  -- immediately invalidates this session on the next refresh/request.
  auth_version_at_issue INTEGER NOT NULL,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- Genuine-activity clock. Advanced ONLY by the explicit activity heartbeat, never
  -- by background polling, refresh, or ordinary API traffic.
  last_activity_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  idle_expires_at       TIMESTAMPTZ NOT NULL,
  -- Hard cap from original login. Never moved once set.
  absolute_expires_at   TIMESTAMPTZ NOT NULL,
  revoked_at            TIMESTAMPTZ,
  revoked_reason        TEXT,
  user_agent            TEXT
);

-- Revoke-all-for-user (logout-all, password change, admin reset, disable/delete).
CREATE INDEX IF NOT EXISTS auth_sessions_user_id_idx
  ON auth_sessions (user_id);

-- Bounded cleanup of revoked / absolutely-expired rows by the maintenance worker.
CREATE INDEX IF NOT EXISTS auth_sessions_absolute_expires_idx
  ON auth_sessions (absolute_expires_at);

COMMENT ON TABLE auth_sessions IS
  'Server-side interactive browser sessions: short access token + rotating refresh, idle + absolute enforcement. Stores only a hash of the refresh secret.';
COMMENT ON COLUMN auth_sessions.last_activity_at IS
  'Advanced only by the explicit user-activity heartbeat; background polling/refresh must NOT touch it.';
COMMENT ON COLUMN auth_sessions.absolute_expires_at IS
  'Hard session lifetime from original login. Refresh never extends this.';
