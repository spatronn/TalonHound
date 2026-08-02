-- Persistent, protected system administrator identity (schema only).
--
-- Adds an explicit flag so protection does NOT rely on email string comparison alone.
--
-- This migration deliberately does NOT touch any row data. It does not auto-promote an existing
-- account to admin, because a migration cannot safely tell whether a pre-existing
-- admin@talonhound.local row is genuinely the bootstrap account or a coincidental user. All
-- reconcile/creation is handled by controlled bootstrap code (lib/systemAdminBootstrap.js) inside
-- a transaction with explicit logging, and — for creation — a securely delivered password.

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS is_system_admin BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN users.is_system_admin IS
  'When true, this is the protected system administrator account (admin@talonhound.local): it cannot be deleted, deactivated, renamed, or demoted below admin. Reconciliation/creation is handled by backend bootstrap, never by this migration.';

-- DB-level guard: AT MOST ONE row may carry the protected flag. (This is only an upper bound; the
-- "at least one active administrator" guarantee is enforced by bootstrap + the backend mutation
-- guards, not by this index.)
CREATE UNIQUE INDEX IF NOT EXISTS uq_users_single_system_admin
  ON users ((is_system_admin))
  WHERE is_system_admin;
