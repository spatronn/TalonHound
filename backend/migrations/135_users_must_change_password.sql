-- Force password change flag for users + one-time default-admin bootstrap marker.
-- Does NOT delete or modify existing users / passwords.
-- Default admin seeding is performed by backend bootstrap (see defaultAdminBootstrap.js),
-- only when users is empty AND default_admin_bootstrapped is false.

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN users.must_change_password IS
  'When true, authenticated user may only read session info, change password, or logout.';

ALTER TABLE system_settings
  ADD COLUMN IF NOT EXISTS default_admin_bootstrapped BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN system_settings.default_admin_bootstrapped IS
  'True after first-install default admin bootstrap has run (or skipped because users already existed). Prevents silent re-create after admin deletion.';
