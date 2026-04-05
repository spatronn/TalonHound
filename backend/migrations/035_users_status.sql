-- Account activation (login allowed only when active).
CREATE TYPE app_user_status AS ENUM ('active', 'passive');

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS status app_user_status NOT NULL DEFAULT 'active';

CREATE INDEX IF NOT EXISTS idx_users_status ON users (status);
