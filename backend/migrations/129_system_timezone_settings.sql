-- System-wide timezone + initial setup gate.
-- Absolute instants remain TIMESTAMPTZ. This table stores active/pending IANA zones.
--
-- IMPORTANT: This migration does NOT adopt a timezone and does NOT silently set UTC.
-- Existing-install adoption is performed at backend bootstrap (see systemTime.js).

CREATE TABLE IF NOT EXISTS system_settings (
  id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  active_system_timezone TEXT,
  pending_system_timezone TEXT,
  initial_setup_completed BOOLEAN NOT NULL DEFAULT FALSE,
  timezone_restart_required BOOLEAN NOT NULL DEFAULT FALSE,
  timezone_configuration_required BOOLEAN NOT NULL DEFAULT FALSE,
  timezone_config_version INTEGER NOT NULL DEFAULT 0,
  active_timezone_config_version INTEGER NOT NULL DEFAULT 0,
  adoption_source TEXT,
  initial_setup_completed_at TIMESTAMPTZ,
  timezone_change_requested_at TIMESTAMPTZ,
  timezone_change_requested_by TEXT,
  timezone_promoted_at TIMESTAMPTZ,
  timezone_updated_at TIMESTAMPTZ,
  timezone_updated_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Compatibility path if an earlier draft of 129 created system_timezone.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'system_settings' AND column_name = 'system_timezone'
  ) AND NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'system_settings' AND column_name = 'active_system_timezone'
  ) THEN
    ALTER TABLE system_settings RENAME COLUMN system_timezone TO active_system_timezone;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'system_settings' AND column_name = 'timezone_configuration_required'
  ) THEN
    ALTER TABLE system_settings
      ADD COLUMN timezone_configuration_required BOOLEAN NOT NULL DEFAULT FALSE;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'system_settings' AND column_name = 'timezone_config_version'
  ) THEN
    ALTER TABLE system_settings
      ADD COLUMN timezone_config_version INTEGER NOT NULL DEFAULT 0;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'system_settings' AND column_name = 'active_timezone_config_version'
  ) THEN
    ALTER TABLE system_settings
      ADD COLUMN active_timezone_config_version INTEGER NOT NULL DEFAULT 0;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'system_settings' AND column_name = 'adoption_source'
  ) THEN
    ALTER TABLE system_settings ADD COLUMN adoption_source TEXT;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'system_settings' AND column_name = 'timezone_change_requested_at'
  ) THEN
    ALTER TABLE system_settings ADD COLUMN timezone_change_requested_at TIMESTAMPTZ;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'system_settings' AND column_name = 'timezone_change_requested_by'
  ) THEN
    ALTER TABLE system_settings ADD COLUMN timezone_change_requested_by TEXT;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'system_settings' AND column_name = 'timezone_promoted_at'
  ) THEN
    ALTER TABLE system_settings ADD COLUMN timezone_promoted_at TIMESTAMPTZ;
  END IF;
END $$;

INSERT INTO system_settings (id)
VALUES (1)
ON CONFLICT (id) DO NOTHING;

COMMENT ON TABLE system_settings IS
  'Singleton system configuration. active_system_timezone is the live IANA zone; pending awaits restart promotion.';
COMMENT ON COLUMN system_settings.active_system_timezone IS
  'Live IANA timezone used by API, UI, schedulers, workers, and logs until a pending change is promoted.';
COMMENT ON COLUMN system_settings.pending_system_timezone IS
  'IANA timezone waiting for successful restart/rollout promotion. Not used for runtime formatting.';
COMMENT ON COLUMN system_settings.timezone_configuration_required IS
  'True for existing installs that need an admin-selected timezone (no silent UTC).';
