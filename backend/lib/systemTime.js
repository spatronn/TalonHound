/**
 * Canonical system timezone configuration for TalonHound.
 *
 * Runtime truth: system_settings.active_system_timezone (IANA).
 * Pending changes live in pending_system_timezone until restart promotion.
 * No silent UTC adoption for existing installs.
 */

const SETTINGS_ID = 1;
const CACHE_TTL_MS = 5_000;
const ADOPTION_LOCK_KEY = 72900129;

/** @type {{ loadedAt: number, config: SystemTimeConfig | null }} */
let cache = { loadedAt: 0, config: null };

/** @type {readonly string[]|null} */
let supportedTimezonesCache = null;
/** @type {Set<string>|null} */
let supportedTimezonesSetCache = null;

/**
 * Valid IANA zones omitted from Intl.supportedValuesOf on some Node/ICU builds.
 * Kept minimal — not a curated dropdown list.
 */
const SUPPLEMENTAL_IANA_TIMEZONES = Object.freeze(['Asia/Kathmandu']);

function isIanaTimezoneId(tz) {
  if (tz === 'UTC') return true;
  return /^[A-Za-z]+(?:_[A-Za-z0-9+-]+)*\/[A-Za-z0-9_+-]+(?:\/[A-Za-z0-9_+-]+)*$/.test(tz);
}

function isRecognizedByIntlDateTimeFormat(tz) {
  try {
    Intl.DateTimeFormat(undefined, { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

/** Process-level immutable IANA timezone list (Node ICU via Intl.supportedValuesOf). */
export function getSupportedIanaTimezones() {
  if (supportedTimezonesCache) return supportedTimezonesCache;

  let zones;
  if (typeof Intl !== 'undefined' && typeof Intl.supportedValuesOf === 'function') {
    zones = Intl.supportedValuesOf('timeZone');
  } else {
    zones = ['UTC'];
  }

  const unique = new Set(zones.map((z) => String(z)));
  unique.add('UTC');
  for (const tz of SUPPLEMENTAL_IANA_TIMEZONES) {
    if (isIanaTimezoneId(tz) && isRecognizedByIntlDateTimeFormat(tz)) {
      unique.add(tz);
    }
  }
  const sorted = [...unique].sort((a, b) => a.localeCompare(b));
  const withoutUtc = sorted.filter((z) => z !== 'UTC');
  supportedTimezonesCache = Object.freeze(['UTC', ...withoutUtc]);
  supportedTimezonesSetCache = new Set(supportedTimezonesCache);
  return supportedTimezonesCache;
}

function getSupportedIanaTimezoneSet() {
  if (!supportedTimezonesSetCache) getSupportedIanaTimezones();
  return supportedTimezonesSetCache;
}

export function clearSupportedIanaTimezonesCache() {
  supportedTimezonesCache = null;
  supportedTimezonesSetCache = null;
}

/**
 * @typedef {object} SystemTimeConfig
 * @property {boolean} initial_setup_completed
 * @property {boolean} timezone_configuration_required
 * @property {string|null} active_system_timezone
 * @property {string|null} pending_system_timezone
 * @property {boolean} timezone_restart_required
 * @property {number} timezone_config_version
 * @property {number} active_timezone_config_version
 * @property {string|null} adoption_source
 * @property {string|null} initial_setup_completed_at
 * @property {string|null} timezone_change_requested_at
 * @property {string|null} timezone_change_requested_by
 * @property {string|null} timezone_promoted_at
 * @property {string|null} timezone_updated_at
 * @property {string|null} timezone_updated_by
 */

export class SystemTimeError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   * @param {number} [status=400]
   */
  constructor(code, message, status = 400) {
    super(message);
    this.name = 'SystemTimeError';
    this.code = code;
    this.status = status;
  }
}

/** Validate IANA timezone; throws SystemTimeError when invalid/empty. */
export function assertValidIanaTimezone(value) {
  const tz = String(value || '').trim();
  if (!tz) {
    throw new SystemTimeError('INVALID_TIMEZONE', 'System timezone is required');
  }
  if (/^(UTC|GMT)?[+-]\d{1,2}(:?\d{2})?$/i.test(tz) && tz.toUpperCase() !== 'UTC') {
    throw new SystemTimeError(
      'INVALID_TIMEZONE',
      'Fixed UTC/GMT offsets are not allowed; use an IANA timezone (e.g. Europe/Istanbul)'
    );
  }
  if (!getSupportedIanaTimezoneSet().has(tz)) {
    throw new SystemTimeError('INVALID_TIMEZONE', `Invalid IANA timezone: ${tz}`);
  }
  return tz;
}

export function isValidIanaTimezone(value) {
  try {
    assertValidIanaTimezone(value);
    return true;
  } catch {
    return false;
  }
}

export function clearSystemTimeCache() {
  cache = { loadedAt: 0, config: null };
}

function mapRow(row) {
  const active = row.active_system_timezone ?? row.system_timezone ?? null;
  return {
    initial_setup_completed: Boolean(row.initial_setup_completed),
    timezone_configuration_required: Boolean(row.timezone_configuration_required),
    active_system_timezone: active ? String(active) : null,
    // Back-compat alias used by older callers/tests
    system_timezone: active ? String(active) : null,
    pending_system_timezone: row.pending_system_timezone
      ? String(row.pending_system_timezone)
      : null,
    timezone_restart_required: Boolean(row.timezone_restart_required),
    timezone_config_version: Number(row.timezone_config_version || 0),
    active_timezone_config_version: Number(row.active_timezone_config_version || 0),
    adoption_source: row.adoption_source ? String(row.adoption_source) : null,
    initial_setup_completed_at: row.initial_setup_completed_at || null,
    timezone_change_requested_at: row.timezone_change_requested_at || null,
    timezone_change_requested_by: row.timezone_change_requested_by || null,
    timezone_promoted_at: row.timezone_promoted_at || null,
    timezone_updated_at: row.timezone_updated_at || null,
    timezone_updated_by: row.timezone_updated_by || null
  };
}

const emptyConfig = () => ({
  initial_setup_completed: false,
  timezone_configuration_required: false,
  active_system_timezone: null,
  system_timezone: null,
  pending_system_timezone: null,
  timezone_restart_required: false,
  timezone_config_version: 0,
  active_timezone_config_version: 0,
  adoption_source: null,
  initial_setup_completed_at: null,
  timezone_change_requested_at: null,
  timezone_change_requested_by: null,
  timezone_promoted_at: null,
  timezone_updated_at: null,
  timezone_updated_by: null
});

/**
 * Bootstrap timezone candidates (non-empty env only — no silent defaults).
 * Priority: SYSTEM_TIMEZONE → INTEGRATION_SCHEDULE_TIMEZONE → TZ (opt-in).
 */
export function readBootstrapTimezoneCandidate(env = process.env) {
  const candidates = [
    { source: 'SYSTEM_TIMEZONE', value: env.SYSTEM_TIMEZONE },
    { source: 'INTEGRATION_SCHEDULE_TIMEZONE', value: env.INTEGRATION_SCHEDULE_TIMEZONE }
  ];
  if (env.TALONHOUND_USE_TZ_AS_SYSTEM === '1' || env.APP_TIMEZONE_FROM_TZ === '1') {
    candidates.push({ source: 'TZ', value: env.TZ });
  }
  for (const c of candidates) {
    const raw = String(c.value || '').trim();
    if (!raw) continue;
    if (!isValidIanaTimezone(raw)) {
      return { timezone: null, source: c.source, invalid: raw };
    }
    return { timezone: raw, source: c.source, invalid: null };
  }
  return { timezone: null, source: null, invalid: null };
}

/**
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {{ force?: boolean }} [opts]
 */
export async function loadSystemTimeConfig(db, opts = {}) {
  const force = Boolean(opts.force);
  const now = Date.now();
  if (!force && cache.config && now - cache.loadedAt < CACHE_TTL_MS) {
    return cache.config;
  }

  try {
    const { rows } = await db.query(
      `SELECT initial_setup_completed, timezone_configuration_required,
              active_system_timezone, pending_system_timezone, timezone_restart_required,
              timezone_config_version, active_timezone_config_version, adoption_source,
              initial_setup_completed_at, timezone_change_requested_at, timezone_change_requested_by,
              timezone_promoted_at, timezone_updated_at, timezone_updated_by
         FROM system_settings
        WHERE id = $1`,
      [SETTINGS_ID]
    );

    if (!rows.length) {
      const empty = emptyConfig();
      cache = { loadedAt: now, config: empty };
      return empty;
    }

    const config = mapRow(rows[0]);
    cache = { loadedAt: now, config };
    return config;
  } catch (err) {
    // Older draft schema with system_timezone only
    if (err?.code === '42703') {
      const { rows } = await db.query(
        `SELECT initial_setup_completed, system_timezone AS active_system_timezone,
                pending_system_timezone, timezone_restart_required,
                initial_setup_completed_at, timezone_updated_at, timezone_updated_by
           FROM system_settings WHERE id = $1`,
        [SETTINGS_ID]
      );
      const config = rows.length ? mapRow(rows[0]) : emptyConfig();
      cache = { loadedAt: now, config };
      return config;
    }
    throw err;
  }
}

/** Cached active timezone when setup is complete; null otherwise. */
export function getCachedSystemTimezone() {
  const cfg = cache.config;
  if (!cfg?.initial_setup_completed || cfg.timezone_configuration_required) return null;
  if (!cfg.active_system_timezone) return null;
  return cfg.active_system_timezone;
}

export function isTimezoneRuntimeReady(config) {
  return Boolean(
    config?.initial_setup_completed
    && !config.timezone_configuration_required
    && config.active_system_timezone
    && isValidIanaTimezone(config.active_system_timezone)
  );
}

/**
 * Require a ready active system timezone.
 * @param {import('pg').Pool|import('pg').PoolClient} db
 */
export async function requireSystemTimezone(db) {
  const cfg = await loadSystemTimeConfig(db, { force: true });
  if (cfg.timezone_configuration_required) {
    throw new SystemTimeError(
      'TIMEZONE_CONFIGURATION_REQUIRED',
      'An existing installation requires an administrator to configure the system timezone',
      428
    );
  }
  if (!cfg.initial_setup_completed || !cfg.active_system_timezone) {
    throw new SystemTimeError(
      'INITIAL_SETUP_REQUIRED',
      'Initial setup is required before the application can run',
      428
    );
  }
  return assertValidIanaTimezone(cfg.active_system_timezone);
}

async function detectExistingInstallation(db) {
  const users = await db.query('SELECT 1 FROM users LIMIT 1').catch(() => ({ rows: [] }));
  if (users.rows.length) return true;
  const iocs = await db.query('SELECT 1 FROM ioc_items LIMIT 1').catch(() => ({ rows: [] }));
  return iocs.rows.length > 0;
}

/**
 * Idempotent bootstrap adoption for existing installs. Never silently chooses UTC.
 * Uses a Postgres advisory lock to avoid multi-instance races.
 * @param {import('pg').Pool} pool
 * @param {{ env?: NodeJS.ProcessEnv, logger?: { info: Function, warn: Function } }} [opts]
 */
export async function adoptSystemTimezoneFromBootstrap(pool, opts = {}) {
  const env = opts.env || process.env;
  const log = opts.logger || console;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock($1)', [ADOPTION_LOCK_KEY]);

    const table = await client.query(`SELECT to_regclass('public.system_settings') AS reg`);
    if (!table.rows[0]?.reg) {
      await client.query('COMMIT');
      return { status: 'skipped', reason: 'system_settings_missing' };
    }

    // Ensure singleton row
    await client.query(
      `INSERT INTO system_settings (id) VALUES ($1) ON CONFLICT (id) DO NOTHING`,
      [SETTINGS_ID]
    );

    const cfg = await loadSystemTimeConfig(client, { force: true });

    // User/DB-selected timezone must never be overwritten by env.
    if (isTimezoneRuntimeReady(cfg)) {
      await client.query('COMMIT');
      clearSystemTimeCache();
      return { status: 'unchanged', config: cfg };
    }

    const existing = await detectExistingInstallation(client);
    const bootstrap = readBootstrapTimezoneCandidate(env);

    if (!existing) {
      // Fresh install: leave setup incomplete.
      await client.query(
        `UPDATE system_settings
            SET timezone_configuration_required = FALSE,
                updated_at = NOW()
          WHERE id = $1
            AND initial_setup_completed = FALSE`,
        [SETTINGS_ID]
      );
      await client.query('COMMIT');
      clearSystemTimeCache();
      return { status: 'fresh_setup_required', config: await loadSystemTimeConfig(client, { force: true }) };
    }

    // Existing install
    if (bootstrap.invalid) {
      await client.query(
        `UPDATE system_settings
            SET timezone_configuration_required = TRUE,
                initial_setup_completed = FALSE,
                active_system_timezone = NULL,
                pending_system_timezone = NULL,
                timezone_restart_required = FALSE,
                adoption_source = NULL,
                updated_at = NOW()
          WHERE id = $1
            AND initial_setup_completed = FALSE`,
        [SETTINGS_ID]
      );
      await client.query('COMMIT');
      clearSystemTimeCache();
      log.warn?.(
        `[system-time] bootstrap timezone invalid source=${bootstrap.source} value=${bootstrap.invalid} — configuration required`
      );
      return {
        status: 'configuration_required',
        reason: 'invalid_bootstrap',
        invalid: bootstrap.invalid,
        config: await loadSystemTimeConfig(pool, { force: true })
      };
    }

    if (bootstrap.timezone) {
      await client.query(
        `UPDATE system_settings
            SET active_system_timezone = $2,
                pending_system_timezone = NULL,
                initial_setup_completed = TRUE,
                timezone_configuration_required = FALSE,
                timezone_restart_required = FALSE,
                adoption_source = $3,
                initial_setup_completed_at = COALESCE(initial_setup_completed_at, NOW()),
                timezone_updated_at = NOW(),
                timezone_updated_by = 'bootstrap',
                timezone_config_version = GREATEST(timezone_config_version, 1),
                active_timezone_config_version = GREATEST(active_timezone_config_version, 1),
                updated_at = NOW()
          WHERE id = $1
            AND initial_setup_completed = FALSE`,
        [SETTINGS_ID, bootstrap.timezone, `bootstrap:${bootstrap.source}`]
      );
      await client.query('COMMIT');
      clearSystemTimeCache();
      const next = await loadSystemTimeConfig(pool, { force: true });
      log.info?.(
        `[system-time] bootstrap adoption timezone=${bootstrap.timezone} source=${bootstrap.source}`
      );
      return { status: 'adopted', timezone: bootstrap.timezone, source: bootstrap.source, config: next };
    }

    await client.query(
      `UPDATE system_settings
          SET timezone_configuration_required = TRUE,
              initial_setup_completed = FALSE,
              active_system_timezone = NULL,
              pending_system_timezone = NULL,
              timezone_restart_required = FALSE,
              adoption_source = NULL,
              updated_at = NOW()
        WHERE id = $1
          AND initial_setup_completed = FALSE`,
      [SETTINGS_ID]
    );
    await client.query('COMMIT');
    clearSystemTimeCache();
    log.warn?.('[system-time] existing install has no bootstrap timezone — configuration required (no silent UTC)');
    return {
      status: 'configuration_required',
      reason: 'missing_bootstrap',
      config: await loadSystemTimeConfig(pool, { force: true })
    };
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch { /* ignore */ }
    throw err;
  } finally {
    client.release();
  }
}

/**
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {string} timezone
 * @param {{ completedBy?: string|null }} [opts]
 */
export async function completeInitialSetup(db, timezone, opts = {}) {
  const tz = assertValidIanaTimezone(timezone);
  const cfg = await loadSystemTimeConfig(db, { force: true });
  if (cfg.initial_setup_completed && isTimezoneRuntimeReady(cfg)) {
    throw new SystemTimeError(
      'SETUP_ALREADY_COMPLETED',
      'Initial setup has already been completed',
      409
    );
  }

  await db.query(
    `UPDATE system_settings
        SET active_system_timezone = $2,
            pending_system_timezone = NULL,
            initial_setup_completed = TRUE,
            timezone_configuration_required = FALSE,
            initial_setup_completed_at = NOW(),
            timezone_restart_required = FALSE,
            adoption_source = COALESCE($3, 'initial_setup'),
            timezone_updated_at = NOW(),
            timezone_updated_by = $4,
            timezone_config_version = GREATEST(timezone_config_version, 1),
            active_timezone_config_version = GREATEST(active_timezone_config_version, 1),
            updated_at = NOW()
      WHERE id = $1`,
    [SETTINGS_ID, tz, opts.adoptionSource || 'initial_setup', opts.completedBy || null]
  );
  clearSystemTimeCache();
  return loadSystemTimeConfig(db, { force: true });
}

/**
 * Admin timezone change: pending only; active stays until promotion after restart.
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {string} timezone
 * @param {{ updatedBy: string, confirm?: boolean }} opts
 */
export async function requestSystemTimezoneChange(db, timezone, opts) {
  if (!opts?.confirm) {
    throw new SystemTimeError(
      'CONFIRMATION_REQUIRED',
      'Timezone change requires explicit confirmation',
      400
    );
  }
  const tz = assertValidIanaTimezone(timezone);
  const cfg = await loadSystemTimeConfig(db, { force: true });
  if (!isTimezoneRuntimeReady(cfg)) {
    throw new SystemTimeError(
      cfg.timezone_configuration_required ? 'TIMEZONE_CONFIGURATION_REQUIRED' : 'INITIAL_SETUP_REQUIRED',
      'Complete timezone configuration before changing the system timezone',
      428
    );
  }
  if (cfg.active_system_timezone === tz && !cfg.timezone_restart_required && !cfg.pending_system_timezone) {
    return { ...cfg, noop: true };
  }
  // Same as current pending → idempotent no-op
  if (cfg.pending_system_timezone === tz && cfg.timezone_restart_required) {
    return { ...cfg, noop: true };
  }

  await db.query(
    `UPDATE system_settings
        SET pending_system_timezone = $2,
            timezone_restart_required = TRUE,
            timezone_config_version = timezone_config_version + 1,
            timezone_change_requested_at = NOW(),
            timezone_change_requested_by = $3,
            timezone_updated_at = NOW(),
            timezone_updated_by = $3,
            updated_at = NOW()
      WHERE id = $1`,
    [SETTINGS_ID, tz, opts.updatedBy || null]
  );
  clearSystemTimeCache();
  return loadSystemTimeConfig(db, { force: true });
}

/**
 * Promote pending → active after successful post-restart health.
 * Atomic and idempotent.
 * @param {import('pg').Pool|import('pg').PoolClient} db
 */
export async function promotePendingSystemTimezone(db) {
  const cfg = await loadSystemTimeConfig(db, { force: true });
  if (!cfg.timezone_restart_required || !cfg.pending_system_timezone) {
    return { status: 'noop', config: cfg };
  }
  const pending = assertValidIanaTimezone(cfg.pending_system_timezone);

  const { rows } = await db.query(
    `UPDATE system_settings
        SET active_system_timezone = pending_system_timezone,
            pending_system_timezone = NULL,
            timezone_restart_required = FALSE,
            active_timezone_config_version = timezone_config_version,
            timezone_promoted_at = NOW(),
            timezone_updated_at = NOW(),
            updated_at = NOW()
      WHERE id = $1
        AND timezone_restart_required = TRUE
        AND pending_system_timezone = $2
      RETURNING *`,
    [SETTINGS_ID, pending]
  );
  clearSystemTimeCache();
  if (!rows.length) {
    return { status: 'noop', config: await loadSystemTimeConfig(db, { force: true }) };
  }
  return { status: 'promoted', timezone: pending, config: mapRow(rows[0]) };
}

/** @deprecated Prefer promotePendingSystemTimezone */
export async function clearTimezoneRestartRequired(db) {
  return promotePendingSystemTimezone(db);
}

export function getTimezoneOffsetMs(date, timeZone) {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23'
  }).formatToParts(date);
  const pick = (type) => Number(parts.find((p) => p.type === type)?.value || 0);
  const asUtc = Date.UTC(pick('year'), pick('month') - 1, pick('day'), pick('hour'), pick('minute'), pick('second'));
  return asUtc - date.getTime();
}

export function formatTimestampWithOffset(value, timeZone) {
  if (value == null || value === '') return null;
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return null;
  const tz = assertValidIanaTimezone(timeZone);

  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: tz,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23'
  }).formatToParts(d);
  const pick = (type) => parts.find((p) => p.type === type)?.value || '00';
  const y = pick('year');
  const mo = pick('month');
  const day = pick('day');
  const h = pick('hour');
  const mi = pick('minute');
  const s = pick('second');

  const offsetMinutes = Math.round(getTimezoneOffsetMs(d, tz) / 60000);
  const sign = offsetMinutes >= 0 ? '+' : '-';
  const abs = Math.abs(offsetMinutes);
  const oh = String(Math.floor(abs / 60)).padStart(2, '0');
  const om = String(abs % 60).padStart(2, '0');
  return `${y}-${mo}-${day}T${h}:${mi}:${s}${sign}${oh}:${om}`;
}

export function currentTimeParts(timeZone, now = new Date()) {
  const tz = assertValidIanaTimezone(timeZone);
  return {
    timezone: tz,
    iso_with_offset: formatTimestampWithOffset(now, tz),
    utc_iso: now.toISOString()
  };
}

export function convertPayloadTimestamps(payload, timeZone) {
  if (!timeZone) return payload;
  const walk = (value) => {
    if (value instanceof Date) {
      return formatTimestampWithOffset(value, timeZone) ?? value.toISOString();
    }
    if (typeof value === 'string') {
      if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(value)) {
        return formatTimestampWithOffset(value, timeZone) || value;
      }
      return value;
    }
    if (Array.isArray(value)) return value.map(walk);
    if (value && typeof value === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(value)) out[k] = walk(v);
      return out;
    }
    return value;
  };
  return walk(payload);
}

export async function setClientSessionTimezone(client, timeZone) {
  const tz = assertValidIanaTimezone(timeZone);
  await client.query(`SET TIME ZONE '${tz.replace(/'/g, "''")}'`);
  return tz;
}

export function buildPgTimezoneOption(timeZone) {
  const tz = assertValidIanaTimezone(timeZone);
  return `-c TimeZone=${tz}`;
}

export async function readPostgresSessionTimezone(db) {
  const { rows } = await db.query('SHOW timezone');
  return String(rows[0]?.TimeZone || rows[0]?.timezone || '').trim();
}

/**
 * @param {import('pg').Pool} pool
 */
export async function buildTimeHealth(pool) {
  let config;
  try {
    config = await loadSystemTimeConfig(pool, { force: true });
  } catch (err) {
    return {
      status: 'unhealthy',
      setup_status: 'error',
      error: err?.message || 'failed to load system time config',
      active_system_timezone: null,
      pending_system_timezone: null,
      system_timezone: null,
      current_utc_time: new Date().toISOString(),
      current_system_time: null,
      backend_timezone: null,
      postgres_session_timezone: null,
      scheduler_timezone: null,
      restart_required: false,
      configuration_consistency: 'unknown'
    };
  }

  const runtimeReady = isTimezoneRuntimeReady(config);
  let activeTz = null;
  let activeValid = false;
  if (config.active_system_timezone) {
    try {
      activeTz = assertValidIanaTimezone(config.active_system_timezone);
      activeValid = true;
    } catch {
      activeTz = config.active_system_timezone;
    }
  }

  let pgTz = null;
  try {
    pgTz = await readPostgresSessionTimezone(pool);
  } catch {
    pgTz = null;
  }

  const now = new Date();
  const currentSystem = activeValid ? formatTimestampWithOffset(now, activeTz) : null;
  const processEnvTz = process.env.SYSTEM_TIMEZONE || null;
  const pgMatches = Boolean(pgTz && activeTz && String(pgTz).toLowerCase() === String(activeTz).toLowerCase());
  const consistent = runtimeReady && activeValid && pgMatches && !config.timezone_restart_required;

  let status = 'ok';
  let setupStatus = 'completed';
  if (config.timezone_configuration_required) {
    status = 'unhealthy';
    setupStatus = 'configuration_required';
  } else if (!runtimeReady || !activeValid) {
    status = 'unhealthy';
    setupStatus = 'required';
  } else if (config.timezone_restart_required || !consistent) {
    status = 'degraded';
  }

  return {
    status,
    setup_status: setupStatus,
    active_system_timezone: activeTz,
    pending_system_timezone: config.pending_system_timezone,
    system_timezone: activeTz,
    current_utc_time: now.toISOString(),
    current_system_time: currentSystem,
    backend_timezone: activeTz || processEnvTz,
    postgres_session_timezone: pgTz,
    scheduler_timezone: activeTz,
    restart_required: Boolean(config.timezone_restart_required),
    timezone_config_version: config.timezone_config_version,
    active_timezone_config_version: config.active_timezone_config_version,
    configuration_consistency: consistent ? 'consistent' : 'inconsistent',
    process_env_tz: processEnvTz,
    mismatched_components: [
      !pgMatches ? 'postgres_session_timezone' : null,
      config.timezone_restart_required ? 'pending_restart' : null
    ].filter(Boolean)
  };
}

/**
 * @param {import('pg').Pool} pool
 * @param {{ logPrefix?: string, pollMs?: number, maxWaitMs?: number|null }} [opts]
 */
export async function waitUntilSetupComplete(pool, opts = {}) {
  const logPrefix = opts.logPrefix || '[system-time]';
  const pollMs = Math.max(Number(opts.pollMs) || 5000, 1000);
  const maxWaitMs = opts.maxWaitMs == null ? null : Number(opts.maxWaitMs);
  const started = Date.now();

  for (;;) {
    try {
      const table = await pool.query(`SELECT to_regclass('public.system_settings') AS reg`);
      if (!table.rows[0]?.reg) {
        console.warn(`${logPrefix} system_settings missing — waiting for migrations/setup`);
      } else {
        const tz = await requireSystemTimezone(pool);
        console.log(`${logPrefix} system timezone ready tz=${tz}`);
        return tz;
      }
    } catch (err) {
      if (err?.code === 'INITIAL_SETUP_REQUIRED' || err?.code === 'TIMEZONE_CONFIGURATION_REQUIRED') {
        console.warn(`${logPrefix} ${err.code} — workers idle until timezone is ready`);
      } else {
        console.warn(`${logPrefix} waiting for system timezone:`, err?.message || err);
      }
    }

    if (maxWaitMs != null && Date.now() - started >= maxWaitMs) {
      throw new SystemTimeError(
        'SETUP_WAIT_TIMEOUT',
        'Timed out waiting for initial setup / system timezone',
        503
      );
    }
    await new Promise((r) => setTimeout(r, pollMs));
  }
}

/**
 * Schedule timezone: always active (never pending). Throws when runtime not ready.
 * @param {SystemTimeConfig|null} config
 */
export function resolveScheduleTimezone(config) {
  if (config && isTimezoneRuntimeReady(config)) {
    return config.active_system_timezone;
  }
  if (config?.initial_setup_completed && config.active_system_timezone
    && !isValidIanaTimezone(config.active_system_timezone)) {
    throw new SystemTimeError(
      'INVALID_SYSTEM_TIMEZONE',
      'Configured system timezone is missing or invalid',
      500
    );
  }
  const envTz = String(process.env.SYSTEM_TIMEZONE || process.env.INTEGRATION_SCHEDULE_TIMEZONE || '').trim();
  if (envTz && isValidIanaTimezone(envTz)) return envTz;
  // Pre-setup schedule helper fallback only — workers must not run until ready.
  return 'UTC';
}
