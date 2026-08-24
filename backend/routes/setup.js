import {
  loadSystemTimeConfig,
  completeInitialSetup,
  requestSystemTimezoneChange,
  currentTimeParts,
  assertValidIanaTimezone,
  getSupportedIanaTimezones,
  SystemTimeError,
  clearSystemTimeCache,
  isTimezoneRuntimeReady
} from '../lib/systemTime.js';
import {
  readSetupState,
  checkSetupCode,
  completeFirstRunSetup,
  FirstRunSetupError
} from '../lib/firstRunSetup.js';
import { isCallerSystemAdmin } from './auditRetention.js';

/**
 * Minimal in-memory, per-client rate limiter for unauthenticated setup-code attempts.
 * Greenfield first-run is single-instance and short-lived, so a process-local limiter is
 * sufficient defense-in-depth on top of the ~80-bit code entropy. Never logs the code.
 */
function createSetupRateLimiter({ windowMs = 5 * 60 * 1000, max = 10 } = {}) {
  const buckets = new Map();
  return function consume(key) {
    const now = Date.now();
    const k = String(key || 'unknown');
    const entry = buckets.get(k);
    if (!entry || now >= entry.resetAt) {
      buckets.set(k, { count: 1, resetAt: now + windowMs });
      if (buckets.size > 5000) {
        for (const [bk, bv] of buckets) if (now >= bv.resetAt) buckets.delete(bk);
      }
      return { allowed: true, retryAfterSec: 0 };
    }
    if (entry.count >= max) {
      return { allowed: false, retryAfterSec: Math.max(1, Math.ceil((entry.resetAt - now) / 1000)) };
    }
    entry.count += 1;
    return { allowed: true, retryAfterSec: 0 };
  };
}

function clientKey(req) {
  return (
    req.ip
    || req.headers?.['x-forwarded-for']
    || req.socket?.remoteAddress
    || 'unknown'
  );
}

function sendFirstRunError(res, err) {
  if (err instanceof FirstRunSetupError) {
    return res.status(err.status || 400).json({ code: err.code, message: err.message });
  }
  return null;
}

function sendSystemTimeError(res, err) {
  if (err instanceof SystemTimeError) {
    return res.status(err.status || 400).json({
      code: err.code,
      message: err.message
    });
  }
  return res.status(500).json({ message: err?.message || 'System time error' });
}

function publicTimezonePayload(config, now = new Date()) {
  const active = config.active_system_timezone;
  let currentSystemTime = null;
  if (active) {
    try {
      currentSystemTime = currentTimeParts(active, now).iso_with_offset;
    } catch {
      currentSystemTime = null;
    }
  }
  return {
    initial_setup_completed: Boolean(config.initial_setup_completed),
    timezone_configuration_required: Boolean(config.timezone_configuration_required),
    active_system_timezone: active,
    system_timezone: active,
    pending_system_timezone: config.pending_system_timezone,
    timezone_restart_required: Boolean(config.timezone_restart_required),
    timezone_config_version: config.timezone_config_version,
    active_timezone_config_version: config.active_timezone_config_version,
    adoption_source: config.adoption_source,
    current_utc_time: now.toISOString(),
    current_system_time: currentSystemTime,
    status: config.timezone_restart_required
      ? 'restart_required'
      : config.timezone_configuration_required
        ? 'configuration_required'
        : isTimezoneRuntimeReady(config)
          ? 'healthy'
          : 'setup_required'
  };
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {{ audit?: { auditSuccess: Function }, onTimezoneChanged?: Function }} [deps]
 */
export function registerSetupRoutes(app, pool, deps = {}) {
  const setupRateLimiter = deps.setupRateLimiter || createSetupRateLimiter();

  app.get('/api/setup/status', async (_req, res) => {
    try {
      const config = await loadSystemTimeConfig(pool, { force: true });
      let setupState = null;
      try {
        setupState = await readSetupState(pool);
      } catch {
        setupState = null;
      }
      return res.json({
        ...publicTimezonePayload(config),
        setup_completed: setupState ? setupState.setup_completed : Boolean(config.initial_setup_completed),
        admin_setup_required: setupState ? setupState.admin_setup_required : false,
        setup_code_required: setupState ? setupState.setup_code_required : false
      });
    } catch (err) {
      return sendSystemTimeError(res, err);
    }
  });

  // First-run only: pre-check a setup code without consuming it (UX for step 1).
  app.post('/api/setup/verify-code', async (req, res) => {
    const limit = setupRateLimiter(clientKey(req));
    if (!limit.allowed) {
      res.set('Retry-After', String(limit.retryAfterSec));
      return res.status(429).json({ code: 'TOO_MANY_ATTEMPTS', message: 'Too many attempts. Try again later.' });
    }
    try {
      const result = await checkSetupCode(pool, req.body?.code);
      if (!result.valid) {
        return res.status(401).json({ code: 'INVALID_SETUP_CODE', message: 'Invalid setup code' });
      }
      return res.json({ valid: true, setup_code_required: result.required });
    } catch (err) {
      const handled = sendFirstRunError(res, err);
      if (handled) return handled;
      return sendSystemTimeError(res, err);
    }
  });

  app.get('/api/system/timezones', (_req, res) => {
    try {
      return res.json({ timezones: getSupportedIanaTimezones() });
    } catch (err) {
      return sendSystemTimeError(res, err);
    }
  });

  app.get('/api/setup/preview', async (req, res) => {
    try {
      const tz = assertValidIanaTimezone(req.query.timezone);
      return res.json(currentTimeParts(tz));
    } catch (err) {
      return sendSystemTimeError(res, err);
    }
  });

  app.post('/api/setup/complete', async (req, res) => {
    try {
      const setupState = await readSetupState(pool);

      // Greenfield first-run: create the System Administrator, select the timezone, and
      // complete setup atomically. Requires the one-time setup code when configured.
      if (setupState.admin_setup_required) {
        const limit = setupRateLimiter(clientKey(req));
        if (!limit.allowed) {
          res.set('Retry-After', String(limit.retryAfterSec));
          return res.status(429).json({ code: 'TOO_MANY_ATTEMPTS', message: 'Too many attempts. Try again later.' });
        }
        try {
          const result = await completeFirstRunSetup(pool, {
            code: req.body?.code ?? req.body?.setup_code,
            username: req.body?.username,
            password: req.body?.password,
            confirmPassword: req.body?.confirm_password ?? req.body?.confirmPassword,
            timezone: req.body?.timezone
          });

          if (deps.audit?.auditSuccess) {
            const actor = {
              actorUsername: result.username,
              actorEmail: result.username,
              actorRole: 'admin'
            };
            // Never audit the setup code, password, or confirmation.
            await deps.audit.auditSuccess({
              action: 'system.setup_completed',
              entityType: 'settings',
              entityId: '1',
              entityDisplay: 'First-run setup',
              severity: 'warning',
              ...actor,
              metadata: { timezone: result.timezone, administrator: result.username, source: 'first_run_setup' }
            }).catch(() => {});
            await deps.audit.auditSuccess({
              action: 'user.created',
              entityType: 'user',
              entityId: result.username,
              entityDisplay: result.username,
              severity: 'warning',
              ...actor,
              metadata: { role: 'admin', is_system_admin: true, source: 'first_run_setup' }
            }).catch(() => {});
            await deps.audit.auditSuccess({
              action: 'system.timezone_configured',
              entityType: 'settings',
              entityId: '1',
              entityDisplay: 'System Timezone',
              severity: 'info',
              ...actor,
              metadata: { timezone: result.timezone, source: 'first_run_setup' }
            }).catch(() => {});
          }

          if (typeof deps.onTimezoneChanged === 'function') {
            await deps.onTimezoneChanged(result.timezone, {
              reason: 'initial_setup',
              active: result.timezone
            });
          }

          const config = await loadSystemTimeConfig(pool, { force: true });
          return res.status(201).json({
            ...publicTimezonePayload(config),
            setup_completed: true,
            administrator: result.username,
            message: 'Setup completed'
          });
        } catch (err) {
          const handled = sendFirstRunError(res, err);
          if (handled) return handled;
          return sendSystemTimeError(res, err);
        }
      }

      // Existing installation path: timezone-only configuration. Anonymous complete is not
      // allowed here — an administrator must be authenticated (AUTH-05).
      const cfgBefore = await loadSystemTimeConfig(pool, { force: true });
      if (cfgBefore.timezone_configuration_required) {
        const role = String(req.user?.role || '').trim().toLowerCase();
        const via = String(req.authVia || '');
        if (via === 'ingest' || !req.user || role !== 'admin') {
          return res.status(401).json({
            code: 'AUTH_REQUIRED',
            message: 'Administrator authentication is required to complete timezone configuration on an existing installation'
          });
        }
      }

      const timezone = req.body?.timezone;
      const config = await completeInitialSetup(pool, timezone, {
        completedBy: req.user?.email || null,
        adoptionSource: cfgBefore.timezone_configuration_required ? 'admin_timezone_configuration' : 'initial_setup'
      });
      if (typeof deps.onTimezoneChanged === 'function') {
        await deps.onTimezoneChanged(config.active_system_timezone, {
          reason: cfgBefore.timezone_configuration_required ? 'timezone_configuration' : 'initial_setup',
          active: config.active_system_timezone
        });
      }
      return res.status(201).json({
        ...publicTimezonePayload(config),
        message: 'Initial setup completed'
      });
    } catch (err) {
      return sendSystemTimeError(res, err);
    }
  });

  app.get('/api/system/timezone', async (req, res) => {
    try {
      const config = await loadSystemTimeConfig(pool, { force: true });
      const canEdit = await isCallerSystemAdmin(pool, req);
      if (config.timezone_configuration_required) {
        return res.status(428).json({
          code: 'TIMEZONE_CONFIGURATION_REQUIRED',
          message: 'An existing installation requires an administrator to configure the system timezone',
          ...publicTimezonePayload(config),
          can_edit: canEdit
        });
      }
      if (!isTimezoneRuntimeReady(config)) {
        return res.status(428).json({
          code: 'INITIAL_SETUP_REQUIRED',
          message: 'Initial setup is required before the application can run',
          ...publicTimezonePayload(config),
          can_edit: canEdit
        });
      }
      return res.json({
        ...publicTimezonePayload(config),
        can_edit: canEdit,
        configured_during_initial_setup: config.adoption_source === 'initial_setup'
      });
    } catch (err) {
      return sendSystemTimeError(res, err);
    }
  });

  app.put('/api/system/timezone', async (req, res) => {
    try {
      // Mutation is System Administrator only (users.is_system_admin), matching
      // Audit Log Retention. Role=admin alone is not sufficient.
      const systemAdmin = await isCallerSystemAdmin(pool, req);
      if (!systemAdmin) {
        return res.status(403).json({
          code: 'FORBIDDEN',
          message: 'Only the System Administrator can change the system timezone'
        });
      }
      const timezone = req.body?.timezone;
      const confirm = Boolean(req.body?.confirm);
      const confirmationText = String(req.body?.confirmation_text || '').trim();
      if (!confirm || confirmationText !== 'CHANGE SYSTEM TIMEZONE') {
        return res.status(400).json({
          code: 'CONFIRMATION_REQUIRED',
          message: 'confirmation_text must be exactly CHANGE SYSTEM TIMEZONE'
        });
      }

      const before = await loadSystemTimeConfig(pool, { force: true });
      const config = await requestSystemTimezoneChange(pool, timezone, {
        confirm,
        updatedBy: req.user?.email || null
      });

      if (deps.audit?.auditSuccess) {
        await deps.audit.auditSuccess({
          action: 'system.timezone_change_requested',
          entityType: 'system_settings',
          entityId: '1',
          entityDisplay: 'System Timezone',
          actorEmail: req.user?.email || null,
          metadata: {
            previous_active_timezone: before.active_system_timezone,
            pending_timezone: config.pending_system_timezone,
            restart_required: true,
            requested_at: config.timezone_change_requested_at,
            noop: Boolean(config.noop)
          }
        });
      }

      // Do NOT apply pending timezone to running process — active stays live.
      if (typeof deps.onTimezoneChanged === 'function' && !config.noop) {
        await deps.onTimezoneChanged(before.active_system_timezone, {
          reason: 'admin_change_pending',
          restartRequired: true,
          pending: config.pending_system_timezone,
          active: before.active_system_timezone
        });
      }

      return res.json({
        ...publicTimezonePayload(config),
        message: 'Timezone change is pending restart',
        restart_instructions: {
          docker_compose: 'docker compose up -d --force-recreate backend integration-scheduler integration-worker ioc-expiration-worker ioc-search-export-worker backup-worker frontend',
          kubernetes: 'kubectl rollout restart deploy/backend deploy/integration-scheduler deploy/integration-worker deploy/ioc-expiration-worker deploy/ioc-search-export-worker deploy/backup-worker deploy/frontend'
        }
      });
    } catch (err) {
      return sendSystemTimeError(res, err);
    }
  });
}

/**
 * Express middleware: block application APIs until timezone runtime is ready.
 */
export function createSetupGate(pool) {
  const allowExact = new Set([
    '/healthz',
    '/readyz',
    '/health',
    '/api/setup/status',
    '/api/setup/preview',
    '/api/setup/complete',
    '/api/system/timezones',
    '/api/auth/login',
    '/api/auth/logout',
    '/api/auth/me',
    '/api/auth/change-password'
  ]);

  return async function setupGate(req, res, next) {
    if (req.method === 'OPTIONS') return next();
    if (allowExact.has(req.path)) return next();
    if (req.path.startsWith('/api/setup/')) return next();
    if (req.path === '/api/health' || req.path === '/api/healthz' || req.path === '/api/readyz') {
      return next();
    }
    // Allow reading timezone status + completing configuration while gated.
    if (req.path === '/api/system/timezone' && (req.method === 'GET' || req.method === 'PUT')) {
      return next();
    }

    try {
      let config = await loadSystemTimeConfig(pool);
      if (!isTimezoneRuntimeReady(config)) {
        config = await loadSystemTimeConfig(pool, { force: true });
      }
      if (isTimezoneRuntimeReady(config)) {
        return next();
      }
      if (config.timezone_configuration_required) {
        return res.status(428).json({
          code: 'TIMEZONE_CONFIGURATION_REQUIRED',
          message: 'An existing installation requires an administrator to configure the system timezone'
        });
      }
      return res.status(428).json({
        code: 'INITIAL_SETUP_REQUIRED',
        message: 'Initial setup is required before the application can run'
      });
    } catch (err) {
      if (!req.path.startsWith('/api')) return next();
      return res.status(428).json({
        code: 'INITIAL_SETUP_REQUIRED',
        message: err?.message || 'Initial setup is required'
      });
    }
  };
}

export { clearSystemTimeCache };
