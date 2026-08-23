import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { createSetupGate } from '../routes/setup.js';
import { SystemTimeError, clearSystemTimeCache } from '../lib/systemTime.js';

function mockPool(config) {
  return {
    async query(sql) {
      if (String(sql).includes('system_settings')) {
        return {
          rows: [
            {
              initial_setup_completed: config.initial_setup_completed,
              timezone_configuration_required: config.timezone_configuration_required || false,
              active_system_timezone: config.active_system_timezone || config.system_timezone || null,
              pending_system_timezone: config.pending_system_timezone || null,
              timezone_restart_required: Boolean(config.timezone_restart_required),
              timezone_config_version: 1,
              active_timezone_config_version: 1,
              adoption_source: null,
              initial_setup_completed_at: null,
              timezone_change_requested_at: null,
              timezone_change_requested_by: null,
              timezone_promoted_at: null,
              timezone_updated_at: null,
              timezone_updated_by: null
            }
          ]
        };
      }
      throw new Error(`unexpected sql: ${sql}`);
    }
  };
}

function withApp(pool) {
  const app = express();
  app.use(createSetupGate(pool));
  app.get('/healthz', (_req, res) => res.json({ ok: true }));
  app.get('/api/setup/status', (_req, res) => res.json({ ok: true }));
  app.get('/api/ioc/list', (_req, res) => res.json({ items: [] }));
  return app;
}

function request(app, path) {
  return new Promise((resolve) => {
    const server = app.listen(0, async () => {
      const { port } = server.address();
      try {
        const res = await fetch(`http://127.0.0.1:${port}${path}`);
        const body = await res.json().catch(() => ({}));
        resolve({ status: res.status, body });
      } finally {
        server.close();
      }
    });
  });
}

test('setup gate blocks API with 428 INITIAL_SETUP_REQUIRED', async () => {
  clearSystemTimeCache();
  const app = withApp(mockPool({ initial_setup_completed: false, active_system_timezone: null }));
  const blocked = await request(app, '/api/ioc/list');
  assert.equal(blocked.status, 428);
  assert.equal(blocked.body.code, 'INITIAL_SETUP_REQUIRED');

  const health = await request(app, '/healthz');
  assert.equal(health.status, 200);

  const setup = await request(app, '/api/setup/status');
  assert.equal(setup.status, 200);
});

test('setup gate blocks with TIMEZONE_CONFIGURATION_REQUIRED for existing installs', async () => {
  clearSystemTimeCache();
  const app = withApp(mockPool({
    initial_setup_completed: false,
    timezone_configuration_required: true,
    active_system_timezone: null
  }));
  const blocked = await request(app, '/api/ioc/list');
  assert.equal(blocked.status, 428);
  assert.equal(blocked.body.code, 'TIMEZONE_CONFIGURATION_REQUIRED');
});

test('setup gate allows API when setup completed with valid active timezone', async () => {
  clearSystemTimeCache();
  const app = withApp(mockPool({
    initial_setup_completed: true,
    active_system_timezone: 'Europe/London'
  }));
  const ok = await request(app, '/api/ioc/list');
  assert.equal(ok.status, 200);
});

test('setup gate allows API while pending restart (active still valid)', async () => {
  clearSystemTimeCache();
  const app = withApp(mockPool({
    initial_setup_completed: true,
    active_system_timezone: 'Europe/Istanbul',
    pending_system_timezone: 'Europe/London',
    timezone_restart_required: true
  }));
  const ok = await request(app, '/api/ioc/list');
  assert.equal(ok.status, 200);
});

test('setup gate rejects invalid configured timezone', async () => {
  clearSystemTimeCache();
  const app = withApp(mockPool({
    initial_setup_completed: true,
    active_system_timezone: 'UTC+3'
  }));
  const blocked = await request(app, '/api/ioc/list');
  assert.equal(blocked.status, 428);
});

test('SystemTimeError carries INITIAL_SETUP_REQUIRED', () => {
  const err = new SystemTimeError('INITIAL_SETUP_REQUIRED', 'need setup', 428);
  assert.equal(err.status, 428);
  assert.equal(err.code, 'INITIAL_SETUP_REQUIRED');
});

test('non-admin cannot request pending timezone change', async () => {
  clearSystemTimeCache();
  const { registerSetupRoutes } = await import('../routes/setup.js');
  const { requestSystemTimezoneChange } = await import('../lib/systemTime.js');
  const state = {
    initial_setup_completed: true,
    timezone_configuration_required: false,
    active_system_timezone: 'Europe/Istanbul',
    pending_system_timezone: null,
    timezone_restart_required: false,
    timezone_config_version: 1,
    active_timezone_config_version: 1
  };
  const pool = {
    async query(sql, params = []) {
      const s = String(sql);
      if (s.includes('FROM system_settings') && s.includes('SELECT')) {
        return {
          rows: [{
            ...state,
            adoption_source: 'initial_setup',
            initial_setup_completed_at: null,
            timezone_change_requested_at: null,
            timezone_change_requested_by: null,
            timezone_promoted_at: null,
            timezone_updated_at: null,
            timezone_updated_by: null
          }]
        };
      }
      if (s.includes('SET pending_system_timezone = $2')) {
        state.pending_system_timezone = params[1];
        state.timezone_restart_required = true;
        return { rows: [] };
      }
      return { rows: [] };
    }
  };
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.user = { role: 'readonly', email: 'ro@example.com' };
    next();
  });
  registerSetupRoutes(app, pool, {});
  const result = await new Promise((resolve) => {
    const server = app.listen(0, async () => {
      const { port } = server.address();
      try {
        const res = await fetch(`http://127.0.0.1:${port}/api/system/timezone`, {
          method: 'PUT',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            timezone: 'Europe/London',
            confirm: true,
            confirmation_text: 'CHANGE SYSTEM TIMEZONE'
          })
        });
        const body = await res.json().catch(() => ({}));
        resolve({ status: res.status, body });
      } finally {
        server.close();
      }
    });
  });
  assert.equal(result.status, 403);
  assert.equal(result.body.code, 'FORBIDDEN');
  assert.equal(state.pending_system_timezone, null);
  // Sanity: admin path helper still works in isolation
  await requestSystemTimezoneChange(pool, 'Europe/London', { confirm: true, updatedBy: 'a@b.c' });
  assert.equal(state.pending_system_timezone, 'Europe/London');
});

test('GET /api/system/timezones returns canonical sorted list', async () => {
  const { registerSetupRoutes } = await import('../routes/setup.js');
  const { getSupportedIanaTimezones } = await import('../lib/systemTime.js');
  const app = express();
  app.use(express.json());
  registerSetupRoutes(app, mockPool({
    initial_setup_completed: false,
    active_system_timezone: null
  }), {});

  const result = await new Promise((resolve) => {
    const server = app.listen(0, async () => {
      const { port } = server.address();
      try {
        const res = await fetch(`http://127.0.0.1:${port}/api/system/timezones`);
        const body = await res.json().catch(() => ({}));
        resolve({ status: res.status, body });
      } finally {
        server.close();
      }
    });
  });

  assert.equal(result.status, 200);
  assert.deepEqual(result.body.timezones, getSupportedIanaTimezones());
  assert.ok(result.body.timezones.includes('Asia/Kathmandu'));
});

test('setup gate allows timezone list before initial setup completes', async () => {
  clearSystemTimeCache();
  const { registerSetupRoutes } = await import('../routes/setup.js');
  const pool = mockPool({ initial_setup_completed: false, active_system_timezone: null });
  const app = express();
  app.use(createSetupGate(pool));
  registerSetupRoutes(app, pool, {});
  const tz = await request(app, '/api/system/timezones');
  assert.equal(tz.status, 200);
  assert.ok(Array.isArray(tz.body.timezones));
  assert.ok(tz.body.timezones.length > 50);
});
