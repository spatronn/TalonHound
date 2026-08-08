import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { registerSetupRoutes } from './setup.js';
import { clearSystemTimeCache } from '../lib/systemTime.js';

function mockPool(config) {
  return {
    async query(sql, params) {
      const s = String(sql);
      if (s.includes('SELECT') && s.includes('system_settings')) {
        return {
          rows: [
            {
              initial_setup_completed: config.initial_setup_completed,
              timezone_configuration_required: Boolean(config.timezone_configuration_required),
              active_system_timezone: config.active_system_timezone || null,
              pending_system_timezone: null,
              timezone_restart_required: false,
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
      if (s.includes('UPDATE system_settings')) {
        config.initial_setup_completed = true;
        config.timezone_configuration_required = false;
        config.active_system_timezone = params[1];
        return { rows: [] };
      }
      throw new Error(`unexpected sql: ${s.slice(0, 120)}`);
    }
  };
}

function withApp(pool, { user = null } = {}) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    if (user) {
      req.user = user;
      req.authVia = 'cookie';
    }
    next();
  });
  registerSetupRoutes(app, pool);
  return app;
}

function post(app, path, body) {
  return new Promise((resolve) => {
    const server = app.listen(0, async () => {
      const { port } = server.address();
      try {
        const res = await fetch(`http://127.0.0.1:${port}${path}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(body)
        });
        const data = await res.json().catch(() => ({}));
        resolve({ status: res.status, body: data });
      } finally {
        server.close();
      }
    });
  });
}

test('AUTH-05: anonymous complete allowed on greenfield (not configuration_required)', async () => {
  clearSystemTimeCache();
  const cfg = { initial_setup_completed: false, timezone_configuration_required: false, active_system_timezone: null };
  const app = withApp(mockPool(cfg));
  const out = await post(app, '/api/setup/complete', { timezone: 'UTC' });
  assert.equal(out.status, 201);
  assert.equal(cfg.initial_setup_completed, true);
});

test('AUTH-05: anonymous complete denied when timezone_configuration_required', async () => {
  clearSystemTimeCache();
  const cfg = { initial_setup_completed: false, timezone_configuration_required: true, active_system_timezone: null };
  const app = withApp(mockPool(cfg));
  const out = await post(app, '/api/setup/complete', { timezone: 'UTC' });
  assert.equal(out.status, 401);
  assert.equal(out.body.code, 'AUTH_REQUIRED');
  assert.equal(cfg.initial_setup_completed, false);
});

test('AUTH-05: admin can complete when timezone_configuration_required', async () => {
  clearSystemTimeCache();
  const cfg = { initial_setup_completed: false, timezone_configuration_required: true, active_system_timezone: null };
  const app = withApp(mockPool(cfg), { user: { email: 'admin@talonhound.local', role: 'admin' } });
  const out = await post(app, '/api/setup/complete', { timezone: 'Europe/Istanbul' });
  assert.equal(out.status, 201);
  assert.equal(cfg.active_system_timezone, 'Europe/Istanbul');
});

test('AUTH-05: analyst cannot complete when timezone_configuration_required', async () => {
  clearSystemTimeCache();
  const cfg = { initial_setup_completed: false, timezone_configuration_required: true, active_system_timezone: null };
  const app = withApp(mockPool(cfg), { user: { email: 'a@x', role: 'analyst' } });
  const out = await post(app, '/api/setup/complete', { timezone: 'UTC' });
  assert.equal(out.status, 401);
});
