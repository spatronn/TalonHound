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

test('non-system-admin cannot request pending timezone change', async () => {
  clearSystemTimeCache();
  const { registerSetupRoutes } = await import('../routes/setup.js');
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
      if (s.includes('FROM users') && s.includes('is_system_admin')) {
        return { rows: [{ is_system_admin: false }] };
      }
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
  // Plain admin (role=admin) who is NOT the System Administrator.
  app.use((req, _res, next) => {
    req.user = { id: 2, role: 'admin', email: 'admin@example.com' };
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
  assert.match(result.body.message, /System Administrator/i);
  assert.equal(state.pending_system_timezone, null);
  assert.equal(state.timezone_restart_required, false);
});

test('readonly role cannot request pending timezone change', async () => {
  clearSystemTimeCache();
  const { registerSetupRoutes } = await import('../routes/setup.js');
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
      if (s.includes('FROM users') && s.includes('is_system_admin')) {
        return { rows: [{ is_system_admin: false }] };
      }
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
    req.user = { id: 3, role: 'readonly', email: 'ro@example.com' };
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
});

test('system administrator can request pending timezone change', async () => {
  clearSystemTimeCache();
  const { registerSetupRoutes } = await import('../routes/setup.js');
  const state = {
    initial_setup_completed: true,
    timezone_configuration_required: false,
    active_system_timezone: 'Europe/Istanbul',
    pending_system_timezone: null,
    timezone_restart_required: false,
    timezone_config_version: 1,
    active_timezone_config_version: 1,
    timezone_change_requested_at: null,
    timezone_change_requested_by: null
  };
  const pool = {
    async query(sql, params = []) {
      const s = String(sql);
      if (s.includes('FROM users') && s.includes('is_system_admin')) {
        const id = Number(params[0]);
        return { rows: [{ is_system_admin: id === 1 }] };
      }
      if (s.includes('FROM system_settings') && s.includes('SELECT')) {
        return {
          rows: [{
            ...state,
            adoption_source: 'initial_setup',
            initial_setup_completed_at: null,
            timezone_promoted_at: null,
            timezone_updated_at: null,
            timezone_updated_by: null
          }]
        };
      }
      if (s.includes('SET pending_system_timezone = $2')) {
        state.pending_system_timezone = params[1];
        state.timezone_restart_required = true;
        state.timezone_change_requested_at = new Date().toISOString();
        state.timezone_change_requested_by = params[2] || null;
        state.timezone_config_version = Number(state.timezone_config_version || 1) + 1;
        return { rows: [] };
      }
      return { rows: [] };
    }
  };
  const auditCalls = [];
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.user = { id: 1, role: 'admin', email: 'sysadmin@example.com' };
    next();
  });
  registerSetupRoutes(app, pool, {
    audit: {
      auditSuccess: async (payload) => { auditCalls.push(payload); }
    }
  });
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
  assert.equal(result.status, 200);
  assert.equal(state.pending_system_timezone, 'Europe/London');
  assert.equal(state.timezone_restart_required, true);
  assert.equal(state.active_system_timezone, 'Europe/Istanbul');
  assert.equal(result.body.pending_system_timezone, 'Europe/London');
  assert.equal(auditCalls.length, 1);
  assert.equal(auditCalls[0].action, 'system.timezone_change_requested');
});

test('GET /api/system/timezone reports can_edit for system administrator only', async () => {
  clearSystemTimeCache();
  const { registerSetupRoutes } = await import('../routes/setup.js');
  const baseState = {
    initial_setup_completed: true,
    timezone_configuration_required: false,
    active_system_timezone: 'Europe/Istanbul',
    pending_system_timezone: null,
    timezone_restart_required: false,
    timezone_config_version: 1,
    active_timezone_config_version: 1
  };

  async function getCanEdit(userId, isSystemAdmin) {
    const pool = {
      async query(sql, params = []) {
        const s = String(sql);
        if (s.includes('FROM users') && s.includes('is_system_admin')) {
          return { rows: [{ is_system_admin: isSystemAdmin }] };
        }
        if (s.includes('FROM system_settings') && s.includes('SELECT')) {
          return {
            rows: [{
              ...baseState,
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
        return { rows: [] };
      }
    };
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => {
      req.user = { id: userId, role: 'admin', email: 'u@example.com' };
      next();
    });
    registerSetupRoutes(app, pool, {});
    return new Promise((resolve) => {
      const server = app.listen(0, async () => {
        const { port } = server.address();
        try {
          const res = await fetch(`http://127.0.0.1:${port}/api/system/timezone`);
          const body = await res.json().catch(() => ({}));
          resolve({ status: res.status, body });
        } finally {
          server.close();
        }
      });
    });
  }

  const sys = await getCanEdit(1, true);
  assert.equal(sys.status, 200);
  assert.equal(sys.body.can_edit, true);
  assert.equal(sys.body.active_system_timezone, 'Europe/Istanbul');

  const plain = await getCanEdit(2, false);
  assert.equal(plain.status, 200);
  assert.equal(plain.body.can_edit, false);
  assert.equal(plain.body.active_system_timezone, 'Europe/Istanbul');
});

test('denied timezone change does not write audit success', async () => {
  clearSystemTimeCache();
  const { registerSetupRoutes } = await import('../routes/setup.js');
  const auditCalls = [];
  const pool = {
    async query(sql) {
      const s = String(sql);
      if (s.includes('FROM users') && s.includes('is_system_admin')) {
        return { rows: [{ is_system_admin: false }] };
      }
      if (s.includes('FROM system_settings') && s.includes('SELECT')) {
        return {
          rows: [{
            initial_setup_completed: true,
            timezone_configuration_required: false,
            active_system_timezone: 'Europe/Istanbul',
            pending_system_timezone: null,
            timezone_restart_required: false,
            timezone_config_version: 1,
            active_timezone_config_version: 1,
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
      throw new Error(`unexpected sql: ${s}`);
    }
  };
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.user = { id: 2, role: 'admin', email: 'admin@example.com' };
    next();
  });
  registerSetupRoutes(app, pool, {
    audit: { auditSuccess: async (p) => { auditCalls.push(p); } }
  });
  const result = await new Promise((resolve) => {
    const server = app.listen(0, async () => {
      const { port } = server.address();
      try {
        const res = await fetch(`http://127.0.0.1:${port}/api/system/timezone`, {
          method: 'PUT',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            timezone: 'UTC',
            confirm: true,
            confirmation_text: 'CHANGE SYSTEM TIMEZONE'
          })
        });
        resolve({ status: res.status });
      } finally {
        server.close();
      }
    });
  });
  assert.equal(result.status, 403);
  assert.equal(auditCalls.length, 0);
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
