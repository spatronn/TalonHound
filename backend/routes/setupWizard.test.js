import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { registerSetupRoutes } from './setup.js';
import { hashSetupCode } from '../lib/setupCode.js';
import { clearSystemTimeCache } from '../lib/systemTime.js';

/** In-memory Postgres stand-in (mirrors lib/firstRunSetup.test.js). */
function makeDb(initial = {}) {
  const state = {
    settings: {
      id: 1,
      setup_completed_at: null,
      setup_code_hash: null,
      initial_setup_completed: false,
      timezone_configuration_required: false,
      active_system_timezone: null,
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
      timezone_updated_by: null,
      ...(initial.settings || {})
    },
    users: initial.users ? [...initial.users] : []
  };

  function run(sql, params = []) {
    const s = String(sql);
    if (s.startsWith('BEGIN') || s.startsWith('COMMIT') || s.startsWith('ROLLBACK')) return { rows: [] };
    if (s.includes('pg_advisory_xact_lock')) return { rows: [{}] };
    if (s.includes('INSERT INTO system_settings (id) VALUES')) return { rows: [] };
    if (s.includes('FROM public.system_settings s') && s.includes('user_count')) {
      return { rows: [{
        setup_completed_at: state.settings.setup_completed_at,
        setup_code_hash: state.settings.setup_code_hash,
        initial_setup_completed: state.settings.initial_setup_completed,
        timezone_configuration_required: state.settings.timezone_configuration_required,
        active_system_timezone: state.settings.active_system_timezone,
        user_count: state.users.length
      }] };
    }
    if (s.includes('SELECT setup_code_hash, setup_completed_at FROM system_settings')) {
      return { rows: [{ setup_code_hash: state.settings.setup_code_hash, setup_completed_at: state.settings.setup_completed_at }] };
    }
    if (s.includes('SELECT setup_code_hash FROM system_settings')) {
      return { rows: [{ setup_code_hash: state.settings.setup_code_hash }] };
    }
    if (s.includes('SELECT COUNT(*)::int AS n FROM users')) {
      return { rows: [{ n: state.users.length }] };
    }
    if (s.includes('INSERT INTO users')) {
      const username = params[0];
      if (state.users.some((u) => String(u.username).toLowerCase() === String(username).toLowerCase())
        || state.users.some((u) => u.is_system_admin)) {
        const err = new Error('unique_violation');
        err.code = '23505';
        throw err;
      }
      state.users.push({ username, is_system_admin: true, role: 'admin' });
      return { rows: [] };
    }
    if (s.includes('UPDATE system_settings') && s.includes('setup_completed_at = NOW()')) {
      state.settings.setup_completed_at = new Date().toISOString();
      state.settings.active_system_timezone = params[1];
      state.settings.initial_setup_completed = true;
      state.settings.timezone_configuration_required = false;
      state.settings.setup_code_hash = null;
      return { rows: [{ setup_completed_at: state.settings.setup_completed_at }] };
    }
    if (s.includes('FROM system_settings') && s.includes('pending_system_timezone') && s.includes('timezone_config_version')) {
      return { rows: [{ ...state.settings }] };
    }
    // completeInitialSetup (timezone-only existing-install path)
    if (s.includes('UPDATE system_settings') && s.includes('active_system_timezone = $2')) {
      state.settings.active_system_timezone = params[1];
      state.settings.initial_setup_completed = true;
      state.settings.timezone_configuration_required = false;
      return { rows: [] };
    }
    return { rows: [] };
  }

  const client = { query: async (sql, params) => run(sql, params), release() {} };
  return {
    query: async (sql, params) => run(sql, params),
    connect: async () => client,
    _state: state
  };
}

function withServer(pool, deps = {}, mw) {
  const app = express();
  app.use(express.json());
  if (mw) app.use(mw);
  registerSetupRoutes(app, pool, deps);
  return app;
}

function req(app, path, { method = 'GET', body } = {}) {
  return new Promise((resolve) => {
    const server = app.listen(0, async () => {
      const { port } = server.address();
      try {
        const res = await fetch(`http://127.0.0.1:${port}${path}`, {
          method,
          headers: body ? { 'content-type': 'application/json' } : undefined,
          body: body ? JSON.stringify(body) : undefined
        });
        const b = await res.json().catch(() => ({}));
        resolve({ status: res.status, body: b, headers: res.headers });
      } finally {
        server.close();
      }
    });
  });
}

test('GET /api/setup/status reports greenfield flags', async () => {
  clearSystemTimeCache();
  const pool = makeDb({ settings: { setup_code_hash: hashSetupCode('ABCD-EFGH-JKMN-PQRS') } });
  const r = await req(withServer(pool), '/api/setup/status');
  assert.equal(r.status, 200);
  assert.equal(r.body.admin_setup_required, true);
  assert.equal(r.body.setup_code_required, true);
  assert.equal(r.body.setup_completed, false);
});

test('POST /api/setup/verify-code accepts valid, rejects invalid', async () => {
  clearSystemTimeCache();
  const pool = makeDb({ settings: { setup_code_hash: hashSetupCode('ABCD-EFGH-JKMN-PQRS') } });
  const app = withServer(pool);
  const good = await req(app, '/api/setup/verify-code', { method: 'POST', body: { code: 'abcd-efgh-jkmn-pqrs' } });
  assert.equal(good.status, 200);
  assert.equal(good.body.valid, true);
  const bad = await req(app, '/api/setup/verify-code', { method: 'POST', body: { code: 'WRON-GCOD-EWRO-NGXX' } });
  assert.equal(bad.status, 401);
  assert.equal(bad.body.code, 'INVALID_SETUP_CODE');
});

test('POST /api/setup/verify-code is rate limited', async () => {
  clearSystemTimeCache();
  const pool = makeDb({ settings: { setup_code_hash: hashSetupCode('ABCD-EFGH-JKMN-PQRS') } });
  let calls = 0;
  const limiter = () => { calls += 1; return calls <= 2 ? { allowed: true } : { allowed: false, retryAfterSec: 60 }; };
  const app = withServer(pool, { setupRateLimiter: limiter });
  await req(app, '/api/setup/verify-code', { method: 'POST', body: { code: 'x' } });
  await req(app, '/api/setup/verify-code', { method: 'POST', body: { code: 'x' } });
  const limited = await req(app, '/api/setup/verify-code', { method: 'POST', body: { code: 'x' } });
  assert.equal(limited.status, 429);
  assert.equal(limited.body.code, 'TOO_MANY_ATTEMPTS');
});

test('POST /api/setup/complete creates admin + timezone on greenfield', async () => {
  clearSystemTimeCache();
  const code = 'ABCD-EFGH-JKMN-PQRS';
  const pool = makeDb({ settings: { setup_code_hash: hashSetupCode(code) } });
  const audits = [];
  const app = withServer(pool, { audit: { auditSuccess: async (e) => { audits.push(e); } } });
  const r = await req(app, '/api/setup/complete', {
    method: 'POST',
    body: {
      code,
      username: 'admin@corp.example',
      password: 'a-strong-passphrase-123',
      confirm_password: 'a-strong-passphrase-123',
      timezone: 'Europe/Istanbul'
    }
  });
  assert.equal(r.status, 201);
  assert.equal(r.body.setup_completed, true);
  assert.equal(r.body.administrator, 'admin@corp.example');
  assert.equal(pool._state.users.length, 1);
  // Audit written for setup completion + admin creation + timezone, never the code/password.
  const actions = audits.map((a) => a.action);
  assert.ok(actions.includes('system.setup_completed'));
  assert.ok(actions.includes('user.created'));
  const serialized = JSON.stringify(audits);
  assert.ok(!serialized.includes('a-strong-passphrase-123'));
  assert.ok(!serialized.includes(code));
});

test('POST /api/setup/complete rejects wrong code without creating a user', async () => {
  clearSystemTimeCache();
  const pool = makeDb({ settings: { setup_code_hash: hashSetupCode('RIGHT-CODE') } });
  const app = withServer(pool);
  const r = await req(app, '/api/setup/complete', {
    method: 'POST',
    body: { code: 'WRONG', username: 'admin@corp.example', password: 'a-strong-passphrase-123', confirm_password: 'a-strong-passphrase-123', timezone: 'Europe/Istanbul' }
  });
  assert.equal(r.status, 401);
  assert.equal(r.body.code, 'INVALID_SETUP_CODE');
  assert.equal(pool._state.users.length, 0);
});

test('POST /api/setup/complete rejects weak password', async () => {
  clearSystemTimeCache();
  const pool = makeDb();
  const app = withServer(pool);
  const r = await req(app, '/api/setup/complete', {
    method: 'POST',
    body: { username: 'admin@corp.example', password: 'short', confirm_password: 'short', timezone: 'Europe/Istanbul' }
  });
  assert.equal(r.status, 400);
  assert.equal(r.body.code, 'INVALID_PASSWORD');
});

test('POST /api/setup/complete is locked after completion', async () => {
  clearSystemTimeCache();
  const pool = makeDb({ settings: { setup_completed_at: new Date().toISOString(), active_system_timezone: 'Europe/Istanbul', initial_setup_completed: true }, users: [{ username: 'admin@corp.example', is_system_admin: true }] });
  const app = withServer(pool);
  const r = await req(app, '/api/setup/complete', {
    method: 'POST',
    body: { username: 'evil@x', password: 'a-strong-passphrase-123', confirm_password: 'a-strong-passphrase-123', timezone: 'Europe/London' }
  });
  // Existing install (users present) -> not greenfield; timezone-only path, already complete.
  assert.equal(r.status, 409);
  assert.equal(pool._state.users.length, 1);
});

test('POST /api/setup/complete (existing install, timezone required) needs admin auth', async () => {
  clearSystemTimeCache();
  const pool = makeDb({ settings: { timezone_configuration_required: true }, users: [{ username: 'root@x', is_system_admin: true }] });
  const app = withServer(pool);
  const anon = await req(app, '/api/setup/complete', { method: 'POST', body: { timezone: 'Europe/Istanbul' } });
  assert.equal(anon.status, 401);
  assert.equal(anon.body.code, 'AUTH_REQUIRED');

  // With admin session -> succeeds (timezone only, no admin creation)
  const app2 = withServer(makeDb({ settings: { timezone_configuration_required: true }, users: [{ username: 'root@x', is_system_admin: true }] }), {}, (r, _res, n) => { r.user = { id: 1, role: 'admin', email: 'root@x' }; n(); });
  const ok = await req(app2, '/api/setup/complete', { method: 'POST', body: { timezone: 'Europe/Istanbul' } });
  assert.equal(ok.status, 201);
});
