import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { createPasswordChangeGate } from './passwordChangeGate.js';

function mockPool({ mustChangePassword = false, missingUser = false, throwOnQuery = false } = {}) {
  return {
    async query(sql, params) {
      if (throwOnQuery) {
        throw new Error('simulated db failure');
      }
      if (String(sql).includes('must_change_password')) {
        if (missingUser) return { rows: [] };
        return { rows: [{ must_change_password: mustChangePassword }] };
      }
      throw new Error(`unexpected sql: ${sql} params=${JSON.stringify(params)}`);
    }
  };
}

function withApp(pool, { user, authVia = 'cookie' } = {}) {
  const app = express();
  app.use((req, _res, next) => {
    if (user) {
      req.user = user;
      req.authVia = authVia;
    }
    next();
  });
  app.use(createPasswordChangeGate(pool));
  app.get('/api/auth/me', (_req, res) => res.json({ ok: true }));
  app.post('/api/auth/logout', (_req, res) => res.status(204).end());
  app.post('/api/auth/change-password', (_req, res) => res.json({ changed: true }));
  app.get('/api/ioc/list', (_req, res) => res.json({ items: [] }));
  return app;
}

function request(app, path, method = 'GET') {
  return new Promise((resolve) => {
    const server = app.listen(0, async () => {
      const { port } = server.address();
      try {
        const res = await fetch(`http://127.0.0.1:${port}${path}`, { method });
        const text = await res.text();
        let body = {};
        try {
          body = text ? JSON.parse(text) : {};
        } catch {
          body = { raw: text };
        }
        resolve({ status: res.status, body });
      } finally {
        server.close();
      }
    });
  });
}

test('password change gate blocks protected API when must_change_password is true', async () => {
  const app = withApp(mockPool({ mustChangePassword: true }), {
    user: { id: 1, email: 'admin@talonhound.local', role: 'admin' }
  });
  const blocked = await request(app, '/api/ioc/list');
  assert.equal(blocked.status, 403);
  assert.equal(blocked.body.code, 'PASSWORD_CHANGE_REQUIRED');
});

test('password change gate allows me / change-password / logout when flag is true', async () => {
  const app = withApp(mockPool({ mustChangePassword: true }), {
    user: { id: 1, email: 'admin@talonhound.local', role: 'admin' }
  });
  const me = await request(app, '/api/auth/me');
  assert.equal(me.status, 200);
  const change = await request(app, '/api/auth/change-password', 'POST');
  assert.equal(change.status, 200);
  const logout = await request(app, '/api/auth/logout', 'POST');
  assert.equal(logout.status, 204);
});

test('password change gate allows protected API when flag is false', async () => {
  const app = withApp(mockPool({ mustChangePassword: false }), {
    user: { id: 1, email: 'admin@talonhound.local', role: 'admin' }
  });
  const ok = await request(app, '/api/ioc/list');
  assert.equal(ok.status, 200);
});

test('password change gate skips ingest auth', async () => {
  const app = withApp(mockPool({ mustChangePassword: true }), {
    user: { id: null, email: 'api-ingest@internal', role: 'admin' },
    authVia: 'ingest'
  });
  const ok = await request(app, '/api/ioc/list');
  assert.equal(ok.status, 200);
});

test('JWT-02: missing userId does not bypass the gate on protected routes', async () => {
  const app = withApp(mockPool({ mustChangePassword: true }), {
    user: { id: null, email: 'legacy@talonhound.local', role: 'admin' }
  });
  const blocked = await request(app, '/api/ioc/list');
  assert.equal(blocked.status, 401);
  assert.equal(blocked.body.message, 'Unauthorized');
});

test('JWT-02: allowlisted password-change routes remain reachable without userId', async () => {
  const app = withApp(mockPool({ mustChangePassword: true }), {
    user: { id: null, email: 'legacy@talonhound.local', role: 'admin' }
  });
  const me = await request(app, '/api/auth/me');
  assert.equal(me.status, 200);
  const logout = await request(app, '/api/auth/logout', 'POST');
  assert.equal(logout.status, 204);
});

test('JWT-02: nonexistent userId is rejected (fail closed)', async () => {
  const app = withApp(mockPool({ missingUser: true }), {
    user: { id: 99999, email: 'gone@talonhound.local', role: 'admin' }
  });
  const blocked = await request(app, '/api/ioc/list');
  assert.equal(blocked.status, 401);
  assert.equal(blocked.body.message, 'Unauthorized');
});

test('JWT-02: DB lookup failure does not authorize', async () => {
  const app = withApp(mockPool({ throwOnQuery: true }), {
    user: { id: 1, email: 'admin@talonhound.local', role: 'admin' }
  });
  const failed = await request(app, '/api/ioc/list');
  assert.equal(failed.status, 500);
  assert.match(String(failed.body.message || ''), /Failed to verify password change status/);
});
