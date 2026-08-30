import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { registerSystemUpdatesRoutes } from './systemUpdates.js';
import { createUpdateCheckService } from '../lib/updateCheckService.js';
import { ROLES } from '../lib/rbac.js';
import { AUDIT_ACTION } from '../lib/auditConstants.js';

function makePool({ systemAdmins = new Set() } = {}) {
  return {
    async query(sql, params = []) {
      const s = String(sql);
      if (s.includes('FROM users') && s.includes('is_system_admin')) {
        const id = Number(params[0]);
        return { rows: [{ is_system_admin: systemAdmins.has(id) }] };
      }
      throw new Error(`unexpected sql: ${s}`);
    }
  };
}

function withEnv(vars, fn) {
  const previous = {};
  for (const [key, value] of Object.entries(vars)) {
    previous[key] = process.env[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  return Promise.resolve()
    .then(fn)
    .finally(() => {
      for (const [key, value] of Object.entries(previous)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    });
}

function request(app, method, path) {
  return new Promise((resolve) => {
    const server = app.listen(0, async () => {
      const { port } = server.address();
      try {
        const res = await fetch(`http://127.0.0.1:${port}${path}`, { method });
        const body = await res.json().catch(() => ({}));
        resolve({ status: res.status, body });
      } finally {
        server.close();
      }
    });
  });
}

function makeService(fetchImpl) {
  const service = createUpdateCheckService({
    fetchImpl: fetchImpl || (async () => ({
      ok: true,
      status: 200,
      headers: { get: () => null },
      arrayBuffer: async () => Buffer.from(JSON.stringify({
        schemaVersion: 1,
        channel: 'beta',
        latest: '0.1.0-beta.2',
        released_at: '2026-09-04T12:00:00Z',
        release_url: 'https://github.com/spatronn/TalonHound/releases/tag/v0.1.0-beta.2',
        critical: false
      }))
    }))
  });
  service._setCacheForTests({
    status: 'unknown',
    currentVersion: '0.1.0-beta.1',
    channel: 'beta',
    latestVersion: null,
    automaticChecksEnabled: true
  });
  return service;
}

/**
 * Mimic production apiAuthGate (requireAuth → 401) in front of the route module.
 */
function makeApp({ user = null, pool, service, audit } = {}) {
  const app = express();
  app.use((req, res, next) => {
    if (user) req.user = { ...user };
    if (!req.user) return res.status(401).json({ message: 'Unauthorized' });
    next();
  });
  registerSystemUpdatesRoutes(app, {
    pool,
    updateCheck: service,
    auditLogService: audit
  });
  return app;
}

const SYS_ADMIN = { id: 1, role: ROLES.ADMIN, email: 'sysadmin@example.com' };
const PLAIN_ADMIN = { id: 2, role: ROLES.ADMIN, email: 'admin@example.com' };
const READONLY = { id: 3, role: ROLES.READONLY, email: 'reader@example.com' };
const ANALYST = { id: 4, role: ROLES.ANALYST, email: 'analyst@example.com' };

test('unauthenticated update endpoints are rejected with 401', async () => {
  await withEnv({
    TALONHOUND_VERSION: '0.1.0-beta.1',
    UPDATE_CHANNEL: 'beta',
    UPDATE_MANIFEST_URL: 'https://example.com/updates/beta.json'
  }, async () => {
    let fetches = 0;
    const service = makeService(async () => {
      fetches += 1;
      throw new Error('should not fetch');
    });
    const before = { ...service.getStatus() };
    const app = makeApp({
      user: null,
      pool: makePool({ systemAdmins: new Set([1]) }),
      service
    });

    const get = await request(app, 'GET', '/api/system/updates');
    assert.equal(get.status, 401);
    assert.equal(get.body.message, 'Unauthorized');

    const post = await request(app, 'POST', '/api/system/updates/check');
    assert.equal(post.status, 401);
    assert.equal(post.body.message, 'Unauthorized');
    assert.equal(fetches, 0);
    assert.equal(service.getStatus().status, before.status);
    assert.equal(service.getStatus().latestVersion, before.latestVersion);
  });
});

test('normal user and non-system-admin administrator cannot access update APIs', async () => {
  await withEnv({
    TALONHOUND_VERSION: '0.1.0-beta.1',
    UPDATE_CHANNEL: 'beta',
    UPDATE_MANIFEST_URL: 'https://example.com/updates/beta.json'
  }, async () => {
    let fetches = 0;
    const service = makeService(async () => {
      fetches += 1;
      throw new Error('should not fetch');
    });
    const auditCalls = [];
    const pool = makePool({ systemAdmins: new Set([1]) });
    const before = { ...service.getStatus() };

    for (const user of [READONLY, ANALYST, PLAIN_ADMIN]) {
      const app = makeApp({
        user,
        pool,
        service,
        audit: { auditSuccess: async (evt) => { auditCalls.push(evt); } }
      });
      const get = await request(app, 'GET', '/api/system/updates');
      assert.equal(get.status, 403, `${user.email} GET`);
      const post = await request(app, 'POST', '/api/system/updates/check');
      assert.equal(post.status, 403, `${user.email} POST`);
      if (user.role === ROLES.ADMIN) {
        assert.equal(get.body.code, 'FORBIDDEN');
        assert.equal(post.body.code, 'FORBIDDEN');
        assert.match(post.body.message, /System Administrator/);
      } else {
        assert.equal(get.body.message, 'Forbidden');
        assert.equal(post.body.message, 'Forbidden');
      }
    }

    assert.equal(fetches, 0);
    assert.equal(auditCalls.length, 0);
    assert.equal(service.getStatus().status, before.status);
    assert.equal(service.getStatus().latestVersion, before.latestVersion);
  });
});

test('System Administrator can read status, check updates, and is audited', async () => {
  await withEnv({
    TALONHOUND_VERSION: '0.1.0-beta.1',
    UPDATE_CHANNEL: 'beta',
    UPDATE_MANIFEST_URL: 'https://example.com/updates/beta.json'
  }, async () => {
    let fetches = 0;
    const service = makeService(async () => {
      fetches += 1;
      return {
        ok: true,
        status: 200,
        headers: { get: () => null },
        arrayBuffer: async () => Buffer.from(JSON.stringify({
          schemaVersion: 1,
          channel: 'beta',
          latest: '0.1.0-beta.2',
          released_at: '2026-09-04T12:00:00Z',
          release_url: 'https://github.com/spatronn/TalonHound/releases/tag/v0.1.0-beta.2',
          critical: false
        }))
      };
    });
    const auditCalls = [];
    const app = makeApp({
      user: SYS_ADMIN,
      pool: makePool({ systemAdmins: new Set([1]) }),
      service,
      audit: { auditSuccess: async (evt) => { auditCalls.push(evt); } }
    });

    const get = await request(app, 'GET', '/api/system/updates');
    assert.equal(get.status, 200);
    assert.equal(get.body.currentVersion, '0.1.0-beta.1');
    assert.equal(fetches, 0, 'GET uses cache and does not fetch the manifest');

    const check = await request(app, 'POST', '/api/system/updates/check');
    assert.equal(check.status, 200);
    assert.equal(check.body.status, 'update_available');
    assert.equal(check.body.latestVersion, '0.1.0-beta.2');
    assert.equal(fetches, 1);
    assert.equal(auditCalls.length, 1);
    assert.equal(auditCalls[0].action, AUDIT_ACTION.UPDATE_CHECK_REQUESTED);
    assert.equal(auditCalls[0].req.user.id, SYS_ADMIN.id);
    assert.equal(auditCalls[0].metadata.latest_version, '0.1.0-beta.2');
  });
});

test('internal scheduled update polling does not require HTTP authorization', async () => {
  await withEnv({
    TALONHOUND_VERSION: '0.1.0-beta.1',
    UPDATE_CHANNEL: 'beta',
    UPDATE_MANIFEST_URL: 'https://example.com/updates/beta.json'
  }, async () => {
    let fetches = 0;
    const service = makeService(async () => {
      fetches += 1;
      return {
        ok: true,
        status: 200,
        headers: { get: () => null },
        arrayBuffer: async () => Buffer.from(JSON.stringify({
          schemaVersion: 1,
          channel: 'beta',
          latest: '0.1.0-beta.2',
          released_at: '2026-09-04T12:00:00Z',
          release_url: 'https://github.com/spatronn/TalonHound/releases/tag/v0.1.0-beta.2',
          critical: false
        }))
      };
    });

    const status = await service.check({ force: true });
    assert.equal(status.status, 'update_available');
    assert.equal(fetches, 1);
    assert.equal(service.getStatus().latestVersion, '0.1.0-beta.2');
  });
});
