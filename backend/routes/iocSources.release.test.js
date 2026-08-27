import test from 'node:test';
import assert from 'node:assert/strict';
import { registerIocSourceRoutes } from './iocSources.js';

function captureApp() {
  const routes = new Map();
  const app = {
    get(path, ...handlers) { routes.set(`GET ${path}`, handlers); },
    post(path, ...handlers) { routes.set(`POST ${path}`, handlers); },
    patch(path, ...handlers) { routes.set(`PATCH ${path}`, handlers); },
    delete(path, ...handlers) { routes.set(`DELETE ${path}`, handlers); }
  };
  return { app, routes };
}

function mockRes() {
  const out = { statusCode: 200, body: null };
  const res = {
    status(code) { out.statusCode = code; return res; },
    json(body) { out.body = body; return res; }
  };
  return { res, out };
}

/**
 * Regression: PATCH nonexistent IOC source must return 404 without double-releasing
 * the pool client (which previously crashed the Node process via pg-pool).
 */
test('PATCH nonexistent IOC source returns 404 and releases the client once', async () => {
  const releases = [];
  const client = {
    async query(sql) {
      if (String(sql).includes('SELECT * FROM ioc_sources')) return { rows: [] };
      if (/^\s*ROLLBACK/i.test(String(sql))) return { rows: [] };
      throw new Error(`unexpected query: ${sql}`);
    },
    release(err) {
      releases.push(err || null);
    }
  };
  const pool = { async connect() { return client; } };

  const { app, routes } = captureApp();
  registerIocSourceRoutes(app, pool, null);
  const handlers = routes.get('PATCH /api/ioc-sources/:id');
  assert.ok(handlers?.length, 'PATCH route registered');
  const handler = handlers[handlers.length - 1];

  const { res, out } = mockRes();
  await handler(
    { params: { id: '999999999' }, body: { active: false }, user: { id: 1, role: 'admin' } },
    res
  );

  assert.equal(out.statusCode, 404);
  assert.equal(out.body?.message, 'IOC source not found');
  await new Promise((r) => setImmediate(r));
  assert.equal(releases.length, 1, `expected one release, got ${releases.length}`);
});
