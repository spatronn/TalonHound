import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import express from 'express';
import { registerBulkTriageRoutes } from '../routes/bulkTriage.js';

const serverSource = readFileSync(
  path.join(path.dirname(fileURLToPath(import.meta.url)), '../server.js'),
  'utf8'
);

test('server registers bulk triage routes before parametric :id handlers', () => {
  const bulkIdx = serverSource.indexOf('registerBulkTriageRoutes(app, pool');
  const matchParamIdx = serverSource.indexOf("app.patch('/api/ioc/match-events/:id/verdict'");
  const incidentParamIdx = serverSource.indexOf("app.patch('/api/incidents/:id'");

  assert.ok(bulkIdx >= 0, 'registerBulkTriageRoutes call missing');
  assert.ok(matchParamIdx >= 0, 'match-events parametric route missing');
  assert.ok(incidentParamIdx >= 0, 'incidents parametric route missing');
  assert.ok(bulkIdx < matchParamIdx, 'bulk match-events route must register before :id/verdict');
  assert.ok(bulkIdx < incidentParamIdx, 'bulk incidents route must register before :id patch');
});

test('bulk match-events path reaches bulk handler not parametric :id handler', async () => {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.user = { role: 'admin', email: 'admin@test.local' };
    next();
  });

  let parametricHit = false;
  registerBulkTriageRoutes(app, { query: async () => ({ rows: [], rowCount: 0 }) }, {
    auditLogService: { auditSuccess: async () => {} },
    findIncidentRow: async () => null
  });

  app.patch('/api/ioc/match-events/:id/verdict', (_req, res) => {
    parametricHit = true;
    res.status(400).json({ message: 'Invalid id' });
  });

  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));
  const { port } = server.address();

  try {
    const res = await fetch(`http://127.0.0.1:${port}/api/ioc/match-events/bulk/verdict`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: [999999999], verdict: 'fp' })
    });
    const body = await res.json();
    assert.equal(parametricHit, false);
    assert.equal(res.status, 400);
    assert.match(String(body.message || ''), /reason/i);
  } finally {
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
  }
});

test('bulk incidents path reaches bulk handler not parametric :id handler', async () => {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.user = { role: 'admin', email: 'admin@test.local' };
    next();
  });

  let parametricHit = false;
  registerBulkTriageRoutes(app, { query: async () => ({ rows: [], rowCount: 0 }) }, {
    auditLogService: { auditSuccess: async () => {} },
    findIncidentRow: async () => null
  });

  app.patch('/api/incidents/:id', (_req, res) => {
    parametricHit = true;
    res.status(404).json({ message: 'Incident not found' });
  });

  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));
  const { port } = server.address();

  try {
    const res = await fetch(`http://127.0.0.1:${port}/api/incidents/bulk`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: ['999999999'], verdict: 'FP' })
    });
    const body = await res.json();
    assert.equal(parametricHit, false);
    assert.equal(res.status, 400);
    assert.match(String(body.message || ''), /reason/i);
  } finally {
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
  }
});
