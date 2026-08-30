import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { registerSystemVersionRoutes } from './systemVersion.js';
import { abbreviateCommit, getProductVersionInfo } from '../lib/productVersion.js';

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

test('GET /api/system/version returns canonical build metadata', async () => {
  const previous = {
    version: process.env.TALONHOUND_VERSION,
    commit: process.env.TALONHOUND_COMMIT,
    buildDate: process.env.TALONHOUND_BUILD_DATE
  };
  process.env.TALONHOUND_VERSION = '0.1.0-beta.1';
  process.env.TALONHOUND_COMMIT = 'abc1234567890abcdef1234567890abcdef1234';
  process.env.TALONHOUND_BUILD_DATE = '2026-08-23T12:00:00.000Z';

  try {
    const app = express();
    registerSystemVersionRoutes(app);
    const res = await request(app, '/api/system/version');
    assert.equal(res.status, 200);
    assert.deepEqual(res.body, {
      product: 'TalonHound',
      version: '0.1.0-beta.1',
      channel: 'beta',
      commit: 'abc1234567890abcdef1234567890abcdef1234',
      buildDate: '2026-08-23T12:00:00.000Z'
    });
    assert.deepEqual(getProductVersionInfo(), res.body);
    assert.equal(res.body.latestVersion, undefined);
    assert.equal(res.body.releaseUrl, undefined);
    assert.equal(res.body.lastCheckedAt, undefined);
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[`TALONHOUND_${key === 'buildDate' ? 'BUILD_DATE' : key.toUpperCase()}`];
      else process.env[`TALONHOUND_${key === 'buildDate' ? 'BUILD_DATE' : key.toUpperCase()}`] = value;
    }
  }
});

test('abbreviateCommit shortens long SHAs only', () => {
  assert.equal(abbreviateCommit('abc1234567890'), 'abc1234');
  assert.equal(abbreviateCommit('unknown'), 'unknown');
});
