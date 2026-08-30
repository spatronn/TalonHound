import test from 'node:test';
import assert from 'node:assert/strict';
import { createUpdateCheckService } from './updateCheckService.js';

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

const goodManifest = {
  schemaVersion: 1,
  channel: 'beta',
  latest: '0.1.0-beta.3',
  released_at: '2026-09-04T12:00:00Z',
  minimum_supported_version: '0.1.0-beta.1',
  release_url: 'https://github.com/spatronn/TalonHound/releases/tag/v0.1.0-beta.3',
  critical: false
};

test('update check reports update_available and caches result', async () => {
  await withEnv({
    TALONHOUND_VERSION: '0.1.0-beta.1',
    UPDATE_CHANNEL: 'beta',
    UPDATE_MANIFEST_URL: 'https://example.com/updates/beta.json',
    UPDATE_CHECK_ENABLED: 'true'
  }, async () => {
    let calls = 0;
    const service = createUpdateCheckService({
      fetchImpl: async () => {
        calls += 1;
        return {
          ok: true,
          status: 200,
          headers: { get: () => null },
          arrayBuffer: async () => Buffer.from(JSON.stringify(goodManifest))
        };
      }
    });

    const first = await service.check({ force: true });
    assert.equal(first.status, 'update_available');
    assert.equal(first.latestVersion, '0.1.0-beta.3');
    assert.equal(first.error, null);

    const cached = service.getStatus();
    assert.equal(cached.status, 'update_available');
    assert.equal(calls, 1);
  });
});

test('update check reports up_to_date', async () => {
  await withEnv({
    TALONHOUND_VERSION: '0.1.0-beta.3',
    UPDATE_CHANNEL: 'beta',
    UPDATE_MANIFEST_URL: 'https://example.com/updates/beta.json'
  }, async () => {
    const service = createUpdateCheckService({
      fetchImpl: async () => ({
        ok: true,
        status: 200,
        headers: { get: () => null },
        arrayBuffer: async () => Buffer.from(JSON.stringify(goodManifest))
      })
    });
    const status = await service.check({ force: true });
    assert.equal(status.status, 'up_to_date');
  });
});

test('network and HTTP failures become unknown without throwing', async () => {
  await withEnv({
    TALONHOUND_VERSION: '0.1.0-beta.1',
    UPDATE_CHANNEL: 'beta',
    UPDATE_MANIFEST_URL: 'https://example.com/updates/beta.json'
  }, async () => {
    const service = createUpdateCheckService({
      fetchImpl: async () => {
        throw new Error('fetch failed');
      }
    });
    const status = await service.check({ force: true });
    assert.equal(status.status, 'unknown');
    assert.match(status.error, /Unable to reach/);
  });
});

test('concurrent checks share one outbound request', async () => {
  await withEnv({
    TALONHOUND_VERSION: '0.1.0-beta.1',
    UPDATE_CHANNEL: 'beta',
    UPDATE_MANIFEST_URL: 'https://example.com/updates/beta.json'
  }, async () => {
    let calls = 0;
    const service = createUpdateCheckService({
      fetchImpl: async () => {
        calls += 1;
        await new Promise((r) => setTimeout(r, 30));
        return {
          ok: true,
          status: 200,
          headers: { get: () => null },
          arrayBuffer: async () => Buffer.from(JSON.stringify(goodManifest))
        };
      }
    });
    const [a, b] = await Promise.all([
      service.check({ force: false }),
      service.check({ force: false })
    ]);
    assert.equal(a.status, 'update_available');
    assert.equal(b.status, 'update_available');
    assert.equal(calls, 1);
  });
});

test('disabled automatic checks still allow manual refresh', async () => {
  await withEnv({
    TALONHOUND_VERSION: '0.1.0-beta.1',
    UPDATE_CHANNEL: 'beta',
    UPDATE_MANIFEST_URL: 'https://example.com/updates/beta.json',
    UPDATE_CHECK_ENABLED: 'false'
  }, async () => {
    const service = createUpdateCheckService({
      fetchImpl: async () => ({
        ok: true,
        status: 200,
        headers: { get: () => null },
        arrayBuffer: async () => Buffer.from(JSON.stringify(goodManifest))
      })
    });
    service.startBackgroundChecks();
    const status = await service.check({ force: true });
    assert.equal(status.automaticChecksEnabled, false);
    assert.equal(status.status, 'update_available');
    service.stopBackgroundChecks();
  });
});

test('http failure and redirects are treated as unknown', async () => {
  await withEnv({
    TALONHOUND_VERSION: '0.1.0-beta.1',
    UPDATE_CHANNEL: 'beta',
    UPDATE_MANIFEST_URL: 'https://example.com/updates/beta.json'
  }, async () => {
    const httpFail = createUpdateCheckService({
      fetchImpl: async () => ({
        ok: false,
        status: 503,
        headers: { get: () => null },
        arrayBuffer: async () => Buffer.from('nope')
      })
    });
    const status = await httpFail.check({ force: true });
    assert.equal(status.status, 'unknown');

    const redirectFail = createUpdateCheckService({
      fetchImpl: async () => {
        const err = new Error('unexpected redirect');
        throw err;
      }
    });
    const redirected = await redirectFail.check({ force: true });
    assert.equal(redirected.status, 'unknown');
  });
});
