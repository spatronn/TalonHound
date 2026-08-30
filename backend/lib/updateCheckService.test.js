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

function jsonResponse(body, status = 200, headerMap = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get: (name) => headerMap[String(name).toLowerCase()] ?? headerMap[name] ?? null
    },
    arrayBuffer: async () => Buffer.from(typeof body === 'string' ? body : JSON.stringify(body))
  };
}

function betaManifest(overrides = {}) {
  return {
    schemaVersion: 1,
    channel: 'beta',
    latest: '0.1.0-beta.3',
    released_at: '2026-09-04T12:00:00Z',
    minimum_supported_version: '0.1.0-beta.1',
    release_url: 'https://github.com/spatronn/TalonHound/releases/tag/v0.1.0-beta.3',
    critical: false,
    ...overrides
  };
}

function stableManifest(overrides = {}) {
  return {
    schemaVersion: 1,
    channel: 'stable',
    latest: '0.1.0',
    released_at: '2026-09-04T12:00:00Z',
    release_url: 'https://github.com/spatronn/TalonHound/releases/tag/v0.1.0',
    critical: false,
    ...overrides
  };
}

test('A. stable release equal current => up_to_date', async () => {
  await withEnv({
    TALONHOUND_VERSION: '0.1.0',
    UPDATE_CHANNEL: 'stable',
    UPDATE_MANIFEST_URL: 'https://example.com/updates/stable.json'
  }, async () => {
    const service = createUpdateCheckService({
      fetchImpl: async () => jsonResponse(stableManifest({ latest: '0.1.0' }))
    });
    const status = await service.check({ force: true });
    assert.equal(status.status, 'up_to_date');
    assert.equal(status.latestVersion, '0.1.0');
    assert.equal(status.error, null);
  });
});

test('B. stable newer release => update_available', async () => {
  await withEnv({
    TALONHOUND_VERSION: '0.1.0',
    UPDATE_CHANNEL: 'stable',
    UPDATE_MANIFEST_URL: 'https://example.com/updates/stable.json'
  }, async () => {
    const service = createUpdateCheckService({
      fetchImpl: async () => jsonResponse(stableManifest({ latest: '0.2.0' }))
    });
    const status = await service.check({ force: true });
    assert.equal(status.status, 'update_available');
    assert.equal(status.latestVersion, '0.2.0');
  });
});

test('C. beta newer prerelease => update_available', async () => {
  await withEnv({
    TALONHOUND_VERSION: '0.1.0-beta.1',
    UPDATE_CHANNEL: 'beta',
    UPDATE_MANIFEST_URL: 'https://example.com/updates/beta.json'
  }, async () => {
    const service = createUpdateCheckService({
      fetchImpl: async () => jsonResponse(betaManifest({ latest: '0.1.0-beta.2' }))
    });
    const status = await service.check({ force: true });
    assert.equal(status.status, 'update_available');
    assert.equal(status.latestVersion, '0.1.0-beta.2');
  });
});

test('D. beta channel accepts prerelease latest', async () => {
  await withEnv({
    TALONHOUND_VERSION: '0.1.0-beta.1',
    UPDATE_CHANNEL: 'beta',
    UPDATE_MANIFEST_URL: 'https://example.com/updates/beta.json'
  }, async () => {
    const service = createUpdateCheckService({
      fetchImpl: async () => jsonResponse(betaManifest({ latest: '0.1.0-beta.2' }))
    });
    const status = await service.check({ force: true });
    assert.equal(status.latestVersion, '0.1.0-beta.2');
    assert.equal(status.status, 'update_available');
  });
});

test('E. stable channel rejects prerelease latest in manifest', async () => {
  await withEnv({
    TALONHOUND_VERSION: '0.1.0',
    UPDATE_CHANNEL: 'stable',
    UPDATE_MANIFEST_URL: 'https://example.com/updates/stable.json'
  }, async () => {
    const service = createUpdateCheckService({
      fetchImpl: async () => jsonResponse(stableManifest({ latest: '0.2.0-beta.1' }))
    });
    const status = await service.check({ force: true });
    assert.equal(status.status, 'check_failed');
    assert.match(status.error, /invalid/i);
  });
});

test('G. beta channel may publish a newer stable as latest', async () => {
  await withEnv({
    TALONHOUND_VERSION: '0.1.0-beta.2',
    UPDATE_CHANNEL: 'beta',
    UPDATE_MANIFEST_URL: 'https://example.com/updates/beta.json'
  }, async () => {
    const service = createUpdateCheckService({
      fetchImpl: async () => jsonResponse(betaManifest({
        latest: '0.1.0',
        release_url: 'https://github.com/spatronn/TalonHound/releases/tag/v0.1.0'
      }))
    });
    const status = await service.check({ force: true });
    assert.equal(status.status, 'update_available');
    assert.equal(status.latestVersion, '0.1.0');
  });
});

test('H. malformed latest in manifest => check_failed', async () => {
  await withEnv({
    TALONHOUND_VERSION: '0.1.0-beta.1',
    UPDATE_CHANNEL: 'beta',
    UPDATE_MANIFEST_URL: 'https://example.com/updates/beta.json'
  }, async () => {
    const service = createUpdateCheckService({
      fetchImpl: async () => jsonResponse(betaManifest({ latest: 'not-a-version' }))
    });
    const status = await service.check({ force: true });
    assert.equal(status.status, 'check_failed');
  });
});

test('I. leading v is not accepted as manifest latest (canonical SemVer without v)', async () => {
  await withEnv({
    TALONHOUND_VERSION: '0.1.0-beta.1',
    UPDATE_CHANNEL: 'beta',
    UPDATE_MANIFEST_URL: 'https://example.com/updates/beta.json'
  }, async () => {
    const service = createUpdateCheckService({
      fetchImpl: async () => jsonResponse(betaManifest({ latest: 'v0.1.0-beta.2' }))
    });
    const status = await service.check({ force: true });
    assert.equal(status.status, 'check_failed');
  });
});

test('J. HTTP 404 => no_release_published', async () => {
  await withEnv({
    TALONHOUND_VERSION: '0.1.0-beta.1',
    UPDATE_CHANNEL: 'beta',
    UPDATE_MANIFEST_URL: 'https://example.com/updates/beta.json'
  }, async () => {
    const service = createUpdateCheckService({
      fetchImpl: async () => jsonResponse('Not Found', 404)
    });
    const status = await service.check({ force: true });
    assert.equal(status.status, 'no_release_published');
    assert.equal(status.latestVersion, null);
    assert.equal(status.error, null);
  });
});

test('K. HTTP 403 / rate-limit => check_failed', async () => {
  await withEnv({
    TALONHOUND_VERSION: '0.1.0-beta.1',
    UPDATE_CHANNEL: 'beta',
    UPDATE_MANIFEST_URL: 'https://example.com/updates/beta.json'
  }, async () => {
    const logs = [];
    const service = createUpdateCheckService({
      logger: { warn: (...args) => logs.push(args), info: () => {} },
      fetchImpl: async () => jsonResponse('Forbidden', 403, {
        'x-ratelimit-remaining': '0',
        'x-ratelimit-reset': '999'
      })
    });
    const status = await service.check({ force: true });
    assert.equal(status.status, 'check_failed');
    assert.match(status.error, /rate-limited|error|reach|failed/i);
    assert.ok(logs.some((entry) => JSON.stringify(entry).includes('403')));
  });
});

test('L. HTTP 500 => check_failed', async () => {
  await withEnv({
    TALONHOUND_VERSION: '0.1.0-beta.1',
    UPDATE_CHANNEL: 'beta',
    UPDATE_MANIFEST_URL: 'https://example.com/updates/beta.json'
  }, async () => {
    const service = createUpdateCheckService({
      fetchImpl: async () => jsonResponse('error', 500)
    });
    const status = await service.check({ force: true });
    assert.equal(status.status, 'check_failed');
  });
});

test('M. no eligible release (404) leaves product usable with clear status', async () => {
  await withEnv({
    TALONHOUND_VERSION: '0.1.0',
    UPDATE_CHANNEL: 'stable',
    UPDATE_MANIFEST_URL: 'https://example.com/updates/stable.json'
  }, async () => {
    const service = createUpdateCheckService({
      fetchImpl: async () => jsonResponse('', 404)
    });
    const status = await service.check({ force: true });
    assert.equal(status.status, 'no_release_published');
  });
});

test('N. non-SemVer current version discovers latest without SemVer comparison', async () => {
  await withEnv({
    // Intentionally not the Docker placeholder "dev" (that falls back to VERSION).
    TALONHOUND_VERSION: 'unversioned-local',
    UPDATE_CHANNEL: 'beta',
    UPDATE_MANIFEST_URL: 'https://example.com/updates/beta.json'
  }, async () => {
    const service = createUpdateCheckService({
      fetchImpl: async () => jsonResponse(betaManifest({
        latest: '0.1.0-beta.1',
        release_url: 'https://github.com/spatronn/TalonHound/releases/tag/v0.1.0-beta.1'
      }))
    });
    const status = await service.check({ force: true });
    assert.equal(status.status, 'development_build');
    assert.equal(status.currentVersion, 'unversioned-local');
    assert.equal(status.latestVersion, '0.1.0-beta.1');
    assert.equal(status.releaseUrl, 'https://github.com/spatronn/TalonHound/releases/tag/v0.1.0-beta.1');
    assert.equal(status.error, null);
    assert.notEqual(status.status, 'up_to_date');
  });
});

test('N2. Docker placeholder TALONHOUND_VERSION=dev compares using VERSION file SemVer', async () => {
  await withEnv({
    TALONHOUND_VERSION: 'dev',
    UPDATE_CHANNEL: 'beta',
    UPDATE_MANIFEST_URL: 'https://example.com/updates/beta.json'
  }, async () => {
    const service = createUpdateCheckService({
      fetchImpl: async () => jsonResponse(betaManifest({
        latest: '0.1.0-beta.1',
        release_url: 'https://github.com/spatronn/TalonHound/releases/tag/v0.1.0-beta.1'
      }))
    });
    const status = await service.check({ force: true });
    assert.equal(status.currentVersion, '0.1.0-beta.1');
    assert.equal(status.latestVersion, '0.1.0-beta.1');
    assert.equal(status.status, 'up_to_date');
  });
});

test('O. network exception / timeout => check_failed', async () => {
  await withEnv({
    TALONHOUND_VERSION: '0.1.0-beta.1',
    UPDATE_CHANNEL: 'beta',
    UPDATE_MANIFEST_URL: 'https://example.com/updates/beta.json'
  }, async () => {
    const network = createUpdateCheckService({
      fetchImpl: async () => {
        throw new Error('fetch failed');
      }
    });
    const networkStatus = await network.check({ force: true });
    assert.equal(networkStatus.status, 'check_failed');
    assert.match(networkStatus.error, /Unable to reach/);

    const timeout = createUpdateCheckService({
      fetchImpl: async () => {
        const err = new Error('aborted');
        err.name = 'AbortError';
        throw err;
      }
    });
    const timeoutStatus = await timeout.check({ force: true });
    assert.equal(timeoutStatus.status, 'check_failed');
    assert.match(timeoutStatus.error, /Unable to reach/);
  });
});

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
        return jsonResponse(betaManifest());
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
      fetchImpl: async () => jsonResponse(betaManifest())
    });
    const status = await service.check({ force: true });
    assert.equal(status.status, 'up_to_date');
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
        return jsonResponse(betaManifest());
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
      fetchImpl: async () => jsonResponse(betaManifest())
    });
    service.startBackgroundChecks();
    const status = await service.check({ force: true });
    assert.equal(status.automaticChecksEnabled, false);
    assert.equal(status.status, 'update_available');
    service.stopBackgroundChecks();
  });
});

test('SemVer ordering does not treat 0.10.0 as less than 0.9.0', async () => {
  await withEnv({
    TALONHOUND_VERSION: '0.9.0',
    UPDATE_CHANNEL: 'stable',
    UPDATE_MANIFEST_URL: 'https://example.com/updates/stable.json'
  }, async () => {
    const service = createUpdateCheckService({
      fetchImpl: async () => jsonResponse(stableManifest({ latest: '0.10.0' }))
    });
    const status = await service.check({ force: true });
    assert.equal(status.status, 'update_available');
    assert.equal(status.latestVersion, '0.10.0');
  });
});
