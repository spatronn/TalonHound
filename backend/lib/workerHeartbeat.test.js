import test from 'node:test';
import assert from 'node:assert/strict';
import {
  HEARTBEAT_KEYS,
  touchWorkerHeartbeat,
  readWorkerHeartbeat,
  workerHeartbeatHealthEntry,
  WORKER_HEARTBEAT_STALE_MS_DEFAULT,
  resolveWorkerHeartbeatStaleMs
} from './workerHeartbeat.js';

function mockRedis(store = new Map()) {
  return {
    store,
    async set(key, value, ex, ttl) {
      assert.equal(ex, 'EX');
      store.set(key, { value: String(value), ttl });
    },
    async get(key) {
      const row = store.get(key);
      return row ? row.value : null;
    }
  };
}

test('resolveWorkerHeartbeatStaleMs defaults', () => {
  assert.equal(resolveWorkerHeartbeatStaleMs(undefined), WORKER_HEARTBEAT_STALE_MS_DEFAULT);
  assert.equal(resolveWorkerHeartbeatStaleMs('90000'), 90_000);
  assert.equal(resolveWorkerHeartbeatStaleMs('nope'), WORKER_HEARTBEAT_STALE_MS_DEFAULT);
});

test('HEARTBEAT_KEYS cover scheduler and expiration worker', () => {
  assert.ok(HEARTBEAT_KEYS.integration_scheduler.includes('integration_scheduler'));
  assert.ok(HEARTBEAT_KEYS.ioc_expiration_worker.includes('ioc_expiration_worker'));
});

test('readWorkerHeartbeat: unknown when key missing', async () => {
  const redis = mockRedis();
  const hb = await readWorkerHeartbeat(redis, HEARTBEAT_KEYS.integration_scheduler, { now: 1_000_000 });
  assert.deepEqual(hb, { lastSeen: null, ageMs: null, status: 'unknown' });
});

test('readWorkerHeartbeat: healthy when within freshness window', async () => {
  const redis = mockRedis();
  const now = 5_000_000;
  await touchWorkerHeartbeat(redis, HEARTBEAT_KEYS.ioc_expiration_worker, { now: now - 30_000 });
  const hb = await readWorkerHeartbeat(redis, HEARTBEAT_KEYS.ioc_expiration_worker, {
    now,
    staleMs: 120_000
  });
  assert.equal(hb.status, 'healthy');
  assert.equal(hb.lastSeen, now - 30_000);
  assert.equal(hb.ageMs, 30_000);
});

test('readWorkerHeartbeat: unhealthy when stale', async () => {
  const redis = mockRedis();
  const now = 5_000_000;
  await touchWorkerHeartbeat(redis, HEARTBEAT_KEYS.integration_scheduler, {
    now: now - 180_000
  });
  const hb = await readWorkerHeartbeat(redis, HEARTBEAT_KEYS.integration_scheduler, {
    now,
    staleMs: 120_000
  });
  assert.equal(hb.status, 'unhealthy');
  assert.equal(hb.ageMs, 180_000);
});

test('workerHeartbeatHealthEntry maps status to reason labels', () => {
  assert.equal(
    workerHeartbeatHealthEntry('k', 'N', { status: 'healthy', lastSeen: 1, ageMs: 0 }).reason,
    'heartbeat_fresh'
  );
  assert.equal(
    workerHeartbeatHealthEntry('k', 'N', { status: 'unhealthy', lastSeen: 1, ageMs: 9 }).reason,
    'heartbeat_stale'
  );
  assert.equal(
    workerHeartbeatHealthEntry('k', 'N', { status: 'unknown', lastSeen: null, ageMs: null }).reason,
    'heartbeat_missing'
  );
});
