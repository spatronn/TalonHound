import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { settleWithTimeout } from './promiseTimeout.js';

describe('settleWithTimeout', () => {
  it('resolves with the operation value when it settles in time', async () => {
    const value = await settleWithTimeout(Promise.resolve({ rows: [1, 2] }), {
      timeoutMs: 1000,
      fallback: () => ({ rows: [] })
    });
    assert.deepEqual(value, { rows: [1, 2] });
  });

  it('falls back when the operation rejects', async () => {
    const value = await settleWithTimeout(Promise.reject(new Error('redis down')), {
      timeoutMs: 1000,
      fallback: () => 'fallback'
    });
    assert.equal(value, 'fallback');
  });

  it('falls back within the cap when the operation never settles (the Redis-stall bug)', async () => {
    // A promise that never resolves nor rejects models getRepeatableJobs() on an
    // ioredis client with maxRetriesPerRequest:null during a reconnect: the plain
    // .catch() fallback is unreachable, so without a timeout the request hangs.
    const neverSettles = new Promise(() => {});
    const started = Date.now();
    const value = await settleWithTimeout(neverSettles, {
      timeoutMs: 40,
      fallback: () => new Map()
    });
    const elapsed = Date.now() - started;
    assert.ok(value instanceof Map, 'returns the fallback value');
    assert.equal(value.size, 0);
    assert.ok(elapsed >= 30 && elapsed < 1000, `fell back promptly (elapsed=${elapsed}ms)`);
  });

  it('returns a fresh fallback instance per call (no shared mutable state)', async () => {
    const a = await settleWithTimeout(Promise.reject(new Error('x')), {
      timeoutMs: 20,
      fallback: () => new Map()
    });
    const b = await settleWithTimeout(Promise.reject(new Error('x')), {
      timeoutMs: 20,
      fallback: () => new Map()
    });
    a.set('k', 'v');
    assert.equal(b.has('k'), false, 'callers must not share the same fallback Map');
  });

  it('ignores a late success after the timeout already fell back', async () => {
    let resolveLate;
    const late = new Promise((r) => { resolveLate = r; });
    const value = await settleWithTimeout(late, { timeoutMs: 20, fallback: 'fb' });
    assert.equal(value, 'fb');
    // Late resolution must not throw or change the already-returned value.
    resolveLate('too late');
    await late;
  });
});
