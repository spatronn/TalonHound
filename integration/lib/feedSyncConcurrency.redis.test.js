/**
 * Redis-backed proof of the global feed-sync concurrency ceiling.
 *
 * These exercise the real BullMQ global-concurrency primitive (setGlobalConcurrency)
 * that worker.js relies on — not a stand-in — so they prove the invariant holds
 * where it actually matters, including across multiple worker instances (Test H).
 *
 * They require a reachable Redis and self-skip when none is available (e.g. plain
 * local checkout). Run them where Redis lives, e.g. inside the deployed stack:
 *   docker compose exec -T integration-worker node --test lib/feedSyncConcurrency.redis.test.js
 *
 * Every run uses a unique, disposable queue name and obliterates it afterwards, so
 * production queues (integration-imports) are never touched.
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';

// Dynamically load the Redis/BullMQ deps so a checkout without node_modules (e.g.
// the git worktree used for review) self-skips instead of failing to import.
let IORedis;
let Queue;
let Worker;
let DEPS_AVAILABLE = true;
try {
  ({ default: IORedis } = await import('ioredis'));
  ({ Queue, Worker } = await import('bullmq'));
} catch {
  DEPS_AVAILABLE = false;
}

function redisUrlFromEnv() {
  const legacy = process.env.REDIS_URL?.trim();
  if (legacy) return legacy;
  const host = process.env.REDIS_HOST || '127.0.0.1';
  const port = String(process.env.REDIS_PORT || '6379');
  const pass = process.env.REDIS_PASSWORD;
  return pass ? `redis://:${encodeURIComponent(pass)}@${host}:${port}` : `redis://${host}:${port}`;
}

async function probeRedis(url) {
  const probe = new IORedis(url, { maxRetriesPerRequest: 1, connectTimeout: 1500, lazyConnect: true, retryStrategy: () => null });
  try {
    await probe.connect();
    await probe.ping();
    return true;
  } catch {
    return false;
  } finally {
    probe.disconnect();
  }
}

const REDIS_URL = redisUrlFromEnv();
const REDIS_AVAILABLE = DEPS_AVAILABLE && await probeRedis(REDIS_URL);

if (!DEPS_AVAILABLE) {
  console.warn('[feedSyncConcurrency.redis.test] ioredis/bullmq not installed here; skipping global-concurrency integration tests.');
} else if (!REDIS_AVAILABLE) {
  // Surface clearly why the real-infra proof did not run.
  console.warn(`[feedSyncConcurrency.redis.test] Redis unreachable at ${REDIS_URL.replace(/:\/\/[^@]*@/, '://***@')}; skipping global-concurrency integration tests.`);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(predicate, { timeoutMs = 5000, intervalMs = 15 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return true;
    await sleep(intervalMs);
  }
  return false;
}

function uniqueQueueName() {
  return `test-feed-sync-conc-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

describe('global feed-sync concurrency (Redis-backed)', { skip: !REDIS_AVAILABLE }, () => {
  let connection;
  // BullMQ does NOT close a connection the caller passes in, so every worker
  // connection is tracked and quit here — otherwise lingering ioredis handles
  // keep the event loop alive and `node --test` never exits.
  const workerConnections = [];

  function spawnWorker(queueName, processor, concurrency) {
    const conn = connection.duplicate();
    workerConnections.push(conn);
    return new Worker(queueName, processor, { connection: conn, concurrency });
  }

  before(() => {
    connection = new IORedis(REDIS_URL, { maxRetriesPerRequest: null });
  });

  after(async () => {
    for (const conn of workerConnections) await conn.quit().catch(() => {});
    if (connection) await connection.quit().catch(() => {});
  });

  // Shared concurrency observer: increments on entry, decrements on exit, tracks
  // the peak number simultaneously inside the processor body.
  function makeTracker() {
    const state = { active: 0, max: 0, started: [], finished: [] };
    return {
      state,
      enter(id) {
        state.active += 1;
        state.max = Math.max(state.max, state.active);
        state.started.push(id);
      },
      exit(id) {
        state.active -= 1;
        state.finished.push(id);
      }
    };
  }

  it('Test A/H — caps at 2 even with local capacity for 4 across two workers', async () => {
    const queueName = uniqueQueueName();
    const queue = new Queue(queueName, { connection });
    await queue.setGlobalConcurrency(2);

    const tracker = makeTracker();
    const processor = async (job) => {
      tracker.enter(job.data.id);
      await sleep(120);
      tracker.exit(job.data.id);
      return { ok: true };
    };

    // Two independent Worker instances, each with local concurrency 2 => local
    // capacity 4. If the cap were merely per-worker, peak would reach 4.
    const workerA = spawnWorker(queueName, processor, 2);
    const workerB = spawnWorker(queueName, processor, 2);

    try {
      for (let i = 0; i < 6; i += 1) {
        await queue.add('threatfeed-sync', { id: `feed-${i}` });
      }
      const done = await waitFor(() => tracker.state.finished.length === 6, { timeoutMs: 8000 });
      assert.equal(done, true, 'all 6 jobs should complete');
      assert.equal(tracker.state.max, 2, `peak concurrency must be exactly 2, saw ${tracker.state.max}`);
    } finally {
      await workerA.close();
      await workerB.close();
      await queue.obliterate({ force: true }).catch(() => {});
      await queue.close();
    }
  });

  it('Test B — third job waits for a slot, then starts on handoff', async () => {
    const queueName = uniqueQueueName();
    const queue = new Queue(queueName, { connection });
    await queue.setGlobalConcurrency(2);

    const tracker = makeTracker();
    const gates = new Map();
    const gateFor = (id) => {
      if (!gates.has(id)) {
        let release;
        const p = new Promise((res) => { release = res; });
        gates.set(id, { p, release });
      }
      return gates.get(id);
    };

    const worker = spawnWorker(queueName, async (job) => {
      tracker.enter(job.data.id);
      await gateFor(job.data.id).p; // block until the test releases this job
      tracker.exit(job.data.id);
      return { ok: true };
    }, 4); // local capacity 4 > global 2

    try {
      await queue.add('sync', { id: 'A' });
      await queue.add('sync', { id: 'B' });
      await queue.add('sync', { id: 'C' });

      // A and B occupy both global slots; C must not start.
      const twoRunning = await waitFor(() => tracker.state.active === 2 && tracker.state.started.length === 2);
      assert.equal(twoRunning, true, 'exactly A and B should be running');
      await sleep(250);
      assert.equal(tracker.state.started.includes('C'), false, 'C must wait for a free slot');
      assert.equal(tracker.state.max, 2);

      // Free one slot: A completes -> C should start automatically.
      gateFor('A').release();
      const cStarted = await waitFor(() => tracker.state.started.includes('C'));
      assert.equal(cStarted, true, 'C should start once a slot frees');
      assert.equal(tracker.state.max, 2, 'concurrency must never exceed 2 during handoff');

      gateFor('B').release();
      gateFor('C').release();
      const allDone = await waitFor(() => tracker.state.finished.length === 3, { timeoutMs: 8000 });
      assert.equal(allDone, true);
    } finally {
      for (const g of gates.values()) g.release();
      await worker.close();
      await queue.obliterate({ force: true }).catch(() => {});
      await queue.close();
    }
  });

  it('Test D — manual and scheduled triggers share one limiter', async () => {
    const queueName = uniqueQueueName();
    const queue = new Queue(queueName, { connection });
    await queue.setGlobalConcurrency(2);

    const tracker = makeTracker();
    const worker = spawnWorker(queueName, async (job) => {
      tracker.enter(job.data.id);
      await sleep(120);
      tracker.exit(job.data.id);
      return { ok: true };
    }, 4);

    try {
      // Two scheduled jobs already queued, then a manual "Sync Now" arrives.
      await queue.add('sync', { id: 'sched-1', triggeredBy: 'scheduler' });
      await queue.add('sync', { id: 'sched-2', triggeredBy: 'scheduler' });
      await queue.add('sync', { id: 'manual-1', triggeredBy: 'manual-ui-one' }, { priority: 1 });

      const done = await waitFor(() => tracker.state.finished.length === 3, { timeoutMs: 8000 });
      assert.equal(done, true);
      // The manual job did NOT create a third concurrent slot.
      assert.equal(tracker.state.max, 2, `manual trigger must not exceed the shared cap, saw ${tracker.state.max}`);
    } finally {
      await worker.close();
      await queue.obliterate({ force: true }).catch(() => {});
      await queue.close();
    }
  });

  it('Test E — a failed job releases its slot so a waiting job runs', async () => {
    const queueName = uniqueQueueName();
    const queue = new Queue(queueName, { connection });
    await queue.setGlobalConcurrency(2);

    const tracker = makeTracker();
    // local concurrency 4 > global 2; jobs enqueued with attempts:1 so the
    // failure is terminal and deterministic.
    const worker = spawnWorker(queueName, async (job) => {
      tracker.enter(job.data.id);
      try {
        if (job.data.id === 'A') {
          await sleep(40);
          throw new Error('simulated feed failure');
        }
        await sleep(200);
        return { ok: true };
      } finally {
        tracker.exit(job.data.id);
      }
    }, 4);

    try {
      await queue.add('sync', { id: 'A' }, { attempts: 1 });
      await queue.add('sync', { id: 'B' }, { attempts: 1 });
      await queue.add('sync', { id: 'C' }, { attempts: 1 });

      const cRan = await waitFor(() => tracker.state.finished.includes('C'), { timeoutMs: 8000 });
      assert.equal(cRan, true, 'C must run after A fails and frees a slot');
      assert.ok(tracker.state.finished.includes('A'), 'A should have terminated (failed)');
      assert.equal(tracker.state.max, 2, 'concurrency must stay within the cap even through a failure');
      // Capacity was not permanently reduced from 2 to 1.
      assert.equal(tracker.state.finished.length, 3);
    } finally {
      await worker.close();
      await queue.obliterate({ force: true }).catch(() => {});
      await queue.close();
    }
  });
});
