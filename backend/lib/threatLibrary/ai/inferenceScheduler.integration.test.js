import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import { createInferenceScheduler } from './inferenceScheduler.js';
import { AI_FAILURE_CODES, aiFailure } from './timeouts.js';

/**
 * Real-Postgres checks of the shared inference-capacity scheduler: FIFO
 * fairness, capacity > 1, two "processes" (separate pools + scheduler
 * instances), crash reclaim through lease expiry, lease loss detection,
 * cancellation while waiting, and progress under connection-pool pressure.
 *
 * ALLOW_THREAT_LIBRARY_DB_TESTS=1 with a migrated throwaway database; every
 * test uses its own resource key and deletes its rows.
 */

const config = {
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound',
  connectionTimeoutMillis: 5000
};
const pool = new pg.Pool({ ...config, max: 6 });
const otherProcessPool = new pg.Pool({ ...config, max: 6 });

let hasDb = false;
if (process.env.ALLOW_THREAT_LIBRARY_DB_TESTS === '1') {
  try {
    await pool.query('SELECT 1 FROM threat_library_ai_capacity_leases LIMIT 0');
    hasDb = true;
  } catch {
    hasDb = false;
  }
}
const opts = { skip: hasDb ? false : 'set ALLOW_THREAT_LIBRARY_DB_TESTS=1 with a migrated throwaway database to run' };

test.after(async () => {
  await pool.end();
  await otherProcessPool.end();
});

const FAST = { pollMs: 25, waitLeaseMs: 1000, holdLeaseMs: 1500, heartbeatMs: 200, waitingNotifyMs: 50 };

function key() {
  return `test|http://scheduler-${crypto.randomUUID()}`;
}

async function cleanup(resourceKey) {
  await pool.query('DELETE FROM threat_library_ai_capacity_leases WHERE resource_key = $1', [resourceKey]);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

test('capacity 1: strict FIFO, one holder at a time, every waiter served (no starvation)', opts, async () => {
  const resourceKey = key();
  const scheduler = createInferenceScheduler(pool, FAST);
  const order = [];
  let holding = 0;
  let maxHolding = 0;
  try {
    const first = await scheduler.acquire({ resourceKey, capacity: 1, maxWaitMs: 10_000 });
    const waiters = [];
    for (let i = 0; i < 6; i += 1) {
      waiters.push(
        (async () => {
          const lease = await scheduler.acquire({ resourceKey, capacity: 1, maxWaitMs: 10_000, reportId: i });
          holding += 1;
          maxHolding = Math.max(maxHolding, holding);
          order.push(i);
          await sleep(30);
          holding -= 1;
          await lease.release();
        })()
      );
      // FIFO is arrival order at the database. Wait until this waiter's row is
      // committed before starting the next (a slow new pool connection could
      // otherwise let a later caller arrive first).
      while ((await pool.query(`SELECT COUNT(*)::int AS n FROM threat_library_ai_capacity_leases WHERE resource_key = $1 AND state = 'waiting'`, [resourceKey])).rows[0].n < i + 1) {
        await sleep(5);
      }
    }
    await sleep(50);
    await first.release();
    await Promise.all(waiters);
    assert.deepEqual(order, [0, 1, 2, 3, 4, 5], 'served in arrival order');
    assert.equal(maxHolding, 1);
    const { rows } = await pool.query('SELECT COUNT(*)::int AS n FROM threat_library_ai_capacity_leases WHERE resource_key = $1', [resourceKey]);
    assert.equal(rows[0].n, 0, 'no leaked lease rows');
  } finally {
    await cleanup(resourceKey);
  }
});

test('capacity 2: two concurrent holders, never three', opts, async () => {
  const resourceKey = key();
  const scheduler = createInferenceScheduler(pool, FAST);
  let holding = 0;
  let maxHolding = 0;
  try {
    await Promise.all(
      Array.from({ length: 6 }, async () => {
        const lease = await scheduler.acquire({ resourceKey, capacity: 2, maxWaitMs: 10_000 });
        holding += 1;
        maxHolding = Math.max(maxHolding, holding);
        await sleep(60);
        holding -= 1;
        await lease.release();
      })
    );
    assert.equal(maxHolding, 2);
  } finally {
    await cleanup(resourceKey);
  }
});

test('two processes (separate pools and scheduler instances) share one capacity budget', opts, async () => {
  const resourceKey = key();
  const backend = createInferenceScheduler(pool, FAST);
  const worker = createInferenceScheduler(otherProcessPool, FAST);
  let holding = 0;
  let maxHolding = 0;
  try {
    await Promise.all(
      Array.from({ length: 8 }, async (_, i) => {
        const scheduler = i % 2 ? backend : worker;
        const lease = await scheduler.acquire({ resourceKey, capacity: 1, maxWaitMs: 10_000 });
        holding += 1;
        maxHolding = Math.max(maxHolding, holding);
        await sleep(25);
        holding -= 1;
        await lease.release();
      })
    );
    assert.equal(maxHolding, 1);
  } finally {
    await cleanup(resourceKey);
  }
});

test('bounded wait: ai_capacity_wait_timeout, and the waiter row is removed', opts, async () => {
  const resourceKey = key();
  const scheduler = createInferenceScheduler(pool, FAST);
  try {
    const holder = await scheduler.acquire({ resourceKey, capacity: 1, maxWaitMs: 1000 });
    const started = Date.now();
    const err = await scheduler.acquire({ resourceKey, capacity: 1, maxWaitMs: 200 }).catch((e) => e);
    assert.equal(err.code, AI_FAILURE_CODES.AI_CAPACITY_WAIT_TIMEOUT);
    assert.ok(Date.now() - started < 1000);
    assert.ok(err.timing.slot_wait_ms >= 200);
    const { rows } = await pool.query(
      `SELECT state FROM threat_library_ai_capacity_leases WHERE resource_key = $1`,
      [resourceKey]
    );
    assert.deepEqual(rows.map((r) => r.state), ['holding']);
    await holder.release();
  } finally {
    await cleanup(resourceKey);
  }
});

test('cancellation while waiting rejects with the abort reason and frees the queue position', opts, async () => {
  const resourceKey = key();
  const scheduler = createInferenceScheduler(pool, FAST);
  try {
    const holder = await scheduler.acquire({ resourceKey, capacity: 1, maxWaitMs: 5000 });
    const controller = new AbortController();
    const pending = scheduler.acquire({ resourceKey, capacity: 1, maxWaitMs: 5000, signal: controller.signal });
    const behind = scheduler.acquire({ resourceKey, capacity: 1, maxWaitMs: 5000 });
    await sleep(80);
    controller.abort(aiFailure(AI_FAILURE_CODES.WORKER_SHUTDOWN));
    const err = await pending.catch((e) => e);
    assert.equal(err.code, AI_FAILURE_CODES.WORKER_SHUTDOWN);
    await holder.release();
    const next = await behind; // the cancelled waiter no longer blocks the one behind it
    await next.release();
  } finally {
    await cleanup(resourceKey);
  }
});

test('crashed holder (hosted provider, not fail-closed): its lease expires and the slot is reclaimed without manual cleanup', opts, async () => {
  const resourceKey = key();
  const scheduler = createInferenceScheduler(pool, FAST);
  try {
    // A holder from a process that died: no heartbeat, lease already expired.
    await pool.query(
      `INSERT INTO threat_library_ai_capacity_leases (resource_key, token, state, owner, lease_expires_at, acquired_at)
       VALUES ($1, $2::uuid, 'holding', 'dead-process', NOW() - INTERVAL '1 second', NOW() - INTERVAL '5 minutes')`,
      [resourceKey, crypto.randomUUID()]
    );
    const lease = await scheduler.acquire({ resourceKey, capacity: 1, maxWaitMs: 2000 });
    assert.ok(lease.waitMs < 1000);
    await lease.release();
  } finally {
    await cleanup(resourceKey);
  }
});

test('a live holder is never displaced: its heartbeat keeps the lease beyond the lease duration', opts, async () => {
  const resourceKey = key();
  const scheduler = createInferenceScheduler(pool, FAST);
  try {
    const holder = await scheduler.acquire({ resourceKey, capacity: 1, maxWaitMs: 2000 });
    const err = await scheduler.acquire({ resourceKey, capacity: 1, maxWaitMs: FAST.holdLeaseMs * 2 }).catch((e) => e);
    assert.equal(err.code, AI_FAILURE_CODES.AI_CAPACITY_WAIT_TIMEOUT, 'still held after 2x the lease duration');
    assert.equal(holder.lost, false);
    await holder.release();
  } finally {
    await cleanup(resourceKey);
  }
});

test('lease loss is detected (row removed by a reclaim) and reported to the holder', opts, async () => {
  const resourceKey = key();
  const scheduler = createInferenceScheduler(pool, FAST);
  try {
    const holder = await scheduler.acquire({ resourceKey, capacity: 1, maxWaitMs: 2000 });
    const lost = new Promise((resolve) => holder.onLost(resolve));
    await pool.query('DELETE FROM threat_library_ai_capacity_leases WHERE token = $1::uuid', [holder.token]);
    const err = await Promise.race([lost, sleep(2000).then(() => null)]);
    assert.ok(err, 'onLost fired');
    assert.equal(err.code, AI_FAILURE_CODES.AI_CAPACITY_LEASE_LOST);
    await holder.release();
  } finally {
    await cleanup(resourceKey);
  }
});

test('waiting holds no pool connection: 10 waiters progress through a 2-connection pool', opts, async () => {
  const resourceKey = key();
  const tiny = new pg.Pool({ ...config, max: 2 });
  const scheduler = createInferenceScheduler(tiny, FAST);
  try {
    const done = await Promise.all(
      Array.from({ length: 10 }, async () => {
        const lease = await scheduler.acquire({ resourceKey, capacity: 1, maxWaitMs: 15_000 });
        await sleep(20);
        await lease.release();
        return true;
      })
    );
    assert.equal(done.length, 10);
  } finally {
    await cleanup(resourceKey);
    await tiny.end();
  }
});

test('queue position is reported to waiters (progress UI) and snapshot shows live counts', opts, async () => {
  const resourceKey = key();
  const scheduler = createInferenceScheduler(pool, FAST);
  try {
    const holder = await scheduler.acquire({ resourceKey, capacity: 1, maxWaitMs: 2000 });
    const positions = [];
    const waiter = scheduler.acquire({ resourceKey, capacity: 1, maxWaitMs: 5000, onWaiting: (v) => positions.push(v.position) });
    await sleep(120);
    const snap = await scheduler.snapshot(resourceKey);
    assert.equal(snap.holding, 1);
    assert.equal(snap.waiting, 1);
    await holder.release();
    const lease = await waiter;
    assert.ok(positions.includes(1));
    await lease.release();
  } finally {
    await cleanup(resourceKey);
  }
});

/** Pool whose lease-renewal queries fail or hang on demand; everything else is real. */
function faultyRenewalPool(mode) {
  return {
    connect: () => pool.connect(),
    query: (sql, params) => {
      if (mode.value && /SET lease_expires_at = NOW\(\)[\s\S]*state = 'holding'/.test(String(sql)) && !/SET state = 'holding'/.test(String(sql))) {
        if (mode.value === 'throw') return Promise.reject(new Error('connection terminated'));
        if (mode.value === 'hang') return new Promise(() => {});
      }
      return pool.query(sql, params);
    }
  };
}

for (const fault of ['throw', 'hang']) {
  test(`lease renewal ${fault === 'throw' ? 'failing' : 'hanging'}: the holder gives the slot up before its lease can expire for others`, opts, async () => {
    const resourceKey = key();
    const mode = { value: null };
    const holderScheduler = createInferenceScheduler(faultyRenewalPool(mode), FAST);
    const other = createInferenceScheduler(pool, FAST);
    try {
      const holder = await holderScheduler.acquire({ resourceKey, capacity: 1, maxWaitMs: 2000 });
      const acquiredAt = Date.now();
      mode.value = fault;
      let lostAt = null;
      holder.onLost(() => { lostAt = Date.now(); });
      // A competitor polls the whole time; it can only get the slot once the row expires.
      const competitor = other.acquire({ resourceKey, capacity: 1, maxWaitMs: 10_000 });
      const lease = await competitor;
      const otherAt = Date.now();
      assert.ok(lostAt, 'holder learned it lost the lease');
      assert.ok(lostAt < otherAt, `loss (${lostAt - acquiredAt}ms) precedes the competitor's grant (${otherAt - acquiredAt}ms)`);
      assert.ok(otherAt - lostAt >= FAST.heartbeatMs, 'at least one heartbeat of margin');
      await lease.release();
      mode.value = null;
      await holder.release();
    } finally {
      await cleanup(resourceKey);
    }
  });
}

test('sustained contention: three reports issuing back-to-back requests are served round-robin, none starves', opts, async () => {
  const resourceKey = key();
  const scheduler = createInferenceScheduler(pool, FAST);
  const grants = [];
  try {
    await Promise.all(['A', 'B', 'C'].map(async (report, idx) => {
      await sleep(idx * 30);
      for (let n = 0; n < 5; n += 1) {
        const lease = await scheduler.acquire({ resourceKey, capacity: 1, maxWaitMs: 20_000, reportId: idx });
        grants.push(report);
        await sleep(25);
        await lease.release(); // immediately re-queues for its next chunk
      }
    }));
    assert.equal(grants.length, 15);
    // Once all three are queued, no report is granted twice in a row while others wait.
    const steady = grants.slice(2, 12);
    for (let i = 1; i < steady.length; i += 1) assert.notEqual(steady[i], steady[i - 1], `grants ${grants.join('')}`);
    for (const r of ['A', 'B', 'C']) assert.equal(grants.filter((g) => g === r).length, 5);
  } finally {
    await cleanup(resourceKey);
  }
});

const QFAST = { ...FAST, verifyIntervalMs: 200 };

test('quarantine is durable and fail-closed: after the quarantining process is gone it outlives its bound; waiters then fail fast', opts, async () => {
  const resourceKey = key();
  const crashed = createInferenceScheduler(pool, QFAST);
  const survivor = createInferenceScheduler(otherProcessPool, QFAST);
  try {
    const lease = await crashed.acquire({ resourceKey, capacity: 1, maxWaitMs: 2000, failClosed: true, maxExecutionMs: 1000 });
    await lease.quarantine({ holdMs: 1000, reason: 'first_token_timeout' });
    const quarantinedAt = Date.now();
    // The quarantining process "dies": no release, no heartbeat. The provider never proves idle.
    let probes = 0;
    const err = await survivor.acquire({ resourceKey, capacity: 1, maxWaitMs: 10_000, failClosed: true, verifyIdle: async () => { probes += 1; return false; } }).catch((e) => e);
    const waited = Date.now() - quarantinedAt;
    assert.equal(err.code, AI_FAILURE_CODES.AI_CAPACITY_QUARANTINED, 'explicit state, not reuse');
    assert.ok(waited >= 950 && waited < 3000, `waited out the bound, then failed fast (${waited}ms), far below its 10s budget`);
    assert.ok(probes >= 2, 'the waiter probed meanwhile');
    await sleep(500);
    const { rows } = await pool.query(`SELECT state FROM threat_library_ai_capacity_leases WHERE resource_key = $1 AND quarantined_at IS NOT NULL`, [resourceKey]);
    assert.deepEqual(rows.map((r) => r.state), ['holding'], 'still held long after the bound: time never frees it');
    // Recovery: the provider proves idle.
    const next = await survivor.acquire({ resourceKey, capacity: 1, maxWaitMs: 5000, failClosed: true, verifyIdle: async () => true });
    await next.release();
  } finally {
    await cleanup(resourceKey);
  }
});

test('quarantine is released early by a waiter in another process once the provider proves idle', opts, async () => {
  const resourceKey = key();
  const a = createInferenceScheduler(pool, QFAST);
  const b = createInferenceScheduler(otherProcessPool, QFAST);
  try {
    const lease = await a.acquire({ resourceKey, capacity: 1, maxWaitMs: 2000 });
    await lease.quarantine({ holdMs: 60_000 });
    const started = Date.now();
    let busyUntil = Date.now() + 400; // the abandoned request finishes on the provider at +400ms
    const next = await b.acquire({ resourceKey, capacity: 1, maxWaitMs: 5000, verifyIdle: async () => Date.now() >= busyUntil });
    const waited = Date.now() - started;
    assert.ok(waited >= 400 && waited < 1500, `released after the provider went idle (${waited}ms), long before the 60s bound`);
    const { rows } = await pool.query(`SELECT COUNT(*)::int AS n FROM threat_library_ai_capacity_leases WHERE resource_key = $1 AND quarantined_at IS NOT NULL`, [resourceKey]);
    assert.equal(rows[0].n, 0);
    await next.release();
    busyUntil = 0;
  } finally {
    await cleanup(resourceKey);
  }
});

test('probes of one quarantined slot are claim-guarded across processes (no probe storm); past the bound both waiters fail fast', opts, async () => {
  const resourceKey = key();
  const a = createInferenceScheduler(pool, QFAST);
  const b2 = createInferenceScheduler(otherProcessPool, QFAST);
  try {
    const lease = await a.acquire({ resourceKey, capacity: 1, maxWaitMs: 2000, failClosed: true });
    await lease.quarantine({ holdMs: 1000 });
    let probes = 0;
    const verifyIdle = async () => { probes += 1; return false; };
    const started = Date.now();
    // Two waiters (two processes) behind the same quarantined slot, polling every 25ms.
    const w1 = a.acquire({ resourceKey, capacity: 1, maxWaitMs: 5000, failClosed: true, verifyIdle }).catch((e) => e);
    await sleep(20);
    const w2 = b2.acquire({ resourceKey, capacity: 1, maxWaitMs: 5000, failClosed: true, verifyIdle }).catch((e) => e);
    const [e1, e2] = await Promise.all([w1, w2]);
    const elapsed = Date.now() - started;
    assert.equal(e1.code, AI_FAILURE_CODES.AI_CAPACITY_QUARANTINED);
    assert.equal(e2.code, AI_FAILURE_CODES.AI_CAPACITY_QUARANTINED);
    const maxProbes = Math.ceil(elapsed / QFAST.verifyIntervalMs) + 1;
    assert.ok(probes <= maxProbes, `${probes} probes in ${elapsed}ms (≤ ${maxProbes} at one per ${QFAST.verifyIntervalMs}ms)`);
  } finally {
    await cleanup(resourceKey);
  }
});

test('quarantine after a lost lease re-occupies the slot instead of letting a request overlap', opts, async () => {
  const resourceKey = key();
  const scheduler = createInferenceScheduler(pool, QFAST);
  try {
    const lease = await scheduler.acquire({ resourceKey, capacity: 1, maxWaitMs: 2000 });
    await pool.query('DELETE FROM threat_library_ai_capacity_leases WHERE token = $1::uuid', [lease.token]);
    await lease.quarantine({ holdMs: 5000 });
    const { rows } = await pool.query(
      `SELECT state, purpose, quarantined_at IS NOT NULL AS q FROM threat_library_ai_capacity_leases WHERE resource_key = $1`,
      [resourceKey]
    );
    assert.deepEqual(rows, [{ state: 'holding', purpose: 'quarantine', q: true }]);
    const err = await scheduler.acquire({ resourceKey, capacity: 1, maxWaitMs: 300 }).catch((e) => e);
    assert.equal(err.code, AI_FAILURE_CODES.AI_CAPACITY_WAIT_TIMEOUT, 'capacity 1 stays occupied');
  } finally {
    await cleanup(resourceKey);
  }
});

/** A pool whose queries all fail while `outage.down` (this process lost the database). */
function outagePool(outage) {
  return {
    connect: async () => {
      if (outage.down) throw new Error('connect ECONNREFUSED (database outage)');
      return pool.connect();
    },
    query: (sql, params) => (outage.down ? Promise.reject(new Error('connect ECONNREFUSED (database outage)')) : pool.query(sql, params))
  };
}

test('database outage during cancellation: the expired lease becomes a quarantine, never free capacity, while the old inference still runs', opts, async () => {
  const resourceKey = key();
  const outage = { down: false };
  const holderScheduler = createInferenceScheduler(outagePool(outage), QFAST);
  const other = createInferenceScheduler(otherProcessPool, QFAST);
  try {
    const holder = await holderScheduler.acquire({ resourceKey, capacity: 1, maxWaitMs: 2000, failClosed: true, maxExecutionMs: 10_000 });
    // Outage: renewals fail; the holder aborts its request (as client.js does on
    // lease loss) and tries to quarantine, which cannot be written either.
    outage.down = true;
    const lost = await new Promise((resolve) => holder.onLost(resolve));
    assert.equal(lost.code, AI_FAILURE_CODES.AI_CAPACITY_LEASE_LOST);
    await holder.quarantine({ holdMs: 10_000, reason: 'ai_capacity_lease_lost' }); // fails silently: database down
    // The lease row expires during the outage (holdLeaseMs 1500).
    await sleep(QFAST.holdLeaseMs + 200);
    // The database is back for everyone else; the old inference is still running on the provider.
    let providerBusy = true;
    let probes = 0;
    let grantedAt = null;
    const waiter = other.acquire({
      resourceKey, capacity: 1, maxWaitMs: 10_000, failClosed: true,
      verifyIdle: async () => { probes += 1; return !providerBusy; }
    }).then((lease) => { grantedAt = Date.now(); return lease; });
    await sleep(700);
    assert.equal(grantedAt, null, 'no capacity handed out while termination is unverified');
    const { rows } = await pool.query(`SELECT state, purpose FROM threat_library_ai_capacity_leases WHERE resource_key = $1 AND quarantined_at IS NOT NULL`, [resourceKey]);
    assert.deepEqual(rows, [{ state: 'holding', purpose: 'quarantine:lease_expired' }], 'fail-closed conversion of the expired lease');
    assert.ok(probes >= 1);
    const idleAt = Date.now();
    providerBusy = false; // the old inference finished
    const lease = await waiter;
    assert.ok(grantedAt >= idleAt, 'granted only after the provider proved idle');
    await lease.release();
  } finally {
    outage.down = false;
    await cleanup(resourceKey);
  }
});

test('multiple workers reclaiming after an outage: one probe at a time, no grant before proof, never two holders', opts, async () => {
  const resourceKey = key();
  const crashed = createInferenceScheduler(pool, QFAST);
  const w1 = createInferenceScheduler(pool, QFAST);
  const w2 = createInferenceScheduler(otherProcessPool, QFAST);
  let holding = 0;
  let maxHolding = 0;
  try {
    // A holder whose process vanished during the outage: its lease simply expires.
    const dead = await crashed.acquire({ resourceKey, capacity: 1, maxWaitMs: 2000, failClosed: true, maxExecutionMs: 60_000 });
    await pool.query(`UPDATE threat_library_ai_capacity_leases SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE token = $1::uuid`, [dead.token]);
    let providerBusy = true;
    let probes = 0;
    let concurrentProbes = 0;
    let maxConcurrentProbes = 0;
    const verifyIdle = async () => {
      probes += 1;
      concurrentProbes += 1;
      maxConcurrentProbes = Math.max(maxConcurrentProbes, concurrentProbes);
      await sleep(30);
      concurrentProbes -= 1;
      return !providerBusy;
    };
    const run = async (scheduler) => {
      const lease = await scheduler.acquire({ resourceKey, capacity: 1, maxWaitMs: 15_000, failClosed: true, verifyIdle });
      holding += 1;
      maxHolding = Math.max(maxHolding, holding);
      await sleep(60);
      holding -= 1;
      await lease.release();
    };
    const started = Date.now();
    const both = Promise.all([run(w1), run(w2)]);
    await sleep(800);
    assert.equal(maxHolding, 0, 'nobody was granted while the provider was busy');
    const elapsed = Date.now() - started;
    assert.ok(probes <= Math.ceil(elapsed / QFAST.verifyIntervalMs) + 1, `${probes} probes in ${elapsed}ms: claim-guarded`);
    assert.equal(maxConcurrentProbes, 1, 'never two probes of the slot at once');
    providerBusy = false;
    await both;
    assert.equal(maxHolding, 1, 'capacity 1 respected across workers');
    dead.release().catch(() => {});
  } finally {
    await cleanup(resourceKey);
  }
});

test('administrator release frees quarantined capacity explicitly (and only quarantined rows)', opts, async () => {
  const resourceKey = key();
  const scheduler = createInferenceScheduler(pool, QFAST);
  try {
    const stuck = await scheduler.acquire({ resourceKey, capacity: 2, maxWaitMs: 2000, failClosed: true });
    await stuck.quarantine({ holdMs: 1 });
    const live = await scheduler.acquire({ resourceKey, capacity: 2, maxWaitMs: 2000, failClosed: true });
    const blocked = await scheduler.acquire({ resourceKey, capacity: 2, maxWaitMs: 5000, failClosed: true, verifyIdle: async () => false }).catch((e) => e);
    assert.equal(blocked.code, AI_FAILURE_CODES.AI_CAPACITY_QUARANTINED);
    assert.equal(await scheduler.releaseQuarantined(resourceKey), 1);
    const { rows } = await pool.query(`SELECT COUNT(*)::int AS n FROM threat_library_ai_capacity_leases WHERE resource_key = $1 AND state = 'holding'`, [resourceKey]);
    assert.equal(rows[0].n, 1, 'the live holder is untouched');
    const next = await scheduler.acquire({ resourceKey, capacity: 2, maxWaitMs: 2000, failClosed: true });
    await next.release();
    await live.release();
  } finally {
    await cleanup(resourceKey);
  }
});
