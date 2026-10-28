import test from 'node:test';
import assert from 'node:assert/strict';
import {
  computeBackoffMs,
  createStartupRecovery,
  failStaleActiveJobs,
  startupRecoveryHealthEntry
} from './startupRecovery.js';

function capturingLog() {
  const lines = [];
  const at = (level) => (message, fields) => lines.push({ level, message, fields });
  return { lines, info: at('info'), warn: at('warn'), error: at('error') };
}

/** Virtual clock: sleep advances time instantly; returns elapsed virtual ms. */
function virtualClock(start = 1_700_000_000_000) {
  let t = start;
  const sleeps = [];
  return {
    now: () => t,
    elapsed: () => t - start,
    sleeps,
    sleep: async (ms, signal) => {
      if (signal?.aborted) throw new Error('aborted');
      sleeps.push(ms);
      t += ms;
    }
  };
}

const connRefused = () => Object.assign(new Error('connect ECONNREFUSED 172.18.0.2:5432'), { code: 'ECONNREFUSED' });

test('backoff is exponential, capped, jittered and never a tight loop', () => {
  assert.equal(computeBackoffMs(1, { random: () => 1 }), 1000);
  assert.equal(computeBackoffMs(4, { random: () => 1 }), 8000);
  assert.equal(computeBackoffMs(20, { random: () => 1 }), 30_000);
  assert.equal(computeBackoffMs(20, { random: () => 0 }), 100);
  const samples = new Set(Array.from({ length: 50 }, () => computeBackoffMs(6)));
  assert.ok(samples.size > 10, 'jitter spreads retries');
  assert.ok([...samples].every((ms) => ms >= 100 && ms <= 30_000));
});

test('PostgreSQL immediately available: one attempt, state completed', async () => {
  const log = capturingLog();
  const states = [];
  let calls = 0;
  const rec = createStartupRecovery({
    attempt: async () => ({ recovered: 0, claimed: (calls += 1, 0) }),
    log,
    onState: (s) => states.push(s.state)
  });
  const final = await rec.start();
  assert.equal(calls, 1);
  assert.equal(final.state, 'completed');
  assert.equal(final.attempts, 1);
  assert.deepEqual(states, ['running', 'completed']);
  assert.ok(log.lines.some((l) => l.message === 'startup recovery completed'));
});

for (const outageSeconds of [30, 60, 90]) {
  test(`PostgreSQL unavailable for ${outageSeconds}s at startup: retries with backoff, then recovers`, async () => {
    const clock = virtualClock();
    const log = capturingLog();
    let calls = 0;
    const rec = createStartupRecovery({
      attempt: async () => {
        calls += 1;
        if (clock.elapsed() < outageSeconds * 1000) throw connRefused();
        return { recovered: 2 };
      },
      log,
      sleep: clock.sleep,
      now: clock.now,
      random: () => 0.5
    });
    const final = await rec.start();
    assert.equal(final.state, 'completed');
    assert.ok(calls > 2, 'multiple failed attempts before success');
    assert.equal(final.attempts, calls);
    assert.ok(clock.elapsed() >= outageSeconds * 1000);
    // Recovers soon after PostgreSQL returns: the last wait is at most the cap.
    assert.ok(clock.elapsed() < outageSeconds * 1000 + 30_000);
    assert.ok(clock.sleeps.every((ms) => ms <= 30_000));
    const warns = log.lines.filter((l) => l.message === 'startup recovery failed; retrying');
    assert.ok(warns.length >= 1);
    assert.equal(warns[0].fields.code, 'ECONNREFUSED');
    assert.ok(Number.isFinite(warns[0].fields.retryInMs));
  });
}

test('a persistent outage escalates to error level periodically and keeps retrying', async () => {
  const clock = virtualClock();
  const log = capturingLog();
  let calls = 0;
  const rec = createStartupRecovery({
    attempt: async () => {
      calls += 1;
      if (calls < 20) throw connRefused();
      return {};
    },
    log,
    sleep: clock.sleep,
    now: clock.now,
    escalateAfter: 8
  });
  const final = await rec.start();
  assert.equal(final.state, 'completed');
  const errors = log.lines.filter((l) => l.level === 'error').map((l) => l.fields.attempt);
  assert.deepEqual(errors, [8, 16]);
});

test('state is published for health while retrying, with the last error', async () => {
  const clock = virtualClock();
  const states = [];
  let calls = 0;
  const rec = createStartupRecovery({
    attempt: async () => {
      calls += 1;
      if (calls < 3) throw connRefused();
      return {};
    },
    log: capturingLog(),
    onState: (s) => states.push({ ...s }),
    sleep: clock.sleep,
    now: clock.now
  });
  await rec.start();
  const retrying = states.filter((s) => s.state === 'retrying');
  assert.equal(retrying.length, 2);
  assert.match(retrying[1].last_error, /ECONNREFUSED/);
  assert.equal(states.at(-1).state, 'completed');
  assert.equal(states.at(-1).last_error, null);
});

test('connectivity dropping mid-recovery fails that attempt; the next one completes the work', async () => {
  // Steps run in order; the second step fails on the first attempt (connection lost).
  const done = new Set();
  let firstPass = true;
  const clock = virtualClock();
  const rec = createStartupRecovery({
    attempt: async () => {
      done.add('sweep');
      if (firstPass) {
        firstPass = false;
        throw Object.assign(new Error('Connection terminated unexpectedly'), { code: 'ECONNRESET' });
      }
      done.add('recover');
      done.add('dispatch');
      return {};
    },
    log: capturingLog(),
    sleep: clock.sleep,
    now: clock.now
  });
  const final = await rec.start();
  assert.equal(final.state, 'completed');
  assert.equal(final.attempts, 2);
  assert.deepEqual([...done], ['sweep', 'recover', 'dispatch']);
});

test('shutdown during a backoff wait stops retrying; start() is single-flight', async () => {
  const log = capturingLog();
  let calls = 0;
  let release;
  const parked = new Promise((r) => { release = r; });
  const rec = createStartupRecovery({
    attempt: async () => {
      calls += 1;
      throw connRefused();
    },
    log,
    sleep: (ms, signal) =>
      new Promise((resolve, reject) => {
        release();
        signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
      })
  });
  const a = rec.start();
  const b = rec.start();
  assert.equal(a, b, 'a second ready event does not start a second loop');
  await parked;
  const final = await rec.stop();
  assert.equal(final.state, 'cancelled');
  assert.equal(calls, 1);
  assert.equal((await a).state, 'cancelled');
});

test('shutdown while an attempt is in flight: no further attempt after it settles', async () => {
  let calls = 0;
  let failAttempt;
  const rec = createStartupRecovery({
    attempt: () => {
      calls += 1;
      return new Promise((_, reject) => { failAttempt = () => reject(connRefused()); });
    },
    log: capturingLog(),
    sleep: async () => {}
  });
  const run = rec.start();
  await new Promise((r) => setImmediate(r));
  rec.stop();
  failAttempt();
  assert.equal((await run).state, 'cancelled');
  assert.equal(calls, 1);
});

function fakeQueue(jobs) {
  const store = new Map(jobs.map((j) => [String(j.id), j]));
  return {
    store,
    async getJobs(states) {
      assert.deepEqual(states, ['active']);
      return [...store.values()].filter((j) => j.state === 'active');
    },
    async getJob(id) {
      return store.get(String(id)) || null;
    }
  };
}

function bullJob(id, processedOn, { failWith = null, vanish = null } = {}) {
  const job = {
    id,
    processedOn,
    state: 'active',
    data: { reportId: 100 + Number(id), jobId: Number(id) },
    moved: [],
    async moveToFailed(err, token, fetchNext) {
      if (failWith) throw failWith;
      if (vanish) {
        vanish();
        throw new Error('Missing key for job');
      }
      job.moved.push({ reason: err.message, token, fetchNext });
      job.state = 'failed';
    }
  };
  return job;
}

test('stale active sweep: force-fails the previous process\'s jobs, never live owners or this process\'s jobs', async () => {
  const startedAt = 1_000_000;
  const previous = bullJob(1, startedAt - 60_000);
  const liveOwner = bullJob(2, startedAt - 60_000);
  const ours = bullJob(3, startedAt + 5_000);
  const queue = fakeQueue([previous, liveOwner, ours]);
  const pool = {
    async query(sql, params) {
      assert.match(sql, /owner_token IS NOT NULL/);
      return { rows: params[0] === '2' ? [{ '?column?': 1 }] : [] };
    }
  };
  const log = capturingLog();
  const result = await failStaleActiveJobs({ queue, pool, workerStartedAt: startedAt, log });
  assert.deepEqual(result.moved.map((m) => m.bullmqJobId), [1]);
  assert.equal(result.skippedLiveOwner, 1);
  // Force token '0' (the dead process's lock token is unknown) and no fetchNext,
  // so the sweep never pulls a waiting job into a lock nobody holds.
  assert.deepEqual(previous.moved, [{ reason: 'worker_restarted', token: '0', fetchNext: false }]);
  assert.equal(liveOwner.moved.length, 0);
  assert.equal(ours.moved.length, 0);
  assert.equal(log.lines.filter((l) => l.message === 'stale analysis recovered').length, 1);
});

test('stale active sweep: a job that finished meanwhile is skipped; any other failure is surfaced for retry', async () => {
  const startedAt = 1_000_000;
  const queueGone = fakeQueue([]);
  const gone = bullJob(7, startedAt - 60_000, { vanish: () => queueGone.store.delete('7') });
  queueGone.store.set('7', gone);
  const pool = { async query() { return { rows: [] }; } };
  const ok = await failStaleActiveJobs({ queue: queueGone, pool, workerStartedAt: startedAt });
  assert.equal(ok.moved.length, 0);

  const broken = bullJob(8, startedAt - 60_000, { failWith: new Error('Connection is closed.') });
  await assert.rejects(
    failStaleActiveJobs({ queue: fakeQueue([broken]), pool, workerStartedAt: startedAt }),
    /Connection is closed/
  );
  // Database unavailable while checking ownership: the attempt fails (and is retried).
  const downPool = { async query() { throw connRefused(); } };
  await assert.rejects(
    failStaleActiveJobs({ queue: fakeQueue([bullJob(9, startedAt - 60_000)]), pool: downPool, workerStartedAt: startedAt }),
    /ECONNREFUSED/
  );
});

test('health row reflects recovery state and worker liveness', () => {
  const now = Date.parse('2026-10-28T12:00:00Z');
  const fresh = '2026-10-28T11:59:40Z';
  assert.equal(startupRecoveryHealthEntry(null).status, 'unknown');
  assert.equal(startupRecoveryHealthEntry({ state: 'completed', alive_at: fresh }, { now }).status, 'healthy');
  const retrying = startupRecoveryHealthEntry(
    { state: 'retrying', attempts: 4, last_error: 'connect ECONNREFUSED', alive_at: fresh },
    { now }
  );
  assert.equal(retrying.status, 'degraded');
  assert.match(retrying.evidence, /attempt 4/);
  const dead = startupRecoveryHealthEntry({ state: 'completed', alive_at: '2026-10-28T11:50:00Z' }, { now });
  assert.equal(dead.status, 'unhealthy');
  assert.equal(dead.reason, 'heartbeat_stale');
});
