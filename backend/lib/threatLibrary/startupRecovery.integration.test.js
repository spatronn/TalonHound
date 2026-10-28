import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import { createJob, createThreatReport } from './store.js';
import { claimJobOwnership } from './jobOwnership.js';
import { dispatchQueuedThreatLibraryAnalyses } from './analysisConcurrency.js';
import { createStartupRecovery, performStartupRecovery } from './startupRecovery.js';

/**
 * Startup recovery against real PostgreSQL with an in-memory stand-in for the
 * BullMQ queue (state per job id, lock-free force-fail). Run with
 * ALLOW_THREAT_LIBRARY_DB_TESTS=1 against a migrated throwaway database,
 * --test-concurrency=1 alongside the other TL itest files.
 */

const pool = new pg.Pool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound',
  connectionTimeoutMillis: 5000,
  max: 8
});

let hasDb = false;
if (process.env.ALLOW_THREAT_LIBRARY_DB_TESTS === '1') {
  try {
    await pool.query('SELECT owner_token, not_before FROM threat_library_jobs LIMIT 0');
    hasDb = true;
  } catch {
    hasDb = false;
  }
}
const opts = { skip: hasDb ? false : 'set ALLOW_THREAT_LIBRARY_DB_TESTS=1 with a migrated throwaway database to run' };

const created = [];
async function cleanup() {
  if (!hasDb || !created.length) return;
  const ids = created.splice(0);
  await pool.query('DELETE FROM threat_library_jobs WHERE report_id = ANY($1)', [ids]);
  await pool.query('DELETE FROM threat_reports WHERE id = ANY($1)', [ids]);
}
// Each scenario starts with free analysis slots.
test.afterEach(cleanup);
test.after(async () => {
  await cleanup();
  await pool.end();
});

const silent = { info() {}, warn() {}, error() {} };

async function newReport() {
  const report = await createThreatReport(pool, {
    title: `itest-startup-recovery-${crypto.randomUUID()}`,
    source_type: 'url',
    source_url: `https://example.test/${crypto.randomUUID()}`
  });
  created.push(report.id);
  return report;
}

/** BullMQ stand-in: jobs by id with a state; `active` jobs carry processedOn. */
function fakeQueue() {
  const jobs = new Map();
  const enqueued = [];
  const put = (id, state, processedOn = null, data = {}) => {
    const job = {
      id: String(id),
      state,
      processedOn,
      data,
      async getState() { return job.state; },
      async moveToFailed(_err, token) {
        assert.equal(token, '0');
        job.state = 'failed';
      }
    };
    jobs.set(String(id), job);
    return job;
  };
  return {
    put,
    enqueued,
    async getJobs(states) { return [...jobs.values()].filter((j) => states.includes(j.state)); },
    async getJob(id) { return jobs.get(String(id)) || null; },
    /** enqueue for dispatchQueuedThreatLibraryAnalyses: one new waiting BullMQ job. */
    enqueue: async (job) => {
      const id = `bull-${job.id}-${enqueued.length}`;
      enqueued.push(job.id);
      put(id, 'waiting', null, { jobId: job.id, reportId: job.report_id });
      return { id };
    }
  };
}

async function occupiedOutsideTest(ourReportIds) {
  const { rows } = await pool.query(
    `SELECT COUNT(*)::int AS n FROM threat_library_jobs
      WHERE status IN ('queued','running') AND bullmq_job_id IS NOT NULL AND NOT (report_id = ANY($1))`,
    [ourReportIds]
  );
  return rows[0].n;
}

async function jobRows(ids) {
  const { rows } = await pool.query(
    'SELECT id, status, owner_token, bullmq_job_id FROM threat_library_jobs WHERE id = ANY($1) ORDER BY id',
    [ids]
  );
  return Object.fromEntries(rows.map((r) => [r.id, r]));
}

/**
 * Previous worker process (started 1 min ago, now dead) left:
 *  A  queued, never claimed
 *  B  running, owned, heartbeat 10 min old, its BullMQ job still `active`
 *  C  claimed (queued + bullmq id), no owner, its BullMQ job still `active`
 *  D  running with a FRESH heartbeat — another live worker — BullMQ `active`
 */
async function strandedScenario(queue, previousStartedAt) {
  const reports = await Promise.all([newReport(), newReport(), newReport(), newReport()]);
  const [A, B, C, D] = await Promise.all(reports.map((r) => createJob(pool, { reportId: r.id, jobType: 'analyze' })));
  queue.put('old-B', 'active', previousStartedAt + 1000);
  queue.put('old-C', 'active', previousStartedAt + 1000);
  queue.put('live-D', 'active', previousStartedAt + 1000);
  await claimJobOwnership(pool, { jobId: B.id, ownerToken: crypto.randomUUID(), bullmqJobId: 'old-B' });
  await pool.query(`UPDATE threat_library_jobs SET heartbeat_at = NOW() - INTERVAL '10 minutes' WHERE id = $1`, [B.id]);
  await pool.query(`UPDATE threat_library_jobs SET bullmq_job_id = 'old-C' WHERE id = $1`, [C.id]);
  await claimJobOwnership(pool, { jobId: D.id, ownerToken: crypto.randomUUID(), bullmqJobId: 'live-D' });
  return { reports, A, B, C, D };
}

test('recovery against an empty queue is a no-op', opts, async () => {
  const queue = fakeQueue();
  const report = await newReport();
  const summary = await performStartupRecovery({
    queue,
    pool,
    workerStartedAt: Date.now(),
    log: silent,
    dispatch: () => dispatchQueuedThreatLibraryAnalyses(pool, { enqueue: queue.enqueue, limitOverride: 4 })
  });
  assert.equal(summary.staleActive, 0);
  assert.equal(summary.recovered, 0);
  assert.ok(!queue.enqueued.includes(report.id));
});

test('queued, interrupted and stale-claimed jobs are recovered once; a live owner is untouched; repeats never duplicate', opts, async (t) => {
  const queue = fakeQueue();
  const workerStartedAt = Date.now();
  const s = await strandedScenario(queue, workerStartedAt - 60_000);
  const ours = s.reports.map((r) => r.id);
  const others = await occupiedOutsideTest(ours);
  if (others > 0) {
    t.skip(`${others} occupied analysis slots from other data; needs an idle database`);
    return;
  }
  const dispatch = () => dispatchQueuedThreatLibraryAnalyses(pool, { enqueue: queue.enqueue, limitOverride: 4 });

  const first = await performStartupRecovery({ queue, pool, workerStartedAt, log: silent, dispatch });
  assert.equal(first.staleActive, 2, 'old-B and old-C force-failed; live-D kept');
  assert.equal(first.staleActiveLiveOwner, 1);
  assert.equal((await queue.getJob('live-D')).state, 'active');
  assert.deepEqual([...queue.enqueued].sort(), [s.A.id, s.B.id, s.C.id].sort());

  const rows = await jobRows([s.A.id, s.B.id, s.C.id, s.D.id]);
  for (const id of [s.A.id, s.B.id, s.C.id]) {
    assert.equal(rows[id].status, 'queued');
    assert.equal(rows[id].owner_token, null);
    assert.match(rows[id].bullmq_job_id, /^bull-/);
  }
  assert.equal(rows[s.D.id].status, 'running');
  assert.equal(rows[s.D.id].bullmq_job_id, 'live-D');

  // Repeated recovery (retries, a second `ready`, safety-net passes): no new deliveries.
  for (let i = 0; i < 3; i += 1) {
    await performStartupRecovery({ queue, pool, workerStartedAt, log: silent, dispatch });
  }
  assert.equal(queue.enqueued.length, 3);
});

test('worker restart in the middle of recovery: the next process finishes it without duplicates', opts, async (t) => {
  const queue = fakeQueue();
  const firstStart = Date.now();
  const s = await strandedScenario(queue, firstStart - 60_000);
  if ((await occupiedOutsideTest(s.reports.map((r) => r.id))) > 0) {
    t.skip('needs an idle database');
    return;
  }
  // Process 1 dies after the sweep and recovery, before dispatch.
  await assert.rejects(
    performStartupRecovery({
      queue,
      pool,
      workerStartedAt: firstStart,
      log: silent,
      dispatch: async () => { throw new Error('SIGKILL'); }
    }),
    /SIGKILL/
  );
  assert.equal(queue.enqueued.length, 0);
  // Process 2 starts later and runs the whole sequence again.
  const dispatch = () => dispatchQueuedThreatLibraryAnalyses(pool, { enqueue: queue.enqueue, limitOverride: 4 });
  await performStartupRecovery({ queue, pool, workerStartedAt: Date.now() + 5000, log: silent, dispatch });
  assert.deepEqual([...queue.enqueued].sort(), [s.A.id, s.B.id, s.C.id].sort());
  const rows = await jobRows([s.D.id]);
  assert.equal(rows[s.D.id].status, 'running', 'live owner still untouched');
});

test('PostgreSQL connection lost mid-recovery: the retry loop completes it exactly once', opts, async (t) => {
  const queue = fakeQueue();
  const workerStartedAt = Date.now();
  const s = await strandedScenario(queue, workerStartedAt - 60_000);
  if ((await occupiedOutsideTest(s.reports.map((r) => r.id))) > 0) {
    t.skip('needs an idle database');
    return;
  }
  // The 3rd query of the first attempt fails as if the server went away.
  let queries = 0;
  let dropped = false;
  const flaky = {
    query: (...args) => {
      queries += 1;
      if (!dropped && queries === 3) {
        dropped = true;
        return Promise.reject(Object.assign(new Error('Connection terminated unexpectedly'), { code: 'ECONNRESET' }));
      }
      return pool.query(...args);
    },
    connect: () => pool.connect()
  };
  const rec = createStartupRecovery({
    attempt: () =>
      performStartupRecovery({
        queue,
        pool: flaky,
        workerStartedAt,
        log: silent,
        dispatch: () => dispatchQueuedThreatLibraryAnalyses(flaky, { enqueue: queue.enqueue, limitOverride: 4 })
      }),
    log: silent,
    sleep: async () => {}
  });
  const final = await rec.start();
  assert.ok(dropped);
  assert.equal(final.state, 'completed');
  assert.equal(final.attempts, 2);
  assert.deepEqual([...queue.enqueued].sort(), [s.A.id, s.B.id, s.C.id].sort());
});

test('recovery respects the analysis concurrency limit', opts, async (t) => {
  const queue = fakeQueue();
  const reports = await Promise.all(Array.from({ length: 5 }, () => newReport()));
  const others = await occupiedOutsideTest(reports.map((r) => r.id));
  if (others > 0) {
    t.skip('needs an idle database');
    return;
  }
  const jobs = await Promise.all(reports.map((r) => createJob(pool, { reportId: r.id, jobType: 'analyze' })));
  const dispatch = () => dispatchQueuedThreatLibraryAnalyses(pool, { enqueue: queue.enqueue, limitOverride: 2 });
  for (let i = 0; i < 3; i += 1) {
    const summary = await performStartupRecovery({ queue, pool, workerStartedAt: Date.now(), log: silent, dispatch });
    assert.ok(summary.occupied <= 2);
  }
  assert.equal(queue.enqueued.length, 2, 'only two slots ever assigned');
  const rows = await jobRows(jobs.map((j) => j.id));
  assert.equal(Object.values(rows).filter((r) => r.bullmq_job_id).length, 2);
  assert.equal(Object.values(rows).filter((r) => r.status === 'queued' && !r.bullmq_job_id).length, 3);
});
