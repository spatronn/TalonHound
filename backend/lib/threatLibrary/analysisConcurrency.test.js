/**
 * Threat Library AI concurrency: setting validation, FIFO claim, race-safe
 * slot budget, runtime limit changes, failure/restart recovery, and URL+PDF
 * sharing one budget. In-memory pool — no live database.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ANALYSIS_SLOT_LOCK_KEY,
  MAX_CONCURRENT_REPORT_ANALYSES_DEFAULT,
  MAX_CONCURRENT_REPORT_ANALYSES_MAX,
  MAX_CONCURRENT_REPORT_ANALYSES_MIN,
  cancelUnclaimedAnalysisJobs,
  dispatchExtraFromJob,
  dispatchQueuedThreatLibraryAnalyses,
  parseMaxConcurrentReportAnalyses,
  recoverInterruptedAnalysisJobs,
  resolveMaxConcurrentReportAnalyses,
  resolveThreatLibraryWorkerConcurrency
} from './analysisConcurrency.js';

test('setting: integer 1–4 only; default preserves historical worker concurrency of 2', () => {
  assert.equal(MAX_CONCURRENT_REPORT_ANALYSES_MIN, 1);
  assert.equal(MAX_CONCURRENT_REPORT_ANALYSES_MAX, 4);
  assert.equal(MAX_CONCURRENT_REPORT_ANALYSES_DEFAULT, 2);
  assert.equal(parseMaxConcurrentReportAnalyses(1), 1);
  assert.equal(parseMaxConcurrentReportAnalyses(4), 4);
  assert.equal(parseMaxConcurrentReportAnalyses('3'), 3);
  assert.equal(resolveMaxConcurrentReportAnalyses(null), 2);
  assert.equal(resolveMaxConcurrentReportAnalyses(undefined), 2);
  for (const bad of [0, 5, 1.5, '2.5', true, false, 'x', {}, []]) {
    assert.throws(() => parseMaxConcurrentReportAnalyses(bad), { code: 'invalid_max_concurrent_report_analyses' });
  }
});

test('worker process ceiling defaults to the setting maximum so a runtime increase needs no restart', () => {
  assert.equal(resolveThreatLibraryWorkerConcurrency(undefined), 4);
  assert.equal(resolveThreatLibraryWorkerConcurrency(''), 4);
  assert.equal(resolveThreatLibraryWorkerConcurrency('2'), 2);
  assert.equal(resolveThreatLibraryWorkerConcurrency('9'), 4);
  assert.equal(resolveThreatLibraryWorkerConcurrency('0'), 1);
});

test('dispatch extras reconstruct URL/PDF/retry payloads without inventing a second queue', () => {
  assert.deepEqual(dispatchExtraFromJob({
    job_type: 'analyze',
    source_url: 'https://vendor.example/a',
    progress: {}
  }), {
    sourceUrl: 'https://vendor.example/a',
    resumeAnalysis: false,
    newAnalysisRun: false,
    jobType: 'analyze'
  });
  assert.equal(dispatchExtraFromJob({ job_type: 'retry', progress: { dispatch: { newAnalysisRun: true } } }).resumeAnalysis, true);
  assert.equal(dispatchExtraFromJob({ job_type: 'retry', progress: { dispatch: { newAnalysisRun: true } } }).newAnalysisRun, true);
});

function createSchedulerWorld({ limit = 2, jobs = [] } = {}) {
  const state = {
    limit,
    jobs: jobs.map((j, i) => ({
      id: j.id ?? i + 1,
      report_id: j.report_id ?? j.id ?? i + 1,
      job_type: j.job_type || 'analyze',
      status: j.status || 'queued',
      bullmq_job_id: j.bullmq_job_id ?? null,
      progress: j.progress || {},
      created_at: j.created_at || new Date(Date.UTC(2026, 8, 1, 10, 0, i)),
      source_url: j.source_url || null,
      report_public_id: j.report_public_id || `r-${j.report_id ?? j.id ?? i + 1}`,
      source_type: j.source_type || 'url',
      deleted_at: j.deleted_at || null
    })),
    reports: new Map(),
    enqueued: [],
    lock: Promise.resolve(),
    lockHeld: false,
    maxObservedActive: 0
  };
  for (const job of state.jobs) {
    state.reports.set(job.report_id, {
      id: job.report_id,
      analysis_status: job.status === 'running' ? 'analyzing' : 'pending',
      import_status: 'processing'
    });
  }

  function occupiedCount() {
    return state.jobs.filter((j) => ['queued', 'running'].includes(j.status) && j.bullmq_job_id).length;
  }

  function refreshObserved() {
    state.maxObservedActive = Math.max(state.maxObservedActive, occupiedCount());
  }

  async function withLock(fn) {
    const previous = state.lock;
    let release;
    state.lock = new Promise((resolve) => { release = resolve; });
    await previous;
    state.lockHeld = true;
    try {
      return await fn();
    } finally {
      state.lockHeld = false;
      release();
    }
  }

  async function query(sql, params = []) {
    const s = String(sql);
    if (/^BEGIN|^COMMIT|^ROLLBACK/.test(s.trim())) return { rows: [] };
    if (/pg_advisory_xact_lock/.test(s)) {
      assert.equal(params[0], ANALYSIS_SLOT_LOCK_KEY);
      // The real dispatcher holds the xact lock for the whole transaction.
      // Tests that need overlap use connect() + concurrent dispatch.
      return { rows: [{}] };
    }
    if (/FROM threat_library_ai_settings/.test(s)) {
      return { rows: [{ max_concurrent_report_analyses: state.limit }] };
    }
    if (/AS occupied/.test(s) && /threat_library_jobs/.test(s)) {
      return { rows: [{ occupied: occupiedCount() }] };
    }
    if (/FOR UPDATE OF j SKIP LOCKED/.test(s)) {
      const available = params[1];
      const rows = state.jobs
        .filter((j) => j.status === 'queued' && !j.bullmq_job_id && !j.deleted_at && ['analyze', 'retry'].includes(j.job_type))
        .sort((a, b) => {
          const at = a.created_at.getTime() - b.created_at.getTime();
          return at !== 0 ? at : a.id - b.id;
        })
        .slice(0, available)
        .map((j) => ({ ...j }));
      return { rows };
    }
    if (/SET bullmq_job_id = \$2/.test(s)) {
      const job = state.jobs.find((j) => j.id === params[0] && j.status === 'queued' && !j.bullmq_job_id);
      if (!job) return { rows: [], rowCount: 0 };
      job.bullmq_job_id = params[1];
      refreshObserved();
      return { rows: [{ id: job.id }], rowCount: 1 };
    }
    if (/SET status = 'queued'[\s\S]*bullmq_job_id = NULL[\s\S]*WHERE id = \$1 AND status = 'running'/.test(s)
      || (/status = 'queued'/.test(s) && /bullmq_job_id = NULL/.test(s) && /status = 'running'/.test(s))) {
      const job = state.jobs.find((j) => j.id === params[0] && j.status === 'running');
      if (job) {
        job.status = 'queued';
        job.bullmq_job_id = null;
      }
      return { rows: job ? [job] : [], rowCount: job ? 1 : 0 };
    }
    if (/SET bullmq_job_id = NULL[\s\S]*status = 'queued'/.test(s)) {
      const job = state.jobs.find((j) => j.id === params[0] && j.status === 'queued');
      if (job) job.bullmq_job_id = null;
      return { rows: job ? [job] : [], rowCount: job ? 1 : 0 };
    }
    if (/UPDATE threat_reports SET/.test(s)) {
      const report = state.reports.get(params[0]) || { id: params[0] };
      if (params[8]) report.analysis_status = params[8];
      state.reports.set(params[0], report);
      return { rows: [report] };
    }
    if (/SELECT j\.id, j\.report_id, j\.status, j\.bullmq_job_id/.test(s)) {
      return {
        rows: state.jobs.filter((j) => ['queued', 'running'].includes(j.status) && j.bullmq_job_id)
      };
    }
    if (/SET status = 'cancelled'/.test(s)) {
      const changed = [];
      for (const job of state.jobs) {
        if (job.report_id === params[0] && job.status === 'queued' && !job.bullmq_job_id) {
          job.status = 'cancelled';
          changed.push({ id: job.id });
        }
      }
      return { rows: changed };
    }
    return { rows: [], rowCount: 0 };
  }

  const pool = {
    query,
    async connect() {
      let active = true;
      return {
        async query(sql, params) {
          const s = String(sql);
          if (/^BEGIN/.test(s.trim())) {
            await new Promise((resolve) => {
              const previous = state.lock;
              state.lock = new Promise((release) => { this._release = release; });
              previous.then(resolve);
            });
            state.lockHeld = true;
            return { rows: [] };
          }
          if (/^COMMIT|^ROLLBACK/.test(s.trim())) {
            state.lockHeld = false;
            if (this._release) this._release();
            return { rows: [] };
          }
          return query(sql, params);
        },
        release() {
          if (active && state.lockHeld && this._release) {
            state.lockHeld = false;
            this._release();
          }
          active = false;
        }
      };
    }
  };

  async function enqueue(job) {
    const id = `bull-${state.enqueued.length + 1}`;
    state.enqueued.push({ id, reportId: job.report_id, jobId: job.id, sourceType: job.source_type, jobType: job.jobType || job.job_type });
    return { id };
  }

  async function dispatch(limitOverride) {
    const result = await dispatchQueuedThreatLibraryAnalyses(pool, { enqueue, limitOverride });
    refreshObserved();
    return result;
  }

  function complete(jobId) {
    const job = state.jobs.find((j) => j.id === jobId);
    assert.ok(job, `job ${jobId} exists`);
    job.status = 'completed';
    job.bullmq_job_id = job.bullmq_job_id || 'done';
    // Terminal jobs no longer occupy a slot (count requires queued/running).
    const report = state.reports.get(job.report_id);
    if (report) report.analysis_status = 'review_required';
  }

  function fail(jobId) {
    const job = state.jobs.find((j) => j.id === jobId);
    job.status = 'failed';
    const report = state.reports.get(job.report_id);
    if (report) report.analysis_status = 'failed';
  }

  function addJob(partial) {
    const id = partial.id ?? state.jobs.length + 1;
    const job = {
      id,
      report_id: partial.report_id ?? id,
      job_type: partial.job_type || 'analyze',
      status: 'queued',
      bullmq_job_id: null,
      progress: partial.progress || {},
      created_at: partial.created_at || new Date(Date.UTC(2026, 8, 1, 10, 0, id)),
      source_url: partial.source_url || null,
      report_public_id: `r-${partial.report_id ?? id}`,
      source_type: partial.source_type || 'url',
      deleted_at: null
    };
    state.jobs.push(job);
    state.reports.set(job.report_id, { id: job.report_id, analysis_status: 'pending', import_status: 'processing' });
    return job;
  }

  return { state, pool, dispatch, complete, fail, addJob, enqueue };
}

test('TEST A — limit=1: A starts; B/C wait; FIFO advance; max simultaneous = 1', async () => {
  const world = createSchedulerWorld({
    limit: 1,
    jobs: [
      { id: 1, source_type: 'url' },
      { id: 2, source_type: 'url' },
      { id: 3, source_type: 'url' }
    ]
  });
  let result = await world.dispatch();
  assert.deepEqual(result.claimed.map((c) => c.jobId), [1]);
  assert.equal(result.occupied, 1);
  assert.equal(world.state.enqueued.length, 1);
  assert.equal(world.state.jobs.filter((j) => !j.bullmq_job_id && j.status === 'queued').map((j) => j.id).join(','), '2,3');

  world.complete(1);
  result = await world.dispatch();
  assert.deepEqual(result.claimed.map((c) => c.jobId), [2]);
  assert.equal(world.state.jobs.find((j) => j.id === 3).bullmq_job_id, null);

  world.complete(2);
  result = await world.dispatch();
  assert.deepEqual(result.claimed.map((c) => c.jobId), [3]);
  assert.equal(world.state.maxObservedActive, 1);
});

test('TEST B — limit=2: A+B start; C/D wait; finishing A starts C (FIFO)', async () => {
  const world = createSchedulerWorld({
    limit: 2,
    jobs: [{ id: 1 }, { id: 2 }, { id: 3 }, { id: 4 }]
  });
  let result = await world.dispatch();
  assert.deepEqual(result.claimed.map((c) => c.jobId), [1, 2]);
  assert.equal(world.state.jobs.find((j) => j.id === 3).bullmq_job_id, null);
  assert.equal(world.state.jobs.find((j) => j.id === 4).bullmq_job_id, null);

  world.complete(1);
  result = await world.dispatch();
  assert.deepEqual(result.claimed.map((c) => c.jobId), [3], 'FIFO: C before D');
  assert.equal(world.state.jobs.find((j) => j.id === 4).bullmq_job_id, null);
  assert.equal(world.state.maxObservedActive, 2);
});

test('TEST C — two schedulers cannot both claim when limit=1', async () => {
  const world = createSchedulerWorld({
    limit: 1,
    jobs: [{ id: 1 }, { id: 2 }]
  });
  const [a, b] = await Promise.all([world.dispatch(), world.dispatch()]);
  const claimed = [...a.claimed, ...b.claimed];
  assert.equal(claimed.length, 1, 'exactly one job becomes active');
  assert.equal(world.state.enqueued.length, 1);
  assert.equal(world.state.jobs.filter((j) => j.bullmq_job_id).length, 1);
  assert.equal(world.state.maxObservedActive, 1);
});

test('TEST D — increasing 1→3 starts queued jobs without restart', async () => {
  const world = createSchedulerWorld({
    limit: 1,
    jobs: [{ id: 1 }, { id: 2 }, { id: 3 }]
  });
  await world.dispatch();
  assert.equal(world.state.enqueued.length, 1);
  world.state.limit = 3;
  const result = await world.dispatch();
  assert.deepEqual(result.claimed.map((c) => c.jobId).sort((x, y) => x - y), [2, 3]);
  assert.equal(result.occupied, 3);
});

test('TEST E — decreasing 3→1 does not terminate A/B/C; D waits until all three finish', async () => {
  const world = createSchedulerWorld({
    limit: 3,
    jobs: [{ id: 1 }, { id: 2 }, { id: 3 }, { id: 4 }]
  });
  await world.dispatch();
  assert.deepEqual(world.state.enqueued.map((e) => e.jobId), [1, 2, 3]);
  world.state.limit = 1;
  let result = await world.dispatch();
  assert.deepEqual(result.claimed, []);
  assert.equal(world.state.jobs.find((j) => j.id === 4).bullmq_job_id, null);
  assert.equal(world.state.jobs.filter((j) => ['queued', 'running'].includes(j.status) && j.bullmq_job_id).length, 3);

  world.complete(1);
  result = await world.dispatch();
  assert.deepEqual(result.claimed, []);
  world.complete(2);
  result = await world.dispatch();
  assert.deepEqual(result.claimed, []);
  world.complete(3);
  result = await world.dispatch();
  assert.deepEqual(result.claimed.map((c) => c.jobId), [4]);
});

test('TEST F — terminal failure of A releases the slot so B starts', async () => {
  const world = createSchedulerWorld({
    limit: 1,
    jobs: [{ id: 1 }, { id: 2 }]
  });
  await world.dispatch();
  world.fail(1);
  const result = await world.dispatch();
  assert.deepEqual(result.claimed.map((c) => c.jobId), [2]);
});

test('TEST G — queued work survives restart; interrupted running jobs are re-queued and not left occupying a slot', async () => {
  const world = createSchedulerWorld({
    limit: 1,
    jobs: [
      { id: 1, status: 'running', bullmq_job_id: 'dead-1' },
      { id: 2, status: 'queued', bullmq_job_id: null }
    ]
  });
  const recovered = await recoverInterruptedAnalysisJobs(world.pool, {
    getJobState: async () => null
  });
  assert.equal(recovered.length, 1);
  assert.equal(recovered[0].reason, 'interrupted_running');
  assert.equal(world.state.jobs.find((j) => j.id === 1).status, 'queued');
  assert.equal(world.state.jobs.find((j) => j.id === 1).bullmq_job_id, null);
  const result = await world.dispatch();
  assert.deepEqual(result.claimed.map((c) => c.jobId), [1], 'FIFO resumes with the recovered job first');
  assert.equal(world.state.jobs.find((j) => j.id === 2).bullmq_job_id, null);
});

test('TEST H — the same job cannot be claimed twice', async () => {
  const world = createSchedulerWorld({
    limit: 2,
    jobs: [{ id: 1 }]
  });
  const [a, b] = await Promise.all([world.dispatch(), world.dispatch()]);
  const claimedIds = [...a.claimed, ...b.claimed].map((c) => c.jobId);
  assert.deepEqual(claimedIds, [1]);
  assert.equal(world.state.enqueued.length, 1);
});

test('TEST I — URL and PDF share the same concurrency budget', async () => {
  const world = createSchedulerWorld({
    limit: 1,
    jobs: [
      { id: 1, source_type: 'url', job_type: 'analyze' },
      { id: 2, source_type: 'pdf', job_type: 'analyze' }
    ]
  });
  const first = await world.dispatch();
  assert.equal(first.claimed.length, 1);
  assert.equal(first.claimed[0].sourceType, 'url');
  assert.equal(world.state.jobs.find((j) => j.source_type === 'pdf').bullmq_job_id, null);
  world.complete(1);
  const second = await world.dispatch();
  assert.equal(second.claimed[0].sourceType, 'pdf');
  assert.equal(world.state.maxObservedActive, 1);
});

test('recover leaves a still-live BullMQ job occupying its slot (no duplicate analysis)', async () => {
  const world = createSchedulerWorld({
    limit: 1,
    jobs: [{ id: 1, status: 'running', bullmq_job_id: 'live-1' }, { id: 2 }]
  });
  const recovered = await recoverInterruptedAnalysisJobs(world.pool, {
    getJobState: async () => 'active'
  });
  assert.deepEqual(recovered, []);
  const result = await world.dispatch();
  assert.deepEqual(result.claimed, []);
});

test('cancel unclaimed jobs does not touch a claimed job', async () => {
  const world = createSchedulerWorld({
    limit: 1,
    jobs: [
      { id: 1, report_id: 10, status: 'queued', bullmq_job_id: 'bull-1' },
      { id: 2, report_id: 10, status: 'queued', bullmq_job_id: null }
    ]
  });
  const cancelled = await cancelUnclaimedAnalysisJobs(world.pool, 10);
  assert.deepEqual(cancelled.map((r) => r.id), [2]);
  assert.equal(world.state.jobs.find((j) => j.id === 1).status, 'queued');
  assert.equal(world.state.jobs.find((j) => j.id === 2).status, 'cancelled');
});
