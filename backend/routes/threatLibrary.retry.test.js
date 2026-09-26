/**
 * Retry route runtime behaviour with a fake pool / queue (no live DB):
 * orphaned active status is recovered exactly once; a genuinely running or
 * just-claimed analysis still answers "already running".
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { registerThreatLibraryRoutes } from './threatLibrary.js';
import { isOrphanedActiveAnalysis } from '../lib/threatLibrary/retryState.js';

const PUBLIC_ID = '11111111-2222-4333-8444-555555555555';

function harness({ report, jobs }) {
  const state = { report: { id: 7, public_id: PUBLIC_ID, source_type: 'url', canonical_document: { blocks: [{ id: 'b0' }] }, ...report }, jobs: [...jobs] };
  const enqueued = [];
  const pool = {
    async query(sql, params = []) {
      const s = String(sql);
      if (/FROM threat_reports WHERE public_id/.test(s)) return { rows: [state.report] };
      if (/FROM threat_library_jobs[\s\S]*status = ANY\(ARRAY\['queued','running'\]\)/.test(s)) {
        return { rows: state.jobs.filter((j) => j.status === 'queued' || j.status === 'running').sort((a, b) => b.id - a.id).slice(0, 1) };
      }
      if (/SELECT status FROM threat_library_jobs WHERE report_id = \$1 ORDER BY id DESC LIMIT 1/.test(s)) {
        return { rows: [...state.jobs].sort((a, b) => b.id - a.id).slice(0, 1) };
      }
      if (/COUNT\(\*\)::int AS n FROM threat_report_candidates/.test(s)) return { rows: [{ n: 5 }] };
      if (/^\s*UPDATE threat_reports SET/.test(s)) {
        if (params[8]) state.report.analysis_status = params[8];
        if (params[21] === true) state.report.failure_code = null;
        return { rows: [state.report] };
      }
      if (/INSERT INTO threat_library_jobs/.test(s)) {
        const job = { id: state.jobs.length + 100, public_id: `job-${state.jobs.length + 100}`, status: 'queued' };
        state.jobs.push(job);
        return { rows: [job] };
      }
      if (/UPDATE threat_library_jobs SET/.test(s)) return { rows: [state.jobs.find((j) => j.id === params[0]) || {}] };
      return { rows: [] };
    }
  };
  const queue = { async add(name, data) { enqueued.push({ name, data }); return { id: String(enqueued.length) }; } };
  const routes = new Map();
  const app = new Proxy({}, {
    get: (_t, method) => (routePath, ...handlers) => {
      routes.set(`${String(method).toUpperCase()} ${routePath}`, handlers[handlers.length - 1]);
    }
  });
  registerThreatLibraryRoutes(app, pool, null, { threatLibraryQueue: queue });
  const retry = routes.get('POST /api/threat-library/reports/:publicId/retry');
  assert.ok(retry, 'retry route registered');
  async function call() {
    const res = { statusCode: 200, body: null, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; return this; } };
    await retry({ params: { publicId: PUBLIC_ID }, body: {}, user: { id: 1 } }, res);
    return res;
  }
  return { state, enqueued, call };
}

test('orphaned helper: active + ended latest job + leftover failure only', () => {
  const orphan = { analysis_status: 'analyzing', failure_code: 'ai_output_parse_error' };
  assert.equal(isOrphanedActiveAnalysis({ report: orphan, latestJob: { status: 'failed' } }), true);
  assert.equal(isOrphanedActiveAnalysis({ report: orphan, latestJob: { status: 'cancelled' } }), true);
  assert.equal(isOrphanedActiveAnalysis({ report: orphan, activeJob: { status: 'running' }, latestJob: { status: 'running' } }), false);
  assert.equal(isOrphanedActiveAnalysis({ report: orphan, latestJob: { status: 'completed' } }), false);
  assert.equal(isOrphanedActiveAnalysis({ report: orphan, latestJob: null }), false, 'no prior job (initial import window)');
  assert.equal(isOrphanedActiveAnalysis({ report: { ...orphan, failure_code: null }, latestJob: { status: 'failed' } }), false, 'claimed by a concurrent retry');
  assert.equal(isOrphanedActiveAnalysis({ report: { ...orphan, analysis_status: 'failed' }, latestJob: { status: 'failed' } }), false, 'terminal status is not orphaned');
});

test('orphaned active status (ended job, leftover failure, no active job) → enqueues exactly one retry', async () => {
  const h = harness({
    report: { analysis_status: 'analyzing', failure_code: 'ai_output_parse_error' },
    jobs: [{ id: 35, status: 'failed' }]
  });
  const res = await h.call();
  assert.equal(res.statusCode, 202);
  assert.equal(res.body.already_running, false);
  assert.equal(res.body.recovered_orphaned_status, true);
  assert.equal(h.enqueued.length, 1);
  assert.equal(h.enqueued[0].name, 'retry');
  assert.equal(h.state.report.failure_code, null, 'failure cleared atomically with the new active status');

  // A second click now sees the claimed report + queued job → no second enqueue.
  const again = await h.call();
  assert.equal(again.body.already_running, true);
  assert.equal(h.enqueued.length, 1);
});

test('genuinely running analysis → already_running, nothing enqueued', async () => {
  const h = harness({
    report: { analysis_status: 'analyzing', failure_code: null },
    jobs: [{ id: 35, status: 'failed' }, { id: 36, status: 'running', public_id: 'job-36' }]
  });
  const res = await h.call();
  assert.equal(res.body.already_running, true);
  assert.equal(res.body.code, 'analysis_already_running');
  assert.equal(res.body.job_id, 'job-36');
  assert.equal(h.enqueued.length, 0);
});

test('active status just set by a concurrent retry (failure cleared, job not yet created) → already_running', async () => {
  const h = harness({
    report: { analysis_status: 'analyzing', failure_code: null },
    jobs: [{ id: 35, status: 'failed' }]
  });
  const res = await h.call();
  assert.equal(res.body.already_running, true);
  assert.equal(h.enqueued.length, 0);
});

test('failed report still retries normally (unchanged path)', async () => {
  const h = harness({ report: { analysis_status: 'failed', failure_code: 'ai_output_parse_error' }, jobs: [{ id: 35, status: 'failed' }] });
  const res = await h.call();
  assert.equal(res.body.already_running, false);
  assert.equal(res.body.recovered_orphaned_status, false);
  assert.equal(h.enqueued.length, 1);
});
