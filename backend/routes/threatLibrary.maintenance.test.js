/**
 * Threat Library maintenance actions at the HTTP boundary (fake pool / queue):
 *   POST …/retry               failure recovery only
 *   POST …/refresh-extraction  deterministic refresh (job_type refresh_extraction)
 *   POST …/rerun-ai            explicit AI re-analysis (job_type rerun_ai)
 * State guards, the atomic claim against concurrent requests, cancel-before-
 * claim restoring the report, RBAC and CSRF.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { registerThreatLibraryRoutes } from './threatLibrary.js';

const PUBLIC_ID = '11111111-2222-4333-8444-555555555555';

function harness(reportPatch = {}, { jobs = [] } = {}) {
  const state = {
    report: {
      id: 7,
      public_id: PUBLIC_ID,
      source_type: 'url',
      source_url: 'https://vendor.example/post',
      analysis_status: 'review_required',
      import_status: 'review_required',
      failure_code: null,
      analysis_progress: { candidate_extraction_version: 'tl-candidates-v13', ai_calls: 4 },
      canonical_document: { blocks: [{ id: 'b0' }] },
      deleted_at: null,
      ...reportPatch
    },
    jobs: jobs.map((j, i) => ({ id: 50 + i, report_id: 7, progress: {}, bullmq_job_id: null, ...j }))
  };
  const enqueued = [];
  const active = () => state.jobs.filter((j) => j.status === 'queued' || j.status === 'running');
  const pool = {
    async query(sql, params = []) {
      const s = String(sql);
      const t = s.trim();
      if (/FROM threat_reports WHERE public_id/.test(s)) return { rows: state.report.deleted_at ? [] : [{ ...state.report }] };
      if (/FROM threat_reports r WHERE r\.id = \$1/.test(s)) return { rows: [{ indicator_count: 3, review_candidate_count: 2, matched_count: 1, entity_count: 0 }] };
      if (/FROM threat_report_tags/.test(s)) return { rows: [] };
      if (/^UPDATE threat_reports\s+SET analysis_status = 'pending'/.test(t)) {
        // claimReportForMaintenance: status predicate + no active job, atomically.
        const allowed = params[1];
        if (!allowed.includes(state.report.analysis_status) || active().length) return { rows: [] };
        state.report.analysis_status = 'pending';
        state.report.import_status = 'processing';
        state.report.analysis_progress = { ...state.report.analysis_progress, ...JSON.parse(params[2]) };
        return { rows: [{ ...state.report }] };
      }
      if (/^UPDATE threat_reports\s+SET analysis_status = \$2,\s+import_status = \$3/.test(t)) {
        state.report.analysis_status = params[1];
        state.report.import_status = params[2];
        state.report.analysis_progress = JSON.parse(params[3]);
        return { rows: [{ ...state.report }] };
      }
      if (/^UPDATE threat_reports\s+SET cancel_requested_at = NOW\(\)/.test(t)) return { rows: [{ ...state.report }] };
      if (/^UPDATE threat_reports SET/.test(t)) {
        if (params[8]) state.report.analysis_status = params[8];
        if (params[7]) state.report.import_status = params[7];
        if (params[21] === true) state.report.failure_code = null;
        return { rows: [{ ...state.report }] };
      }
      if (/SELECT public_id, job_type, status, stage FROM threat_library_jobs/.test(s)) {
        return { rows: active().sort((a, b) => b.id - a.id).slice(0, 1) };
      }
      if (/FROM threat_library_jobs[\s\S]*status = ANY\(ARRAY\['queued','running'\]\)/.test(s)) {
        return { rows: active().sort((a, b) => b.id - a.id).slice(0, 1) };
      }
      if (/SELECT status FROM threat_library_jobs WHERE report_id = \$1 ORDER BY id DESC LIMIT 1/.test(s)) {
        return { rows: [...state.jobs].sort((a, b) => b.id - a.id).slice(0, 1) };
      }
      if (/COUNT\(\*\)::int AS n FROM threat_report_candidates/.test(s)) return { rows: [{ n: 5 }] };
      if (/INSERT INTO threat_library_jobs/.test(s)) {
        const job = {
          id: 100 + state.jobs.length,
          public_id: `job-${100 + state.jobs.length}`,
          report_id: 7,
          job_type: params[1],
          status: 'queued',
          bullmq_job_id: null,
          progress: {},
          created_at: new Date(),
          source_url: state.report.source_url
        };
        state.jobs.push(job);
        return { rows: [{ ...job }] };
      }
      if (/^(BEGIN|COMMIT|ROLLBACK)/.test(t) || /pg_advisory_xact_lock/.test(s)) return { rows: [] };
      if (/FROM threat_library_ai_settings/.test(s)) return { rows: [{ max_concurrent_report_analyses: 2 }] };
      if (/AS occupied/.test(s)) return { rows: [{ occupied: 0 }] };
      if (/FOR UPDATE OF j SKIP LOCKED/.test(s)) {
        if (state.holdDispatch) return { rows: [] };
        return {
          rows: state.jobs
            .filter((j) => j.status === 'queued' && !j.bullmq_job_id && params[0].includes(j.job_type))
            .map((j) => ({ ...j, report_public_id: PUBLIC_ID, source_type: 'url' }))
        };
      }
      if (/SET bullmq_job_id = \$2/.test(s)) {
        const job = state.jobs.find((j) => j.id === params[0] && !j.bullmq_job_id);
        if (!job) return { rows: [], rowCount: 0 };
        job.bullmq_job_id = params[1];
        return { rows: [{ id: job.id }], rowCount: 1 };
      }
      if (/^UPDATE threat_library_jobs\s+SET status = 'cancelled'/.test(t)) {
        const cancelled = state.jobs.filter((j) => j.status === 'queued' && !j.bullmq_job_id && params[1].includes(j.job_type));
        for (const j of cancelled) j.status = 'cancelled';
        return { rows: cancelled.map((j) => ({ id: j.id, job_type: j.job_type, progress: j.progress })) };
      }
      if (/^UPDATE threat_library_jobs SET/.test(t)) {
        const job = state.jobs.find((j) => j.id === params[0]);
        if (job) {
          if (params[1]) job.status = params[1];
          if (params[3]) job.progress = JSON.parse(JSON.stringify(params[3]));
        }
        return { rows: job ? [{ ...job }] : [] };
      }
      throw new Error(`unexpected SQL: ${t.slice(0, 100)}`);
    },
    async connect() {
      return { query: (...args) => pool.query(...args), release() {} };
    }
  };
  const queue = { async add(name, data) { enqueued.push({ name, data }); return { id: String(enqueued.length) }; } };
  const routes = new Map();
  const app = new Proxy({}, {
    get: (_t, method) => (routePath, ...handlers) => {
      routes.set(`${String(method).toUpperCase()} ${routePath}`, handlers);
    }
  });
  registerThreatLibraryRoutes(app, pool, null, { threatLibraryQueue: queue });
  async function call(action, user = { id: 1, role: 'analyst' }) {
    const handlers = routes.get(`POST /api/threat-library/reports/:publicId/${action}`);
    assert.ok(handlers, `${action} registered`);
    const res = { statusCode: 200, body: null, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; return this; } };
    const req = { params: { publicId: PUBLIC_ID }, body: {}, query: {}, user };
    let i = 0;
    const next = async () => { const h = handlers[i++]; if (h) await h(req, res, next); };
    await next();
    return res;
  }
  return { state, enqueued, call, routes };
}

// ---------------------------------------------------------------- Refresh

test('refresh-extraction on review_required: 202, refresh_extraction job, restore target carried, no AI flags', async () => {
  const h = harness();
  const res = await h.call('refresh-extraction');
  assert.equal(res.statusCode, 202, JSON.stringify(res.body));
  assert.equal(res.body.mode, 'refresh_extraction');
  assert.equal(res.body.ai_analysis, false);
  assert.equal(h.state.jobs.length, 1);
  assert.equal(h.state.jobs[0].job_type, 'refresh_extraction');
  assert.equal(h.enqueued.length, 1);
  assert.equal(h.enqueued[0].name, 'refresh_extraction');
  assert.deepEqual(h.enqueued[0].data.restoreStatus, { analysis_status: 'review_required', import_status: 'review_required' });
  assert.equal(h.enqueued[0].data.newAnalysisRun, false);
  assert.equal(h.enqueued[0].data.resumeAnalysis, false);
  assert.equal(h.state.report.analysis_status, 'pending');
  assert.equal(h.state.report.analysis_progress.ai_calls, 4, 'claim merges progress, keeps prior AI provenance');
  assert.equal(h.state.report.analysis_progress.mode, 'refresh_extraction');
});

test('refresh-extraction on a finalized report is accepted and will restore "ready"', async () => {
  const h = harness({ analysis_status: 'ready', import_status: 'ready', finalized_at: '2026-10-01T00:00:00Z' });
  const res = await h.call('refresh-extraction');
  assert.equal(res.statusCode, 202);
  assert.deepEqual(h.enqueued[0].data.restoreStatus, { analysis_status: 'ready', import_status: 'ready' });
});

test('8. refresh state guards: failed → 409 (use Retry), queued / running → 409 already running, THIB → 400', async () => {
  {
    const status = 'failed';
    const h = harness({ analysis_status: status, import_status: 'failed' });
    const res = await h.call('refresh-extraction');
    assert.equal(res.statusCode, 409, status);
    assert.equal(res.body.code, 'refresh_extraction_not_allowed');
    assert.equal(h.state.jobs.length, 0);
  }
  for (const status of ['pending', 'extracting', 'analyzing', 'matching']) {
    const h = harness({ analysis_status: status, import_status: 'processing' }, { jobs: [{ status: status === 'pending' ? 'queued' : 'running', job_type: 'analyze' }] });
    const res = await h.call('refresh-extraction');
    assert.equal(res.statusCode, 409, status);
    assert.equal(res.body.code, 'analysis_already_running');
    assert.equal(h.state.jobs.length, 1, 'no second job');
    assert.equal(h.enqueued.length, 0);
  }
  const thib = harness({ source_type: 'thib', analysis_status: 'skipped', import_status: 'ready' });
  assert.equal((await thib.call('refresh-extraction')).statusCode, 400);
});

test('10. concurrency: two simultaneous refresh requests create exactly one job', async () => {
  const h = harness();
  const [a, b] = await Promise.all([h.call('refresh-extraction'), h.call('refresh-extraction')]);
  const codes = [a.statusCode, b.statusCode].sort();
  assert.deepEqual(codes, [202, 409]);
  assert.equal([a, b].find((r) => r.statusCode === 409).body.code, 'analysis_already_running');
  assert.equal(h.state.jobs.length, 1);
  assert.equal(h.enqueued.length, 1);
  // A refresh while one is queued is refused as well.
  const third = await h.call('refresh-extraction');
  assert.equal(third.statusCode, 409);
  assert.equal(h.state.jobs.length, 1);
});

test('refresh + rerun-ai cannot race each other on the same report', async () => {
  const h = harness();
  const [a, b] = await Promise.all([h.call('refresh-extraction'), h.call('rerun-ai')]);
  assert.deepEqual([a.statusCode, b.statusCode].sort(), [202, 409]);
  assert.equal(h.state.jobs.length, 1);
});

test('cancel before a worker claims a refresh: job cancelled, report returns to its prior status', async () => {
  const h = harness({ analysis_status: 'ready', import_status: 'ready' });
  h.state.holdDispatch = true; // no free slot: the job stays unclaimed
  assert.equal((await h.call('refresh-extraction')).statusCode, 202);
  assert.equal(h.state.report.analysis_status, 'pending');
  const res = await h.call('cancel');
  assert.equal(res.statusCode, 200);
  assert.equal(h.state.jobs[0].status, 'cancelled');
  assert.equal(h.state.report.analysis_status, 'ready');
  assert.equal(h.state.report.import_status, 'ready');
  assert.equal('mode' in h.state.report.analysis_progress, false);
});

// ---------------------------------------------------------------- Re-run AI

test('9. rerun-ai on review_required: 202, rerun_ai job on a new analysis run', async () => {
  const h = harness();
  const res = await h.call('rerun-ai');
  assert.equal(res.statusCode, 202);
  assert.equal(res.body.mode, 'rerun_ai');
  assert.equal(res.body.ai_analysis, true);
  assert.equal(h.state.jobs[0].job_type, 'rerun_ai');
  assert.equal(h.enqueued[0].name, 'rerun_ai');
  assert.equal(h.enqueued[0].data.newAnalysisRun, true, 'cached chunks are not replayed');
  assert.equal(h.enqueued[0].data.resumeAnalysis, true, 'document + candidates are reused');
});

test('rerun-ai guards: finalized → 409 (never reopened implicitly), failed → 409 (use Retry)', async () => {
  for (const status of ['ready', 'failed']) {
    const h = harness({ analysis_status: status, import_status: status });
    const res = await h.call('rerun-ai');
    assert.equal(res.statusCode, 409, status);
    assert.equal(res.body.code, 'rerun_ai_not_allowed');
    assert.equal(h.state.jobs.length, 0);
  }
});

// ---------------------------------------------------------------- Retry

test('7. Retry on a failed report keeps its full semantics (retry job, resume, AI stage)', async () => {
  const h = harness({ analysis_status: 'failed', import_status: 'failed', failure_code: 'ai_timeout' });
  const res = await h.call('retry');
  assert.equal(res.statusCode, 202, JSON.stringify(res.body));
  assert.equal(h.state.jobs[0].job_type, 'retry');
  assert.equal(h.enqueued[0].name, 'retry');
  assert.equal(h.enqueued[0].data.resumeAnalysis, true);
});

test('Retry contract: review_required / finalized reports are refused (409 retry_not_applicable), no job', async () => {
  for (const status of ['review_required', 'ready']) {
    const h = harness({ analysis_status: status, import_status: status });
    const res = await h.call('retry');
    assert.equal(res.statusCode, 409, status);
    assert.equal(res.body.code, 'retry_not_applicable');
    assert.match(res.body.message, /Refresh extraction/);
    assert.equal(h.state.jobs.length, 0);
    assert.equal(h.enqueued.length, 0);
  }
});

test('Retry still recovers an orphaned active status (ended job + leftover failure)', async () => {
  const h = harness(
    { analysis_status: 'analyzing', import_status: 'processing', failure_code: 'ai_output_parse_error' },
    { jobs: [{ status: 'failed', job_type: 'retry' }] }
  );
  const res = await h.call('retry');
  assert.equal(res.statusCode, 202);
  assert.equal(res.body.recovered_orphaned_status, true);
});

// ---------------------------------------------------------------- Auth / CSRF

test('maintenance routes are analyst/admin only (readonly → 403, no job)', async () => {
  for (const action of ['refresh-extraction', 'rerun-ai', 'retry']) {
    const h = harness();
    const res = await h.call(action, { id: 9, role: 'readonly' });
    assert.equal(res.statusCode, 403, action);
    assert.equal(h.state.jobs.length, 0);
  }
  const admin = harness();
  assert.equal((await admin.call('refresh-extraction', { id: 2, role: 'admin' })).statusCode, 202);
});

test('maintenance routes sit behind the global CSRF check (no exemption)', async () => {
  // auth.js loads ensure-jwt-secret at import (same setup as auth.test.js).
  if (!process.env.JWT_SECRET || String(process.env.JWT_SECRET).trim().length < 32) {
    process.env.JWT_SECRET = 'test-jwt-secret-for-unit-tests-only!!';
  }
  const { csrfProtection, CSRF_COOKIE_NAME } = await import('../lib/auth.js');
  for (const action of ['refresh-extraction', 'rerun-ai']) {
    const path = `/api/threat-library/reports/${PUBLIC_ID}/${action}`;
    const res = { statusCode: 200, status(c) { this.statusCode = c; return this; }, json() { return this; } };
    let passed = false;
    csrfProtection({ method: 'POST', path, headers: {}, cookies: {} }, res, () => { passed = true; });
    assert.equal(passed, false, `${action} without token`);
    assert.equal(res.statusCode, 403);
    let ok = false;
    const token = 'tok-123';
    csrfProtection({ method: 'POST', path, headers: { 'x-csrf-token': token }, cookies: { [CSRF_COOKIE_NAME]: token } }, res, () => { ok = true; });
    assert.equal(ok, true, `${action} with matching token`);
  }
});
