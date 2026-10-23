import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import {
  candidateColumns,
  createJob,
  createThreatReport,
  markAnalysisChunkFailed,
  saveAnalysisChunkResult
} from './store.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildLayoutVariant } from './benchmark/layoutVariants.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { claimJobOwnership, startJobHeartbeat, requeueOwnedJob } from './jobOwnership.js';
import {
  createExclusivePipelineJob,
  dispatchQueuedThreatLibraryAnalyses,
  recoverInterruptedAnalysisJobs
} from './analysisConcurrency.js';
import { maybeScheduleAutoRetry, AUTO_RETRY_BASE_DELAY_MS } from './autoRetry.js';
import { runAnalysisPipeline } from './pipeline.js';
import { buildAnalysisChunks } from './ai/analyze.js';
import { createInferenceScheduler } from './ai/inferenceScheduler.js';
import { startMockOllama } from '../../test-support/mockOllamaServer.js';

/**
 * Real-Postgres checks of Threat Library job ownership, duplicate-run
 * prevention, crash recovery, delayed-retry dispatch, chunk attempt history,
 * bounded automatic retry — and end-to-end IOC / review integrity across an
 * AI failure and its resume (real pipeline, real HTTP to a mock Ollama, real
 * inference scheduler).
 *
 * ALLOW_THREAT_LIBRARY_DB_TESTS=1 with a migrated throwaway database; run with
 * --test-concurrency=1 alongside the other TL itest files. Every test deletes
 * the reports it creates; AI settings are restored afterwards.
 */

const config = {
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound',
  connectionTimeoutMillis: 5000,
  max: 8
};
const pool = new pg.Pool(config);

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

let savedSettings = null;
test.before(async () => {
  if (!hasDb) return;
  savedSettings = (await pool.query('SELECT * FROM threat_library_ai_settings WHERE id = 1')).rows[0] || null;
});
test.after(async () => {
  if (hasDb && savedSettings) {
    await pool.query(
      `UPDATE threat_library_ai_settings
       SET enabled = $1, provider = $2, base_url = $3, model = $4, max_input_chars = $5,
           max_concurrent_ai_requests = $6, auto_retry_max_attempts = $7
       WHERE id = 1`,
      [
        savedSettings.enabled,
        savedSettings.provider,
        savedSettings.base_url,
        savedSettings.model,
        savedSettings.max_input_chars,
        savedSettings.max_concurrent_ai_requests,
        savedSettings.auto_retry_max_attempts
      ]
    );
  }
  await pool.end();
});

const created = [];
async function newReport(status = 'failed') {
  const variant = buildLayoutVariant('html_c2_then_loaders/table');
  const report = await createThreatReport(pool, {
    title: `itest-ai-reliability-${crypto.randomUUID()}`,
    source_type: 'url',
    source_url: `${variant.sourceUrl}?r=${crypto.randomUUID()}`
  });
  created.push(report.id);
  const extracted = extractReportCandidates({ source_type: 'url', source_url: variant.sourceUrl }, variant.document);
  // Narrative prose after the indicators (~9k chars; chunks have a 4k floor) yields
  // several semantic chunks (candidates are unaffected: they are reused).
  const prose = 'The operators rotate infrastructure between waves and reuse the loader with new configuration blobs. '.repeat(4);
  extracted.document.blocks.push(
    ...Array.from({ length: 22 }, (_, i) => ({
      id: `b9${String(i).padStart(2, '0')}`,
      type: 'paragraph',
      text: `${prose}Wave ${i + 1}.`,
      page: null,
      section: 'Conclusion'
    }))
  );
  await pool.query(
    `UPDATE threat_reports
     SET canonical_document = $2::jsonb, analysis_status = $3, import_status = 'processing',
         analysis_progress = $4::jsonb
     WHERE id = $1`,
    [report.id, JSON.stringify(extracted.document), status, JSON.stringify({ candidate_extraction_version: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION })]
  );
  for (const c of extracted.candidates) {
    const col = candidateColumns(c);
    await pool.query(
      `INSERT INTO threat_report_candidates (
         report_id, candidate_type, original_value, normalized_value, assessment, role, review_status,
         match_state, is_ioc, source_assertion, evidence, has_original_document_occurrence, promotion_outcome
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13)`,
      [
        report.id, col.candidate_type, col.original_value, col.normalized_value, col.assessment, col.role, col.review_status,
        col.match_state, col.is_ioc, col.source_assertion, JSON.stringify(col.evidence), col.has_original_document_occurrence !== false,
        col.promotion_outcome || null
      ]
    );
  }
  return { report, extracted };
}

async function dropReport(reportId) {
  await pool.query(`DELETE FROM threat_report_candidate_source_links WHERE candidate_id IN (SELECT id FROM threat_report_candidates WHERE report_id = $1)`, [reportId]);
  for (const table of ['threat_report_ioc_sources', 'threat_report_candidates', 'threat_library_analysis_chunks', 'threat_library_jobs', 'threat_report_entities', 'threat_relationships']) {
    await pool.query(`DELETE FROM ${table} WHERE report_id = $1`, [reportId]);
  }
  await pool.query(`DELETE FROM threat_reports WHERE id = $1`, [reportId]);
}

test.afterEach(async () => {
  if (!hasDb) return;
  while (created.length) await dropReport(created.pop());
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ------------------------------------------------------------- ownership

test('job ownership: one owner; a duplicate delivery is refused while the owner heartbeats; stale owner is replaced', opts, async () => {
  const { report } = await newReport();
  const job = await createJob(pool, { reportId: report.id, jobType: 'analyze' });
  const a = crypto.randomUUID();
  const b = crypto.randomUUID();
  assert.ok(await claimJobOwnership(pool, { jobId: job.id, ownerToken: a, bullmqJobId: '1' }));
  assert.equal(await claimJobOwnership(pool, { jobId: job.id, ownerToken: b, bullmqJobId: '2' }), null, 'live owner keeps the job');
  // The owner stops heartbeating (crash): after the stale window a new delivery takes over.
  await pool.query(`UPDATE threat_library_jobs SET heartbeat_at = NOW() - INTERVAL '10 minutes' WHERE id = $1`, [job.id]);
  const takeover = await claimJobOwnership(pool, { jobId: job.id, ownerToken: b, bullmqJobId: '2' });
  assert.equal(takeover.owner_token, b);
  // The displaced owner learns it on its next heartbeat and stops.
  let lostReason = null;
  const hb = startJobHeartbeat(pool, { jobId: job.id, ownerToken: a, intervalMs: 50, onLost: (r) => { lostReason = r; } });
  await sleep(200);
  hb.stop();
  assert.equal(lostReason, 'owner_changed_or_job_ended');
  // Only the current owner can requeue.
  assert.equal(await requeueOwnedJob(pool, { jobId: job.id, ownerToken: a, reason: 'x' }), null);
  const requeued = await requeueOwnedJob(pool, { jobId: job.id, ownerToken: b, reason: 'requeued after worker shutdown' });
  assert.equal(requeued.status, 'queued');
  assert.equal(requeued.owner_token, null);
  assert.equal(requeued.bullmq_job_id, null);
  // A finished job can never be claimed again.
  await pool.query(`UPDATE threat_library_jobs SET status = 'completed' WHERE id = $1`, [job.id]);
  assert.equal(await claimJobOwnership(pool, { jobId: job.id, ownerToken: crypto.randomUUID() }), null);
});

test('concurrent Retry requests: exactly one pipeline job per report (10 parallel creators)', opts, async () => {
  const { report } = await newReport();
  const results = await Promise.all(
    Array.from({ length: 10 }, () => createExclusivePipelineJob(pool, { reportId: report.id, jobType: 'retry' }))
  );
  assert.equal(results.filter((r) => r.created).length, 1);
  assert.equal(new Set(results.map((r) => r.job.id)).size, 1);
  const { rows } = await pool.query(`SELECT COUNT(*)::int AS n FROM threat_library_jobs WHERE report_id = $1 AND status IN ('queued','running')`, [report.id]);
  assert.equal(rows[0].n, 1);
});

test('recovery requeues only jobs whose owner stopped heartbeating; a live owner is never displaced', opts, async () => {
  const { report: r1 } = await newReport();
  const { report: r2 } = await newReport();
  const dead = await createJob(pool, { reportId: r1.id, jobType: 'analyze' });
  const live = await createJob(pool, { reportId: r2.id, jobType: 'analyze' });
  await claimJobOwnership(pool, { jobId: dead.id, ownerToken: crypto.randomUUID(), bullmqJobId: 'b1' });
  await claimJobOwnership(pool, { jobId: live.id, ownerToken: crypto.randomUUID(), bullmqJobId: 'b2' });
  await pool.query(`UPDATE threat_library_jobs SET heartbeat_at = NOW() - INTERVAL '10 minutes' WHERE id = $1`, [dead.id]);
  // BullMQ still reports both "active" (a crashed worker's lock has not expired yet).
  const recovered = await recoverInterruptedAnalysisJobs(pool, { getJobState: async () => 'active' });
  assert.deepEqual(recovered.map((r) => r.jobId), [dead.id]);
  const rows = (await pool.query(`SELECT id, status, owner_token, bullmq_job_id FROM threat_library_jobs WHERE id = ANY($1) ORDER BY id`, [[dead.id, live.id]])).rows;
  assert.equal(rows[0].status, 'queued');
  assert.equal(rows[0].owner_token, null);
  assert.equal(rows[1].status, 'running');
});

test('dispatch: a delayed retry waits for not_before; a second live job for the same report is never claimed', opts, async () => {
  const { report: r1 } = await newReport();
  const { report: r2 } = await newReport();
  // r1: one running job, plus a stray queued duplicate (legacy rows / race) that must not run beside it.
  const running = await createJob(pool, { reportId: r1.id, jobType: 'analyze' });
  await claimJobOwnership(pool, { jobId: running.id, ownerToken: crypto.randomUUID(), bullmqJobId: 'live' });
  const stray = await createJob(pool, { reportId: r1.id, jobType: 'retry' });
  // r2: an automatic retry still in its backoff.
  const delayed = await createExclusivePipelineJob(pool, { reportId: r2.id, jobType: 'retry', notBefore: new Date(Date.now() + 60_000) });
  const enqueued = [];
  const enqueue = async (job) => {
    enqueued.push(job.id);
    return { id: `bull-${job.id}` };
  };
  await dispatchQueuedThreatLibraryAnalyses(pool, { enqueue, limitOverride: 4 });
  assert.ok(!enqueued.includes(stray.id), 'no second run for r1');
  assert.ok(!enqueued.includes(delayed.job.id), 'backoff respected');
  await pool.query(`UPDATE threat_library_jobs SET not_before = NOW() - INTERVAL '1 second' WHERE id = $1`, [delayed.job.id]);
  await dispatchQueuedThreatLibraryAnalyses(pool, { enqueue, limitOverride: 4 });
  assert.ok(enqueued.includes(delayed.job.id), 'due retry dispatched');
});

test('chunk attempt history keeps earlier failures after a successful retry, bounded to 10', opts, async () => {
  const { report } = await newReport();
  const runId = crypto.randomUUID();
  const chunk = { chunk_index: 0, chunk_key: 'chunk-001', block_ids: ['b1'] };
  await markAnalysisChunkFailed(pool, report.id, runId, chunk, 'first_token_timeout', 'AI provider did not start responding', {
    timing: [{ kind: 'chunk', failed: 'first_token_timeout', slot_wait_ms: 0 }]
  });
  await saveAnalysisChunkResult(pool, report.id, runId, chunk, { summary: 'ok' }, { timing: [{ kind: 'chunk', ms: 10 }] });
  let row = (await pool.query(`SELECT status, attempt_history, timing FROM threat_library_analysis_chunks WHERE report_id = $1`, [report.id])).rows[0];
  assert.equal(row.status, 'completed');
  assert.equal(row.attempt_history.length, 1);
  assert.equal(row.attempt_history[0].status, 'failed');
  assert.equal(row.attempt_history[0].error_code, 'first_token_timeout');
  assert.equal(row.attempt_history[0].timing[0].failed, 'first_token_timeout');
  for (let i = 0; i < 12; i += 1) {
    await markAnalysisChunkFailed(pool, report.id, runId, chunk, 'provider_unreachable', `attempt ${i}`, {});
  }
  row = (await pool.query(`SELECT attempt_history FROM threat_library_analysis_chunks WHERE report_id = $1`, [report.id])).rows[0];
  assert.equal(row.attempt_history.length, 10);
});

test('automatic retry: transient only, delayed with backoff, checkpoint contract kept, bounded attempts, single job', opts, async () => {
  await pool.query(`UPDATE threat_library_ai_settings SET auto_retry_max_attempts = 2 WHERE id = 1`);
  const { report } = await newReport('failed');
  const failedJob = await createJob(pool, { reportId: report.id, jobType: 'analyze' });
  await pool.query(`UPDATE threat_library_jobs SET status = 'failed' WHERE id = $1`, [failedJob.id]);

  const permanent = await maybeScheduleAutoRetry(pool, { reportId: report.id, jobId: failedJob.id, jobType: 'analyze', result: { code: 'ai_output_schema_error' } });
  assert.equal(permanent.scheduled, false);

  const before = Date.now();
  const first = await maybeScheduleAutoRetry(pool, { reportId: report.id, jobId: failedJob.id, jobType: 'analyze', result: { code: 'first_token_timeout' } }, { random: () => 0 });
  assert.equal(first.scheduled, true);
  assert.equal(first.attempt, 1);
  assert.ok(first.notBefore.getTime() >= before + AUTO_RETRY_BASE_DELAY_MS - 1000);
  const rep = (await pool.query(`SELECT analysis_status, failure_code, analysis_progress FROM threat_reports WHERE id = $1`, [report.id])).rows[0];
  assert.equal(rep.analysis_status, 'pending');
  assert.equal(rep.analysis_progress.candidate_extraction_version, THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'candidates + checkpoints stay reusable');
  assert.equal(rep.analysis_progress.auto_retry.attempt, 1);

  // While it is pending nothing else can be scheduled for the report.
  await pool.query(`UPDATE threat_reports SET analysis_status = 'failed' WHERE id = $1`, [report.id]);
  const dup = await maybeScheduleAutoRetry(pool, { reportId: report.id, jobId: failedJob.id, jobType: 'analyze', result: { code: 'first_token_timeout' } });
  assert.equal(dup.scheduled, false);
  assert.equal(dup.reason, 'job_already_active');

  // The retry itself failed again (attempt 2 of 2), then no third attempt.
  await pool.query(`UPDATE threat_library_jobs SET status = 'failed' WHERE id = $1`, [first.jobId]);
  const second = await maybeScheduleAutoRetry(pool, { reportId: report.id, jobId: first.jobId, jobType: 'retry', jobPayload: { auto_retry: { attempt: 1 } }, result: { code: 'provider_unreachable' } });
  assert.equal(second.scheduled, true);
  assert.equal(second.attempt, 2);
  await pool.query(`UPDATE threat_library_jobs SET status = 'failed' WHERE id = $1`, [second.jobId]);
  await pool.query(`UPDATE threat_reports SET analysis_status = 'failed' WHERE id = $1`, [report.id]);
  const third = await maybeScheduleAutoRetry(pool, { reportId: report.id, jobId: second.jobId, jobType: 'retry', jobPayload: { auto_retry: { attempt: 2 } }, result: { code: 'provider_unreachable' } });
  assert.equal(third.scheduled, false);
  assert.equal(third.reason, 'attempts_exhausted');
});

// ------------------------------------------------- IOC / review integrity

const IDENTITY_COLS = 'id, candidate_type, normalized_value, review_status, assessment, is_ioc, role, source_assertion';
const candidateSnapshot = async (reportId) =>
  (await pool.query(`SELECT ${IDENTITY_COLS} FROM threat_report_candidates WHERE report_id = $1 ORDER BY id`, [reportId])).rows;

test('AI failure mid-analysis then Retry: candidates and analyst decisions untouched, checkpoint reused, no IOC writes, never finalized', opts, async () => {
  const { report, extracted } = await newReport('pending');
  // Analyst decisions recorded before (re)analysis.
  const ids = (await candidateSnapshot(report.id)).map((r) => r.id);
  assert.ok(ids.length >= 3, 'fixture has candidates');
  await pool.query(`UPDATE threat_report_candidates SET review_status = 'approved' WHERE id = $1`, [ids[0]]);
  await pool.query(`UPDATE threat_report_candidates SET review_status = 'ignored' WHERE id = $1`, [ids[1]]);
  const before = await candidateSnapshot(report.id);
  const iocCountBefore = (await pool.query('SELECT COUNT(*)::int AS n FROM ioc_items')).rows[0].n;

  const maxInputChars = 1000;
  const chunks = buildAnalysisChunks(extracted.document, { maxInputChars });
  assert.ok(chunks.length >= 2, `fixture yields ${chunks.length} chunks`);

  let failSecond = true;
  const ollama = await startMockOllama({
    capacity: 1,
    plan: (r) => {
      if (failSecond && r.id === 2) return { fault: 'disconnect_mid_stream' };
      return { promptEvalMs: 5, genMs: 10 };
    }
  });
  await pool.query(
    `UPDATE threat_library_ai_settings SET enabled = true, provider = 'ollama', base_url = $1, model = 'qwen3.5:9b', max_input_chars = $2, max_concurrent_ai_requests = 1 WHERE id = 1`,
    [ollama.baseUrl, maxInputChars]
  );
  const scheduler = createInferenceScheduler(pool, { pollMs: 25, waitLeaseMs: 1000, holdLeaseMs: 3000, heartbeatMs: 500 });
  try {
    const job1 = await createJob(pool, { reportId: report.id, jobType: 'analyze' });
    const failed = await runAnalysisPipeline(pool, { reportId: report.id, jobId: job1.id, jobType: 'analyze' }, { inferenceScheduler: scheduler });
    assert.equal(failed.ok, false);
    assert.equal(failed.code, 'provider_unreachable');

    let rep = (await pool.query(`SELECT analysis_status, failure_code, failure_stage, finalized_at, failure_details FROM threat_reports WHERE id = $1`, [report.id])).rows[0];
    assert.equal(rep.analysis_status, 'failed');
    assert.equal(rep.failure_stage, 'analyzing');
    assert.equal(rep.finalized_at, null);
    assert.deepEqual(await candidateSnapshot(report.id), before, 'a failed AI stage never changes candidate rows');
    assert.equal((await pool.query(`SELECT COUNT(*)::int AS n FROM threat_report_entities WHERE report_id = $1`, [report.id])).rows[0].n, 0);
    const completed = (await pool.query(`SELECT chunk_key FROM threat_library_analysis_chunks WHERE report_id = $1 AND status = 'completed'`, [report.id])).rows;
    assert.deepEqual(completed.map((c) => c.chunk_key), ['chunk-001']);
    assert.equal(rep.failure_details.progress.analysis_chunks_completed, 1);

    // Retry with a healthy provider resumes from the checkpoint.
    failSecond = false;
    const requestsBefore = ollama.requests.length;
    const job2 = await createJob(pool, { reportId: report.id, jobType: 'retry' });
    const ok = await runAnalysisPipeline(pool, { reportId: report.id, jobId: job2.id, jobType: 'retry', resumeAnalysis: true }, { inferenceScheduler: scheduler });
    assert.equal(ok.ok, true, JSON.stringify(ok));
    const retryRequests = ollama.requests.slice(requestsBefore);
    const synthesisCalls = chunks.length > 1 ? 1 : 0;
    assert.equal(retryRequests.length, chunks.length - 1 + synthesisCalls, 'completed chunk-001 is not re-sent');

    rep = (await pool.query(`SELECT analysis_status, finalized_at FROM threat_reports WHERE id = $1`, [report.id])).rows[0];
    assert.equal(rep.analysis_status, 'review_required');
    assert.equal(rep.finalized_at, null, 'analysis never finalizes a report');
    const after = await candidateSnapshot(report.id);
    assert.deepEqual(
      after.map((r) => [r.id, r.normalized_value, r.review_status, r.is_ioc]),
      before.map((r) => [r.id, r.normalized_value, r.review_status, r.is_ioc]),
      'same rows, same identities, analyst decisions preserved'
    );
    assert.equal((await pool.query('SELECT COUNT(*)::int AS n FROM ioc_items')).rows[0].n, iocCountBefore, 'analysis creates no IOCs');
    const leases = (await pool.query(`SELECT COUNT(*)::int AS n FROM threat_library_ai_capacity_leases WHERE resource_key LIKE $1`, [`ollama|${ollama.baseUrl}%`])).rows[0].n;
    assert.equal(leases, 0, 'no leaked inference slots');
  } finally {
    await ollama.close();
  }
});

test('two reports analysed concurrently through the gate: both succeed, provider never runs two requests, no cross-report state', opts, async () => {
  const { report: r1 } = await newReport('pending');
  const { report: r2 } = await newReport('pending');
  const before1 = await candidateSnapshot(r1.id);
  const before2 = await candidateSnapshot(r2.id);
  const ollama = await startMockOllama({ capacity: 1, plan: () => ({ promptEvalMs: 5, genMs: 40 }) });
  await pool.query(
    `UPDATE threat_library_ai_settings SET enabled = true, provider = 'ollama', base_url = $1, model = 'qwen3.5:9b', max_input_chars = 1000, max_concurrent_ai_requests = 1 WHERE id = 1`,
    [ollama.baseUrl]
  );
  const scheduler = createInferenceScheduler(pool, { pollMs: 25, waitLeaseMs: 1000, holdLeaseMs: 3000, heartbeatMs: 500 });
  try {
    const j1 = await createJob(pool, { reportId: r1.id, jobType: 'analyze' });
    const j2 = await createJob(pool, { reportId: r2.id, jobType: 'analyze' });
    const [a, b] = await Promise.all([
      runAnalysisPipeline(pool, { reportId: r1.id, jobId: j1.id, jobType: 'analyze' }, { inferenceScheduler: scheduler }),
      runAnalysisPipeline(pool, { reportId: r2.id, jobId: j2.id, jobType: 'analyze' }, { inferenceScheduler: scheduler })
    ]);
    assert.equal(a.ok, true, JSON.stringify(a));
    assert.equal(b.ok, true, JSON.stringify(b));
    assert.equal(ollama.stats().maxExecuting, 1);
    assert.equal(ollama.stats().maxQueued, 0, 'no request waited inside the provider');
    assert.deepEqual((await candidateSnapshot(r1.id)).map((r) => r.id), before1.map((r) => r.id));
    assert.deepEqual((await candidateSnapshot(r2.id)).map((r) => r.id), before2.map((r) => r.id));
  } finally {
    await ollama.close();
  }
});

test('job heartbeat hanging (no error): ownership loss is declared before a recovery pass could take the job', opts, async () => {
  const { report } = await newReport();
  const job = await createJob(pool, { reportId: report.id, jobType: 'analyze' });
  const token = crypto.randomUUID();
  await claimJobOwnership(pool, { jobId: job.id, ownerToken: token });
  const hangingPool = { query: () => new Promise(() => {}) };
  const staleMs = 600;
  const intervalMs = 50;
  let lostAt = null;
  const started = Date.now();
  const hb = startJobHeartbeat(hangingPool, { jobId: job.id, ownerToken: token, intervalMs, staleMs, onLost: () => { lostAt = Date.now(); } });
  await sleep(staleMs + 100);
  hb.stop();
  assert.ok(lostAt, 'loss declared even though the heartbeat query never returned');
  assert.ok(lostAt - started < staleMs, `declared after ${lostAt - started}ms, stale window ${staleMs}ms`);
});

test('dispatch: two unclaimed pipeline jobs of one report are never both claimed in one pass', opts, async () => {
  const { report } = await newReport();
  const a = await createJob(pool, { reportId: report.id, jobType: 'retry' });
  const b = await createJob(pool, { reportId: report.id, jobType: 'refresh_extraction' });
  const enqueued = [];
  await dispatchQueuedThreatLibraryAnalyses(pool, { enqueue: async (job) => { enqueued.push(job.id); return { id: `bull-${job.id}` }; }, limitOverride: 4 });
  const mine = enqueued.filter((id) => id === a.id || id === b.id);
  assert.deepEqual(mine, [a.id], 'oldest claimed, the duplicate waits');
  // While the first is claimed, a later pass does not start the second either.
  await dispatchQueuedThreatLibraryAnalyses(pool, { enqueue: async (job) => { enqueued.push(job.id); return { id: `bull-${job.id}` }; }, limitOverride: 4 });
  assert.ok(!enqueued.includes(b.id));
});

for (const takeoverAt of ['mid_chunks', 'during_synthesis']) {
  test(`stale owner (${takeoverAt}): after another worker takes the job, the old run writes no candidates, entities or terminal status`, opts, async () => {
    const { report, extracted } = await newReport('pending');
    const before = await candidateSnapshot(report.id);
    const chunks = buildAnalysisChunks(extracted.document, { maxInputChars: 1000 });
    assert.ok(chunks.length >= 2);
    const job = await createJob(pool, { reportId: report.id, jobType: 'analyze' });
    const mine = crypto.randomUUID();
    await claimJobOwnership(pool, { jobId: job.id, ownerToken: mine });
    // Request number at which another worker takes over (stalled-owner takeover).
    const takeoverRequest = takeoverAt === 'mid_chunks' ? 1 : chunks.length + 1;
    const ollama = await startMockOllama({
      capacity: 1,
      plan: (r) => {
        if (r.id === takeoverRequest) {
          pool.query(`UPDATE threat_library_jobs SET owner_token = $2::uuid, heartbeat_at = NOW() WHERE id = $1`, [job.id, crypto.randomUUID()]).catch(() => {});
        }
        return { promptEvalMs: 40, genMs: 10 };
      }
    });
    await pool.query(
      `UPDATE threat_library_ai_settings SET enabled = true, provider = 'ollama', base_url = $1, model = 'qwen3.5:9b', max_input_chars = 1000, max_concurrent_ai_requests = 1 WHERE id = 1`,
      [ollama.baseUrl]
    );
    const scheduler = createInferenceScheduler(pool, { pollMs: 25, waitLeaseMs: 1000, holdLeaseMs: 3000, heartbeatMs: 500 });
    // The worker's fence (threat-library-worker.js assertOwnership).
    const assertOwnership = async () => {
      const owned = await pool.query(`SELECT 1 FROM threat_library_jobs WHERE id = $1 AND owner_token = $2::uuid AND status = 'running'`, [job.id, mine]);
      if (!owned.rowCount) throw Object.assign(new Error('lost'), { code: 'job_ownership_lost' });
    };
    try {
      const result = await runAnalysisPipeline(pool, { reportId: report.id, jobId: job.id, jobType: 'analyze', assertOwnership }, { inferenceScheduler: scheduler });
      assert.equal(result.ok, false, JSON.stringify(result));
      assert.equal(result.interrupted, true);
      assert.equal(result.code, 'job_ownership_lost');
      const rep = (await pool.query(`SELECT analysis_status, failure_code, finalized_at FROM threat_reports WHERE id = $1`, [report.id])).rows[0];
      assert.ok(!['failed', 'review_required'].includes(rep.analysis_status), `status ${rep.analysis_status}`);
      assert.equal(rep.failure_code, null);
      assert.equal(rep.finalized_at, null);
      assert.deepEqual(await candidateSnapshot(report.id), before, 'no candidate writes from the stale owner');
      assert.equal((await pool.query(`SELECT COUNT(*)::int AS n FROM threat_report_entities WHERE report_id = $1`, [report.id])).rows[0].n, 0);
      const jobRow = (await pool.query(`SELECT status FROM threat_library_jobs WHERE id = $1`, [job.id])).rows[0];
      assert.equal(jobRow.status, 'running', 'the new owner keeps the job');
    } finally {
      await ollama.close();
    }
  });
}
