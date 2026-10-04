/**
 * Refresh extraction (deterministic, AI-free) at the worker / service boundary.
 *
 * A stateful fake database stands in for Postgres: candidates, entities,
 * relationships (with the real ON DELETE CASCADE on candidate endpoints),
 * report tags, analysis chunks, the IOC catalog, reports and jobs. Every SQL
 * statement is recorded, and an unknown statement fails the test, so a new
 * write path cannot slip in unnoticed.
 *
 * The model seam is a spy (`deps.analyzeThreatDocument`) and `globalThis.fetch`
 * is replaced by a throwing spy: a refresh must reach neither.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { extractReportCandidates, mergeAiCandidateUpdates, matchCandidateSet } from './extractionStages.js';
import { replaceCandidates } from './store.js';
import { runThreatLibraryJob } from './jobRunner.js';
import { runAnalysisPipeline } from './pipeline.js';
import { aiReplayUpdatesFromRows, applyAnalystState, resolveRefreshRestoreStatus } from './extractionRefresh.js';
import { parseJobMode, jobModeInvokesAi, evaluateMaintenanceAction, UnknownJobModeError } from './jobModes.js';
import { isActionableReviewIndicator } from './promotion.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SOURCE = 'https://research.example/blog/refresh-extraction/';
const SHA_A = crypto.createHash('sha256').update('refresh-extraction-sample-a').digest('hex');
const AI_DOMAIN = 'beacon-relay-hub.org';
const BODY_DOMAIN = 'docs-mirror-cache.example';

function fixtureHtml({ withSecondNetworkIoc = true } = {}) {
  return `<!doctype html><html lang="en"><head><title>Refresh fixture</title></head><body><article>
<h1>Synthetic intrusion campaign</h1>
${Array.from({ length: 4 }, (_, i) => `<p>Background paragraph ${i + 1} describes initial access, tooling and operator tradecraft across several victims.</p>`).join('\n')}
<p>The loader was also configured with subdomains of 'beacon-relay-hub[.]org' as a C&amp;C, blending in with update traffic.</p>
<p>Researchers compared the lure with documentation hosted at docs-mirror-cache[.]example during the analysis.</p>
<h2>Indicators of Compromise</h2>
<h3>File indicators</h3>
<p>${SHA_A}</p>
<h3>Network IOCs</h3>
<p>relay-voxmail[.]com</p>
${withSecondNetworkIoc ? '<p>inbox-notice-hub[.]net</p>' : ''}
</article></body></html>`;
}

function buildDocument(opts) {
  const r = extractCanonicalDocumentFromHtml(fixtureHtml(opts), { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true);
  return r.document;
}

const key = (c) => `${c.candidate_type}|${c.normalized_value}`;
const clone = (v) => JSON.parse(JSON.stringify(v));

/** Stateful fake Postgres for the Threat Library tables a refresh can touch. */
function createFakeDb({ report, iocCatalog = [] }) {
  const db = {
    report: { deleted_at: null, cancel_requested_at: null, failure_code: null, ...report },
    candidates: [],
    entities: [],
    relationships: [],
    reportTags: [],
    chunks: [],
    jobs: [{ id: 41, report_id: report.id, job_type: 'refresh_extraction', status: 'running', progress: {} }],
    sql: [],
    calls: [],
    nextCandidateId: 1000
  };
  const iocByKey = new Map(iocCatalog.map((i) => [`${i.observable_type}\0${i.observable}`, i]));
  const exec = async (text, params = []) => {
    const s = String(text);
    db.sql.push(s);
    db.calls.push({ sql: s, params });
    const t = s.trim();
    if (/^(BEGIN|COMMIT|ROLLBACK)/.test(t)) return { rows: [] };
    if (/FROM threat_reports WHERE id = \$1 AND deleted_at IS NULL/.test(s)) return { rows: [clone(db.report)] };
    if (/^UPDATE threat_reports SET\s+title = COALESCE\(\$2, title\)/.test(t)) {
      const p = params;
      const r = db.report;
      if (p[7] != null) r.import_status = p[7];
      if (p[8] != null) r.analysis_status = p[8];
      if (p[11] != null) r.candidate_summary = clone(p[11]);
      if (p[12] != null) r.canonical_document = clone(p[12]);
      if (p[13] != null) r.ai_result = clone(p[13]);
      if (p[17] != null) r.analysis_progress = clone(p[17]);
      if (p[19] != null) r.analysis_run_id = p[19];
      if (p[21] === true) r.failure_code = null;
      for (const [i, col] of [[1, 'title'], [3, 'tlp'], [4, 'confidence'], [5, 'report_type'], [6, 'summary']]) {
        if (p[i] != null) r[col] = p[i];
      }
      return { rows: [clone(r)] };
    }
    if (/^UPDATE threat_reports\s+SET analysis_status = \$2,\s+import_status = \$3/.test(t)) {
      Object.assign(db.report, { analysis_status: params[1], import_status: params[2], analysis_progress: JSON.parse(params[3]) });
      return { rows: [clone(db.report)] };
    }
    if (/^UPDATE threat_reports SET\s+published_at = \$2/.test(t)) {
      db.report.published_at = params[1];
      return { rows: [clone(db.report)] };
    }
    if (/^UPDATE threat_reports SET analysis_run_id = \$2::uuid/.test(t)) {
      db.report.analysis_run_id = params[1];
      return { rows: [], rowCount: 1 };
    }
    if (/SELECT cancel_requested_at FROM threat_reports/.test(s)) return { rows: [{ cancel_requested_at: null }] };
    if (/FROM threat_report_artifacts/.test(s)) return { rows: [] };
    if (/^UPDATE threat_library_jobs SET/.test(t)) {
      const job = db.jobs.find((j) => j.id === params[0]);
      if (job) {
        if (params[1] != null) job.status = params[1];
        if (params[2] != null) job.stage = params[2];
        if (params[3] != null) job.progress = clone(params[3]);
        job.error_message = params[4];
      }
      return { rows: job ? [clone(job)] : [] };
    }
    if (/SELECT \* FROM threat_report_candidates WHERE report_id = \$1 ORDER BY id/.test(s)) {
      return { rows: clone(db.candidates.filter((c) => c.report_id === params[0])) };
    }
    if (/COUNT\(\*\)::int AS n FROM threat_report_candidates/.test(s)) {
      return { rows: [{ n: db.candidates.filter((c) => c.report_id === params[0]).length }] };
    }
    if (/^SELECT candidate_type, original_value, normalized_value/.test(t)) {
      return { rows: clone(db.candidates.filter((c) => c.report_id === params[0])) };
    }
    if (/^INSERT INTO threat_report_candidates/.test(t)) {
      const [report_id, portable_id, candidate_type, original_value, normalized_value, assessment, role, confidence,
        evidence_text, section, block_id, page_number, review_status, match_state, matched_ioc_id,
        matched_ioc_observable_type, is_ioc, source_assertion, evidence] = params;
      const row = {
        id: db.nextCandidateId++, public_id: crypto.randomUUID(), report_id, portable_id, candidate_type, original_value,
        normalized_value, assessment, role, confidence: confidence == null ? null : Number(confidence).toFixed(3),
        evidence_text, section, block_id, page_number, review_status, match_state, matched_ioc_id,
        matched_ioc_observable_type, is_ioc, source_assertion, evidence: JSON.parse(evidence),
        promotion_outcome: null, promotion_detail: null, promoted_at: null
      };
      db.candidates.push(row);
      return { rows: [clone(row)] };
    }
    if (/^UPDATE threat_report_candidates SET\s+original_value = \$2/.test(t)) {
      const row = db.candidates.find((c) => c.id === params[0]);
      const cols = ['original_value', 'assessment', 'role', 'confidence', 'evidence_text', 'section', 'block_id', 'page_number',
        'review_status', 'match_state', 'matched_ioc_id', 'matched_ioc_observable_type', 'is_ioc', 'source_assertion', 'evidence'];
      cols.forEach((col, i) => {
        const v = params[i + 1];
        row[col] = col === 'evidence' ? JSON.parse(v) : col === 'confidence' && v != null ? Number(v).toFixed(3) : v;
      });
      row.updated = true;
      return { rows: [clone(row)] };
    }
    if (/^DELETE FROM threat_report_candidates WHERE report_id = \$1 AND id = ANY/.test(t)) {
      const ids = new Set(params[1].map(Number));
      db.candidates = db.candidates.filter((c) => !ids.has(c.id));
      // ON DELETE CASCADE (subject/object_candidate_id)
      db.relationships = db.relationships.filter((r) => !ids.has(r.subject_candidate_id) && !ids.has(r.object_candidate_id));
      return { rows: [], rowCount: ids.size };
    }
    if (/^DELETE FROM threat_report_candidates WHERE report_id = \$1$/.test(t)) {
      const gone = new Set(db.candidates.filter((c) => c.report_id === params[0]).map((c) => c.id));
      db.candidates = db.candidates.filter((c) => c.report_id !== params[0]);
      db.relationships = db.relationships.filter((r) => !gone.has(r.subject_candidate_id) && !gone.has(r.object_candidate_id));
      return { rows: [] };
    }
    if (/FROM ioc_items/.test(s) && /unnest/.test(s)) {
      const [types, values] = params;
      const rows = [];
      types.forEach((type, i) => {
        const hit = iocByKey.get(`${type}\0${values[i]}`);
        if (hit) rows.push({ ...hit, status: 'active' });
      });
      return { rows };
    }
    if (/FROM threat_library_ai_settings/.test(s)) {
      return { rows: [{ id: 1, enabled: true, provider: 'ollama', model: 'test-model', base_url: 'http://model.invalid', max_input_chars: 120000 }] };
    }
    throw new Error(`fake db: unexpected SQL: ${t.slice(0, 120)}`);
  };
  return { db, pool: { query: exec, connect: async () => ({ query: exec, release() {} }) } };
}

const IOC_CATALOG = [{ id: 501, public_id: 'ioc-501', observable: 'relay-voxmail.com', observable_type: 'domain' }];

/**
 * A report as the full pipeline left it: deterministic candidates, one AI
 * decision on an ai_needed body domain, matching, entities, a relationship,
 * report tags and analysis chunks. `previousContract` simulates an older
 * extractor; `mutate(candidates)` edits the persisted set before analyst state.
 */
async function seedAnalyzedReport({ status = 'review_required', previousContract = THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, html, mutate } = {}) {
  const document = buildDocument(html);
  const report = {
    id: 77,
    public_id: '77777777-2222-4333-8444-555555555555',
    source_type: 'url',
    source_url: SOURCE,
    title: 'Refresh fixture',
    analysis_status: status,
    import_status: status,
    tlp: 'clear',
    tlp_source: 'default',
    confidence: '0.800',
    report_type: 'campaign',
    summary: 'AI summary of the campaign.',
    ai_result: { entity_count: 2, relationship_count: 1, ai_calls: 3 },
    analysis_run_id: '00000000-0000-4000-8000-000000000001',
    finalized_at: status === 'ready' ? '2026-10-01T00:00:00.000Z' : null,
    analysis_progress: {
      stage: status,
      completed: true,
      candidate_extraction_version: previousContract,
      schema_version: 'threat-library-semantic-v9',
      ai_calls: 3
    }
  };
  const { db, pool } = createFakeDb({ report, iocCatalog: IOC_CATALOG });
  const extracted = extractReportCandidates(report, document);
  db.report.canonical_document = extracted.document;
  const merged = mergeAiCandidateUpdates(extracted.candidates, {
    candidate_updates: [{
      candidate_type: 'domain', normalized_value: AI_DOMAIN, assessment: 'malicious',
      role: 'command_and_control', confidence: 0.95, evidence_text: 'configured with subdomains of beacon-relay-hub[.]org as a C&C'
    }]
  }, { document: extracted.document });
  const matched = await matchCandidateSet(pool, merged);
  await replaceCandidates(pool, report.id, mutate ? mutate(matched.candidates) : matched.candidates);
  const byKey = (k) => db.candidates.find((c) => key(c) === k);

  db.entities = [
    { report_id: 77, entity_id: 9001, name: 'SyntheticLoader', confidence: '0.900' },
    { report_id: 77, entity_id: 9002, name: 'Operator Group X', confidence: '0.700' }
  ];
  const aiRow = byKey(`domain|${AI_DOMAIN}`);
  db.relationships = aiRow
    ? [{ id: 3001, report_id: 77, subject_kind: 'entity', subject_entity_id: 9001, relationship_type: 'communicates_with', object_kind: 'candidate', object_candidate_id: aiRow.id }]
    : [];
  db.reportTags = [{ report_id: 77, tag_id: 11 }, { report_id: 77, tag_id: 12 }];
  db.chunks = [{ report_id: 77, analysis_run_id: report.analysis_run_id, chunk_key: 'c0', status: 'completed' }];
  db.sql.length = 0;
  db.calls.length = 0;
  return { db, pool, document: extracted.document, byKey };
}

function noAiSpies(t) {
  const calls = { analyze: 0, fetch: 0 };
  const analyzeThreatDocument = async () => {
    calls.analyze += 1;
    throw new Error('model must not be invoked');
  };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    calls.fetch += 1;
    throw new Error('network must not be used');
  };
  t.after(() => { globalThis.fetch = originalFetch; });
  return { calls, deps: { analyzeThreatDocument } };
}

const AI_OWNED_TABLES = /threat_library_analysis_chunks|threat_report_entities|threat_relationships|threat_report_tags|threat_entities|threat_library_ai_settings/i;
// updateReportStatus params owned by AI analysis: title, tlp, confidence,
// report_type, summary, ai_result, analysis_run_id, tlp_source.
const AI_OWNED_REPORT_PARAMS = [1, 3, 4, 5, 6, 13, 19, 23];

/** Every statement a refresh issued that touches AI-owned tables or report columns. */
function aiOwnedWrites(db) {
  const out = [];
  for (const { sql, params } of db.calls) {
    if (AI_OWNED_TABLES.test(sql) || /SET analysis_run_id/.test(sql)) out.push(sql.trim().slice(0, 80));
    if (/^\s*UPDATE threat_reports SET\s+title = COALESCE/.test(sql)) {
      for (const i of AI_OWNED_REPORT_PARAMS) if (params[i] != null) out.push(`updateReportStatus param ${i + 1}`);
    }
  }
  return out;
}

async function refresh(pool, deps, restoreStatus = { analysis_status: 'review_required' }) {
  return runThreatLibraryJob(pool, { reportId: 77, jobId: 41, jobType: 'refresh_extraction', restoreStatus }, deps);
}

test('job modes: explicit enum, unknown values rejected, only refresh is AI-free', () => {
  assert.equal(parseJobMode('refresh_extraction'), 'refresh_extraction');
  assert.equal(parseJobMode('rerun_ai'), 'rerun_ai');
  for (const bad of ['', 'refresh', 'skipAi', null, undefined, 42, 'RETRY']) {
    assert.throws(() => parseJobMode(bad), UnknownJobModeError);
  }
  assert.equal(jobModeInvokesAi('refresh_extraction'), false);
  for (const m of ['analyze', 'retry', 'rerun_ai']) assert.equal(jobModeInvokesAi(m), true);
});

test('state guards: refresh on review_required / finalized, rerun AI on review_required, retry on failed', () => {
  const g = (status, mode, source_type = 'url') => evaluateMaintenanceAction({ analysis_status: status, source_type }, mode);
  assert.equal(g('review_required', 'refresh_extraction').ok, true);
  assert.equal(g('ready', 'refresh_extraction').ok, true);
  for (const s of ['failed', 'cancelled', 'pending', 'analyzing', 'extracting', 'skipped']) {
    assert.equal(g(s, 'refresh_extraction').code, 'refresh_extraction_not_allowed', s);
  }
  assert.equal(g('review_required', 'rerun_ai').ok, true);
  for (const s of ['ready', 'failed', 'pending']) assert.equal(g(s, 'rerun_ai').code, 'rerun_ai_not_allowed', s);
  assert.equal(g('failed', 'retry').ok, true);
  assert.equal(g('cancelled', 'retry').ok, true);
  for (const s of ['review_required', 'ready']) assert.equal(g(s, 'retry').code, 'retry_not_applicable', s);
  assert.equal(g('review_required', 'refresh_extraction', 'thib').status, 400);
});

test('static guarantee: no model client is reachable from the refresh code path', () => {
  const seen = new Set();
  const visit = (file) => {
    if (seen.has(file)) return;
    seen.add(file);
    const src = fs.readFileSync(file, 'utf8');
    for (const m of src.matchAll(/(?:import|export)\s[^'"]*?from\s+'(\.{1,2}\/[^']+)'|import\(\s*'(\.{1,2}\/[^']+)'\s*\)/g)) {
      const spec = m[1] || m[2];
      visit(path.resolve(path.dirname(file), spec));
    }
  };
  visit(path.join(HERE, 'extractionRefresh.js'));
  const reached = [...seen].map((f) => path.relative(HERE, f).replace(/\\/g, '/'));
  assert.ok(reached.includes('extractionStages.js') && reached.includes('store.js'), 'graph walked');
  assert.deepEqual(reached.filter((f) => /(^|\/)ai\//.test(f) || /pipeline\.js$/.test(f)), [], 'refresh never imports ./ai/* or pipeline.js');
});

test('the AI pipeline refuses a refresh_extraction job (defence in depth)', async () => {
  const { pool } = createFakeDb({ report: { id: 77 } });
  await assert.rejects(runAnalysisPipeline(pool, { reportId: 77, jobId: 41, jobType: 'refresh_extraction' }), { code: 'invalid_job_mode' });
});

test('1. refresh with an ai_needed candidate: extractor + matching run, zero model / network calls, no AI-owned SQL', async (t) => {
  const { calls, deps } = noAiSpies(t);
  // Older contract + the AI never decided the second body domain → it is ai_needed.
  const { db, pool } = await seedAnalyzedReport({ previousContract: 'tl-candidates-v13' });
  assert.equal(db.candidates.find((c) => c.normalized_value === BODY_DOMAIN).evidence.ai_needed, true);

  const result = await refresh(pool, deps);

  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(calls.analyze, 0, 'no model call');
  assert.equal(calls.fetch, 0, 'no provider / network request');
  assert.equal(result.summary.ai_invoked, false);
  assert.equal(result.summary.extraction_contract, THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION);
  assert.deepEqual(aiOwnedWrites(db), [], 'no chunk / entity / relationship / tag SQL, no AI-owned report column written');
  assert.ok(db.sql.some((q) => /FROM ioc_items/.test(q)), 'IOC matching ran');
  // ai_needed stays ai_needed: no classification is fabricated.
  const body = db.candidates.find((c) => c.normalized_value === BODY_DOMAIN);
  assert.equal(body.evidence.ai_needed, true);
  assert.equal(body.evidence.decision_source, 'pending');
  assert.equal(body.assessment, 'unknown');
  // Status + provenance
  assert.equal(db.report.analysis_status, 'review_required');
  assert.equal(db.report.import_status, 'review_required');
  assert.equal(db.report.analysis_progress.candidate_extraction_version, THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION);
  assert.equal(db.report.analysis_progress.last_refresh.ai_invoked, false);
  assert.equal(db.report.analysis_progress.ai_calls, 3, 'previous AI run stats are kept, not rewritten');
  assert.equal(db.jobs[0].status, 'completed');
  assert.equal(db.jobs[0].progress.mode, 'refresh_extraction');
  assert.equal(db.jobs[0].progress.refresh.ai_invoked, false);
});

test('2. AI-derived report state is preserved exactly (tags, entities, relationships, chunks, summary, run id)', async (t) => {
  const { calls, deps } = noAiSpies(t);
  const { db, pool } = await seedAnalyzedReport();
  const before = clone({
    entities: db.entities, relationships: db.relationships, tags: db.reportTags, chunks: db.chunks,
    summary: db.report.summary, confidence: db.report.confidence, report_type: db.report.report_type,
    tlp: [db.report.tlp, db.report.tlp_source], ai_result: db.report.ai_result, run: db.report.analysis_run_id
  });
  const result = await refresh(pool, deps);
  assert.equal(result.ok, true);
  assert.equal(calls.analyze, 0);
  assert.deepEqual(clone({
    entities: db.entities, relationships: db.relationships, tags: db.reportTags, chunks: db.chunks,
    summary: db.report.summary, confidence: db.report.confidence, report_type: db.report.report_type,
    tlp: [db.report.tlp, db.report.tlp_source], ai_result: db.report.ai_result, run: db.report.analysis_run_id
  }), before);
  // The AI decision on the surviving identity is replayed, not lost or re-asked.
  const ai = db.candidates.find((c) => c.normalized_value === AI_DOMAIN);
  assert.equal(ai.assessment, 'malicious');
  assert.equal(ai.evidence.decision_source, 'ai');
  assert.equal(ai.evidence.ai_needed, false);
});

test('unchanged report: refresh is a no-op on every row (ids, public ids, values) — no UPDATE / INSERT / DELETE', async (t) => {
  const { calls, deps } = noAiSpies(t);
  const { db, pool } = await seedAnalyzedReport();
  const before = clone(db.candidates);
  const result = await refresh(pool, deps);
  assert.equal(result.ok, true);
  assert.equal(calls.analyze, 0);
  assert.deepEqual(clone(db.candidates), before);
  assert.equal(result.summary.added, 0);
  assert.equal(result.summary.removed, 0);
  assert.equal(result.summary.updated, 0);
  assert.equal(result.summary.unchanged, before.length);
  assert.equal(db.sql.some((q) => /^\s*(UPDATE|INSERT INTO|DELETE FROM) threat_report_candidates/.test(q)), false);
  // A second refresh is idempotent as well.
  const again = await refresh(pool, deps);
  assert.equal(again.summary.updated + again.summary.added + again.summary.removed, 0);
});

test('3. surviving identities keep analyst state: review decisions, Context only, promotion override + outcome, row ids', async (t) => {
  const { calls, deps } = noAiSpies(t);
  const { db, pool, byKey } = await seedAnalyzedReport({ previousContract: 'tl-candidates-v13' });
  // Analyst work, exactly as reviewService persists it.
  const sha = byKey(`sha256|${SHA_A}`);
  Object.assign(sha, { review_status: 'approved', promotion_outcome: 'created', promotion_detail: 'IOC created', promoted_at: '2026-10-02T10:00:00.000Z' });
  const inbox = byKey('domain|inbox-notice-hub.net');
  Object.assign(inbox, { review_status: 'context_only', assessment: 'context_only', match_state: 'context_only' });
  const relay = byKey('domain|relay-voxmail.com');
  relay.review_status = 'ignored';
  const body = byKey(`domain|${BODY_DOMAIN}`);
  // promote_to_ioc on a row the pipeline had left context-only
  Object.assign(body, {
    review_status: 'approved', assessment: 'suspicious', role: 'unknown', is_ioc: true, match_state: 'new',
    evidence: { ...body.evidence, decision_source: 'analyst', policy_decision: 'analyst_promoted_from_context_only',
      promoted_from: { assessment: 'context_only', role: 'reference', match_state: 'context_only', review_status: 'pending', is_ioc: true, policy_decision: 'pass', decision_source: 'deterministic', promoted_at: '2026-10-02T10:00:00.000Z', promoted_by: 'analyst@example' } }
  });
  // Make the promoted row context-only under the refreshed reading as it was when promoted.
  const ids = new Map(db.candidates.map((c) => [key(c), { id: c.id, public_id: c.public_id, portable_id: c.portable_id }]));

  const result = await refresh(pool, deps);
  assert.equal(result.ok, true);
  assert.equal(calls.analyze, 0);
  for (const c of db.candidates) {
    assert.deepEqual({ id: c.id, public_id: c.public_id, portable_id: c.portable_id }, ids.get(key(c)), `${key(c)} keeps its row identity`);
  }
  const after = (k) => db.candidates.find((c) => key(c) === k);
  assert.equal(after(`sha256|${SHA_A}`).review_status, 'approved');
  assert.equal(after(`sha256|${SHA_A}`).promotion_outcome, 'created');
  assert.equal(after(`sha256|${SHA_A}`).promoted_at, '2026-10-02T10:00:00.000Z');
  assert.equal(after('domain|inbox-notice-hub.net').review_status, 'context_only');
  assert.equal(after('domain|inbox-notice-hub.net').assessment, 'context_only');
  assert.equal(after('domain|inbox-notice-hub.net').match_state, 'context_only');
  assert.equal(after('domain|relay-voxmail.com').review_status, 'ignored');
  assert.equal(after('domain|relay-voxmail.com').matched_ioc_id, 501, 'matching recomputed');
  const promoted = after(`domain|${BODY_DOMAIN}`);
  assert.equal(promoted.review_status, 'approved');
  assert.equal(promoted.evidence.promoted_from.promoted_by, 'analyst@example', 'promotion provenance kept');
  // Relationship rows attached to surviving candidates stay attached.
  assert.equal(db.relationships.length, 1);
  assert.equal(db.relationships[0].object_candidate_id, after(`domain|${AI_DOMAIN}`).id);
});

test('promotion override is re-applied when the refreshed reading is context-only again', () => {
  const candidate = { candidate_type: 'domain', normalized_value: 'cdn.example', assessment: 'context_only', match_state: 'context_only', role: 'reference', is_ioc: true, matched_ioc_id: null };
  const prior = {
    review_status: 'approved',
    evidence: { decision_source: 'analyst', promoted_from: { assessment: 'context_only', decision_source: 'deterministic' } }
  };
  applyAnalystState(candidate, prior);
  assert.equal(candidate.assessment, 'suspicious');
  assert.equal(candidate.role, 'unknown');
  assert.equal(candidate.match_state, 'new');
  assert.equal(candidate.decision_source, 'analyst');
  assert.equal(candidate.policy_decision, 'analyst_promoted_from_context_only');
  assert.equal(candidate.review_status, 'approved');
  // A new identity always starts pending.
  assert.equal(applyAnalystState({ candidate_type: 'ip', normalized_value: '203.0.113.9' }, null).review_status, 'pending');
});

test('AI replay: only rows the model decided are replayed, keyed by identity; block pointers dropped when the document was rebuilt', () => {
  const rows = [
    { candidate_type: 'domain', normalized_value: 'a.example', assessment: 'malicious', role: 'command_and_control', confidence: '0.950', evidence_text: 'x', section: 'report_body', block_id: 'b3', evidence: { decision_source: 'ai' } },
    { candidate_type: 'domain', normalized_value: 'b.example', assessment: 'malicious', role: 'malicious_infrastructure', confidence: '0.900', evidence: { decision_source: 'deterministic', ai_role_suggestion: 'command_and_control' } },
    { candidate_type: 'domain', normalized_value: 'c.example', assessment: 'unknown', role: 'unknown', confidence: null, evidence: { decision_source: 'pending', ai_needed: true } },
    { candidate_type: 'domain', normalized_value: 'd.example', assessment: 'suspicious', role: 'unknown', confidence: '0.600', evidence: { decision_source: 'analyst', promoted_from: { decision_source: 'ai', assessment: 'context_only', role: 'reference' } } }
  ];
  const same = aiReplayUpdatesFromRows(rows, { documentRebuilt: false });
  assert.deepEqual(same.map((u) => u.normalized_value), ['a.example', 'b.example', 'd.example']);
  assert.deepEqual(same[0], { candidate_type: 'domain', normalized_value: 'a.example', assessment: 'malicious', role: 'command_and_control', confidence: 0.95, evidence_text: 'x', section: 'report_body', evidence_block_ids: ['b3'] });
  assert.deepEqual(same[1], { candidate_type: 'domain', normalized_value: 'b.example', role: 'command_and_control', confidence: 0.9 });
  assert.equal(same[2].assessment, 'context_only', 'the model decision recorded before the analyst promotion');
  const rebuilt = aiReplayUpdatesFromRows(rows, { documentRebuilt: true });
  assert.equal('evidence_block_ids' in rebuilt[0], false);
  assert.equal('section' in rebuilt[0], false);
});

test('4. new deterministic IOC: created by refresh, joins Indicators, no AI', async (t) => {
  const { calls, deps } = noAiSpies(t);
  // The stored set (older contract) lacks inbox-notice-hub.net.
  const { db, pool } = await seedAnalyzedReport({
    previousContract: 'tl-candidates-v13',
    mutate: (cands) => cands.filter((c) => c.normalized_value !== 'inbox-notice-hub.net')
  });
  const membersBefore = db.candidates.filter((c) => isActionableReviewIndicator(c)).length;
  const result = await refresh(pool, deps);
  assert.equal(result.ok, true);
  assert.equal(calls.analyze, 0);
  assert.equal(result.summary.added, 1);
  const added = db.candidates.find((c) => c.normalized_value === 'inbox-notice-hub.net');
  assert.ok(added, 'candidate created');
  assert.equal(added.source_assertion, 'explicit_ioc');
  assert.equal(added.review_status, 'pending');
  assert.equal(db.candidates.filter((c) => isActionableReviewIndicator(c)).length, membersBefore + 1, 'Indicators membership corrected');
  assert.deepEqual(db.report.analysis_progress.last_refresh.added_identities, [{ candidate_type: 'domain', normalized_value: 'inbox-notice-hub.net' }]);
});

test('5. removed deterministic candidate: no longer a report candidate; its relationship rows cascade', async (t) => {
  const { calls, deps } = noAiSpies(t);
  const { db, pool } = await seedAnalyzedReport({
    previousContract: 'tl-candidates-v13',
    mutate: (cands) => [...cands, {
      ...cands.find((c) => c.normalized_value === 'relay-voxmail.com'),
      candidate_type: 'domain', normalized_value: 'cs.append', original_value: 'cs.append', matched_ioc_id: null, portable_id: null
    }]
  });
  const stale = db.candidates.find((c) => c.normalized_value === 'cs.append');
  stale.review_status = 'approved';
  db.relationships.push({ id: 3002, report_id: 77, subject_kind: 'entity', subject_entity_id: 9002, relationship_type: 'uses', object_kind: 'candidate', object_candidate_id: stale.id });
  const result = await refresh(pool, deps);
  assert.equal(result.ok, true);
  assert.equal(calls.analyze, 0);
  assert.equal(result.summary.removed, 1);
  assert.equal(db.candidates.some((c) => c.normalized_value === 'cs.append'), false);
  assert.deepEqual(db.relationships.map((r) => r.id), [3001], 'only the relationship of the removed identity is gone');
  assert.deepEqual(db.report.analysis_progress.last_refresh.removed_identities, [
    { candidate_type: 'domain', normalized_value: 'cs.append', review_status: 'approved', promotion_outcome: null }
  ]);
});

test('6. identity correction (technical_artifact → domain): corrected identity, no state migration, no AI', async (t) => {
  const { calls, deps } = noAiSpies(t);
  const { db, pool } = await seedAnalyzedReport({
    previousContract: 'tl-candidates-v13',
    mutate: (cands) => cands.map((c) => (c.normalized_value === 'relay-voxmail.com'
      ? { ...c, candidate_type: 'technical_artifact', normalized_value: 'rElay-voxMail.COM', original_value: 'rElay-voxMail.COM', assessment: 'context_only', match_state: 'context_only', is_ioc: false, matched_ioc_id: null, matched_ioc_observable_type: null }
      : c))
  });
  const artifact = db.candidates.find((c) => c.candidate_type === 'technical_artifact');
  artifact.review_status = 'ignored';
  const result = await refresh(pool, deps);
  assert.equal(result.ok, true);
  assert.equal(calls.analyze, 0);
  assert.equal(db.candidates.some((c) => c.candidate_type === 'technical_artifact'), false, 'old identity removed');
  const domain = db.candidates.find((c) => key(c) === 'domain|relay-voxmail.com');
  assert.ok(domain, 'corrected identity present');
  assert.equal(domain.review_status, 'pending', 'analyst state is not guessed across identities');
  assert.equal(domain.source_assertion, 'explicit_ioc');
  assert.equal(domain.matched_ioc_id, 501);
  assert.equal(isActionableReviewIndicator(domain), true);
});

test('finalized report: refresh keeps it finalized (status, finalized_at), never reopens it', async (t) => {
  const { calls, deps } = noAiSpies(t);
  const { db, pool } = await seedAnalyzedReport({ status: 'ready', previousContract: 'tl-candidates-v13' });
  const result = await refresh(pool, deps, resolveRefreshRestoreStatus({ analysis_status: 'ready' }));
  assert.equal(result.ok, true);
  assert.equal(calls.analyze, 0);
  assert.equal(db.report.analysis_status, 'ready');
  assert.equal(db.report.import_status, 'ready');
  assert.equal(db.report.finalized_at, '2026-10-01T00:00:00.000Z');
  assert.equal(db.jobs[0].stage, 'ready');
});

test('restore status: only a committed review set or finalized report is restorable; nothing else is finalized implicitly', () => {
  assert.deepEqual(resolveRefreshRestoreStatus({ analysis_status: 'ready' }), { analysis_status: 'ready', import_status: 'ready' });
  assert.deepEqual(resolveRefreshRestoreStatus({ analysis_status: 'review_required' }), { analysis_status: 'review_required', import_status: 'review_required' });
  for (const bad of [null, {}, { analysis_status: 'failed' }, { analysis_status: 'pending' }]) {
    assert.deepEqual(resolveRefreshRestoreStatus(bad), { analysis_status: 'review_required', import_status: 'review_required' });
  }
});

test('refresh failure: report returns to its prior status (not failed), job records the failure, still no AI', async (t) => {
  const { calls, deps } = noAiSpies(t);
  const { db, pool } = await seedAnalyzedReport({ status: 'ready' });
  // Stored document predates the current extractor and there is no retained source.
  db.report.canonical_document = { ...db.report.canonical_document, meta: { ...db.report.canonical_document.meta, extractor: 'threat_library_html_v1' } };
  const before = clone(db.candidates);
  const result = await refresh(pool, deps, { analysis_status: 'ready' });
  assert.equal(result.ok, false);
  assert.equal(result.code, 'refresh_source_unavailable');
  assert.equal(calls.analyze, 0);
  assert.equal(calls.fetch, 0, 'a refresh never re-fetches the source');
  assert.equal(db.report.analysis_status, 'ready');
  assert.equal(db.report.import_status, 'ready');
  assert.equal(db.report.analysis_progress.last_refresh.error_code, 'refresh_source_unavailable');
  assert.deepEqual(clone(db.candidates), before);
  assert.equal(db.jobs[0].status, 'failed');
  assert.equal(db.jobs[0].progress.dispatch.restoreStatus.analysis_status, 'ready', 'mode + restore target survive on the job');
});

test('9. rerun_ai routes to the AI pipeline: the model is invoked on a NEW analysis run (cached chunks are not replayed)', async () => {
  const { db, pool } = await seedAnalyzedReport();
  db.jobs[0].job_type = 'rerun_ai';
  const seen = [];
  const analyzeThreatDocument = async (_settings, input, hooks) => {
    seen.push({ candidates: input.candidates.length, aiNeeded: input.candidates.filter((c) => c.ai_needed).length });
    assert.equal(typeof hooks.loadCompletedChunk, 'function');
    return { ok: false, error: 'stub model stops here' };
  };
  const result = await runThreatLibraryJob(pool, {
    reportId: 77, jobId: 41, jobType: 'rerun_ai', resumeAnalysis: true, newAnalysisRun: true
  }, { analyzeThreatDocument });
  assert.equal(seen.length, 1, 'the model path ran exactly once');
  assert.ok(seen[0].aiNeeded >= 1, 'ai_needed candidates are offered to the model');
  assert.notEqual(db.report.analysis_run_id, '00000000-0000-4000-8000-000000000001', 'new analysis run id');
  assert.equal(result.ok, false);
});

test('unknown job mode is rejected before any stage runs', async () => {
  const { db, pool } = createFakeDb({ report: { id: 77 } });
  db.sql.length = 0;
  await assert.rejects(runThreatLibraryJob(pool, { reportId: 77, jobId: 41, jobType: 'refresh_and_ai' }), UnknownJobModeError);
  assert.deepEqual(db.sql, []);
});
