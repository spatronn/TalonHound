/**
 * The whole import, through the supported surface: real HTTP against the real routes,
 * real audit service, the job the route enqueues run by the real job runner, a real
 * pipeline and a provider that can fail on demand, then review, MCP preview and finalize.
 * Every report is deleted afterwards; nothing here reaches a live system.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import express from 'express';
import pg from 'pg';

const storage = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-import-'));
process.env.THREAT_LIBRARY_STORAGE_DIR = storage;

const { registerThreatLibraryRoutes } = await import('../../routes/threatLibrary.js');
const { createAuditLogService } = await import('../auditLogService.js');
const { runThreatLibraryJob } = await import('./jobRunner.js');
const { createInferenceScheduler } = await import('./ai/inferenceScheduler.js');
const { mcpThreatLibraryFinalizeReport } = await import('./mcpThreatLibraryReviewService.js');
const { startMockOllama } = await import('../../test-support/mockOllamaServer.js');

const pool = new pg.Pool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound',
  connectionTimeoutMillis: 3000,
  max: 8
});

let hasDb = false;
if (process.env.ALLOW_THREAT_LIBRARY_DB_TESTS === '1') {
  try {
    await pool.query('SELECT 1 FROM threat_report_finalize_exceptions LIMIT 0');
    hasDb = true;
  } catch {
    hasDb = false;
  }
}
const opts = { skip: hasDb ? false : 'set ALLOW_THREAT_LIBRARY_DB_TESTS=1 with a migrated throwaway database to run' };

function buildPdf(lines) {
  const esc = (s) => s.replace(/[\\()]/g, (c) => `\\${c}`);
  const content = `BT /F1 11 Tf 50 780 Td 14 TL\n${lines.map((l) => `(${esc(l)}) Tj T*`).join('\n')}\nET`;
  const objs = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
    `<< /Length ${Buffer.byteLength(content)} >>\nstream\n${content}\nendstream`
  ];
  let out = '%PDF-1.4\n';
  const offsets = [];
  objs.forEach((o, i) => { offsets.push(Buffer.byteLength(out)); out += `${i + 1} 0 obj\n${o}\nendobj\n`; });
  const xref = Buffer.byteLength(out);
  out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n${offsets.map((n) => `${String(n).padStart(10, '0')} 00000 n \n`).join('')}`;
  out += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(out);
}

const PDF_LINES = (salt) => [
  'Synthetic report for the import workflow test.',
  `Run ${salt}. The operators of the fictional campaign relied on a small set of servers.`,
  'The loader beacons to narrative-c2-host.net during installation.',
  'The full IOC list is available at https://github.com/synthetic-publisher/iocs/blob/main/full.csv',
  'Indicators of Compromise',
  'listed-c2-one.net',
  'listed-c2-two.net',
  'Recommendations',
  'Review outbound connections regularly.'
];

let server;
let base;
let enqueued = [];
let currentRole = 'admin';
let scheduler;
let saved;
const created = [];

test.before(async () => {
  if (!hasDb) return;
  saved = (await pool.query('SELECT * FROM threat_library_ai_settings WHERE id = 1')).rows[0];
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.user = { id: null, role: currentRole, email: 'itest@talonhound.test' };
    next();
  });
  const queue = { add: async (name, data) => { enqueued.push(data); return { id: String(enqueued.length) }; } };
  registerThreatLibraryRoutes(app, pool, createAuditLogService(pool), { threatLibraryQueue: queue });
  await new Promise((resolve) => { server = app.listen(0, '127.0.0.1', resolve); });
  base = `http://127.0.0.1:${server.address().port}/api/threat-library`;
  scheduler = createInferenceScheduler(pool, { pollMs: 25, waitLeaseMs: 1000, holdLeaseMs: 3000, heartbeatMs: 500 });
});

test.after(async () => {
  if (hasDb) {
    await new Promise((resolve) => server.close(resolve));
    for (const id of created) await pool.query('DELETE FROM threat_reports WHERE id = $1', [id]).catch(() => {});
    await pool.query(
      `UPDATE threat_library_ai_settings SET enabled = $1, provider = $2, base_url = $3, model = $4, auto_retry_max_attempts = $5 WHERE id = 1`,
      [saved.enabled, saved.provider, saved.base_url, saved.model, saved.auto_retry_max_attempts]
    );
    scheduler?.stop?.();
  }
  await pool.end();
  fs.rmSync(storage, { recursive: true, force: true });
});

const api = async (method, url, body) => {
  const res = await fetch(`${base}${url}`, {
    method,
    headers: body ? { 'content-type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined
  });
  return { status: res.status, body: await res.json().catch(() => null) };
};

async function useModel(baseUrl, retries = 0) {
  await pool.query(
    `UPDATE threat_library_ai_settings SET enabled = TRUE, provider = 'ollama', base_url = $1, model = 'itest-model', auto_retry_max_attempts = $2 WHERE id = 1`,
    [baseUrl, retries]
  );
}

/** Upload through the route, then run the job it enqueued. */
async function importAndRun() {
  enqueued = [];
  const form = new FormData();
  const salt = crypto.randomUUID();
  form.append('file', new Blob([buildPdf(PDF_LINES(salt))], { type: 'application/pdf' }), `itest-${salt}.pdf`);
  const res = await fetch(`${base}/import/pdf`, { method: 'POST', body: form });
  const body = await res.json();
  assert.equal(res.status, 202, JSON.stringify(body));
  const publicId = body.report.id;
  const { rows: [row] } = await pool.query('SELECT id FROM threat_reports WHERE public_id = $1', [publicId]);
  created.push(row.id);
  assert.equal(enqueued.length, 1, 'the route enqueued one job');
  const job = enqueued[0];
  const result = await runThreatLibraryJob(pool, job, { inferenceScheduler: scheduler });
  return { publicId, id: row.id, result };
}

const answer = (values) => JSON.stringify({
  summary: 'Synthetic.',
  report_type: 'malware',
  language: 'en',
  tlp: 'TLP:CLEAR',
  confidence: 0.5,
  entities: [],
  candidate_updates: values,
  relationships: []
});

test('import route to finalize: audit, ledgers, review queue, MCP parity, obligations', opts, async () => {
  const ollama = await startMockOllama({ plan: () => ({ promptEvalMs: 2, genMs: 5, content: answer([]) }) });
  try {
    await useModel(ollama.baseUrl);
    const { publicId, id, result } = await importAndRun();
    assert.equal(result.ok, true, JSON.stringify(result));

    // Import audit record, from the route.
    const audit = (await pool.query(`SELECT action, status FROM audit_logs WHERE entity_id = $1 ORDER BY id`, [publicId])).rows;
    assert.ok(audit.some((a) => /import/.test(a.action) && a.status === 'success'), JSON.stringify(audit));

    // Immutable first-pass snapshot, evidence and dispositions.
    const { rows: [run] } = await pool.query(`SELECT * FROM threat_report_extraction_runs WHERE report_id = $1`, [id]);
    assert.equal(run.is_first_pass, true);
    assert.equal(run.operational_status, 'completed');
    assert.equal(run.ai_provenance.model, 'itest-model');
    assert.match(run.ai_provenance.prompt_hash, /^[0-9a-f]{64}$/);
    assert.equal(run.ai_provenance.coverage.requested, run.ai_provenance.coverage.answered + run.ai_provenance.coverage.unanswered);
    assert.equal(run.counts.dispositions.undispositioned, 0);
    await assert.rejects(pool.query(`UPDATE threat_report_extraction_runs SET operational_status = 'degraded' WHERE id = $1`, [run.id]), /append-only/);

    // The report as the UI reads it.
    const read = await api('GET', `/reports/${publicId}`);
    assert.equal(read.status, 200);
    assert.equal(read.body.report.status_axes.generation, 'first_pass_recorded');
    assert.equal(read.body.report.package_coverage.status, 'pending');
    const c = (v) => read.body.candidates.find((x) => x.normalized_value === v);
    assert.equal(c('listed-c2-one.net').evidence.membership_decision?.rule_id ?? c('listed-c2-one.net').membership_decision?.rule_id, 'R10_publisher_assertion');
    const narrative = c('narrative-c2-host.net');
    assert.equal((narrative.evidence?.membership_decision ?? narrative.membership_decision).outcome, 'needs_review', 'prose is not asserted');

    // The header counts what finalize will ask for.
    assert.equal(read.body.report.review_progress.pending + read.body.report.review_progress.uncertain_pending, read.body.report.status_axes.analyst_review.pending);

    // Source discovery, read from the ledger route.
    const ledger = await api('GET', `/reports/${publicId}/source-discovery`);
    assert.equal(ledger.body.runs[0].status, 'completed');
    assert.ok(ledger.body.references.some((r) => r.decision === 'accepted' && /full\.csv/.test(r.url)));

    // MCP preview and the write agree while work is open.
    const preview = await mcpThreatLibraryFinalizeReport(pool, { report_id: publicId, dry_run: true }, { user: { role: 'analyst' } });
    assert.equal(preview.body.would_finalize, false);
    const refused = await api('POST', `/reports/${publicId}/finalize`, {});
    assert.equal(refused.status, 409);
    assert.deepEqual(preview.body.blockers.map((b) => b.code).sort(), refused.body.blockers.map((b) => b.code).sort());

    // Resolve the package with evidence, decide the candidates, then finalize.
    const sources = await api('GET', `/reports/${publicId}/ioc-sources`);
    const source = sources.body.sources?.[0] || sources.body.items?.[0];
    const dismissed = await api('POST', `/ioc-sources/${source.id}/dismiss`, { reason: 'Synthetic package link used by the workflow test.' });
    assert.equal(dismissed.status, 200, JSON.stringify(dismissed.body));
    const open = read.body.candidates.filter((x) => (x.review_status || 'pending') === 'pending');
    const reviewed = await api('POST', `/reports/${publicId}/review`, { action: 'ignore', candidate_ids: open.map((x) => x.id) });
    assert.equal(reviewed.status, 200, JSON.stringify(reviewed.body));

    const clear = await mcpThreatLibraryFinalizeReport(pool, { report_id: publicId, dry_run: true }, { user: { role: 'analyst' } });
    assert.equal(clear.body.would_finalize, true, JSON.stringify(clear.body));
    const done = await api('POST', `/reports/${publicId}/finalize`, {});
    assert.equal(done.status, 200, JSON.stringify(done.body));
    const after = (await pool.query(`SELECT action FROM audit_logs WHERE entity_id = $1`, [publicId])).rows.map((a) => a.action);
    assert.ok(after.some((a) => /finalized/.test(a)), after.join(','));
    assert.ok(after.some((a) => /dismissed/.test(a)), after.join(','));
    assert.equal((await pool.query(`SELECT count(*)::int n FROM ioc_items WHERE value LIKE 'listed-c2-%'`).catch(() => ({ rows: [{ n: 0 }] }))).rows[0].n, 0, 'no IOC was created');
  } finally {
    await ollama.close();
  }
});

test('a model that keeps failing: deterministic results stay, marked degraded, and review works', opts, async () => {
  const ollama = await startMockOllama({ plan: () => ({ promptEvalMs: 1, genMs: 1, content: 'this is not json at all' }) });
  try {
    await useModel(ollama.baseUrl);
    const { publicId, id, result } = await importAndRun();
    assert.equal(result.ok, true, JSON.stringify(result));
    const { rows: [run] } = await pool.query(`SELECT operational_status, ai_provenance, counts FROM threat_report_extraction_runs WHERE report_id = $1`, [id]);
    assert.equal(run.operational_status, 'degraded');
    assert.ok(ollama.requests.length >= 2, 'the provider was really called, and the failed chunk retried');
    assert.ok(run.ai_provenance.degraded?.code, JSON.stringify(run.ai_provenance.degraded));
    const read = await api('GET', `/reports/${publicId}`);
    assert.equal(read.body.report.analysis_status, 'review_required');
    assert.equal(read.body.report.status_axes.operational_execution.status, 'degraded');
    assert.ok(read.body.report.extraction_quality.warnings.some((w) => w.code === 'ai_analysis_degraded'));
    for (const warning of read.body.report.extraction_quality.warnings) {
      for (const value of warning.candidates || []) assert.equal(typeof value, 'string', `${warning.code} lists plain identities`);
    }
    const listed = read.body.candidates.find((x) => x.normalized_value === 'listed-c2-one.net');
    assert.ok(listed, 'deterministic candidates are all there');
    assert.ok(read.body.candidates.every((x) => (x.review_status || 'pending') === 'pending'), 'nothing is decided for the analyst');
    assert.equal(read.body.candidates.find((x) => x.normalized_value === 'narrative-c2-host.net').evidence?.ai_decision_status ?? 'unanswered', 'unanswered');
  } finally {
    await ollama.close();
  }
});

test('a provider outage goes to the automatic retry first, and degrades once retries are spent', opts, async () => {
  const ollama = await startMockOllama({ plan: () => ({ fault: 'http_503' }) });
  try {
    await useModel(ollama.baseUrl, 2);
    const first = await importAndRun();
    assert.equal(first.result.ok, false, JSON.stringify(first.result));
    assert.equal(first.result.code, 'provider_http_error');
    assert.ok(ollama.requests.length >= 1, 'the provider was really called');
    assert.equal((await pool.query(`SELECT analysis_status FROM threat_reports WHERE id = $1`, [first.id])).rows[0].analysis_status, 'failed');
    assert.equal((await pool.query(`SELECT count(*)::int n FROM threat_report_extraction_runs WHERE report_id = $1`, [first.id])).rows[0].n, 0, 'no run is recorded for a job that will retry');

    await useModel(ollama.baseUrl, 0);
    const second = await importAndRun();
    assert.equal(second.result.ok, true, JSON.stringify(second.result));
    const { rows: [run] } = await pool.query(`SELECT operational_status, ai_provenance FROM threat_report_extraction_runs WHERE report_id = $1`, [second.id]);
    assert.equal(run.operational_status, 'degraded');
    assert.equal(run.ai_provenance.model, 'itest-model');
  } finally {
    await ollama.close();
  }
});

test('an unauthorised exception is refused over HTTP; a reasoned admin exception is recorded', opts, async () => {
  const ollama = await startMockOllama({ plan: () => ({ promptEvalMs: 1, genMs: 1, content: answer([]) }) });
  try {
    await useModel(ollama.baseUrl);
    const { publicId, id } = await importAndRun();
    await pool.query(`INSERT INTO threat_report_source_discovery_runs (report_id, discovery_version, status, error_detail) VALUES ($1, 'itest', 'failed', 'itest')`, [id]);
    const read = await api('GET', `/reports/${publicId}`);
    await api('POST', `/reports/${publicId}/review`, { action: 'ignore', candidate_ids: read.body.candidates.filter((x) => (x.review_status || 'pending') === 'pending').map((x) => x.id) });
    const sources = await api('GET', `/reports/${publicId}/ioc-sources`);
    await api('POST', `/ioc-sources/${(sources.body.sources?.[0] || sources.body.items?.[0]).id}/dismiss`, { reason: 'Synthetic package link used by the workflow test.' });

    const blocked = await api('POST', `/reports/${publicId}/finalize`, {});
    assert.equal(blocked.body.code, 'finalize_obligations_unmet');
    currentRole = 'analyst';
    const analyst = await api('POST', `/reports/${publicId}/finalize`, { obligation_exception: { reason: 'Discovery failed but the publisher has no package.' } });
    assert.equal(analyst.status, 403);
    currentRole = 'admin';
    const admin = await api('POST', `/reports/${publicId}/finalize`, { obligation_exception: { reason: 'Discovery failed but the publisher has no package.' } });
    assert.equal(admin.status, 200, JSON.stringify(admin.body));
    const { rows } = await pool.query(`SELECT obligation_code, reason FROM threat_report_finalize_exceptions WHERE report_id = $1`, [id]);
    assert.deepEqual(rows.map((r) => r.obligation_code), ['ioc_source_discovery_incomplete']);
    const audit = (await pool.query(`SELECT severity, metadata FROM audit_logs WHERE entity_id = $1 AND action LIKE '%finalized%'`, [publicId])).rows;
    assert.ok(audit.some((a) => a.metadata?.finalize_obligation_exception));
  } finally {
    currentRole = 'admin';
    await ollama.close();
  }
});
