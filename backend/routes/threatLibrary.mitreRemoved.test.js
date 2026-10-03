/**
 * Threat Library MITRE ATT&CK removal (semantic-v8), route runtime with a fake
 * pool that still holds historical threat_report_mitre_mappings rows: the
 * report response never reads or exposes them, Retry never writes them, and
 * the manual technique endpoints are gone.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { registerThreatLibraryRoutes } from './threatLibrary.js';

const PUBLIC_ID = '11111111-2222-4333-8444-555555555555';

function harness() {
  const sql = [];
  const report = {
    id: 18631,
    public_id: PUBLIC_ID,
    title: 'Talos report',
    source_type: 'url',
    import_status: 'completed',
    analysis_status: 'review_required',
    canonical_document: { blocks: [{ id: 'b0' }] }
  };
  // Dormant historical data: present in the table, must stay invisible.
  const historicalMitre = [
    { report_id: 18631, attack_id: 'T1203', confidence: 0.9, evidence_text: 'x' },
    { report_id: 18631, attack_id: 'T1566.001', confidence: 0.9, evidence_text: 'x' },
    { report_id: 18631, attack_id: 'T1568', confidence: 0.9, evidence_text: 'x' }
  ];
  const jobs = [];
  const pool = {
    async query(text, params = []) {
      const s = String(text);
      sql.push(s);
      if (/threat_report_mitre_mappings/.test(s)) return { rows: historicalMitre, rowCount: historicalMitre.length };
      if (/FROM threat_reports WHERE public_id/.test(s)) return { rows: [report] };
      if (/FROM threat_reports WHERE id = \$1/.test(s)) return { rows: [report] };
      if (/FROM threat_reports r WHERE r\.id = \$1/.test(s)) return { rows: [{ indicator_count: 0 }] };
      if (/FROM threat_report_tags/.test(s)) {
        return { rows: [{ report_id: 18631, id: 1, name: 'backdoor', type: null }, { report_id: 18631, id: 2, name: 'cloud', type: null }] };
      }
      if (/^\s*UPDATE threat_reports SET/.test(s)) return { rows: [report] };
      if (/INSERT INTO threat_library_jobs/.test(s)) {
        const job = { id: 100 + jobs.length, public_id: `job-${jobs.length}`, report_id: report.id, job_type: 'retry', status: 'queued', progress: {}, created_at: new Date() };
        jobs.push(job);
        return { rows: [job] };
      }
      if (/FROM threat_library_ai_settings/.test(s)) return { rows: [{ max_concurrent_report_analyses: 2 }] };
      if (/AS occupied/.test(s)) return { rows: [{ occupied: 0 }] };
      if (/FOR UPDATE OF j SKIP LOCKED/.test(s)) return { rows: jobs.filter((j) => !j.bullmq_job_id).map((j) => ({ ...j, report_public_id: PUBLIC_ID })) };
      if (/bullmq_job_id = \$2/.test(s)) {
        const job = jobs.find((j) => j.id === params[0]);
        if (job) job.bullmq_job_id = params[1];
        return { rows: job ? [{ id: job.id }] : [], rowCount: job ? 1 : 0 };
      }
      return { rows: [], rowCount: 0 };
    },
    async connect() {
      return { query: (...args) => pool.query(...args), release() {} };
    }
  };
  const routes = new Map();
  const app = new Proxy({}, {
    get: (_t, method) => (routePath, ...handlers) => {
      routes.set(`${String(method).toUpperCase()} ${routePath}`, handlers[handlers.length - 1]);
    }
  });
  const queue = { async add() { return { id: '1' }; } };
  registerThreatLibraryRoutes(app, pool, null, { threatLibraryQueue: queue });
  async function call(key, req = {}) {
    const handler = routes.get(key);
    assert.ok(handler, `${key} registered`);
    const res = { statusCode: 200, body: null, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; return this; } };
    await handler({ params: { publicId: PUBLIC_ID }, body: {}, query: {}, user: { id: 1 }, ...req }, res);
    return res;
  }
  return { sql, routes, call };
}

test('report detail with historical MITRE rows in the DB exposes no MITRE and never queries them; tags remain', async () => {
  const h = harness();
  const res = await h.call('GET /api/threat-library/reports/:publicId');
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.body.report.tags.map((t) => t.name), ['backdoor', 'cloud']);
  assert.equal('mitre_attack' in res.body.report, false);
  const blob = JSON.stringify(res.body);
  assert.doesNotMatch(blob, /mitre|T1566|T1203|T1568/i);
  assert.equal(h.sql.some((q) => /mitre/i.test(q)), false);
});

test('Retry performs no MITRE read or write', async () => {
  const h = harness();
  const res = await h.call('POST /api/threat-library/reports/:publicId/retry');
  assert.ok([200, 202].includes(res.statusCode), `status ${res.statusCode}`);
  assert.equal(h.sql.some((q) => /mitre/i.test(q)), false);
});

test('manual ATT&CK technique endpoints are not registered', () => {
  const h = harness();
  assert.equal([...h.routes.keys()].some((k) => /mitre|technique/i.test(k)), false);
  assert.ok(h.routes.has('POST /api/threat-library/reports/:publicId/tags'));
});
