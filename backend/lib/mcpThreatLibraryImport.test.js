/**
 * MCP threat_library_import_url / get_threat_library_import_status.
 *
 * The MCP tool must be Import Intelligence → URL → Start Import itself, so the
 * core tests run the real UI route (POST /api/threat-library/import/url) and
 * the real MCP tool handler against the same in-memory threat_reports /
 * threat_library_jobs store and spy queue, and compare what each wrote, queued
 * and audited. Fetch / extraction / analysis are the worker's job and are
 * never reached here (the queue hand-off is the boundary), as in the UI tests.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { registerThreatLibraryRoutes } from '../routes/threatLibrary.js';
import { registerMcpTools } from './mcpTools.js';
import { authorizeMcpTool, MCP_TOOL_SCOPES } from './mcpPermissions.js';
import { ACCESS_PROFILE, API_SCOPE, scopesForAccessProfile } from './apiKeyProfiles.js';
import { getMcpConfig } from './mcpConfig.js';
import { AUDIT_ACTION } from './auditConstants.js';

const ACTOR_PUBLIC_ID = '00000000-0000-4000-8000-00000000aaaa';
const ANALYST = { id: 2, role: 'analyst', username: 'analyst', email: 'analyst' };
const ANALYST_SCOPES = scopesForAccessProfile(ACCESS_PROFILE.MCP_ANALYST);
const READ_SCOPES = scopesForAccessProfile(ACCESS_PROFILE.MCP_READ);

function createState() {
  return { reports: [], jobs: [], queued: [], audits: [], queries: [], reportInserts: 0, seq: 0, locks: new Map() };
}

/**
 * In-memory threat_reports / threat_library_jobs keyed on the SQL the import
 * path issues. pg_advisory_xact_lock is a real per-key mutex held until the
 * holding client's COMMIT / ROLLBACK, so concurrent claims serialize exactly
 * as in PostgreSQL.
 */
function createPool(state) {
  async function run(sql, params, client) {
    const flat = String(sql).replace(/\s+/g, ' ').trim();
    state.queries.push({ sql: flat, params });
    if (/pg_advisory_xact_lock/.test(flat)) {
      const key = params[0];
      while (state.locks.has(key)) await state.locks.get(key).released;
      let release;
      state.locks.set(key, { released: new Promise((r) => { release = r; }) });
      client.held.push(() => { state.locks.delete(key); release(); });
      return { rows: [] };
    }
    if (/^(COMMIT|ROLLBACK)/.test(flat)) {
      for (const free of client?.held.splice(0) || []) free();
      return { rows: [], rowCount: 0 };
    }
    if (/^BEGIN/.test(flat)) return { rows: [], rowCount: 0 };
    if (/^INSERT INTO threat_reports /.test(flat)) {
      state.reportInserts += 1;
      state.seq += 1;
      const row = {
        id: state.seq,
        public_id: `00000000-0000-4000-8000-${String(state.seq).padStart(12, '0')}`,
        title: params[0],
        source_type: params[1],
        source_name: params[2],
        source_url: params[3],
        tlp: params[8],
        import_status: params[12],
        analysis_status: params[13],
        created_by: params[16],
        tlp_source: params[17],
        source_url_canonical: params[21],
        created_at: new Date(Date.UTC(2026, 9, 13, 10, state.seq)).toISOString(),
        deleted_at: null
      };
      state.reports.push(row);
      return { rows: [row], rowCount: 1 };
    }
    if (/^SELECT \* FROM threat_reports WHERE source_type = 'url' AND deleted_at IS NULL AND source_url_canonical = \$1/.test(flat)) {
      const rows = state.reports.filter((r) => r.source_type === 'url' && !r.deleted_at && r.source_url_canonical === params[0]);
      // Read, then yield like a real round trip: callers that are not
      // serialized by the advisory lock would all see "no report" and insert.
      await new Promise((r) => setImmediate(r));
      return { rows: rows.slice(0, 1) };
    }
    if (/^SELECT \* FROM threat_reports WHERE public_id = \$1::uuid AND deleted_at IS NULL/.test(flat)) {
      return { rows: state.reports.filter((r) => r.public_id === params[0] && !r.deleted_at).slice(0, 1) };
    }
    if (/^INSERT INTO threat_library_jobs/.test(flat)) {
      const job = {
        id: state.jobs.length + 1,
        public_id: `00000000-0000-4000-9000-${String(state.jobs.length + 1).padStart(12, '0')}`,
        report_id: params[0],
        job_type: params[1] || 'analyze',
        status: 'queued',
        stage: 'queued',
        requested_by: params[2] ?? null,
        bullmq_job_id: null,
        progress: {},
        error_message: null,
        created_at: new Date(Date.UTC(2026, 9, 13, 10, state.jobs.length)),
        finished_at: null
      };
      state.jobs.push(job);
      return { rows: [job], rowCount: 1 };
    }
    if (/FROM threat_library_ai_settings/.test(flat)) return { rows: [{ max_concurrent_report_analyses: state.maxConcurrent ?? 2 }] };
    if (/AS occupied/.test(flat) && /threat_library_jobs/.test(flat)) {
      return { rows: [{ occupied: state.jobs.filter((j) => ['queued', 'running'].includes(j.status) && j.bullmq_job_id).length }] };
    }
    if (/FOR UPDATE OF j SKIP LOCKED/.test(flat)) {
      const available = params[1] ?? params[0];
      const rows = state.jobs
        .filter((j) => j.status === 'queued' && !j.bullmq_job_id)
        .slice(0, available)
        .map((j) => {
          const report = state.reports.find((r) => r.id === j.report_id) || {};
          return { ...j, source_url: report.source_url || null, report_public_id: report.public_id, source_type: report.source_type };
        });
      return { rows };
    }
    if (/SET bullmq_job_id = \$2/.test(flat)) {
      const job = state.jobs.find((j) => j.id === params[0] && !j.bullmq_job_id);
      if (!job) return { rows: [], rowCount: 0 };
      job.bullmq_job_id = params[1];
      return { rows: [{ id: job.id }], rowCount: 1 };
    }
    if (/^UPDATE threat_library_jobs SET/.test(flat)) {
      const job = state.jobs.find((j) => j.id === params[0]);
      if (job && params[3]) job.progress = JSON.parse(JSON.stringify(params[3]));
      return { rows: [job || {}], rowCount: job ? 1 : 0 };
    }
    if (/FROM threat_library_jobs WHERE id = \$1/.test(flat)) {
      return { rows: state.jobs.filter((j) => j.id === params[0]) };
    }
    if (/FROM threat_library_jobs WHERE report_id = \$1 ORDER BY id DESC LIMIT 1/.test(flat)) {
      return { rows: state.jobs.filter((j) => j.report_id === params[0]).slice(-1) };
    }
    return { rows: [], rowCount: 0 };
  }
  return {
    query: (sql, params = []) => run(sql, params, null),
    async connect() {
      const client = { held: [] };
      return { query: (sql, params = []) => run(sql, params, client), release() {} };
    }
  };
}

function createHarness() {
  const state = createState();
  const pool = createPool(state);
  const queue = {
    async add(name, data) { state.queued.push({ name, data }); return { id: `bull-${state.queued.length}` }; }
  };
  const audit = {
    auditLog: async (event) => { state.audits.push(event); },
    auditSuccess: async (event) => { state.audits.push({ ...event, generic: true }); },
    auditFailure: async (event) => { state.audits.push({ ...event, generic: true }); },
    resolveActor: async (req) => (req?.user ? { ...req.user, publicId: ACTOR_PUBLIC_ID } : null)
  };
  return { state, pool, queue, audit };
}

/** Call a registered MCP tool the way /mcp does: per-request context with the authenticated key. */
async function callTool(h, name, args, { scopes = ANALYST_SCOPES, role = 'analyst', queue = h.queue } = {}) {
  const tools = new Map();
  const req = {
    headers: {},
    authVia: 'mcp',
    user: { ...ANALYST, role, publicId: ACTOR_PUBLIC_ID },
    mcpAuth: { scopes, ownerRole: role, apiKeyId: 77, apiKeyName: 'automation', keyType: ACCESS_PROFILE.MCP_ANALYST }
  };
  registerMcpTools({ registerTool: (n, def, handler) => tools.set(n, { def, handler }) }, {
    pool: h.pool,
    audit: h.audit,
    getRequestContext: () => ({ req }),
    threatLibraryQueue: queue
  });
  const res = await tools.get(name).handler(args);
  return { res, data: res.structuredContent, error: res.isError ? res.structuredContent.error : null };
}

async function uiImport(h, url) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.user = ANALYST; next(); });
  registerThreatLibraryRoutes(app, h.pool, h.audit, { threatLibraryQueue: h.queue });
  const server = app.listen(0);
  try {
    const res = await fetch(`http://127.0.0.1:${server.address().port}/api/threat-library/import/url`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ url })
    });
    return { status: res.status, body: await res.json() };
  } finally {
    await new Promise((r) => server.close(r));
  }
}

const REPORT_URL = 'https://vendor.example/research/apt-report';
// threat_reports.portable_id is a fresh random id per inserted report.
const normalizeQueries = (queries) => queries.map((q) => ({
  sql: q.sql,
  params: q.params.map((v) => (typeof v === 'string' && v.startsWith('report--') ? 'report--<portable_id>' : v))
}));
const stripVolatile = (row) => {
  const { public_id: _p, created_at: _c, ...rest } = row;
  return rest;
};

// --- Parity with the UI ------------------------------------------------------

test('parity: MCP import issues the same SQL, writes the same rows, queues the same worker job and emits the same audit event as UI Start Import', async () => {
  const ui = createHarness();
  const mcp = createHarness();
  const uiRes = await uiImport(ui, REPORT_URL);
  assert.equal(uiRes.status, 202);
  const uiQueryCount = ui.state.queries.length;
  const { data, error } = await callTool(mcp, 'threat_library_import_url', { url: REPORT_URL });
  assert.equal(error, null);

  // Identical statement sequence (+ params) for the import itself; the MCP
  // handler only adds read-backs of the persisted state afterwards.
  assert.deepEqual(normalizeQueries(mcp.state.queries.slice(0, uiQueryCount)), normalizeQueries(ui.state.queries));
  for (const q of mcp.state.queries.slice(uiQueryCount)) assert.match(q.sql, /^SELECT /, 'MCP adds reads only');

  assert.deepEqual(mcp.state.reports.map(stripVolatile), ui.state.reports.map(stripVolatile));
  assert.equal(mcp.state.reports[0].created_by, ACTOR_PUBLIC_ID, 'provenance: importing analyst');
  assert.equal(mcp.state.reports[0].source_url, REPORT_URL);
  assert.equal(mcp.state.reports[0].tlp_source, 'default');
  assert.deepEqual(mcp.state.jobs.map(({ created_at: _c, public_id: _p, ...j }) => j), ui.state.jobs.map(({ created_at: _c, public_id: _p, ...j }) => j));
  assert.deepEqual(mcp.state.queued, ui.state.queued, 'same BullMQ job name + payload → same worker path');
  assert.equal(mcp.state.queued[0].name, 'analyze');
  assert.equal(mcp.state.queued[0].data.sourceUrl, REPORT_URL);

  const [uiAudit] = ui.state.audits;
  const [mcpAudit] = mcp.state.audits;
  assert.equal(mcp.state.audits.length, 1, 'no extra generic mcp.tool_call event');
  assert.equal(mcpAudit.action, uiAudit.action);
  assert.equal(mcpAudit.action, AUDIT_ACTION.THREAT_LIBRARY_REPORT_IMPORTED_URL);
  for (const [k, v] of Object.entries(uiAudit.metadata)) {
    if (k !== 'job_public_id') assert.deepEqual(mcpAudit.metadata[k], v, `audit metadata ${k}`);
  }
  assert.equal(mcpAudit.metadata.channel, 'mcp');
  assert.equal(mcpAudit.metadata.api_key_id, 77);
  assert.equal(mcpAudit.metadata.tool, 'threat_library_import_url');
  assert.equal(mcpAudit.req.authVia, 'mcp', 'audit source resolves to mcp');
  assert.equal(data.job_id, mcpAudit.metadata.job_public_id);
});

test('new import: returns real report/job ids and the persisted processing state, never a premature completion', async () => {
  const h = createHarness();
  const { data, error } = await callTool(h, 'threat_library_import_url', { url: `  ${REPORT_URL}  ` });
  assert.equal(error, null);
  assert.equal(data.outcome, 'import_started');
  assert.equal(data.already_imported, false);
  assert.equal(data.report_id, h.state.reports[0].public_id);
  assert.equal(data.job_id, h.state.jobs[0].public_id);
  assert.equal(data.source_url, REPORT_URL);
  assert.equal(data.report.source_url, REPORT_URL);
  assert.equal(data.report.import_status, 'processing');
  assert.equal(data.report.analysis_status, 'pending');
  assert.equal(data.report.review_phase, 'preparing');
  assert.equal(data.report.failure, null);
  assert.equal(data.job.status, 'queued');
  assert.equal(data.job.job_type, 'analyze');
  assert.equal(data.job.dispatched_to_worker, true);
  assert.equal(data.ingestion_complete, false);
  assert.equal(data.ingestion_failed, false);
  assert.equal(data.readable_with_get_threat_report, false);

  const status = await callTool(h, 'get_threat_library_import_status', { report_id: data.report_id });
  assert.equal(status.error, null);
  assert.equal(status.data.report.review_phase, 'preparing');
  assert.equal(status.data.latest_job.id, data.job_id);
  assert.equal(status.data.ingestion_complete, false);
});

test('a job waiting for an analysis slot is reported as queued and not dispatched (no fabricated progress)', async () => {
  const h = createHarness();
  h.state.maxConcurrent = 1;
  await callTool(h, 'threat_library_import_url', { url: 'https://vendor.example/a' });
  const second = await callTool(h, 'threat_library_import_url', { url: 'https://vendor.example/b' });
  assert.equal(second.data.outcome, 'import_started');
  assert.equal(second.data.job.status, 'queued');
  assert.equal(second.data.job.dispatched_to_worker, false);
  assert.equal(h.state.queued.length, 1, 'shared AI concurrency budget, as in the UI');
});

// --- Duplicates --------------------------------------------------------------

test('duplicate: same or canonical-equivalent URL returns already_exists with the existing report and creates/queues nothing', async () => {
  const h = createHarness();
  const first = await callTool(h, 'threat_library_import_url', { url: REPORT_URL });
  for (const spelling of [REPORT_URL, 'https://VENDOR.example:443/research/apt-report/#section-2']) {
    const again = await callTool(h, 'threat_library_import_url', { url: spelling });
    assert.equal(again.error, null);
    assert.equal(again.data.outcome, 'already_exists');
    assert.equal(again.data.already_imported, true);
    assert.equal(again.data.duplicate_reason, 'url');
    assert.equal(again.data.message, 'This report has already been imported.');
    assert.equal(again.data.report_id, first.data.report_id);
    assert.equal(again.data.job_id, null);
    assert.equal(again.data.latest_job.id, first.data.job_id, 'existing processing state is visible');
  }
  assert.equal(h.state.reportInserts, 1);
  assert.equal(h.state.jobs.length, 1);
  assert.equal(h.state.queued.length, 1);
  const dupAudits = h.state.audits.filter((a) => a.metadata?.already_imported === true);
  assert.equal(dupAudits.length, 2);
  assert.equal(dupAudits[0].action, AUDIT_ACTION.THREAT_LIBRARY_REPORT_IMPORTED_URL);
  assert.equal(dupAudits[0].metadata.channel, 'mcp');
});

test('duplicate identity is shared with the UI: a UI-imported URL is already_exists over MCP and vice versa', async () => {
  const h = createHarness();
  const ui = await uiImport(h, REPORT_URL);
  const viaMcp = await callTool(h, 'threat_library_import_url', { url: REPORT_URL });
  assert.equal(viaMcp.data.outcome, 'already_exists');
  assert.equal(viaMcp.data.report_id, ui.body.report.id);

  const mcpFirst = await callTool(h, 'threat_library_import_url', { url: 'https://vendor.example/other' });
  const uiAgain = await uiImport(h, 'https://vendor.example/other');
  assert.equal(uiAgain.status, 200);
  assert.equal(uiAgain.body.already_imported, true);
  assert.equal(uiAgain.body.report.id, mcpFirst.data.report_id);
  assert.equal(h.state.reportInserts, 2);
});

test('concurrent MCP + UI requests for the same report create exactly one report, one job and one queue entry', async () => {
  const h = createHarness();
  const spellings = [REPORT_URL, `${REPORT_URL}/`, 'https://Vendor.Example/research/apt-report', `${REPORT_URL}#x`, REPORT_URL];
  const results = await Promise.all([
    ...spellings.map((url) => callTool(h, 'threat_library_import_url', { url })),
    uiImport(h, REPORT_URL)
  ]);
  assert.equal(h.state.reportInserts, 1);
  assert.equal(h.state.jobs.length, 1);
  assert.equal(h.state.queued.length, 1);
  const mcpOutcomes = results.slice(0, spellings.length).map((r) => r.data.outcome);
  const started = mcpOutcomes.filter((o) => o === 'import_started').length + (results.at(-1).status === 202 ? 1 : 0);
  assert.equal(started, 1);
  const ids = new Set(results.slice(0, spellings.length).map((r) => r.data.report_id));
  ids.add(results.at(-1).body.report.id);
  assert.equal(ids.size, 1);
});

// --- URL policy (same checks as the UI, before any write) --------------------

test('invalid, private, localhost, metadata and credential URLs are rejected with the UI message before any lookup or write', async () => {
  const h = createHarness();
  const cases = [
    'not a url',
    'ftp://vendor.example/report',
    'javascript:alert(1)',
    'file:///etc/passwd',
    'https://user:secret@vendor.example/report',
    'http://localhost/report',
    'http://localhost./report',
    'http://127.0.0.1:8080/report',
    'http://10.1.2.3/report',
    'http://192.168.1.190/report',
    'http://169.254.169.254/latest/meta-data/',
    'http://metadata.google.internal/computeMetadata/v1/',
    'http://[::1]/report',
    'http://[::ffff:127.0.0.1]/report',
    'http://intranet/report'
  ];
  for (const url of cases) {
    const viaMcp = await callTool(h, 'threat_library_import_url', { url });
    const viaUi = await uiImport(h, url);
    assert.equal(viaUi.status, 400, url);
    assert.ok(viaMcp.error, url);
    assert.equal(viaMcp.error.code, 'INVALID_URL', url);
    assert.equal(viaMcp.error.message, viaUi.body.message, `same policy message for ${url}`);
  }
  assert.equal(h.state.reportInserts, 0);
  assert.equal(h.state.jobs.length, 0);
  assert.equal(h.state.queued.length, 0);
  assert.equal(h.state.queries.filter((q) => /threat_reports|threat_library_jobs/.test(q.sql)).length, 0);
});

test('tool input schema accepts only a URL (no TLP, source, review or promotion knobs)', async () => {
  const h = createHarness();
  const tools = new Map();
  registerMcpTools({ registerTool: (n, def) => tools.set(n, def) }, { pool: h.pool, getRequestContext: () => ({}) });
  const def = tools.get('threat_library_import_url');
  assert.deepEqual(Object.keys(def.inputSchema), ['url']);
  assert.equal(def.inputSchema.url.safeParse('x'.repeat(getMcpConfig().valueMaxChars + 1)).success, false);
  assert.equal(def.annotations.readOnlyHint, false);
  assert.match(def.description, /Never auto-approves IOC candidates/);
  assert.deepEqual(Object.keys(tools.get('get_threat_library_import_status').inputSchema), ['report_id']);
  assert.equal(tools.get('get_threat_library_import_status').annotations.readOnlyHint, true);
});

// --- Authorization -----------------------------------------------------------

test('authorization: scope + owner role gate the import exactly like the UI role check; nothing is written when denied', async () => {
  assert.deepEqual(MCP_TOOL_SCOPES.threat_library_import_url, [API_SCOPE.MCP_IOC_READ, API_SCOPE.MCP_THREAT_LIBRARY_IMPORT]);
  const h = createHarness();
  const denied = [
    [{ scopes: READ_SCOPES, role: 'analyst' }, 'MISSING_SCOPE'],
    [{ scopes: ANALYST_SCOPES.filter((s) => s !== API_SCOPE.MCP_THREAT_LIBRARY_IMPORT), role: 'admin' }, 'MISSING_SCOPE'],
    [{ scopes: [API_SCOPE.MCP_THREAT_LIBRARY_IMPORT], role: 'admin' }, 'MISSING_SCOPE'],
    [{ scopes: ANALYST_SCOPES, role: 'readonly' }, 'RBAC_DENIED'],
    [{ scopes: ANALYST_SCOPES, role: null }, 'RBAC_DENIED']
  ];
  for (const [auth, code] of denied) {
    const { error } = await callTool(h, 'threat_library_import_url', { url: REPORT_URL }, auth);
    assert.equal(error?.code, code, JSON.stringify(auth));
  }
  assert.equal(h.state.queries.length, 0, 'denied before any database access');
  assert.equal(h.state.queued.length, 0);

  for (const role of ['analyst', 'admin']) {
    assert.equal(authorizeMcpTool('threat_library_import_url', { scopes: ANALYST_SCOPES, ownerRole: role }).ok, true, role);
  }
  // The import scope never unlocks other write tools.
  for (const tool of ['import_iocs', 'enrich_ioc', 'add_ioc_tags']) {
    const gate = authorizeMcpTool(tool, { scopes: [API_SCOPE.MCP_IOC_READ, API_SCOPE.MCP_THREAT_LIBRARY_IMPORT], ownerRole: 'admin' });
    assert.equal(gate.code, 'MISSING_SCOPE', tool);
  }
  // Status is a read: an MCP Read key may poll it.
  assert.equal(authorizeMcpTool('get_threat_library_import_status', { scopes: READ_SCOPES, ownerRole: 'readonly' }).ok, true);
});

// --- Failures ----------------------------------------------------------------

test('queue unavailable: actionable error category, failure audited, no internal message leaked, report not claimed complete', async () => {
  const h = createHarness();
  const { error } = await callTool(h, 'threat_library_import_url', { url: REPORT_URL }, { queue: null });
  assert.equal(error.code, 'IMPORT_FAILED');
  assert.equal(error.reason, 'queue_unavailable');
  assert.doesNotMatch(JSON.stringify(error), /stack|password|secret/i);
  const failed = h.state.audits.find((a) => a.action === AUDIT_ACTION.THREAT_LIBRARY_REPORT_IMPORT_FAILED);
  assert.ok(failed);
  assert.equal(failed.metadata.error_code, 'queue_unavailable');
  assert.equal(failed.metadata.channel, 'mcp');
  assert.equal(failed.metadata.host, 'vendor.example');
  // Same state the UI leaves behind: the report + queued job exist for the dispatcher safety net.
  const status = await callTool(h, 'get_threat_library_import_status', { report_id: h.state.reports[0].public_id });
  assert.equal(status.data.ingestion_complete, false);
  assert.equal(status.data.latest_job.status, 'queued');
});

test('failed ingestion job (e.g. blocked redirect, PDF behind a URL) is surfaced from persisted state', async () => {
  const h = createHarness();
  const { data } = await callTool(h, 'threat_library_import_url', { url: REPORT_URL });
  // What the worker persists when fetchFeedUrl refuses a redirect hop to a forbidden address.
  Object.assign(h.state.reports[0], {
    import_status: 'failed',
    analysis_status: 'failed',
    failure_stage: 'fetch',
    failure_code: 'redirect_blocked',
    failure_reason: 'Redirect target is not allowed: Private, loopback, and localhost URLs are not allowed'
  });
  Object.assign(h.state.jobs[0], { status: 'failed', stage: 'fetch', error_message: 'redirect_blocked', finished_at: new Date() });
  const status = await callTool(h, 'get_threat_library_import_status', { report_id: data.report_id });
  assert.equal(status.data.report.review_phase, 'failed');
  assert.equal(status.data.ingestion_failed, true);
  assert.equal(status.data.ingestion_complete, false);
  assert.deepEqual(status.data.report.failure, {
    stage: 'fetch',
    code: 'redirect_blocked',
    reason: 'Redirect target is not allowed: Private, loopback, and localhost URLs are not allowed'
  });
  assert.equal(status.data.latest_job.status, 'failed');

  // A re-import of the same URL is a duplicate (UI behaviour) and shows the failure; Retry stays a UI action.
  const again = await callTool(h, 'threat_library_import_url', { url: REPORT_URL });
  assert.equal(again.data.outcome, 'already_exists');
  assert.equal(again.data.ingestion_failed, true);
  assert.equal(h.state.queued.length, 1);
});

test('status: finished analysis is reported as complete and readable; unknown or malformed ids are errors', async () => {
  const h = createHarness();
  const { data } = await callTool(h, 'threat_library_import_url', { url: REPORT_URL });
  Object.assign(h.state.reports[0], { import_status: 'review_required', analysis_status: 'review_required' });
  const status = await callTool(h, 'get_threat_library_import_status', { report_id: data.report_id });
  assert.equal(status.data.report.review_phase, 'review_ready');
  assert.equal(status.data.ingestion_complete, true);
  assert.equal(status.data.readable_with_get_threat_report, true);

  assert.equal((await callTool(h, 'get_threat_library_import_status', { report_id: '00000000-0000-4000-8000-000000000999' })).error.code, 'NOT_FOUND');
  assert.equal((await callTool(h, 'get_threat_library_import_status', { report_id: 'x'.repeat(36) })).error.code, 'INVALID_REPORT_ID');
});

// --- No review side effects --------------------------------------------------

test('import never approves candidates, runs Create IOCs, writes IOCs or touches review state', async () => {
  const h = createHarness();
  await callTool(h, 'threat_library_import_url', { url: REPORT_URL });
  await callTool(h, 'threat_library_import_url', { url: REPORT_URL });
  const writes = h.state.queries.filter((q) => /^(INSERT|UPDATE|DELETE)/.test(q.sql));
  for (const w of writes) {
    assert.match(w.sql, /^(INSERT INTO threat_reports |INSERT INTO threat_library_jobs|UPDATE threat_library_jobs)/, w.sql);
  }
  assert.equal(h.state.queries.some((q) => /threat_report_candidates|ioc_items|ioc_sources|ioc_tags|review_status|promot/i.test(q.sql)), false);
  assert.ok(h.state.queued.every((j) => j.name === 'analyze'), 'only the analysis job is queued (no create_iocs / promotion job)');
  assert.ok(h.state.audits.every((a) => a.action === AUDIT_ACTION.THREAT_LIBRARY_REPORT_IMPORTED_URL));
});
