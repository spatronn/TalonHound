/**
 * Threat Library URL / PDF import deduplication + list page-size contract,
 * exercised through the real HTTP routes (express + multer) with an in-memory
 * pool and a spy queue. Backend enforcement only — no frontend involved.
 *
 * "Expensive work" for an import is everything behind the queue: fetch,
 * extraction and AI analysis all run in threat-library-worker. The route's
 * only hand-off to it is queue.add, so a duplicate must never reach
 * INSERT threat_reports, the artifact store, INSERT threat_library_jobs or
 * queue.add.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mkdtempSync, readdirSync, rmSync, existsSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import express from 'express';
import { registerThreatLibraryRoutes } from './threatLibrary.js';

const storageDir = mkdtempSync(path.join(os.tmpdir(), 'tl-dedup-'));
process.env.THREAT_LIBRARY_STORAGE_DIR = storageDir;
test.after(() => rmSync(storageDir, { recursive: true, force: true }));

const ANALYST = { id: 2, role: 'analyst', username: 'analyst' };

function createState() {
  return { reports: [], jobs: [], artifacts: [], queued: [], audits: [], queries: [], reportInserts: 0, seq: 0 };
}

/** Minimal in-memory threat_reports / jobs / artifacts, keyed on the SQL the routes issue. */
function createPool(state) {
  async function query(sql, params = []) {
    const flat = String(sql).replace(/\s+/g, ' ').trim();
    state.queries.push({ sql: flat, params });
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
        source_file_name: params[4],
        source_sha256: params[5],
        tlp: params[8],
        import_status: params[12],
        analysis_status: params[13],
        source_url_canonical: params[21],
        created_at: new Date(Date.UTC(2026, 8, 1, 10, state.seq)).toISOString(),
        deleted_at: null
      };
      state.reports.push(row);
      return { rows: [row], rowCount: 1 };
    }
    if (/^SELECT \* FROM threat_reports WHERE source_type = 'url' AND deleted_at IS NULL AND source_url_canonical = \$1/.test(flat)) {
      const rows = state.reports.filter((r) => r.source_type === 'url' && !r.deleted_at && r.source_url_canonical === params[0]);
      return { rows: rows.slice(0, 1) };
    }
    if (/^SELECT \* FROM threat_reports WHERE source_type = 'pdf' AND deleted_at IS NULL AND source_sha256 = \$1/.test(flat)) {
      const rows = state.reports.filter((r) => r.source_type === 'pdf' && !r.deleted_at && r.source_sha256 === params[0]);
      return { rows: rows.slice(0, 1) };
    }
    if (/^INSERT INTO threat_library_jobs/.test(flat)) {
      const job = { id: state.jobs.length + 1, public_id: `job-${state.jobs.length + 1}`, report_id: params[0] };
      state.jobs.push(job);
      return { rows: [job], rowCount: 1 };
    }
    if (/^INSERT INTO threat_report_artifacts/.test(flat)) {
      state.artifacts.push({ report_id: params[0] });
      return { rows: [{ id: state.artifacts.length }], rowCount: 1 };
    }
    // List endpoint (page + count) for the page-size tests.
    if (/COUNT\(\*\)::int AS total FROM threat_reports r/.test(flat)) return { rows: [{ total: state.reports.length }] };
    if (/^SELECT r\.\*, .* FROM threat_reports r WHERE .* LIMIT \$\d+ OFFSET \$\d+$/.test(flat)) {
      const [limit, offset] = params.slice(-2);
      return { rows: state.reports.slice(offset, offset + limit) };
    }
    return { rows: [], rowCount: 0 };
  }
  return {
    query,
    async connect() { return { query, release() {} }; }
  };
}

async function withServer(fn) {
  const state = createState();
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.user = ANALYST; next(); });
  registerThreatLibraryRoutes(app, createPool(state), {
    auditLog: async (event) => { state.audits.push(event); },
    resolveActor: async () => ({ ...ANALYST, publicId: '00000000-0000-4000-8000-00000000aaaa' })
  }, {
    threatLibraryQueue: {
      async add(name, data) { state.queued.push({ name, data }); return { id: `bull-${state.queued.length}` }; }
    }
  });
  const server = app.listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    await fn({ base, state });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

async function json(res) {
  const text = await res.text();
  return text ? JSON.parse(text) : null;
}

function importUrl(base, url) {
  return fetch(`${base}/api/threat-library/import/url`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url })
  }).then(async (res) => ({ status: res.status, body: await json(res) }));
}

function importPdf(base, bytes, fileName) {
  const form = new FormData();
  form.append('file', new Blob([bytes], { type: 'application/pdf' }), fileName);
  return fetch(`${base}/api/threat-library/import/pdf`, { method: 'POST', body: form })
    .then(async (res) => ({ status: res.status, body: await json(res) }));
}

function pdfBytes(label) {
  return Buffer.from(`%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n% ${label}\n%%EOF\n`, 'latin1');
}

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
const storedReportDirs = () => (existsSync(path.join(storageDir, 'reports')) ? readdirSync(path.join(storageDir, 'reports')) : []);

// --- URL -------------------------------------------------------------------------

test('URL: first import is accepted and queued; the same URL again is a 200 no-op that returns the existing report', async () => {
  await withServer(async ({ base, state }) => {
    const first = await importUrl(base, 'https://vendor.example/research/apt-report');
    assert.equal(first.status, 202);
    assert.equal(first.body.already_imported, false);
    assert.ok(first.body.job_id);
    assert.equal(state.reportInserts, 1);
    assert.equal(state.queued.length, 1);
    assert.equal(state.reports[0].source_url_canonical, 'https://vendor.example/research/apt-report');

    const again = await importUrl(base, 'https://vendor.example/research/apt-report');
    assert.equal(again.status, 200, 'duplicate is an expected no-op, not an error');
    assert.equal(again.body.already_imported, true);
    assert.equal(again.body.duplicate_reason, 'url');
    assert.equal(again.body.message, 'This report has already been imported.');
    assert.equal(again.body.report.id, first.body.report.id, 'links to the existing report');
    assert.equal(again.body.report.title, first.body.report.title);
    assert.ok(again.body.report.created_at, 'import date is returned for the UI');
    assert.equal(again.body.job_id, undefined);

    // Nothing created, nothing queued -> no fetch / extraction / AI.
    assert.equal(state.reportInserts, 1);
    assert.equal(state.jobs.length, 1);
    assert.equal(state.queued.length, 1);
  });
});

test('URL: canonical-equivalent spellings are duplicates; a different document (path or query) is not blocked', async () => {
  await withServer(async ({ base, state }) => {
    assert.equal((await importUrl(base, 'https://vendor.example/blog/post?id=7')).status, 202);
    for (const variant of [
      'HTTPS://Vendor.Example/blog/post?id=7',
      'https://vendor.example:443/blog/post?id=7',
      'https://vendor.example/blog/post?id=7#iocs',
      'https://vendor.example/blog/post/?id=7'
    ]) {
      const res = await importUrl(base, variant);
      assert.equal(res.status, 200, variant);
      assert.equal(res.body.already_imported, true, variant);
    }
    assert.equal(state.queued.length, 1);

    for (const different of [
      'https://vendor.example/blog/post?id=8',
      'https://vendor.example/blog/post',
      'https://vendor.example/blog/other?id=7',
      'http://vendor.example/blog/post?id=7'
    ]) {
      const res = await importUrl(base, different);
      assert.equal(res.status, 202, different);
      assert.equal(res.body.already_imported, false, different);
    }
    assert.equal(state.reportInserts, 5);
    assert.equal(state.queued.length, 5);
  });
});

test('URL: the duplicate check runs under the identity advisory lock before INSERT, and the duplicate is audited as a no-op', async () => {
  await withServer(async ({ base, state }) => {
    await importUrl(base, 'https://vendor.example/r');
    state.queries.length = 0;
    await importUrl(base, 'https://vendor.example/r#x');
    const sqls = state.queries.map((q) => q.sql);
    const lockAt = sqls.findIndex((s) => s.startsWith('SELECT pg_advisory_xact_lock'));
    const lookupAt = sqls.findIndex((s) => s.includes('source_url_canonical = $1'));
    assert.ok(lockAt >= 0 && lookupAt > lockAt);
    assert.deepEqual(state.queries[lockAt].params, ['threat_library.import_identity:url:https://vendor.example/r']);
    assert.ok(!sqls.some((s) => /^INSERT INTO (threat_reports|threat_library_jobs|threat_report_artifacts)/.test(s)));
    const audit = state.audits.at(-1);
    assert.equal(audit.metadata.already_imported, true);
    assert.equal(audit.metadata.duplicate_reason, 'url');
  });
});

test('URL: a soft-deleted report does not block re-import', async () => {
  await withServer(async ({ base, state }) => {
    await importUrl(base, 'https://vendor.example/r');
    state.reports[0].deleted_at = new Date().toISOString();
    const res = await importUrl(base, 'https://vendor.example/r');
    assert.equal(res.status, 202);
    assert.equal(state.queued.length, 2);
  });
});

test('URL: invalid URLs are still rejected before any lookup', async () => {
  await withServer(async ({ base, state }) => {
    const res = await importUrl(base, 'ftp://vendor.example/r');
    assert.equal(res.status, 400);
    assert.equal(state.queries.length, 0);
  });
});

// --- PDF -------------------------------------------------------------------------

test('PDF: identical bytes are a duplicate under the same or a different filename; different bytes are allowed', async () => {
  await withServer(async ({ base, state }) => {
    const bytes = pdfBytes('report-a');
    const first = await importPdf(base, bytes, 'report-a.pdf');
    assert.equal(first.status, 202);
    assert.equal(first.body.already_imported, false);
    assert.equal(first.body.report.source_sha256, sha256(bytes), 'identity = SHA-256 of the original uploaded bytes');
    assert.equal(state.queued.length, 1);
    assert.equal(state.artifacts.length, 1);
    assert.deepEqual(storedReportDirs(), [String(state.reports[0].id)]);

    for (const name of ['report-a.pdf', 'renamed-report.pdf']) {
      const dup = await importPdf(base, bytes, name);
      assert.equal(dup.status, 200, name);
      assert.equal(dup.body.already_imported, true, name);
      assert.equal(dup.body.duplicate_reason, 'sha256');
      assert.equal(dup.body.message, 'This PDF has already been imported.');
      assert.equal(dup.body.report.id, first.body.report.id);
      assert.equal(dup.body.report.source_file_name, 'report-a.pdf', 'the existing report is returned unchanged');
    }
    // Duplicates never stored the file, created a job or reached the worker.
    assert.equal(state.reportInserts, 1);
    assert.equal(state.artifacts.length, 1);
    assert.equal(state.jobs.length, 1);
    assert.equal(state.queued.length, 1);
    assert.deepEqual(storedReportDirs(), [String(state.reports[0].id)]);

    const other = await importPdf(base, pdfBytes('vendor-regenerated'), 'report-a.pdf');
    assert.equal(other.status, 202, 'same filename, different bytes -> a different report');
    assert.equal(other.body.already_imported, false);
    assert.equal(state.reportInserts, 2);
    assert.equal(state.queued.length, 2);
  });
});

test('PDF: the hash lookup happens under the identity lock before INSERT; duplicate audit carries the hash', async () => {
  await withServer(async ({ base, state }) => {
    const bytes = pdfBytes('locked');
    await importPdf(base, bytes, 'a.pdf');
    state.queries.length = 0;
    await importPdf(base, bytes, 'b.pdf');
    const sqls = state.queries.map((q) => q.sql);
    const lockAt = sqls.findIndex((s) => s.startsWith('SELECT pg_advisory_xact_lock'));
    assert.deepEqual(state.queries[lockAt].params, [`threat_library.import_identity:sha256:${sha256(bytes)}`]);
    assert.ok(sqls.findIndex((s) => s.includes('source_sha256 = $1')) > lockAt);
    assert.ok(!sqls.some((s) => /^INSERT INTO/.test(s)));
    const audit = state.audits.at(-1);
    assert.equal(audit.metadata.already_imported, true);
    assert.equal(audit.metadata.duplicate_reason, 'sha256');
    assert.equal(audit.metadata.sha256, sha256(bytes));
  });
});

test('PDF: URL and PDF identities are independent (a PDF hash never matches a URL report and vice versa)', async () => {
  await withServer(async ({ base, state }) => {
    await importUrl(base, 'https://vendor.example/r');
    const res = await importPdf(base, pdfBytes('x'), 'r.pdf');
    assert.equal(res.status, 202);
    assert.equal(state.queued.length, 2);
  });
});

// --- List page size -------------------------------------------------------------------

test('report list: limit is restricted to 25 / 50 (default 25) and echoed with the offset', async () => {
  await withServer(async ({ base, state }) => {
    for (let i = 0; i < 60; i += 1) {
      state.reports.push({ id: i + 1, public_id: `r-${i}`, title: `Report ${i}`, source_type: 'url', created_at: new Date().toISOString() });
    }
    const cases = [
      ['', 25], ['?limit=25', 25], ['?limit=50', 50], ['?limit=%2050%20', 50],
      ['?limit=10', 25], ['?limit=100', 25], ['?limit=200', 25], ['?limit=abc', 25],
      ['?limit=-50', 25], ['?limit=50.5', 25], ['?limit=25&limit=50', 25]
    ];
    for (const [qs, expected] of cases) {
      state.queries.length = 0;
      const res = await fetch(`${base}/api/threat-library/reports${qs}`);
      const body = await json(res);
      assert.equal(res.status, 200, qs);
      assert.equal(body.limit, expected, qs);
      assert.equal(body.items.length, expected, qs);
      assert.equal(body.total, 60, qs);
      const page = state.queries.find((q) => /LIMIT \$\d+ OFFSET/.test(q.sql));
      assert.deepEqual(page.params.slice(-2), [expected, 0], `${qs} reaches SQL as ${expected}`);
    }
    const last = await json(await fetch(`${base}/api/threat-library/reports?limit=25&offset=50`));
    assert.equal(last.offset, 50);
    assert.equal(last.items.length, 10, 'final partial page');
    const beyond = await json(await fetch(`${base}/api/threat-library/reports?limit=50&offset=100`));
    assert.equal(beyond.items.length, 0);
    assert.equal(beyond.total, 60);
  });
});
