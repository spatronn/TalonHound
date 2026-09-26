import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  IMPORT_DUPLICATE_MESSAGES,
  backfillReportImportIdentity,
  canonicalizeReportUrl,
  claimReportImport,
  findExistingReportImport,
  normalizeSha256
} from './importIdentity.js';

// --- URL canonicalisation ----------------------------------------------------

test('canonicalizeReportUrl folds scheme/host case, default ports, fragments, credentials, empty ? and one trailing slash', () => {
  const base = 'https://vendor.example/blog/report-1';
  for (const variant of [
    'https://vendor.example/blog/report-1',
    '  https://vendor.example/blog/report-1  ',
    'HTTPS://Vendor.EXAMPLE/blog/report-1',
    'https://vendor.example:443/blog/report-1',
    'https://vendor.example/blog/report-1#section-2',
    'https://vendor.example/blog/report-1/',
    'https://vendor.example/blog/report-1/#top',
    'https://vendor.example/blog/report-1?',
    'https://user:pw@vendor.example/blog/report-1'
  ]) {
    assert.equal(canonicalizeReportUrl(variant), base, variant);
  }
  assert.equal(canonicalizeReportUrl('http://vendor.example:80/a'), 'http://vendor.example/a');
  // Root path: "/" is the path itself, not a trailing slash.
  assert.equal(canonicalizeReportUrl('https://vendor.example'), 'https://vendor.example/');
  assert.equal(canonicalizeReportUrl('https://vendor.example/'), 'https://vendor.example/');
  // IDN host -> punycode (WHATWG), so both spellings share one identity.
  assert.equal(canonicalizeReportUrl('https://bücher.example/x'), canonicalizeReportUrl('https://xn--bcher-kva.example/x'));
});

test('canonicalizeReportUrl is conservative: query, path case, scheme and non-default ports stay distinct', () => {
  const a = canonicalizeReportUrl('https://vendor.example/view?id=1');
  assert.equal(a, 'https://vendor.example/view?id=1');
  assert.notEqual(a, canonicalizeReportUrl('https://vendor.example/view?id=2'), 'query selects a different document');
  assert.notEqual(a, canonicalizeReportUrl('https://vendor.example/view'), 'query is never stripped');
  assert.notEqual(
    canonicalizeReportUrl('https://vendor.example/view?a=1&b=2'),
    canonicalizeReportUrl('https://vendor.example/view?b=2&a=1'),
    'query order is kept verbatim'
  );
  assert.equal(canonicalizeReportUrl('https://vendor.example/view?utm_source=x'), 'https://vendor.example/view?utm_source=x', 'tracking params are not stripped');
  assert.notEqual(canonicalizeReportUrl('https://vendor.example/Report'), canonicalizeReportUrl('https://vendor.example/report'), 'path is case-sensitive');
  assert.notEqual(canonicalizeReportUrl('http://vendor.example/r'), canonicalizeReportUrl('https://vendor.example/r'), 'scheme is kept');
  assert.notEqual(canonicalizeReportUrl('https://vendor.example:8443/r'), canonicalizeReportUrl('https://vendor.example/r'));
  // Only ONE trailing slash is folded.
  assert.equal(canonicalizeReportUrl('https://vendor.example/a//'), 'https://vendor.example/a/');
  // Query on a trailing-slash path keeps the query.
  assert.equal(canonicalizeReportUrl('https://vendor.example/a/?p=1#f'), 'https://vendor.example/a?p=1');
});

test('canonicalizeReportUrl rejects non-http(s) and malformed input', () => {
  for (const bad of ['', '   ', null, undefined, 'not a url', 'ftp://vendor.example/r', 'javascript:alert(1)', 'file:///etc/passwd']) {
    assert.equal(canonicalizeReportUrl(bad), null, String(bad));
  }
});

test('normalizeSha256 accepts only 64-hex digests (case-folded)', () => {
  const hex = crypto.createHash('sha256').update('x').digest('hex');
  assert.equal(normalizeSha256(hex.toUpperCase()), hex);
  assert.equal(normalizeSha256(` ${hex} `), hex);
  assert.equal(normalizeSha256(crypto.createHash('md5').update('x').digest('hex')), null, 'MD5 is never an identity');
  assert.equal(normalizeSha256('z'.repeat(64)), null);
  assert.equal(normalizeSha256(null), null);
});

test('duplicate messages match the product copy', () => {
  assert.equal(IMPORT_DUPLICATE_MESSAGES.url, 'This report has already been imported.');
  assert.equal(IMPORT_DUPLICATE_MESSAGES.sha256, 'This PDF has already been imported.');
});

// --- Lookup / claim ------------------------------------------------------------

const SHA = crypto.createHash('sha256').update('%PDF-1.7 one').digest('hex');

function fakePool({ existing = null, failCreate = false } = {}) {
  const log = [];
  const client = {
    released: false,
    async query(sql, params = []) {
      log.push({ sql: sql.replace(/\s+/g, ' ').trim(), params });
      if (/FROM threat_reports/.test(sql)) return { rows: existing ? [existing] : [] };
      return { rows: [], rowCount: 0 };
    },
    release() { this.released = true; }
  };
  return {
    log,
    client,
    async connect() { return client; },
    failCreate
  };
}

test('findExistingReportImport scopes by source type, excludes soft-deleted rows and returns the oldest', async () => {
  const pool = fakePool();
  await findExistingReportImport(pool.client, { kind: 'url', key: 'https://vendor.example/r' });
  await findExistingReportImport(pool.client, { kind: 'sha256', key: SHA });
  const [url, pdf] = pool.log;
  assert.match(url.sql, /WHERE source_type = 'url' AND deleted_at IS NULL AND source_url_canonical = \$1 ORDER BY created_at ASC, id ASC LIMIT 1/);
  assert.deepEqual(url.params, ['https://vendor.example/r']);
  // PDF identity is the existing source_sha256 column, never source_url / file name.
  assert.match(pdf.sql, /WHERE source_type = 'pdf' AND deleted_at IS NULL AND source_sha256 = \$1 ORDER BY created_at ASC, id ASC LIMIT 1/);
  assert.doesNotMatch(pdf.sql, /source_file_name|title|md5/);
  assert.deepEqual(pdf.params, [SHA]);
});

test('findExistingReportImport / claimReportImport refuse malformed identities before touching the database', async () => {
  const pool = fakePool();
  for (const identity of [{ kind: 'url', key: '' }, { kind: 'sha256', key: 'abc' }, { kind: 'sha256', key: SHA.toUpperCase() }, { kind: 'md5', key: 'x' }, null]) {
    await assert.rejects(findExistingReportImport(pool.client, identity), { code: 'invalid_import_identity' });
    await assert.rejects(claimReportImport(pool, identity, async () => ({})), { code: 'invalid_import_identity' });
  }
  assert.equal(pool.log.length, 0);
});

test('claimReportImport on a duplicate: lock -> lookup -> COMMIT, and never runs create', async () => {
  const existing = { id: 7, public_id: 'existing-uuid', title: 'Existing' };
  const pool = fakePool({ existing });
  let created = 0;
  const result = await claimReportImport(pool, { kind: 'sha256', key: SHA }, async () => { created += 1; return {}; });
  assert.deepEqual(result, { duplicate: true, report: existing });
  assert.equal(created, 0);
  assert.deepEqual(pool.log.map((q) => q.sql.split(' ').slice(0, 2).join(' ')), ['BEGIN', 'SELECT pg_advisory_xact_lock(hashtext($1)::bigint)', 'SELECT *', 'COMMIT']);
  assert.deepEqual(pool.log[1].params, [`threat_library.import_identity:sha256:${SHA}`]);
  assert.equal(pool.client.released, true);
});

test('claimReportImport on a new identity creates the row inside the same locked transaction', async () => {
  const pool = fakePool();
  let seenClient = null;
  const result = await claimReportImport(pool, { kind: 'url', key: 'https://vendor.example/r' }, async (db) => {
    seenClient = db;
    await db.query('INSERT INTO threat_reports (title) VALUES ($1) RETURNING *', ['x']);
    return { id: 1, public_id: 'new-uuid' };
  });
  assert.deepEqual(result, { duplicate: false, report: { id: 1, public_id: 'new-uuid' } });
  assert.equal(seenClient, pool.client, 'create must use the transaction client that holds the lock');
  const order = pool.log.map((q) => q.sql.split(' ')[0]);
  assert.deepEqual(order, ['BEGIN', 'SELECT', 'SELECT', 'INSERT', 'COMMIT']);
  assert.equal(pool.client.released, true);
});

test('claimReportImport rolls back and releases when create fails', async () => {
  const pool = fakePool();
  await assert.rejects(
    claimReportImport(pool, { kind: 'url', key: 'https://vendor.example/r' }, async () => { throw new Error('insert failed'); }),
    /insert failed/
  );
  assert.equal(pool.log.at(-1).sql, 'ROLLBACK');
  assert.ok(!pool.log.some((q) => q.sql === 'COMMIT'));
  assert.equal(pool.client.released, true);
});

// --- Historical backfill ---------------------------------------------------------

test('backfillReportImportIdentity fills only the NULL identity column of URL rows and reports (never touches) duplicates', async () => {
  const log = [];
  const db = {
    async query(sql, params = []) {
      const flat = sql.replace(/\s+/g, ' ').trim();
      log.push({ sql: flat, params });
      if (flat.startsWith('SELECT id, source_url')) {
        return { rows: [
          { id: 1, source_url: 'HTTPS://Vendor.example/a/#x' },
          { id: 2, source_url: 'https://vendor.example/a' },
          { id: 3, source_url: 'not a url' }
        ] };
      }
      if (flat.startsWith('UPDATE')) return { rowCount: 1 };
      return { rows: [{ kind: 'url', key: 'https://vendor.example/a', count: 2, report_ids: ['u1', 'u2'] }] };
    }
  };
  const result = await backfillReportImportIdentity(db);
  assert.equal(result.scanned, 3);
  assert.equal(result.updated, 2, 'unparseable legacy URLs stay NULL');
  assert.deepEqual(result.duplicateGroups, [{ kind: 'url', key: 'https://vendor.example/a', count: 2, report_ids: ['u1', 'u2'] }]);
  assert.match(log[0].sql, /WHERE source_type = 'url' AND source_url_canonical IS NULL AND source_url IS NOT NULL/);
  const updates = log.filter((q) => q.sql.startsWith('UPDATE'));
  assert.deepEqual(updates.map((q) => q.params), [[1, 'https://vendor.example/a'], [2, 'https://vendor.example/a']]);
  for (const u of updates) {
    // Only the new column, only while still NULL; no updated_at bump, no other data.
    assert.equal(u.sql, 'UPDATE threat_reports SET source_url_canonical = $2 WHERE id = $1 AND source_url_canonical IS NULL');
  }
  assert.ok(!log.some((q) => /DELETE|deleted_at =/.test(q.sql)), 'historical duplicates are never merged or deleted');
});
