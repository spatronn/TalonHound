import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import {
  backfillReportImportIdentity,
  canonicalizeReportUrl,
  claimReportImport,
  findExistingReportImport
} from './importIdentity.js';
import { createThreatReport, listThreatReports } from './store.js';

/**
 * Real-Postgres integration test for Threat Library import identity (migration
 * 031): concurrent duplicate submissions, index-backed lookups, the historical
 * backfill and 25/50-row paging.
 *
 * The concurrency tests must COMMIT from several sessions, so they only run
 * with ALLOW_THREAT_LIBRARY_DB_TESTS=1 against a throwaway database; every row
 * they create carries a random marker and is hard-deleted afterwards. All
 * other tests run inside a rolled-back transaction.
 */

const { Pool } = pg;

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound',
  connectionTimeoutMillis: 2000,
  max: 12
});

let hasDb = false;
if (process.env.ALLOW_THREAT_LIBRARY_DB_TESTS === '1') {
  try {
    await pool.query('SELECT source_url_canonical FROM threat_reports LIMIT 0');
    hasDb = true;
  } catch {
    hasDb = false;
  }
}
const opts = { skip: hasDb ? false : 'set ALLOW_THREAT_LIBRARY_DB_TESTS=1 with a migrated throwaway database to run' };

test.after(() => pool.end());

const marker = () => `itest-${crypto.randomUUID()}`;

async function cleanup(tag) {
  await pool.query(`DELETE FROM threat_reports WHERE title = $1`, [tag]);
}

async function inTx(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await fn(client);
  } finally {
    await client.query('ROLLBACK').catch(() => {});
    client.release();
  }
}

/** create() that widens the check->insert window so an unlocked race would show. */
function slowCreate(fields) {
  return async (db) => {
    await db.query('SELECT pg_sleep(0.15)');
    return createThreatReport(db, fields);
  };
}

test('concurrent imports of the same URL (different spellings) create exactly one report', opts, async () => {
  const tag = marker();
  const url = `https://vendor.example/${tag}`;
  const key = canonicalizeReportUrl(url);
  try {
    const spellings = [url, `${url}/`, `${url}#iocs`, url.replace('https://vendor', 'HTTPS://VENDOR'), `https://vendor.example:443/${tag}`, url, url, url];
    const results = await Promise.all(spellings.map((u) => claimReportImport(
      pool,
      { kind: 'url', key: canonicalizeReportUrl(u) },
      slowCreate({ title: tag, source_type: 'url', source_url: u, source_url_canonical: canonicalizeReportUrl(u) })
    )));
    const created = results.filter((r) => !r.duplicate);
    assert.equal(created.length, 1);
    assert.equal(results.filter((r) => r.duplicate).length, spellings.length - 1);
    assert.ok(results.every((r) => String(r.report.id) === String(created[0].report.id)), 'every duplicate points at the one report');
    const { rows } = await pool.query(`SELECT COUNT(*)::int AS n FROM threat_reports WHERE source_url_canonical = $1`, [key]);
    assert.equal(rows[0].n, 1);
  } finally {
    await cleanup(tag);
  }
});

test('concurrent uploads of the same PDF bytes create exactly one report', opts, async () => {
  const tag = marker();
  const sha = crypto.createHash('sha256').update(`%PDF-1.7 ${tag}`).digest('hex');
  try {
    const results = await Promise.all(['a.pdf', 'b.pdf', 'renamed.pdf', 'a.pdf', 'c.pdf', 'd.pdf'].map((name) => claimReportImport(
      pool,
      { kind: 'sha256', key: sha },
      slowCreate({ title: tag, source_type: 'pdf', source_file_name: name, source_sha256: sha })
    )));
    assert.equal(results.filter((r) => !r.duplicate).length, 1);
    const { rows } = await pool.query(`SELECT COUNT(*)::int AS n FROM threat_reports WHERE source_sha256 = $1`, [sha]);
    assert.equal(rows[0].n, 1);
  } finally {
    await cleanup(tag);
  }
});

test('control: the same race WITHOUT the identity lock does create duplicates (the lock is what prevents it)', opts, async () => {
  const tag = marker();
  const key = `https://vendor.example/${tag}`;
  try {
    await Promise.all(Array.from({ length: 4 }, async () => {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const existing = await findExistingReportImport(client, { kind: 'url', key });
        if (!existing) await slowCreate({ title: tag, source_type: 'url', source_url: key, source_url_canonical: key })(client);
        await client.query('COMMIT');
      } finally {
        client.release();
      }
    }));
    const { rows } = await pool.query(`SELECT COUNT(*)::int AS n FROM threat_reports WHERE title = $1`, [tag]);
    assert.ok(rows[0].n > 1, `unlocked check-then-insert raced (${rows[0].n} rows)`);
  } finally {
    await cleanup(tag);
  }
});

test('duplicate lookups use the 031 partial indexes, not a table scan', opts, async () => {
  await inTx(async (client) => {
    await client.query(
      `INSERT INTO threat_reports (title, source_type, source_url, source_url_canonical, source_sha256, created_at)
       SELECT 'bulk ' || g,
              CASE WHEN g % 2 = 0 THEN 'url' ELSE 'pdf' END,
              'https://bulk.example/' || g,
              CASE WHEN g % 2 = 0 THEN 'https://bulk.example/' || g END,
              CASE WHEN g % 2 = 1 THEN encode(sha256(g::text::bytea), 'hex') END,
              NOW() - (g || ' seconds')::interval
       FROM generate_series(1, 5000) g`
    );
    await client.query('ANALYZE threat_reports');
    const plan = async (sql, params) => (await client.query(`EXPLAIN ${sql}`, params)).rows.map((r) => r['QUERY PLAN']).join('\n');
    const urlPlan = await plan(
      `SELECT * FROM threat_reports WHERE source_type = 'url' AND deleted_at IS NULL AND source_url_canonical = $1 ORDER BY created_at ASC, id ASC LIMIT 1`,
      ['https://bulk.example/42']
    );
    assert.match(urlPlan, /idx_threat_reports_url_import_identity/, urlPlan);
    assert.doesNotMatch(urlPlan, /Seq Scan/, urlPlan);
    const pdfPlan = await plan(
      `SELECT * FROM threat_reports WHERE source_type = 'pdf' AND deleted_at IS NULL AND source_sha256 = $1 ORDER BY created_at ASC, id ASC LIMIT 1`,
      [crypto.createHash('sha256').update('43').digest('hex')]
    );
    assert.match(pdfPlan, /idx_threat_reports_pdf_import_identity/, pdfPlan);
    assert.doesNotMatch(pdfPlan, /Seq Scan/, pdfPlan);
    // First list page is served by the existing created_at index.
    const listPlan = await plan(`SELECT r.id FROM threat_reports r WHERE r.deleted_at IS NULL ORDER BY r.created_at DESC LIMIT 25 OFFSET 0`, []);
    assert.match(listPlan, /idx_threat_reports_created_at/, listPlan);
  });
});

test('historical backfill fills source_url_canonical only, keeps updated_at, and reports duplicates without touching them', opts, async () => {
  await inTx(async (client) => {
    await client.query('UPDATE threat_reports SET deleted_at = NOW() WHERE deleted_at IS NULL');
    const legacyAt = '2026-01-01T00:00:00Z';
    const { rows: seeded } = await client.query(
      `INSERT INTO threat_reports (title, source_type, source_url, updated_at) VALUES
         ('legacy a', 'url', 'HTTPS://Legacy.example/post/#top', $1),
         ('legacy b', 'url', 'https://legacy.example/post', $1),
         ('legacy c', 'url', 'https://legacy.example/other', $1),
         ('legacy pdf', 'pdf', NULL, $1)
       RETURNING id, title`,
      [legacyAt]
    );
    const result = await backfillReportImportIdentity(client);
    assert.ok(result.updated >= 3);
    const { rows } = await client.query(
      `SELECT title, source_url, source_url_canonical, updated_at FROM threat_reports WHERE id = ANY($1) ORDER BY title`,
      [seeded.map((r) => r.id)]
    );
    assert.deepEqual(rows.map((r) => [r.title, r.source_url_canonical]), [
      ['legacy a', 'https://legacy.example/post'],
      ['legacy b', 'https://legacy.example/post'],
      ['legacy c', 'https://legacy.example/other'],
      ['legacy pdf', null]
    ]);
    assert.equal(rows[0].source_url, 'HTTPS://Legacy.example/post/#top', 'provenance source_url is never rewritten');
    for (const r of rows) assert.equal(new Date(r.updated_at).toISOString(), new Date(legacyAt).toISOString());
    const group = result.duplicateGroups.find((g) => g.kind === 'url' && g.key === 'https://legacy.example/post');
    assert.equal(group.count, 2);
    const { rows: alive } = await client.query(`SELECT COUNT(*)::int AS n FROM threat_reports WHERE id = ANY($1) AND deleted_at IS NULL`, [seeded.map((r) => r.id)]);
    assert.equal(alive[0].n, 4, 'historical duplicates are reported, never deleted');
    // Idempotent: a second run has nothing left to fill.
    assert.equal((await backfillReportImportIdentity(client)).updated, 0);
    // New imports then see the legacy report as the existing one.
    const existing = await findExistingReportImport(client, { kind: 'url', key: canonicalizeReportUrl('https://legacy.example/post#x') });
    assert.equal(existing.title, 'legacy a', 'oldest legacy row wins');
  });
});

test('list paging with 25 and 50 rows: complete, no overlap, last page, search + page size', opts, async () => {
  await inTx(async (client) => {
    await client.query('UPDATE threat_reports SET deleted_at = NOW() WHERE deleted_at IS NULL');
    await client.query(
      `INSERT INTO threat_reports (title, source_type, source_url, created_at)
       SELECT CASE WHEN g % 3 = 0 THEN 'apt paging ' ELSE 'misc paging ' END || g, 'url', 'https://paging.example/' || g,
              NOW() - (g || ' minutes')::interval
       FROM generate_series(1, 120) g`
    );
    for (const size of [25, 50]) {
      const seen = [];
      let page = 0;
      for (;;) {
        const r = await listThreatReports(client, { limit: size, offset: page * size });
        assert.equal(r.total, 120);
        if (!r.items.length) break;
        seen.push(...r.items.map((x) => x.title));
        page += 1;
      }
      assert.equal(seen.length, 120, `size ${size}: every row exactly once`);
      assert.equal(new Set(seen).size, 120);
      assert.equal(page, Math.ceil(120 / size));
    }
    const lastOf50 = await listThreatReports(client, { limit: 50, offset: 100 });
    assert.equal(lastOf50.items.length, 20);
    // search + page size: 40 "apt paging" rows -> 25 + 15, or 40 on one 50-row page.
    const s1 = await listThreatReports(client, { search: 'apt paging', limit: 25, offset: 0 });
    const s2 = await listThreatReports(client, { search: 'apt paging', limit: 25, offset: 25 });
    assert.equal(s1.total, 40);
    assert.deepEqual([s1.items.length, s2.items.length], [25, 15]);
    assert.equal(new Set([...s1.items, ...s2.items].map((x) => x.id)).size, 40);
    assert.equal((await listThreatReports(client, { search: 'apt paging', limit: 50, offset: 0 })).items.length, 40);
    assert.equal((await listThreatReports(client, { search: 'no-such-report', limit: 50 })).total, 0);
  });
});
