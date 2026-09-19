import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { listThreatReports } from './store.js';

/**
 * Real-Postgres integration test for Threat Library report-list search.
 * Runs `listThreatReports` against the migrated schema with ~60 seeded reports so
 * matching, case-folding, wildcard escaping and filtered pagination are proven
 * on the actual ILIKE semantics rather than a fake pool. Every test runs inside
 * a transaction that is rolled back, so it never leaves rows behind. Skips
 * cleanly when no database is reachable (local dev without a DB).
 */

const { Pool } = pg;

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound',
  connectionTimeoutMillis: 2000,
  max: 2
});

let hasDb = false;
try {
  await pool.query('SELECT 1');
  await pool.query('SELECT title, source_url, source_file_name, report_type FROM threat_reports LIMIT 0');
  hasDb = true;
} catch {
  hasDb = false;
}

const opts = { skip: hasDb ? false : 'no database available (set DB_HOST/DB_PASSWORD to run)' };

const SEED = [
  { title: 'Iranian cyber targeting of dissidents, activists and journalists', source_type: 'url', source_name: 'NCSC', source_url: 'https://www.ncsc.gov.uk/news/iranian-cyber-targeting', report_type: 'advisory' },
  { title: 'VectraRAT: a new remote access trojan', source_type: 'url', source_name: 'SOCRadar', source_url: 'https://socradar.io/vectrarat-analysis', report_type: 'threat_report' },
  { title: 'CTA joint analysis: DPRK IT workers', source_type: 'pdf', source_name: null, source_url: null, source_file_name: 'CTA-NK-IT-Workers-2025.pdf', report_type: 'threat_report' },
  { title: 'Quarterly threat landscape', source_type: 'thib', source_name: 'Vendor Bundle', source_url: null, report_type: 'bundle' },
  { title: 'Report with 100% confidence', source_type: 'url', source_name: 'Example', source_url: 'https://example.org/100-percent', report_type: 'blog' },
  { title: 'Under_score title', source_type: 'url', source_name: 'Example', source_url: 'https://example.org/underscore', report_type: 'blog' }
];

async function seed(client) {
  // Only the summary / canonical_document mention "needle-in-blob": search must not see it.
  for (const r of SEED) {
    await client.query(
      `INSERT INTO threat_reports (title, source_type, source_name, source_url, source_file_name, report_type, summary, canonical_document)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)`,
      [r.title, r.source_type, r.source_name, r.source_url, r.source_file_name || null, r.report_type,
        'needle-in-blob summary text', JSON.stringify({ blocks: [{ type: 'paragraph', text: 'needle-in-blob body' }] })]
    );
  }
  // Bulk filler so the library is clearly larger than one screen: 54 more rows,
  // 30 of which match "filler-iran" and 24 "filler-other".
  for (let i = 0; i < 54; i += 1) {
    const iran = i < 30;
    await client.query(
      `INSERT INTO threat_reports (title, source_type, source_name, source_url, report_type, created_at)
       VALUES ($1, 'url', $2, $3, 'threat_report', NOW() - ($4::int * INTERVAL '1 minute'))`,
      [iran ? `filler-iran ${i}` : `filler-other ${i}`, 'Filler', `https://filler.example/${i}`, i + 10]
    );
  }
  // A soft-deleted match must never surface.
  await client.query(
    `INSERT INTO threat_reports (title, source_type, source_name, report_type, deleted_at)
     VALUES ('Iranian deleted report', 'url', 'NCSC', 'advisory', NOW())`
  );
}

async function withSeededTx(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Tests must be independent of pre-existing rows, so scope them to a clean library.
    await client.query('DELETE FROM threat_reports');
    await seed(client);
    await fn(client);
  } finally {
    await client.query('ROLLBACK').catch(() => {});
    client.release();
  }
}

const titles = (r) => r.items.map((x) => x.title);

test('no search returns every non-deleted report (baseline unchanged)', opts, async () => {
  await withSeededTx(async (client) => {
    const r = await listThreatReports(client, { limit: 200, offset: 0 });
    assert.equal(r.total, 60);
    assert.equal(r.items.length, 60);
    assert.equal(titles(r).includes('Iranian deleted report'), false);
  });
});

test('search by title, source name, source domain, file name and report type', opts, async () => {
  await withSeededTx(async (client) => {
    assert.deepEqual(titles(await listThreatReports(client, { search: 'iranian' })), ['Iranian cyber targeting of dissidents, activists and journalists']);
    assert.deepEqual(titles(await listThreatReports(client, { search: 'ncsc' })), ['Iranian cyber targeting of dissidents, activists and journalists']);
    assert.deepEqual(titles(await listThreatReports(client, { search: 'vectrarat' })), ['VectraRAT: a new remote access trojan']);
    assert.deepEqual(titles(await listThreatReports(client, { search: 'socradar' })), ['VectraRAT: a new remote access trojan']);
    assert.deepEqual(titles(await listThreatReports(client, { search: 'cta-nk' })), ['CTA joint analysis: DPRK IT workers']);
    const byType = await listThreatReports(client, { search: 'threat_report', limit: 200 });
    assert.equal(byType.total, 2 + 54);
    assert.ok(titles(byType).includes('VectraRAT: a new remote access trojan'));
    assert.ok(titles(byType).includes('CTA joint analysis: DPRK IT workers'));
  });
});

test('search is case-insensitive and trims whitespace', opts, async () => {
  await withSeededTx(async (client) => {
    for (const q of ['IRANIAN', 'Iranian', '  iranian  ', '\tIrAnIaN\n']) {
      const r = await listThreatReports(client, { search: q });
      assert.equal(r.total, 1, q);
      assert.equal(r.search, q.trim());
    }
  });
});

test('zero matches returns an empty page with total 0', opts, async () => {
  await withSeededTx(async (client) => {
    const r = await listThreatReports(client, { search: 'zzz-no-such-report' });
    assert.deepEqual(r.items, []);
    assert.equal(r.total, 0);
  });
});

test('LIKE wildcards in the term match literally, not as wildcards', opts, async () => {
  await withSeededTx(async (client) => {
    assert.deepEqual(titles(await listThreatReports(client, { search: '100%' })), ['Report with 100% confidence']);
    // "%" alone would otherwise match everything.
    assert.equal((await listThreatReports(client, { search: '%' })).total, 1);
    assert.equal((await listThreatReports(client, { search: 'Under_score' })).total, 1);
    // "_" alone must not act as a single-char wildcard (which would match all 60);
    // literally it matches the 56 report_type='threat_report' rows + 'Under_score title'.
    const underscoreOnly = await listThreatReports(client, { search: '_', limit: 200 });
    assert.equal(underscoreOnly.total, 57);
    assert.ok(titles(underscoreOnly).includes('Under_score title'));
    assert.equal((await listThreatReports(client, { search: 'thr_at' })).total, 0);
  });
});

test('SQL-injection-like input is plain search text', opts, async () => {
  await withSeededTx(async (client) => {
    for (const q of ["'; DROP TABLE threat_reports; --", "x' OR 1=1 --", "\\'; SELECT pg_sleep(0); --", 'a\u0000b']) {
      const r = await listThreatReports(client, { search: q });
      assert.equal(r.total, 0, q);
    }
    // The table is intact and nothing leaked.
    assert.equal((await listThreatReports(client, { limit: 200 })).total, 60);
  });
});

test('extracted content (summary / canonical_document) is never searched', opts, async () => {
  await withSeededTx(async (client) => {
    assert.equal((await listThreatReports(client, { search: 'needle-in-blob' })).total, 0);
  });
});

test('pagination operates over the filtered set and total reflects the filter', opts, async () => {
  await withSeededTx(async (client) => {
    const p1 = await listThreatReports(client, { search: 'filler-iran', limit: 10, offset: 0 });
    const p2 = await listThreatReports(client, { search: 'filler-iran', limit: 10, offset: 10 });
    const p3 = await listThreatReports(client, { search: 'filler-iran', limit: 10, offset: 20 });
    const p4 = await listThreatReports(client, { search: 'filler-iran', limit: 10, offset: 30 });
    for (const p of [p1, p2, p3, p4]) assert.equal(p.total, 30);
    assert.equal(p1.items.length, 10);
    assert.equal(p2.items.length, 10);
    assert.equal(p3.items.length, 10);
    assert.equal(p4.items.length, 0);
    const all = new Set([...titles(p1), ...titles(p2), ...titles(p3)]);
    assert.equal(all.size, 30);
    for (const t of all) assert.match(t, /^filler-iran /);
    // Newest-first ordering is preserved within the filtered set.
    assert.deepEqual(titles(p1), Array.from({ length: 10 }, (_, i) => `filler-iran ${i}`));
  });
});

test('over-long search terms are bounded and still parameterised', opts, async () => {
  await withSeededTx(async (client) => {
    const r = await listThreatReports(client, { search: 'iranian' + ' '.repeat(50) + 'x'.repeat(1000) });
    assert.equal(r.search.length <= 200, true);
    assert.equal(r.total, 0);
  });
});

// --- Page-size-25 pagination over a 157-report library -----------------------

async function withLargeLibraryTx(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM threat_reports');
    // 157 reports, newest first by created_at; odd numbers are threat_report (79),
    // even numbers blog (78). Titles "Library report 001" ... "Library report 157".
    await client.query(
      `INSERT INTO threat_reports (title, source_type, source_name, source_url, report_type, created_at)
       SELECT 'Library report ' || lpad(g::text, 3, '0'), 'url', 'Bulk source', 'https://bulk.example/' || g,
              CASE WHEN g % 2 = 1 THEN 'threat_report' ELSE 'blog' END,
              NOW() - (g * INTERVAL '1 minute')
       FROM generate_series(1, 157) AS g`
    );
    await fn(client);
  } finally {
    await client.query('ROLLBACK').catch(() => {});
    client.release();
  }
}

test('157 reports at 25 per page produce 7 pages; page 7 holds the final 7 rows', opts, async () => {
  await withLargeLibraryTx(async (client) => {
    const pages = [];
    for (let p = 1; p <= 8; p += 1) {
      pages.push(await listThreatReports(client, { limit: 25, offset: (p - 1) * 25 }));
    }
    for (const pg of pages) assert.equal(pg.total, 157);
    assert.deepEqual(pages.slice(0, 6).map((pg) => pg.items.length), [25, 25, 25, 25, 25, 25]);
    assert.equal(pages[6].items.length, 7, 'page 7 = rows 151-157');
    assert.equal(pages[7].items.length, 0, 'page 8 is past the end');
    assert.deepEqual(titles(pages[0]).slice(0, 2), ['Library report 001', 'Library report 002']);
    assert.deepEqual(titles(pages[6]), Array.from({ length: 7 }, (_, i) => `Library report ${String(151 + i).padStart(3, '0')}`));
    // Every row appears exactly once across the pages.
    const all = pages.flatMap(titles);
    assert.equal(all.length, 157);
    assert.equal(new Set(all).size, 157);
  });
});

test('filtered pagination pages over the 79 threat_report rows with the filtered COUNT', opts, async () => {
  await withLargeLibraryTx(async (client) => {
    const pages = [];
    for (let p = 1; p <= 5; p += 1) {
      pages.push(await listThreatReports(client, { search: 'threat_report', limit: 25, offset: (p - 1) * 25 }));
    }
    for (const pg of pages) assert.equal(pg.total, 79, 'total is the filtered count, not 157');
    assert.deepEqual(pages.map((pg) => pg.items.length), [25, 25, 25, 4, 0]);
    const all = pages.flatMap(titles);
    assert.equal(new Set(all).size, 79);
    for (const t of all) assert.equal(Number(t.slice(-3)) % 2, 1, `${t} is a threat_report row`);
    // A different filter paginates independently.
    const blog = await listThreatReports(client, { search: 'blog', limit: 25, offset: 75 });
    assert.equal(blog.total, 78);
    assert.equal(blog.items.length, 3);
  });
});

test.after(async () => {
  await pool.end().catch(() => {});
});
