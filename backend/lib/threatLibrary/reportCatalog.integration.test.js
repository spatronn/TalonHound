import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { listReportCatalog, checkReportUrls } from './reportCatalog.js';

/**
 * Real-Postgres integration test for the Threat Library report catalog
 * (MCP threat_library_list_reports / threat_library_check_report_urls).
 * Proves on the migrated schema: newest-imported ordering, exact UTC day
 * boundaries at microsecond precision, import vs publication windows,
 * publisher / status / phase filters, keyset paging across identical
 * timestamps, URL identity matches incl. duplicates and soft-deleted rows,
 * list ↔ URL-check consistency, and that nothing is written. Each test runs
 * in a rolled-back transaction. Skips cleanly when no database is reachable.
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
  await pool.query('SELECT source_url_canonical, published_at_precision, failure_code FROM threat_reports LIMIT 0');
  hasDb = true;
} catch {
  hasDb = false;
}

const opts = { skip: hasDb ? false : 'no database available (set DB_HOST/DB_PASSWORD to run)' };

// key → row. created_at strings are exact (µs) UTC instants.
const SEED = [
  { key: 'prev_day_end', created_at: '2026-10-29T23:59:59.999999Z', source_name: 'Unit 42', url: 'https://unit42.example/prev' },
  { key: 'day_start', created_at: '2026-10-30T00:00:00.000000Z', source_name: 'Unit 42', url: 'https://unit42.example/start',
    published_at: '2025-05-01T00:00:00Z', published_at_precision: 'date' },
  { key: 'tie_a', created_at: '2026-10-30T12:00:00.123456Z', source_name: 'CrowdStrike', url: 'https://crowdstrike.example/a' },
  { key: 'tie_b', created_at: '2026-10-30T12:00:00.123456Z', source_name: 'CrowdStrike', url: 'https://crowdstrike.example/b',
    import_status: 'review_required', analysis_status: 'review_required', finalized: false },
  { key: 'tie_c', created_at: '2026-10-30T12:00:00.123456Z', source_name: 'crowdstrike blog', url: 'https://crowdstrike.example/c',
    import_status: 'failed', analysis_status: 'failed', finalized: false, failure_stage: 'fetch', failure_code: 'http_404' },
  // Same millisecond as the ties, one microsecond later: a ms-precision cursor would lose it.
  { key: 'tie_us', created_at: '2026-10-30T12:00:00.123457Z', source_name: 'CrowdStrike', url: 'https://crowdstrike.example/us' },
  { key: 'day_end', created_at: '2026-10-30T23:59:59.999999Z', source_name: 'Talos', url: 'https://talos.example/end',
    import_status: 'processing', analysis_status: 'analyzing', finalized: false },
  { key: 'next_day', created_at: '2026-10-31T00:00:00.000000Z', source_name: 'Talos', url: 'https://talos.example/next',
    published_at: '2026-10-30T09:00:00Z', published_at_precision: 'datetime' },
  // Duplicate import identity (historical, before dedup existed).
  { key: 'dup_old', created_at: '2026-09-01T00:00:00Z', source_name: 'ESET', url: 'https://eset.example/dup',
    stored_url: 'https://ESET.example/dup/' },
  { key: 'dup_new', created_at: '2026-09-02T00:00:00Z', source_name: 'ESET', url: 'https://eset.example/dup',
    import_status: 'review_required', analysis_status: 'review_required', finalized: false },
  // PDF upload: no URL at all.
  { key: 'pdf', created_at: '2026-08-01T00:00:00Z', source_type: 'pdf', source_name: null, url: null },
  // PDF uploads whose analyst-set source_url points at an article: no import
  // identity, matched only through the stored URL (same canonical form).
  { key: 'pdf_url', created_at: '2026-08-01T12:00:00Z', source_type: 'pdf', source_name: null, url: null,
    stored_url: ' https://user@Talos.example:443/end/#appendix ' },
  { key: 'pdf_other', created_at: '2026-08-01T06:00:00Z', source_type: 'pdf', source_name: null, url: null,
    stored_url: 'https://talos.example/END' },
  // Soft-deleted copy of a live identity: never listed, never matched.
  { key: 'deleted', created_at: '2026-10-30T13:00:00Z', source_name: 'Talos', url: 'https://talos.example/next', deleted: true }
];

async function seed(client) {
  const ids = new Map();
  for (const r of SEED) {
    const finalized = r.finalized !== false && !r.deleted && (r.analysis_status || 'ready') === 'ready';
    const { rows } = await client.query(
      `INSERT INTO threat_reports
         (title, source_type, source_name, source_url, source_url_canonical, import_status, analysis_status,
          failure_stage, failure_code, created_at, finalized_at, published_at, published_at_precision, deleted_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::timestamptz,
               CASE WHEN $11::boolean THEN $10::timestamptz + INTERVAL '1 hour' END, $12::timestamptz, $13,
               CASE WHEN $14::boolean THEN now() END)
       RETURNING public_id::text`,
      [
        `Report ${r.key}`, r.source_type || 'url', r.source_name, r.stored_url || r.url, r.url,
        r.import_status || 'ready', r.analysis_status || 'ready', r.failure_stage || null, r.failure_code || null,
        r.created_at, finalized, r.published_at || null, r.published_at_precision || null, Boolean(r.deleted)
      ]
    );
    ids.set(r.key, rows[0].public_id);
  }
  return ids;
}

async function withSeededTx(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Independent of pre-existing rows: a clean library inside the transaction.
    await client.query('DELETE FROM threat_reports');
    const ids = await seed(client);
    await fn(client, ids);
  } finally {
    await client.query('ROLLBACK').catch(() => {});
    client.release();
  }
}

function keysOf(ids, items) {
  const byId = new Map([...ids].map(([k, v]) => [v, k]));
  return items.map((i) => byId.get(i.report_id));
}

async function listAll(db, input) {
  const out = [];
  let cursor = input.cursor;
  for (let guard = 0; guard < 50; guard += 1) {
    const page = await listReportCatalog(db, { ...input, cursor });
    out.push(...page.items);
    if (!page.has_more) return out;
    cursor = page.next_cursor;
  }
  throw new Error('paging did not terminate');
}

test.after(async () => {
  await pool.end().catch(() => {});
});

test('latest imported first; ties break on id; deleted reports never listed', opts, async () => {
  await withSeededTx(async (db, ids) => {
    const latest = await listReportCatalog(db, { limit: 1 });
    assert.deepEqual(keysOf(ids, latest.items), ['next_day']);
    assert.equal(latest.has_more, true);

    const all = await listReportCatalog(db, { limit: 200 });
    assert.equal(all.has_more, false);
    assert.equal(all.next_cursor, null);
    assert.deepEqual(keysOf(ids, all.items), [
      'next_day', 'day_end', 'tie_us', 'tie_c', 'tie_b', 'tie_a', 'day_start', 'prev_day_end', 'dup_new', 'dup_old', 'pdf_url', 'pdf_other', 'pdf'
    ]);
    const asc = await listReportCatalog(db, { limit: 200, sort: 'imported_asc' });
    assert.deepEqual(keysOf(ids, asc.items), keysOf(ids, all.items).reverse());
  });
});

test('exact UTC day: imported_from = imported_to = day includes 00:00:00 and 23:59:59.999999 only of that day', opts, async () => {
  await withSeededTx(async (db, ids) => {
    const day = await listReportCatalog(db, { imported_from: '2026-10-30', imported_to: '2026-10-30' });
    assert.deepEqual(keysOf(ids, day.items), ['day_end', 'tie_us', 'tie_c', 'tie_b', 'tie_a', 'day_start']);
    assert.deepEqual(day.filters.imported_at, { gte: '2026-10-30T00:00:00.000Z', lt: '2026-10-31T00:00:00.000Z' });

    const range = await listReportCatalog(db, { imported_from: '2026-10-29', imported_to: '2026-10-31' });
    assert.equal(range.count, 8);
    // Timestamp bounds are inclusive.
    const window = await listReportCatalog(db, {
      imported_from: '2026-10-30T12:00:00.123Z', imported_to: '2026-10-31T00:00:00Z'
    });
    assert.deepEqual(keysOf(ids, window.items), ['next_day', 'day_end', 'tie_us', 'tie_c', 'tie_b', 'tie_a']);
  });
});

test('imported date is not the publication date', opts, async () => {
  await withSeededTx(async (db, ids) => {
    // Published on 2026-10-30 but imported on 2026-10-31.
    const pub = await listReportCatalog(db, { published_from: '2026-10-30', published_to: '2026-10-30' });
    assert.deepEqual(keysOf(ids, pub.items), ['next_day']);
    const imported = await listReportCatalog(db, { imported_from: '2026-10-30', imported_to: '2026-10-30' });
    assert.ok(!keysOf(ids, imported.items).includes('next_day'));
    // Imported 2026-10-30, published 2025-05-01 (date precision).
    const old = await listReportCatalog(db, { published_to: '2025-12-31' });
    assert.deepEqual(keysOf(ids, old.items), ['day_start']);
    assert.equal(old.items[0].published_date, '2025-05-01');
    assert.equal(old.items[0].published_at_precision, 'date');
    assert.equal(old.items[0].imported_at, '2026-10-30T00:00:00.000Z');
    // Published sort: known dates first (desc), unknown last, then import order.
    const byPub = await listAll(db, { sort: 'published_desc', limit: 3 });
    assert.deepEqual(keysOf(ids, byPub).slice(0, 3), ['next_day', 'day_start', 'day_end']);
    assert.equal(byPub.length, 13);
    const byPubAsc = await listAll(db, { sort: 'published_asc', limit: 2 });
    assert.deepEqual(keysOf(ids, byPubAsc).slice(0, 3), ['day_start', 'next_day', 'pdf']);
    assert.equal(new Set(byPubAsc.map((i) => i.report_id)).size, 13);
  });
});

test('publisher, import_status and review_phase filters', opts, async () => {
  await withSeededTx(async (db, ids) => {
    const cs = await listReportCatalog(db, { publisher: 'crowdSTRIKE' });
    assert.deepEqual(keysOf(ids, cs.items), ['tie_us', 'tie_c', 'tie_b', 'tie_a']);
    const failed = await listReportCatalog(db, { import_status: 'failed' });
    assert.deepEqual(keysOf(ids, failed.items), ['tie_c']);
    assert.equal(failed.items[0].processing_state, 'failed');
    assert.deepEqual(failed.items[0].failure, { stage: 'fetch', code: 'http_404' });
    const review = await listReportCatalog(db, { review_phase: ['review_ready'] });
    assert.deepEqual(keysOf(ids, review.items), ['tie_b', 'dup_new']);
    const open = await listReportCatalog(db, { review_phase: ['review_ready', 'preparing', 'failed'], publisher: 'talos' });
    assert.deepEqual(keysOf(ids, open.items), ['day_end']);
    const finalizedCs = await listReportCatalog(db, { review_phase: 'finalized', publisher: 'CrowdStrike' });
    assert.deepEqual(keysOf(ids, finalizedCs.items), ['tie_us', 'tie_a']);
    assert.ok(finalizedCs.items.every((i) => i.finalized && i.finalized_at));
    // No match on a wildcard character taken literally.
    assert.equal((await listReportCatalog(db, { publisher: '%' })).count, 0);
  });
});

test('stable keyset paging across identical (µs) timestamps: every page size yields the unpaged order exactly once', opts, async () => {
  await withSeededTx(async (db) => {
    for (const sort of ['imported_desc', 'imported_asc', 'published_desc', 'published_asc']) {
      const full = (await listReportCatalog(db, { sort, limit: 200 })).items.map((i) => i.report_id);
      for (const limit of [1, 2, 3, 4]) {
        const paged = (await listAll(db, { sort, limit })).map((i) => i.report_id);
        assert.deepEqual(paged, full, `${sort} limit ${limit}`);
      }
    }
    // A row inserted mid-paging with an older timestamp still appears; nothing repeats.
    const first = await listReportCatalog(db, { limit: 3 });
    await db.query(
      `INSERT INTO threat_reports (title, source_type, source_url, source_url_canonical, created_at)
       VALUES ('late', 'url', 'https://late.example/x', 'https://late.example/x', '2026-10-30T12:00:00.123456Z')`
    );
    const rest = await listAll(db, { limit: 3, cursor: first.next_cursor });
    const seen = [...first.items, ...rest].map((i) => i.report_id);
    assert.equal(new Set(seen).size, seen.length);
    assert.ok(rest.some((i) => i.title === 'late'));
  });
});

test('batch URL check: matches, misses, equivalent spellings, non-equivalent URLs, duplicates, deleted and failed', opts, async () => {
  await withSeededTx(async (db, ids) => {
    const { results, summary } = await checkReportUrls(db, [
      'https://CROWDSTRIKE.example:443/a/#x',
      'http://crowdstrike.example/a',
      'https://crowdstrike.example/A',
      'https://crowdstrike.example/a?ref=1',
      'https://eset.example/dup',
      'https://talos.example/next',
      'https://crowdstrike.example/c',
      'https://crowdstrike.example/b',
      'https://never.example/report',
      'mailto:x@example.com',
      null
    ]);
    assert.equal(results[0].matched_report_id, ids.get('tie_a'));
    assert.equal(results[0].normalized_url, 'https://crowdstrike.example/a');
    assert.deepEqual(results.slice(1, 4).map((r) => r.exists), [false, false, false]);
    // Duplicate identity → ambiguous, oldest first, stored original URL kept.
    assert.equal(results[4].ambiguous, true);
    assert.equal(results[4].matched_report_id, null);
    assert.deepEqual(results[4].matches.map((m) => m.report_id), [ids.get('dup_old'), ids.get('dup_new')]);
    assert.equal(results[4].matches[0].source_url, 'https://ESET.example/dup/');
    assert.equal(results[4].finalized, false);
    assert.equal(results[4].requires_review, true);
    // Soft-deleted copy is not a second match.
    assert.deepEqual([results[5].match_count, results[5].matched_report_id], [1, ids.get('next_day')]);
    // Failed import: exists, not processed.
    assert.deepEqual([results[6].exists, results[6].finalized, results[6].requires_further_processing], [true, false, true]);
    assert.equal(results[6].report.review_phase, 'failed');
    // Pending review: exists, not finalized.
    assert.deepEqual([results[7].exists, results[7].finalized, results[7].requires_review], [true, false, true]);
    assert.equal(results[8].exists, false);
    assert.deepEqual(results.slice(9).map((r) => [r.valid, r.invalid_reason]), [[false, 'not_http_url'], [false, 'empty']]);
    assert.deepEqual(summary, {
      queried: 11, valid: 9, invalid: 2, existing: 5, missing: 4, ambiguous: 1, finalized: 2, requiring_action: 3
    });
  });
});

test('batch URL check: the www twin of a stored report URL is the same import identity', opts, async () => {
  await withSeededTx(async (db, ids) => {
    const { results } = await checkReportUrls(db, ['https://www.crowdstrike.example/a', 'https://www.talos.example/next']);
    assert.equal(results[0].matched_report_id, ids.get('tie_a'));
    assert.equal(results[0].import_would_deduplicate, true);
    assert.equal(results[0].match_count, 1);
    assert.equal(results[1].matched_report_id, ids.get('next_day'));
  });
});

test('stored source_url of a PDF upload is matched with the import canonical form, never loosely', opts, async () => {
  await withSeededTx(async (db, ids) => {
    const { results } = await checkReportUrls(db, ['https://talos.example/end', 'https://talos.example/other', 'https://talos.example/End']);
    // URL import of the article + PDF upload of the same article: both, nothing chosen.
    assert.deepEqual([results[0].exists, results[0].ambiguous, results[0].match_count, results[0].matched_report_id],
      [true, true, 2, null]);
    assert.deepEqual(results[0].matches.map((m) => [m.report_id, m.match_basis]), [
      [ids.get('pdf_url'), 'source_url'],
      [ids.get('day_end'), 'import_identity']
    ]);
    assert.equal(results[0].import_would_deduplicate, true);
    assert.equal(results[0].matches[0].source_url, ' https://user@Talos.example:443/end/#appendix ');
    assert.equal(results[1].exists, false);
    // Path case is kept: /End matches neither /end nor the stored /END.
    assert.equal(results[2].exists, false);
    const pdfOnly = await checkReportUrls(db, ['https://TALOS.example/END']);
    assert.deepEqual([pdfOnly.results[0].matched_report_id, pdfOnly.results[0].import_would_deduplicate, pdfOnly.results[0].report.match_basis],
      [ids.get('pdf_other'), false, 'source_url']);
  });
});

test('list and URL check agree on every listed URL report', opts, async () => {
  await withSeededTx(async (db) => {
    const listed = await listAll(db, { limit: 4 });
    const urlReports = listed.filter((i) => i.source_type === 'url');
    const { results } = await checkReportUrls(db, urlReports.map((i) => i.source_url));
    urlReports.forEach((item, n) => {
      const r = results[n];
      assert.equal(r.exists, true, item.source_url);
      const match = r.matches.find((m) => m.report_id === item.report_id);
      const { match_basis: basis, ...same } = match;
      assert.equal(basis, 'import_identity');
      assert.deepEqual(same, item, 'same serialized report from both tools');
    });
  });
});

test('read-only: no report, candidate, IOC or review row changes', opts, async () => {
  await withSeededTx(async (db) => {
    const fingerprint = async () => {
      const { rows } = await db.query(
        `SELECT
           (SELECT md5(COALESCE(string_agg(t::text, '|' ORDER BY t.id), '')) FROM threat_reports t) AS reports,
           (SELECT md5(COALESCE(string_agg(c::text, '|' ORDER BY c.id), '')) FROM threat_report_candidates c) AS candidates,
           (SELECT COUNT(*) FROM threat_library_jobs) AS jobs`
      );
      return rows[0];
    };
    const before = await fingerprint();
    await listAll(db, { limit: 2 });
    await listAll(db, { sort: 'published_asc', limit: 3, review_phase: ['failed', 'review_ready'] });
    await checkReportUrls(db, ['https://crowdstrike.example/a', 'https://eset.example/dup', 'https://new.example/z']);
    assert.deepEqual(await fingerprint(), before);
  });
});
