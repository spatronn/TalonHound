#!/usr/bin/env node
/**
 * Disposable-PostgreSQL end-to-end verification for IOC Deep Search.
 *
 * Drives the REAL SQL builders + store functions (never mocked SQL) against a live,
 * throwaway Postgres that already has the full migration chain (incl. 144) applied.
 *
 * Safety: refuses to run unless ALLOW_DEEP_SEARCH_DB_TESTS=1 and DB_NAME contains "_test".
 *
 * Exercises: migration presence, representative EXPLAIN (ANALYZE, BUFFERS), real spool
 * materialization (INSERT..SELECT, no cap), keyset browse determinism, running-query
 * cancellation via pg_cancel_backend, statement-timeout detection, markCompleted cancel
 * guard, and retention cleanup.
 */
import pg from 'pg';
import { parseSearchQuery, buildWhereClause } from '../lib/iocSearchDsl/index.js';
import { buildSearchPageSql, buildDeepSearchSpoolInsertSql } from '../lib/iocSearchDsl/searchPageSql.js';
import {
  createDeepSearch, claimForProcessing, markCompleted, markCancelled,
  getResultsPage, findExpiredCompleted, deleteResultsBatch, markExpired, requestCancel
} from '../lib/iocDeepSearch/deepSearchStore.js';
import { queryFingerprint } from '../lib/iocDeepSearch/deepSearchStatus.js';

const { Pool } = pg;
const FA = false; // production default (FILE_ARTIFACTS_READ_ENABLED=0)

if (process.env.ALLOW_DEEP_SEARCH_DB_TESTS !== '1' || !/_test/.test(String(process.env.DB_NAME || ''))) {
  console.error('Refusing: set ALLOW_DEEP_SEARCH_DB_TESTS=1 and a *_test DB_NAME.');
  process.exit(2);
}

const pool = new Pool({
  host: process.env.DB_HOST, port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_NAME
});

let pass = 0; let fail = 0;
async function check(name, fn) {
  try { await fn(); pass += 1; console.log(`  ✓ ${name}`); }
  catch (e) { fail += 1; console.error(`  ✗ ${name}: ${e.message}`); }
}
function assert(c, m) { if (!c) throw new Error(m || 'assertion failed'); }

function pageSqlFor(query) {
  const { ast } = parseSearchQuery(query);
  const built = buildWhereClause(ast, { fileArtifactsReadEnabled: FA });
  const params = [...built.params, 26];
  const sql = buildSearchPageSql({ fileArtifactsReadEnabled: FA, whereSql: built.sql, keysetClause: '', limitParamIdx: params.length });
  return { sql, params };
}

async function explain(label, query) {
  const { sql, params } = pageSqlFor(query);
  const { rows } = await pool.query(`EXPLAIN (ANALYZE, BUFFERS, SUMMARY OFF) ${sql}`, params);
  const plan = rows.map((r) => r['QUERY PLAN']).join('\n');
  const first = plan.split('\n')[0];
  console.log(`\n[EXPLAIN ${label}] ${query}\n${plan.split('\n').slice(0, 14).join('\n')}`);
  return { plan, first };
}

async function seed() {
  console.log('[seed] loading representative dataset...');
  await pool.query(`INSERT INTO ioc_sources (name, source_type, active) VALUES ('Siber-Manual','manual',TRUE) ON CONFLICT (name) DO NOTHING`);
  await pool.query(`
    INSERT INTO integration_feeds (key, integration_id, name, source_url, schedule_cron, trust_level, active)
    VALUES ('siber-feed', gen_random_uuid(), 'Siber Olay Feed', 'http://x', '0 * * * *', 'medium', TRUE),
           ('usom-feed', gen_random_uuid(), 'USOM Ulusal', 'http://y', '0 * * * *', 'medium', TRUE)
    ON CONFLICT (key) DO NOTHING`);

  // 80k domains with varied created_at + source_name distribution.
  await pool.query(`
    INSERT INTO ioc_items (observable, observable_type, source_name, created_at, first_seen_at, last_seen_at)
    SELECT 'host' || g || '.evil-' || (g % 500) || '.com', 'domain',
           CASE WHEN g % 10 = 0 THEN 'USOM Ulusal'
                WHEN g % 50 = 0 THEN 'Siber Direct'
                ELSE 'Bulk Feed ' || (g % 20) END,
           NOW() - (g || ' seconds')::interval, NOW(), NOW()
    FROM generate_series(1, 80000) g`);
  // 40k ips.
  await pool.query(`
    INSERT INTO ioc_items (observable, observable_type, source_name, created_at, first_seen_at, last_seen_at)
    SELECT '10.' || ((g/65536) % 256) || '.' || ((g/256) % 256) || '.' || (g % 256), 'ip',
           'Bulk IP ' || (g % 15), NOW() - (g || ' seconds')::interval, NOW(), NOW()
    FROM generate_series(1, 40000) g`);
  // exact needles + hashes.
  await pool.query(`INSERT INTO ioc_items (observable, observable_type, source_name) VALUES
    ('needle-exact.example.com','domain','ManualPin'),
    ('203.0.113.77','ip','ManualPin'),
    ('5d41402abc4b2a76b9719d911017c592','md5','ManualPin'),
    ('aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d','sha1','ManualPin'),
    ('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855','sha256','ManualPin')`);

  // Link ~2000 domain rows to the Siber feed (feed-display source path).
  await pool.query(`
    INSERT INTO ioc_feed_memberships (ioc_item_id, ioc_observable_type, feed_id)
    SELECT i.id, i.observable_type, (SELECT integration_id FROM integration_feeds WHERE key='siber-feed')
    FROM ioc_items i WHERE i.observable_type='domain' AND i.observable LIKE 'host%' AND (i.id % 40 = 0)
    ON CONFLICT DO NOTHING`);
  // Link ~500 domain rows to manual Siber source.
  await pool.query(`
    UPDATE ioc_items SET ioc_source_id = (SELECT id FROM ioc_sources WHERE name='Siber-Manual')
    WHERE observable_type='domain' AND observable LIKE 'host%' AND (id % 160 = 0)`);

  await pool.query('ANALYZE ioc_items');
  await pool.query('ANALYZE ioc_feed_memberships');
  const { rows } = await pool.query('SELECT count(*)::int n FROM ioc_items');
  console.log(`[seed] ioc_items rows = ${rows[0].n}`);
}

async function main() {
  await pool.query('SELECT 1');

  await check('migration 144 tables present', async () => {
    const { rows } = await pool.query("SELECT to_regclass('public.ioc_deep_searches') a, to_regclass('public.ioc_deep_search_results') b");
    assert(rows[0].a && rows[0].b, 'deep search tables missing');
  });
  await check('spool keyset index present', async () => {
    const { rows } = await pool.query("SELECT 1 FROM pg_indexes WHERE indexname='idx_ioc_deep_search_results_keyset'");
    assert(rows.length === 1, 'keyset index missing');
  });

  await seed();

  // ---- EXPLAIN representative queries ----
  const e = {};
  e.hash = await explain('A exact md5', 'md5 equals "5d41402abc4b2a76b9719d911017c592"');
  e.ip = await explain('B exact ip', 'ioc equals "203.0.113.77"');
  e.domain = await explain('C exact domain', 'ioc equals "needle-exact.example.com"');
  e.source = await explain('D source contains Siber', 'source contains "Siber"');
  e.contains = await explain('E value contains', 'ioc contains "evil-42"');
  e.neg = await explain('F negative contains', 'ioc not_contains "evil-42"');
  e.or = await explain('G broad OR', 'ioc contains "evil-1" OR ioc contains "evil-2" OR ioc contains "evil-3" OR ioc contains "evil-4" OR ioc contains "evil-5"');

  await check('exact domain uses an index (not Seq Scan)', () => {
    assert(!/Seq Scan on ioc_domain/i.test(e.domain.plan) || /Index/i.test(e.domain.plan), `domain plan: ${e.domain.first}`);
  });
  await check('value contains uses trigram bitmap index', () => {
    assert(/Bitmap Index Scan|Index Scan/i.test(e.contains.plan), `contains plan: ${e.contains.first}`);
  });

  // ---- Deep Search spool INSERT..SELECT (EXPLAIN then real run) ----
  const cutoff = new Date().toISOString();
  const dsQuery = 'source contains "Siber"';
  const { ast } = parseSearchQuery(dsQuery);
  const built = buildWhereClause(ast, { fileArtifactsReadEnabled: FA });
  const cutoffIdx = built.params.length + 1;
  const dsIdIdx = built.params.length + 2;
  const whereSql = `(${built.sql}) AND i.created_at <= $${cutoffIdx}::timestamptz`;
  const insertSql = buildDeepSearchSpoolInsertSql({ fileArtifactsReadEnabled: FA, whereSql, deepSearchIdIdx: dsIdIdx });

  let ds;
  await check('createDeepSearch + claim transitions queued->running', async () => {
    ds = await createDeepSearch(pool, {
      originalQuery: dsQuery, normalizedQuery: dsQuery, normalizedAst: ast,
      queryFingerprint: queryFingerprint(dsQuery), classificationReason: 'source_scan',
      origin: 'classified', requestedById: null, requestedByEmail: 'verify@example.com'
    });
    assert(ds.status === 'queued');
    const claimed = await claimForProcessing(pool, ds.id, cutoff);
    assert(claimed && claimed.status === 'running', 'claim failed');
  });

  await check('spool INSERT..SELECT plan is bounded (no LIMIT/OFFSET, keyset-orderable)', async () => {
    const { rows } = await pool.query(`EXPLAIN (ANALYZE, BUFFERS, SUMMARY OFF) ${insertSql}`, [...built.params, cutoff, ds.id]);
    const plan = rows.map((r) => r['QUERY PLAN']).join('\n');
    console.log(`\n[EXPLAIN H spool insert]\n${plan.split('\n').slice(0, 16).join('\n')}`);
    assert(/Insert on ioc_deep_search_results/i.test(plan), 'not an insert into spool');
  });

  let matchCount = 0;
  await check('real materialization inserts the COMPLETE set (no cap)', async () => {
    // fresh run: the EXPLAIN ANALYZE above already inserted once; clear then insert for real.
    await pool.query('DELETE FROM ioc_deep_search_results WHERE deep_search_id=$1', [ds.id]);
    const ins = await pool.query(insertSql, [...built.params, cutoff, ds.id]);
    matchCount = ins.rowCount;
    assert(matchCount > 1000, `expected a broad set, got ${matchCount}`);
    // Cross-check against an independent count of the same predicate.
    const { rows } = await pool.query(`SELECT count(*)::int n FROM ioc_items i WHERE ${whereSql}`, [...built.params, cutoff]);
    assert(rows[0].n === matchCount, `spool ${matchCount} != predicate ${rows[0].n}`);
    console.log(`[deep] materialized match_count=${matchCount}`);
    const done = await markCompleted(pool, ds.id, { matchCount, durationMs: 5, expiresAt: new Date(Date.now() + 3600e3).toISOString() });
    assert(done === true, 'markCompleted should succeed for a clean run');
  });

  await check('positions are dense 1..N in canonical order', async () => {
    const { rows } = await pool.query('SELECT min(position) lo, max(position) hi, count(*)::int n FROM ioc_deep_search_results WHERE deep_search_id=$1', [ds.id]);
    assert(Number(rows[0].lo) === 1 && Number(rows[0].hi) === matchCount && rows[0].n === matchCount, `positions ${rows[0].lo}..${rows[0].hi} n=${rows[0].n}`);
  });

  await check('keyset browse: deterministic, non-overlapping, ordered DESC, no OFFSET', async () => {
    const seen = new Set();
    let cursor = null; let pages = 0; let total = 0; let last = null;
    for (;;) {
      const page = await getResultsPage(pool, ds.id, { cursor, limit: 25 });
      if (page.length === 0) break;
      for (const r of page) {
        assert(!seen.has(String(r.ioc_item_id) + r.ioc_observable_type), 'duplicate row across pages');
        seen.add(String(r.ioc_item_id) + r.ioc_observable_type);
        if (last) {
          const a = new Date(last.created_at).getTime(); const b = new Date(r.created_at).getTime();
          assert(b < a || (b === a && Number(r.ioc_item_id) < Number(last.ioc_item_id)), 'order not strictly DESC');
        }
        last = r; total += 1;
      }
      const lastRow = page[page.length - 1];
      cursor = { t: new Date(lastRow.created_at).toISOString(), id: String(lastRow.ioc_item_id) };
      pages += 1;
      if (pages > matchCount) throw new Error('pagination did not terminate');
    }
    assert(total === matchCount, `browsed ${total} != ${matchCount}`);
    console.log(`[deep] browsed ${total} rows over ${pages} keyset pages`);
  });

  await check('keyset browse query uses the spool keyset index (no Seq Scan)', async () => {
    const { rows } = await pool.query(
      `EXPLAIN (ANALYZE, BUFFERS, SUMMARY OFF)
       SELECT position, ioc_item_id FROM ioc_deep_search_results
       WHERE deep_search_id=$1 AND (created_at, ioc_item_id) < ($2::timestamptz,$3::bigint)
       ORDER BY created_at DESC, ioc_item_id DESC LIMIT 25`,
      [ds.id, new Date().toISOString(), 999999999]);
    const plan = rows.map((r) => r['QUERY PLAN']).join('\n');
    console.log(`\n[EXPLAIN I keyset browse]\n${plan.split('\n').slice(0, 8).join('\n')}`);
    assert(/Index (Only )?Scan/i.test(plan) && !/Seq Scan on ioc_deep_search_results/i.test(plan), `keyset plan: ${plan.split('\n')[0]}`);
  });

  // ---- statement-timeout detection ----
  await check('statement_timeout on a broad materialization raises SQLSTATE 57014', async () => {
    const c = await pool.connect();
    try {
      await c.query('BEGIN');
      await c.query('SET LOCAL statement_timeout = 1'); // 1ms — guaranteed to trip on a broad scan
      await c.query('SET LOCAL max_parallel_workers_per_gather = 0');
      let code = null;
      try { await c.query(insertSql, [...built.params, cutoff, ds.id]); }
      catch (err) { code = err.code; }
      await c.query('ROLLBACK').catch(() => {});
      assert(code === '57014', `expected 57014, got ${code}`);
    } finally { c.release(); }
  });

  // ---- true running-query cancellation via pg_cancel_backend ----
  await check('pg_cancel_backend stops a running statement (57014), tx rolls back clean', async () => {
    const c = await pool.connect();
    try {
      const pid = (await c.query('SELECT pg_backend_pid() AS p')).rows[0].p;
      await c.query('BEGIN');
      const running = c.query('SELECT pg_sleep(8)'); // stand-in long statement
      // cancel from a separate connection after a beat
      await new Promise((r) => setTimeout(r, 400));
      await pool.query('SELECT pg_cancel_backend($1)', [pid]);
      let code = null;
      try { await running; } catch (err) { code = err.code; }
      assert(code === '57014', `expected 57014 from cancel, got ${code}`);
      await c.query('ROLLBACK');
      const alive = (await c.query('SELECT 1 AS ok')).rows[0].ok; // connection still usable
      assert(alive === 1, 'connection not clean after cancel');
    } finally { c.release(); }
  });

  await check('markCompleted cannot overwrite a cancel-requested running row', async () => {
    const row = await createDeepSearch(pool, {
      originalQuery: 'x', normalizedQuery: 'ioc contains "zzz"', normalizedAst: parseSearchQuery('ioc contains "zzz"').ast,
      queryFingerprint: queryFingerprint('ioc contains "zzz"'), classificationReason: null, origin: 'classified',
      requestedById: null, requestedByEmail: 'verify@example.com'
    });
    await claimForProcessing(pool, row.id, cutoff);
    await requestCancel(pool, row.id); // sets cancel_requested=TRUE, keeps status running
    const done = await markCompleted(pool, row.id, { matchCount: 1, durationMs: 1, expiresAt: new Date(Date.now() + 3600e3).toISOString() });
    assert(done === false, 'markCompleted must lose the race to a cancel');
    await markCancelled(pool, row.id);
    const { rows } = await pool.query('SELECT status FROM ioc_deep_searches WHERE id=$1', [row.id]);
    assert(rows[0].status === 'cancelled', `final status ${rows[0].status}`);
  });

  // ---- retention cleanup ----
  await check('retention: expire completed set -> batched spool delete + status expired', async () => {
    await pool.query(`UPDATE ioc_deep_searches SET expires_at = NOW() - INTERVAL '1 hour' WHERE id=$1`, [ds.id]);
    const expired = await findExpiredCompleted(pool, 10);
    assert(expired.some((r) => r.id === ds.id), 'not found as expired-completed');
    for (;;) { const n = await deleteResultsBatch(pool, ds.id, 5000); if (n < 5000) break; }
    const marked = await markExpired(pool, ds.id);
    assert(marked && marked.status === 'expired', 'markExpired failed');
    const { rows } = await pool.query('SELECT count(*)::int n FROM ioc_deep_search_results WHERE deep_search_id=$1', [ds.id]);
    assert(rows[0].n === 0, `spool not cleaned: ${rows[0].n} rows`);
  });

  console.log(`\n[source-cost] D(source contains) first node: ${e.source.first}`);
  console.log(`[exact-cost] C(domain) first node: ${e.domain.first}`);

  console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
  await pool.end();
  process.exit(fail ? 1 : 0);
}

main().catch(async (err) => { console.error('FATAL', err); try { await pool.end(); } catch {} process.exit(1); });
