/**
 * Real-Postgres regression for Threat Library report tags → IOC effective tags.
 *
 *   report tags (threat_report_tags) are inherited by IOC records linked to the
 *   report through an IOC-eligible candidate, at READ time. Direct ioc_tags rows
 *   are never written; classifications are never inherited.
 *
 * Covers add/idempotent/remove, one report → many IOCs, direct+inherited dedup,
 * multi-report provenance, report deletion, context-only / rejected candidates,
 * search (DSL / MCP / REST), MCP lookup / context / bulk serialization, CSV
 * export enrichment, classification safety and bounded query counts.
 *
 * Commits fixture rows (search opens its own transaction), so it only runs on a
 * disposable database (assertFileArtifactDbTestAllowed: ALLOW_FILE_ARTIFACT_DB_TESTS=1,
 * localhost, DB_NAME containing "_test"). Fixture rows are removed in `after`.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import { assertFileArtifactDbTestAllowed } from '../fileArtifacts/dbTestGuard.js';
import { addReportTag, removeReportTag, loadReportTags } from './reportTags.js';
import { loadInheritedReportTagRows, groupInheritedTagsBySeed } from './reportTagInheritance.js';
import { deleteThreatReport } from './store.js';
import { hydrateIocApiMetadata } from '../iocApiMetadata.js';
import { iocPairKey } from '../iocThreatClassifications.js';
import { mcpLookupIoc, mcpBulkLookupIocs, mcpGetIocContext, mcpSearchIocs } from '../mcpIocService.js';
import { searchApiIocs } from '../apiIocReadService.js';
import { enrichExportBatch } from '../iocSearchExport/exportRows.js';

// Disposable DB only: either the *_test localhost guard, or an explicit opt-in on an
// ephemeral CI database (THREAT_LIBRARY_TAG_ITEST=1). Fixture rows are removed in `after`.
let dbConfig = null;
try {
  dbConfig = assertFileArtifactDbTestAllowed();
} catch {
  dbConfig = process.env.THREAT_LIBRARY_TAG_ITEST === '1'
    ? {
      host: process.env.DB_HOST || 'localhost',
      port: Number(process.env.DB_PORT || 5432),
      user: process.env.DB_USER || 'talonhound',
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME || 'talonhound'
    }
    : null;
}
const pool = dbConfig ? new pg.Pool({ ...dbConfig, connectionTimeoutMillis: 3000, max: 4 }) : null;
let hasDb = false;
if (pool) {
  try {
    await pool.query('SELECT 1 FROM threat_report_tags LIMIT 0');
    hasDb = true;
  } catch {
    hasDb = false;
  }
}
const opts = { skip: hasDb ? false : 'disposable migrated test DB not available (ALLOW_FILE_ARTIFACT_DB_TESTS=1 + *_test DB)' };

const CONFIG = { valueMaxChars: 2048, bulkLookupMax: 100, searchPageMax: 50 };
const MARK = `tlt${crypto.randomBytes(5).toString('hex')}`;
const T = {
  winpot: `${MARK}-winpot`,
  atm: `${MARK}-atm`,
  fin: `${MARK}-financial-sector`,
  phishing: `${MARK}-phishing`,
  clickfix: `${MARK}-clickfix`,
  other: `${MARK}-other`
};
const D = (n) => `${MARK}-${n}.example`;
const tagIds = {};
const ioc = {};
const rep = {};

async function mkTag(client, name) {
  const { rows } = await client.query(
    `INSERT INTO tags (name, type, slug) VALUES ($1, 'threat', $1) RETURNING id`, [name]
  );
  tagIds[name] = Number(rows[0].id);
}
async function mkIoc(client, key, { confidence = 'high', note = null } = {}) {
  const { rows } = await client.query(
    `INSERT INTO ioc_items (public_id, observable, observable_type, source_name, confidence, note, created_at)
     VALUES (gen_random_uuid(), $1, 'domain', $2, $3, $4, NOW()) RETURNING id, public_id, observable, observable_type`,
    [D(key), MARK, confidence, note]
  );
  ioc[key] = { ...rows[0], id: Number(rows[0].id) };
}
async function mkReport(client, key, { importStatus = 'ready' } = {}) {
  const { rows } = await client.query(
    `INSERT INTO threat_reports (title, source_type, source_name, import_status, analysis_status)
     VALUES ($1, 'url', $2, $3, 'ready') RETURNING id, public_id, title`,
    [`${MARK} ${key} report`, MARK, importStatus]
  );
  rep[key] = { ...rows[0], id: Number(rows[0].id) };
}
async function link(client, reportKey, iocKey, { review = 'approved', assessment = 'malicious', isIoc = true, matchState = 'existing' } = {}) {
  const i = ioc[iocKey];
  await client.query(
    `INSERT INTO threat_report_candidates
       (report_id, candidate_type, original_value, normalized_value, assessment, review_status,
        match_state, matched_ioc_id, matched_ioc_observable_type, is_ioc)
     VALUES ($1, 'domain', $2, $2, $3, $4, $5, $6, 'domain', $7)`,
    [rep[reportKey].id, i.observable, assessment, review, matchState, i.id, isIoc]
  );
}
async function effective(key) {
  const i = ioc[key];
  const map = await hydrateIocApiMetadata(pool, [{ id: i.id, observable_type: 'domain' }]);
  return map.get(iocPairKey(i.id, 'domain'));
}
async function directTagRowCount() {
  const { rows } = await pool.query(
    `SELECT count(*)::int AS n FROM ioc_tags WHERE ioc_id = ANY($1::bigint[])`,
    [Object.values(ioc).map((i) => i.id)]
  );
  return rows[0].n;
}
function countingPool() {
  const counter = { n: 0 };
  return {
    counter,
    wrapped: {
      query: (...a) => { counter.n += 1; return pool.query(...a); },
      connect: async () => {
        const c = await pool.connect();
        return { query: (...a) => { counter.n += 1; return c.query(...a); }, release: () => c.release() };
      }
    }
  };
}
const searchValues = async (q) => (await mcpSearchIocs(pool, { query: q, limit: 50 }, { config: CONFIG })).body.items.map((x) => x.value).sort();

describe('Threat Library report tags → IOC effective tags (real Postgres)', opts, () => {
  before(async () => {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      for (const name of Object.values(T)) await mkTag(client, name);
      for (const k of ['one', 'two', 'three', 'x', 'benign', 'rejected', 'deletedonly', 'unrelated', 'directonly']) {
        await mkIoc(client, k, { note: `${k} note` });
      }
      for (let n = 0; n < 12; n += 1) await mkIoc(client, `fill${n}`);
      await mkReport(client, 'A');
      await mkReport(client, 'B');
      await mkReport(client, 'C');
      await mkReport(client, 'F');
      // Report A → IOC one/two/three/x; benign is context-only, rejected was rejected.
      for (const k of ['one', 'two', 'three', 'x']) await link(client, 'A', k);
      await link(client, 'A', 'benign', { review: 'context_only', assessment: 'context_only', isIoc: false, matchState: 'context_only' });
      await link(client, 'A', 'rejected', { review: 'rejected' });
      // Report B → IOC x. Report C → IOC deletedonly (C is deleted later).
      await link(client, 'B', 'x');
      await link(client, 'C', 'deletedonly');
      for (let n = 0; n < 12; n += 1) await link(client, 'F', `fill${n}`);
      // Direct tags: one has a direct winpot + clickfix, directonly has clickfix.
      for (const [k, t] of [['one', T.winpot], ['one', T.clickfix], ['directonly', T.clickfix]]) {
        await client.query(
          `INSERT INTO ioc_tags (ioc_id, ioc_observable_type, tag_id, origin) VALUES ($1, 'domain', $2, 'manual')`,
          [ioc[k].id, tagIds[t]]
        );
      }
      // IOC one's intrinsic classification is malware.
      await client.query(
        `INSERT INTO ioc_threat_classifications (ioc_id, ioc_observable_type, classification_slug) VALUES ($1, 'domain', 'malware')`,
        [ioc.one.id]
      );
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  });

  after(async () => {
    if (!pool) return;
    try {
      const reportIds = Object.values(rep).map((r) => r.id);
      const iocIds = Object.values(ioc).map((i) => i.id);
      await pool.query('DELETE FROM threat_report_tags WHERE report_id = ANY($1::bigint[])', [reportIds]);
      await pool.query('DELETE FROM threat_report_candidates WHERE report_id = ANY($1::bigint[])', [reportIds]);
      await pool.query('DELETE FROM threat_reports WHERE id = ANY($1::bigint[])', [reportIds]);
      await pool.query('DELETE FROM ioc_threat_classifications WHERE ioc_id = ANY($1::bigint[])', [iocIds]);
      await pool.query('DELETE FROM ioc_tags WHERE ioc_id = ANY($1::bigint[])', [iocIds]);
      await pool.query('DELETE FROM ioc_items WHERE source_name = $1', [MARK]);
      await pool.query('DELETE FROM tags WHERE name LIKE $1', [`${MARK}-%`]);
    } finally {
      await pool.end();
    }
  });

  it('report tag add is idempotent and remove only deletes the report↔tag row', async () => {
    assert.equal(await addReportTag(pool, rep.A.id, tagIds[T.winpot]), true);
    assert.equal(await addReportTag(pool, rep.A.id, tagIds[T.winpot]), false, 'duplicate add is a no-op');
    assert.equal(await addReportTag(pool, rep.A.id, tagIds[T.atm]), true);
    assert.deepEqual((await loadReportTags(pool, rep.A.id)).map((t) => t.name), [T.atm, T.winpot]);
    const { rows } = await pool.query('SELECT count(*)::int n FROM threat_report_tags WHERE report_id = $1', [rep.A.id]);
    assert.equal(rows[0].n, 2);
    assert.equal(await removeReportTag(pool, rep.A.id, tagIds[T.atm]), true);
    assert.equal(await removeReportTag(pool, rep.A.id, tagIds[T.atm]), false, 'duplicate remove is a no-op');
    await addReportTag(pool, rep.A.id, tagIds[T.atm]);
  });

  it('one report → every linked IOC exposes the report tags; ioc_tags is never written', async () => {
    const before = await directTagRowCount();
    for (const k of ['two', 'three', 'x']) {
      const m = await effective(k);
      assert.deepEqual(m.tags, [T.atm, T.winpot].sort(), k);
      const ctx = m.tag_context.find((c) => c.tag === T.winpot);
      assert.deepEqual(ctx.sources, [{ type: 'threat_library', report_id: rep.A.public_id, title: rep.A.title, tlp: 'clear' }]);
      assert.equal(m.tags_detail.find((t) => t.name === T.winpot).origin, 'threat_library');
    }
    assert.equal(await directTagRowCount(), before);
  });

  it('context-only, rejected and unlinked IOCs do not inherit', async () => {
    for (const k of ['benign', 'rejected', 'unrelated']) {
      assert.deepEqual((await effective(k)).tags, [], k);
    }
  });

  it('direct + inherited same tag appears once; removing the report tag keeps the direct tag', async () => {
    let m = await effective('one');
    assert.deepEqual(m.tags, [T.clickfix, T.winpot, T.atm], 'direct tags first, inherited-only after');
    assert.equal(m.tags.filter((t) => t === T.winpot).length, 1);
    const winpot = m.tag_context.find((c) => c.tag === T.winpot);
    assert.deepEqual(winpot.sources.map((s) => s.type), ['direct', 'threat_library']);
    assert.equal(m.tags_detail.find((t) => t.name === T.winpot).origin, 'manual');
    assert.ok(m.tags_detail.find((t) => t.name === T.winpot).origins.includes('threat_library'));

    await removeReportTag(pool, rep.A.id, tagIds[T.winpot]);
    m = await effective('one');
    assert.ok(m.tags.includes(T.winpot), 'direct winpot survives');
    assert.deepEqual(m.tag_context.find((c) => c.tag === T.winpot).sources, [{ type: 'direct', origin: 'manual' }]);
    assert.ok(!(await effective('two')).tags.includes(T.winpot), 'inherited-only winpot is gone');
    await addReportTag(pool, rep.A.id, tagIds[T.winpot]);
  });

  it('multiple reports: provenance lists both; removing one report keeps the tag through the other', async () => {
    await addReportTag(pool, rep.B.id, tagIds[T.winpot]);
    await addReportTag(pool, rep.B.id, tagIds[T.fin]);
    let m = await effective('x');
    assert.deepEqual(m.tags, [T.atm, T.fin, T.winpot].sort());
    assert.deepEqual(
      m.tag_context.find((c) => c.tag === T.winpot).sources.map((s) => s.report_id).sort(),
      [rep.A.public_id, rep.B.public_id].sort()
    );
    await removeReportTag(pool, rep.A.id, tagIds[T.winpot]);
    m = await effective('x');
    assert.ok(m.tags.includes(T.winpot), 'still inherited through report B');
    assert.deepEqual(m.tag_context.find((c) => c.tag === T.winpot).sources.map((s) => s.report_id), [rep.B.public_id]);
    await addReportTag(pool, rep.A.id, tagIds[T.winpot]);
  });

  it('report deletion removes only that report\'s inheritance', async () => {
    await addReportTag(pool, rep.C.id, tagIds[T.other]);
    await addReportTag(pool, rep.C.id, tagIds[T.winpot]);
    assert.deepEqual((await effective('deletedonly')).tags, [T.other, T.winpot].sort());
    const directBefore = await directTagRowCount();
    await deleteThreatReport(pool, rep.C.id);
    assert.deepEqual((await effective('deletedonly')).tags, [], 'inheritance from the deleted report disappears');
    assert.ok((await effective('one')).tags.includes(T.winpot), 'direct winpot untouched');
    assert.ok((await effective('two')).tags.includes(T.winpot), 'inheritance from report A untouched');
    assert.equal(await directTagRowCount(), directBefore);
  });

  it('tag equals finds direct AND inherited IOCs and nothing unrelated (DSL / MCP / REST)', async () => {
    const want = [D('one'), D('two'), D('three'), D('x')].sort();
    assert.deepEqual(await searchValues(`tag equals "${T.winpot}"`), want);
    const rest = await searchApiIocs(pool, { query: `tag equals "${T.winpot}"`, limit: 50 });
    assert.deepEqual(rest.body.items.map((x) => x.value).sort(), want);
    // Direct-only tag search unchanged.
    assert.deepEqual(await searchValues(`tag equals "${T.clickfix}"`), [D('directonly'), D('one')].sort());
    // Inherited tag appears in the returned items' own tags.
    const item = rest.body.items.find((x) => x.value === D('two'));
    assert.ok(item.tags.includes(T.winpot));
    assert.ok(item.tag_context.some((c) => c.tag === T.winpot));
    // `in` keeps effective semantics (NOT is deep-search only; covered by the builder unit test).
    assert.deepEqual(await searchValues(`tag in ("${T.fin}", "${T.clickfix}")`), [D('directonly'), D('one'), D('x')].sort());
  });

  it('after removing the report tag, search stops returning inherited-only IOCs', async () => {
    await removeReportTag(pool, rep.A.id, tagIds[T.atm]);
    assert.deepEqual(await searchValues(`tag equals "${T.atm}"`), []);
    await addReportTag(pool, rep.A.id, tagIds[T.atm]);
    assert.deepEqual(await searchValues(`tag equals "${T.atm}"`), [D('one'), D('two'), D('three'), D('x')].sort());
  });

  it('MCP lookup / get_ioc_context / bulk expose effective tags + tag_context', async () => {
    const lookup = await mcpLookupIoc(pool, { value: D('two') }, { config: CONFIG });
    assert.deepEqual(lookup.body.tags, [T.atm, T.winpot].sort());
    assert.ok(lookup.body.tag_context.every((c) => c.sources.every((s) => s.type === 'threat_library')));
    const ctx = await mcpGetIocContext(pool, { value: D('two') }, { config: CONFIG });
    assert.deepEqual(ctx.body.tags, lookup.body.tags);
    assert.deepEqual(ctx.body.tag_context, lookup.body.tag_context);
    assert.equal(ctx.body.tags_detail.find((t) => t.name === T.atm).origin, 'threat_library');
    const bulk = await mcpBulkLookupIocs(pool, { iocs: [D('two'), D('directonly')] }, { config: CONFIG });
    const byValue = new Map(bulk.body.existing.map((e) => [e.value, e]));
    assert.deepEqual(byValue.get(D('two')).tags, lookup.body.tags);
    assert.deepEqual(byValue.get(D('directonly')).tags, [T.clickfix]);
    assert.deepEqual(byValue.get(D('directonly')).tag_context, [{ tag: T.clickfix, sources: [{ type: 'direct', origin: 'manual' }] }]);
  });

  it('report tags never change IOC classification', async () => {
    await addReportTag(pool, rep.A.id, tagIds[T.phishing]);
    const m = await effective('one');
    assert.ok(m.tags.includes(T.phishing), 'report tag is inherited as a tag');
    assert.deepEqual(m.classifications, ['malware'], 'classification stays intrinsic');
    assert.deepEqual((await effective('two')).classifications, [], 'no classification appears from a report tag');
    const ctx = await mcpGetIocContext(pool, { value: D('one') }, { config: CONFIG });
    assert.deepEqual(ctx.body.classifications, ['malware']);
    await removeReportTag(pool, rep.A.id, tagIds[T.phishing]);
  });

  it('IOC Details endpoint loader groups provenance per tag', async () => {
    const rows = await loadInheritedReportTagRows(pool, [ioc.x.id]);
    const grouped = groupInheritedTagsBySeed(rows, new Map([[ioc.x.id, [ioc.x.id]]])).get(ioc.x.id);
    const winpot = grouped.find((t) => t.name === T.winpot);
    assert.deepEqual(winpot.reports.map((r) => r.title).sort(), [rep.A.title, rep.B.title].sort());
  });

  it('CSV export tags column carries effective tags (one batch query)', async () => {
    const rows = await enrichExportBatch(pool, [
      { id: ioc.two.id, observable: D('two'), observable_type: 'domain' },
      { id: ioc.one.id, observable: D('one'), observable_type: 'domain' }
    ]);
    const tagsOf = (value) => rows.find((r) => r.observable === value).tags;
    assert.ok(tagsOf(D('two')).includes(T.winpot), 'inherited tag exported');
    assert.ok(tagsOf(D('one')).includes(T.clickfix), 'direct tag exported');
    assert.equal(tagsOf(D('one')).filter((t) => t === T.winpot).length, 1, 'direct + inherited exported once');
  });

  it('no N+1: hydration / search query counts do not grow with the number of IOCs', async () => {
    await addReportTag(pool, rep.F.id, tagIds[T.fin]);
    const small = countingPool();
    const s1 = await mcpSearchIocs(small.wrapped, { query: `tag equals "${T.fin}"`, limit: 2 }, { config: CONFIG });
    const large = countingPool();
    const s2 = await mcpSearchIocs(large.wrapped, { query: `tag equals "${T.fin}"`, limit: 12 }, { config: CONFIG });
    assert.equal(s1.body.items.length, 2);
    assert.equal(s2.body.items.length, 12);
    assert.equal(large.counter.n, small.counter.n);
    const values = Array.from({ length: 12 }, (_, n) => D(`fill${n}`));
    const b1 = countingPool();
    await mcpBulkLookupIocs(b1.wrapped, { iocs: values.slice(0, 2) }, { config: CONFIG });
    const b2 = countingPool();
    const out = await mcpBulkLookupIocs(b2.wrapped, { iocs: values }, { config: CONFIG });
    assert.ok(out.body.existing.every((e) => e.tags.includes(T.fin)));
    assert.equal(b2.counter.n, b1.counter.n);
  });
});
