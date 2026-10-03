/**
 * Real-Postgres regression for Threat Library report tags → IOC tags.
 *
 *   Report context is not an IOC assertion: a report tag (threat_report_tags) is
 *   an IOC tag only for IOC records linked through an IOC-eligible candidate
 *   whose OWN evidence (evidence_text, occurrence heading / surrounding text)
 *   names the tag — derived at READ time. Every other report tag stays report
 *   context (report_context_tags). Direct ioc_tags rows are never written;
 *   classifications are never inherited.
 *
 * Covers add/idempotent/remove, report context vs IOC-level tags (sector /
 * theme tags such as banking / government / healthcare / espionage / phishing /
 * ransomware never spread to every IOC of the report), whole-term matching and
 * spelling equivalence in SQL, direct+report dedup, multi-report provenance,
 * report deletion, context-only / rejected candidates, search (DSL / MCP / REST),
 * MCP lookup / context / bulk serialization, CSV export, classification safety
 * and bounded query counts.
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
  other: `${MARK}-other`,
  // Report-level sector / theme context: never an IOC tag without IOC evidence.
  banking: `${MARK}-banking`,
  government: `${MARK}-government`,
  healthcare: `${MARK}-healthcare`,
  espionage: `${MARK}-espionage`,
  ransomware: `${MARK}-ransomware`
};
const SECTOR_TAGS = [T.banking, T.government, T.healthcare, T.espionage, T.phishing, T.ransomware];
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
async function link(client, reportKey, iocKey, {
  review = 'approved', assessment = 'malicious', isIoc = true, matchState = 'existing',
  evidenceText = null, occurrences = []
} = {}) {
  const i = ioc[iocKey];
  await client.query(
    `INSERT INTO threat_report_candidates
       (report_id, candidate_type, original_value, normalized_value, assessment, review_status,
        match_state, matched_ioc_id, matched_ioc_observable_type, is_ioc, evidence_text, evidence)
     VALUES ($1, 'domain', $2, $2, $3, $4, $5, $6, 'domain', $7, $8, $9::jsonb)`,
    [rep[reportKey].id, i.observable, assessment, review, matchState, i.id, isIoc,
      evidenceText ?? i.observable, JSON.stringify({ occurrences })]
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

describe('Threat Library report tags → IOC tags (real Postgres)', opts, () => {
  before(async () => {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      for (const name of Object.values(T)) await mkTag(client, name);
      for (const k of ['one', 'two', 'three', 'x', 'benign', 'rejected', 'deletedonly', 'unrelated', 'directonly', 'near']) {
        await mkIoc(client, k, { note: `${k} note` });
      }
      for (let n = 0; n < 12; n += 1) await mkIoc(client, `fill${n}`);
      await mkReport(client, 'A');
      await mkReport(client, 'B');
      await mkReport(client, 'C');
      await mkReport(client, 'F');
      // Report A → IOC one/two/three/x/near; benign is context-only, rejected was rejected.
      // Only some candidates' OWN evidence names a report tag:
      //   two   — evidence sentence names winpot;
      //   three — an occurrence (table row) names financial_sector (underscore spelling)
      //           under a heading that names atm;
      //   near  — evidence names "<atm>osphere" / "pre<winpot>": substrings, not the terms.
      await link(client, 'A', 'one');
      await link(client, 'A', 'two', { evidenceText: `${D('two')} delivers the ${T.winpot} ATM jackpotting payload.` });
      await link(client, 'A', 'three', {
        occurrences: [{
          zone: 'table',
          section_heading: `Indicators: ${T.atm} infrastructure`,
          surrounding_text: `${D('three')} | ${MARK} financial_sector | 2026-09-01`
        }]
      });
      await link(client, 'A', 'x');
      await link(client, 'A', 'near', { evidenceText: `${D('near')} ${T.atm}osphere pre${T.winpot}` });
      await link(client, 'A', 'benign', {
        review: 'context_only', assessment: 'context_only', isIoc: false, matchState: 'context_only',
        evidenceText: `${D('benign')} legitimate ${T.winpot} research portal`
      });
      await link(client, 'A', 'rejected', { review: 'rejected', evidenceText: `${D('rejected')} ${T.winpot}` });
      // Report B → IOC x, whose occurrence heading names winpot + financial-sector.
      // Report C → IOC deletedonly (C is deleted later).
      await link(client, 'B', 'x', {
        occurrences: [{ zone: 'section', section_heading: `${T.winpot} / ${T.fin} C2`, surrounding_text: D('x') }]
      });
      await link(client, 'C', 'deletedonly', { evidenceText: `${D('deletedonly')} ${T.other} ${T.winpot}` });
      for (let n = 0; n < 12; n += 1) {
        await link(client, 'F', `fill${n}`, { evidenceText: `${D(`fill${n}`)} targets the ${T.fin}` });
      }
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

  it('report-level sector / theme tags never become IOC tags without IOC evidence, but stay report context', async () => {
    for (const t of SECTOR_TAGS) await addReportTag(pool, rep.A.id, tagIds[t]);
    const before = await directTagRowCount();
    for (const k of ['one', 'two', 'three', 'x', 'near']) {
      const m = await effective(k);
      for (const t of SECTOR_TAGS) {
        assert.ok(!m.tags.includes(t), `${k} must not carry report context tag ${t}`);
        const ctx = m.report_context_tags.find((c) => c.tag === t);
        assert.ok(ctx, `${k}: report tag ${t} is still visible as report context`);
        assert.equal(ctx.ioc_evidence, false);
        assert.deepEqual(ctx.reports.map((r) => r.id), [rep.A.public_id]);
      }
    }
    // Report tags are not lost on the report itself.
    const reportTagNames = (await loadReportTags(pool, rep.A.id)).map((t) => t.name);
    for (const t of SECTOR_TAGS) assert.ok(reportTagNames.includes(t));
    // DSL / MCP / REST search do not match on report-only context.
    assert.deepEqual(await searchValues(`tag equals "${T.banking}"`), []);
    assert.equal(await directTagRowCount(), before, 'ioc_tags is never written');
    for (const t of SECTOR_TAGS) await removeReportTag(pool, rep.A.id, tagIds[t]);
  });

  it('IOC evidence (sentence, occurrence row, section heading) makes the report tag an IOC tag', async () => {
    const two = await effective('two');
    assert.deepEqual(two.tags, [T.winpot], 'evidence sentence names winpot; atm is only report context');
    assert.deepEqual(two.tag_context.find((c) => c.tag === T.winpot).sources, [
      { type: 'threat_library', report_id: rep.A.public_id, title: rep.A.title, tlp: 'clear', basis: 'ioc_evidence' }
    ]);
    assert.equal(two.tags_detail.find((t) => t.name === T.winpot).origin, 'threat_library');
    assert.deepEqual(two.report_context_tags.map((t) => [t.tag, t.ioc_evidence]), [[T.atm, false], [T.winpot, true]]);

    const three = await effective('three');
    assert.deepEqual(three.tags, [T.atm], 'occurrence section heading names atm');
  });

  it('whole-term match only: substrings of a longer word are not evidence', async () => {
    const near = await effective('near');
    assert.deepEqual(near.tags, [], `"${T.atm}osphere" / "pre${T.winpot}" do not name the tags`);
    assert.ok(near.report_context_tags.every((t) => t.ioc_evidence === false));
  });

  it('context-only, rejected and unlinked IOCs never get report tags even when their text names them', async () => {
    for (const k of ['benign', 'rejected', 'unrelated']) {
      const m = await effective(k);
      assert.deepEqual(m.tags, [], k);
      assert.deepEqual(m.report_context_tags, [], `${k}: not an IOC of the report, so no report context either`);
    }
  });

  it('explicit IOC tag is kept; a report without IOC evidence adds no provenance to it', async () => {
    const m = await effective('one');
    assert.deepEqual(m.tags, [T.clickfix, T.winpot]);
    assert.deepEqual(m.tag_context.find((c) => c.tag === T.winpot).sources, [{ type: 'direct', origin: 'manual' }]);
    assert.equal(m.tags_detail.find((t) => t.name === T.winpot).origin, 'manual');
    assert.ok(m.report_context_tags.some((t) => t.tag === T.winpot && t.ioc_evidence === false));
    await removeReportTag(pool, rep.A.id, tagIds[T.winpot]);
    assert.ok((await effective('one')).tags.includes(T.winpot), 'direct winpot survives report tag removal');
    assert.ok(!(await effective('two')).tags.includes(T.winpot), 'report-only winpot is gone');
    await addReportTag(pool, rep.A.id, tagIds[T.winpot]);
  });

  it('multiple reports: provenance lists only the reports whose IOC evidence names the tag; spelling variants match', async () => {
    await addReportTag(pool, rep.B.id, tagIds[T.winpot]);
    await addReportTag(pool, rep.B.id, tagIds[T.fin]);
    await addReportTag(pool, rep.A.id, tagIds[T.fin]);
    let m = await effective('x');
    // x: report A has no x evidence; report B's heading names winpot and financial-sector.
    assert.deepEqual(m.tags, [T.fin, T.winpot].sort());
    assert.deepEqual(m.tag_context.find((c) => c.tag === T.winpot).sources.map((s) => s.report_id), [rep.B.public_id]);
    const ctx = m.report_context_tags.find((c) => c.tag === T.winpot);
    assert.deepEqual(ctx.reports.map((r) => r.id).sort(), [rep.A.public_id, rep.B.public_id].sort());
    // three: the occurrence row says "financial_sector" — same term as tag "...-financial-sector".
    assert.ok((await effective('three')).tags.includes(T.fin), 'space / hyphen / underscore spellings are equivalent');
    await removeReportTag(pool, rep.B.id, tagIds[T.winpot]);
    m = await effective('x');
    assert.ok(!m.tags.includes(T.winpot), 'no IOC evidence left for winpot on x');
    assert.ok(m.report_context_tags.some((c) => c.tag === T.winpot), 'still report context through report A');
    await removeReportTag(pool, rep.A.id, tagIds[T.fin]);
  });

  it('report deletion removes only that report\'s tags', async () => {
    await addReportTag(pool, rep.C.id, tagIds[T.other]);
    await addReportTag(pool, rep.C.id, tagIds[T.winpot]);
    assert.deepEqual((await effective('deletedonly')).tags, [T.other, T.winpot].sort());
    const directBefore = await directTagRowCount();
    await deleteThreatReport(pool, rep.C.id);
    const gone = await effective('deletedonly');
    assert.deepEqual(gone.tags, [], 'tags from the deleted report disappear');
    assert.deepEqual(gone.report_context_tags, []);
    assert.ok((await effective('one')).tags.includes(T.winpot), 'direct winpot untouched');
    assert.ok((await effective('two')).tags.includes(T.winpot), 'report A evidence tag untouched');
    assert.equal(await directTagRowCount(), directBefore);
  });

  it('tag equals finds direct AND evidence-backed report tags and nothing else (DSL / MCP / REST)', async () => {
    const want = [D('one'), D('two')].sort();
    assert.deepEqual(await searchValues(`tag equals "${T.winpot}"`), want);
    const rest = await searchApiIocs(pool, { query: `tag equals "${T.winpot}"`, limit: 50 });
    assert.deepEqual(rest.body.items.map((x) => x.value).sort(), want);
    // Direct-only tag search unchanged.
    assert.deepEqual(await searchValues(`tag equals "${T.clickfix}"`), [D('directonly'), D('one')].sort());
    // The report tag appears in the returned item's own tags.
    const item = rest.body.items.find((x) => x.value === D('two'));
    assert.ok(item.tags.includes(T.winpot));
    assert.ok(item.tag_context.some((c) => c.tag === T.winpot));
    assert.deepEqual(await searchValues(`tag in ("${T.atm}", "${T.clickfix}")`), [D('directonly'), D('one'), D('three')].sort());
  });

  it('after removing the report tag, search stops returning report-only IOCs', async () => {
    await removeReportTag(pool, rep.A.id, tagIds[T.atm]);
    assert.deepEqual(await searchValues(`tag equals "${T.atm}"`), []);
    await addReportTag(pool, rep.A.id, tagIds[T.atm]);
    assert.deepEqual(await searchValues(`tag equals "${T.atm}"`), [D('three')]);
  });

  it('MCP lookup / get_ioc_context / bulk expose IOC tags, tag_context and report_context_tags', async () => {
    const lookup = await mcpLookupIoc(pool, { value: D('two') }, { config: CONFIG });
    assert.deepEqual(lookup.body.tags, [T.winpot]);
    assert.ok(lookup.body.tag_context.every((c) => c.sources.every((s) => s.type === 'threat_library' && s.basis === 'ioc_evidence')));
    assert.ok(lookup.body.report_context_tags.some((t) => t.tag === T.atm && t.ioc_evidence === false));
    const ctx = await mcpGetIocContext(pool, { value: D('two') }, { config: CONFIG });
    assert.deepEqual(ctx.body.tags, lookup.body.tags);
    assert.deepEqual(ctx.body.tag_context, lookup.body.tag_context);
    assert.deepEqual(ctx.body.report_context_tags, lookup.body.report_context_tags);
    assert.equal(ctx.body.tags_detail.find((t) => t.name === T.winpot).origin, 'threat_library');
    // Threat Library is listed once as an evidence source; the report link is intact.
    assert.deepEqual(ctx.body.evidence_sources.filter((e) => e.kind === 'threat_library').map((e) => e.reports.map((r) => r.id)), [[rep.A.public_id]]);
    assert.ok(ctx.body.threat_context.claims.some((c) => c.report.id === rep.A.public_id));
    const bulk = await mcpBulkLookupIocs(pool, { iocs: [D('two'), D('directonly')] }, { config: CONFIG });
    const byValue = new Map(bulk.body.existing.map((e) => [e.value, e]));
    assert.deepEqual(byValue.get(D('two')).tags, lookup.body.tags);
    assert.deepEqual(byValue.get(D('directonly')).tags, [T.clickfix]);
    assert.deepEqual(byValue.get(D('directonly')).tag_context, [{ tag: T.clickfix, sources: [{ type: 'direct', origin: 'manual' }] }]);
  });

  it('report tags never change IOC classification', async () => {
    await addReportTag(pool, rep.A.id, tagIds[T.phishing]);
    const m = await effective('one');
    assert.ok(!m.tags.includes(T.phishing), 'no IOC evidence → report context only');
    assert.deepEqual(m.classifications, ['malware'], 'classification stays intrinsic');
    assert.deepEqual((await effective('two')).classifications, [], 'no classification appears from a report tag');
    const ctx = await mcpGetIocContext(pool, { value: D('one') }, { config: CONFIG });
    assert.deepEqual(ctx.body.classifications, ['malware']);
    await removeReportTag(pool, rep.A.id, tagIds[T.phishing]);
  });

  it('IOC Details Threat Context loader lists every report tag with its IOC-evidence flag', async () => {
    await addReportTag(pool, rep.B.id, tagIds[T.winpot]);
    const rows = await loadInheritedReportTagRows(pool, [ioc.x.id]);
    const grouped = groupInheritedTagsBySeed(rows, new Map([[ioc.x.id, [ioc.x.id]]])).get(ioc.x.id);
    const winpot = grouped.find((t) => t.name === T.winpot);
    assert.deepEqual(winpot.reports.map((r) => [r.title, r.ioc_evidence]).sort(), [[rep.A.title, false], [rep.B.title, true]].sort());
    assert.equal(winpot.ioc_evidence, true);
    await removeReportTag(pool, rep.B.id, tagIds[T.winpot]);
  });

  it('CSV export tags column carries IOC tags only (one batch query)', async () => {
    const rows = await enrichExportBatch(pool, [
      { id: ioc.two.id, observable: D('two'), observable_type: 'domain' },
      { id: ioc.one.id, observable: D('one'), observable_type: 'domain' },
      { id: ioc.x.id, observable: D('x'), observable_type: 'domain' }
    ]);
    const tagsOf = (value) => rows.find((r) => r.observable === value).tags;
    assert.ok(tagsOf(D('two')).includes(T.winpot), 'evidence-backed report tag exported');
    assert.ok(!tagsOf(D('two')).includes(T.atm), 'report context tag not exported as an IOC tag');
    assert.ok(tagsOf(D('one')).includes(T.clickfix), 'direct tag exported');
    assert.equal(tagsOf(D('one')).filter((t) => t === T.winpot).length, 1, 'direct + report exported once');
    assert.ok(!tagsOf(D('x')).includes(T.winpot));
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
