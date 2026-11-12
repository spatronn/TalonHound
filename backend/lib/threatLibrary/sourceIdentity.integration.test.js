import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import {
  backfillReportIdentityKeys,
  canonicalizeReportUrl,
  claimReportImport,
  findExistingReportImport
} from './importIdentity.js';
import { resolveSourceIdentity } from './sourceIdentity.js';
import { claimFetchedReportIdentity } from './sourceIdentityClaim.js';
import { claimReportSourceIdentity } from './pipeline.js';
import {
  loadReportIdentitySummary,
  reconcileDuplicateReports,
  supersededReportConflict
} from './reportSupersession.js';
import { createThreatReport, getIocThreatContext, listThreatReports } from './store.js';
import { checkReportUrls } from './reportCatalog.js';
import { createAuditLogService } from '../auditLogService.js';

/**
 * Real-Postgres integration tests for logical article identity (migration
 * 056): equivalent URLs of one publisher article never become two live
 * reports, in either import order or concurrently; look-alike articles stay
 * separate; reconciliation of existing duplicates is non-destructive,
 * idempotent and atomic.
 *
 * Runs only with ALLOW_THREAT_LIBRARY_DB_TESTS=1 against a migrated throwaway
 * database (CI: "Threat Library integration tests", which fails on a skip).
 * Every row carries a random marker title and is removed afterwards.
 */

const { Pool } = pg;
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound',
  connectionTimeoutMillis: 2000,
  max: 16
});

let hasDb = false;
if (process.env.ALLOW_THREAT_LIBRARY_DB_TESTS === '1') {
  try {
    await pool.query('SELECT superseded_by_report_id FROM threat_reports LIMIT 0');
    await pool.query('SELECT identity_key FROM threat_report_identity_keys LIMIT 0');
    hasDb = true;
  } catch {
    hasDb = false;
  }
}
const opts = { skip: hasDb ? false : 'set ALLOW_THREAT_LIBRARY_DB_TESTS=1 with a migrated throwaway database to run' };
test.after(() => pool.end());

const here = path.dirname(fileURLToPath(import.meta.url));
const SECURELIST_HTML = readFileSync(path.join(here, 'fixtures/source-identity/securelist-121715-head.html'), 'utf8');

const marker = () => `itest-identity-${crypto.randomUUID()}`;
/** Unique host per test so concurrent / repeated runs never share identity keys. */
const hostFor = (tag) => `${tag.slice(-12)}.example`;

async function cleanup(tag) {
  await pool.query(
    `UPDATE threat_reports SET superseded_by_report_id = NULL, superseded_at = NULL WHERE title = $1`,
    [tag]
  );
  await pool.query(`DELETE FROM threat_reports WHERE title = $1`, [tag]);
}

async function importUrl(tag, url) {
  const canonical = canonicalizeReportUrl(url);
  return claimReportImport(pool, { kind: 'url', key: canonical }, (db) => createThreatReport(db, {
    title: tag,
    source_type: 'url',
    source_url: url,
    source_url_canonical: canonical,
    source_name: new URL(url).hostname,
    tlp: 'clear'
  }));
}

async function reportRow(id) {
  const { rows } = await pool.query('SELECT * FROM threat_reports WHERE id = $1', [id]);
  return rows[0];
}

/** The worker's post-fetch gate, exactly as pipeline.js calls it. */
async function fetched(reportId, { url, finalUrl = null, html = null }) {
  const report = await reportRow(reportId);
  return claimReportSourceIdentity(pool, report, { url, finalUrl, bodyText: html });
}

async function liveReports(tag) {
  const { rows } = await pool.query(
    `SELECT id, public_id, superseded_by_report_id FROM threat_reports
      WHERE title = $1 AND deleted_at IS NULL ORDER BY id`,
    [tag]
  );
  return { all: rows, primaries: rows.filter((r) => r.superseded_by_report_id == null) };
}

/** Securelist-shaped page for an isolated test host. */
function securelistLike(host) {
  return SECURELIST_HTML.replaceAll('https://securelist.com/', `https://${host}/`);
}

function page({ canonical, ogUrl, wpRest, shortlink, hreflang = [] } = {}) {
  return `<!doctype html><html><head>
    ${canonical ? `<link rel="canonical" href="${canonical}">` : ''}
    ${ogUrl ? `<meta property="og:url" content="${ogUrl}">` : ''}
    ${wpRest ? `<link rel="alternate" type="application/json" href="${wpRest}">` : ''}
    ${shortlink ? `<link rel="shortlink" href="${shortlink}">` : ''}
    ${hreflang.map(([l, h]) => `<link rel="alternate" hreflang="${l}" href="${h}">`).join('')}
    <title>Same title</title></head><body><p>1.2.3.4</p></body></html>`;
}

// --- Identity resolution ----------------------------------------------------------

test('(1) original URL first, /tr/ URL second: the second import returns the existing report', opts, async () => {
  const tag = marker();
  const host = hostFor(tag);
  const bare = `https://${host}/cyberstrikeai-attacks/121715/`;
  const tr = `https://${host}/tr/cyberstrikeai-attacks/121715/`;
  try {
    const first = await importUrl(tag, bare);
    assert.equal(first.duplicate, false);
    const gate = await fetched(first.report.id, { url: bare, finalUrl: tr, html: securelistLike(host) });
    assert.equal(gate.outcome, 'claimed');

    const second = await importUrl(tag, tr);
    assert.equal(second.duplicate, true, 'the redirect target is already a proven identity of the first report');
    assert.equal(Number(second.report.id), Number(first.report.id));
    // (4) repeated imports of either URL are idempotent.
    for (const u of [bare, tr, `${tr}#iocs`, `${bare}?utm_source=x`]) {
      const again = await importUrl(tag, u);
      assert.equal(again.duplicate, true, u);
      assert.equal(Number(again.report.id), Number(first.report.id));
    }
    assert.equal((await liveReports(tag)).all.length, 1);
  } finally {
    await cleanup(tag);
  }
});

test('(2) /tr/ URL first, original URL second: the second report is superseded before extraction', opts, async () => {
  const tag = marker();
  const host = hostFor(tag);
  const bare = `https://${host}/cyberstrikeai-attacks/121715/`;
  const tr = `https://${host}/tr/cyberstrikeai-attacks/121715/`;
  try {
    const first = await importUrl(tag, tr);
    assert.equal((await fetched(first.report.id, { url: tr, finalUrl: tr, html: securelistLike(host) })).outcome, 'claimed');

    // The bare URL cannot be recognised before the fetch (different submitted key).
    const second = await importUrl(tag, bare);
    assert.equal(second.duplicate, false);
    const gate = await fetched(second.report.id, { url: bare, finalUrl: tr, html: securelistLike(host) });
    assert.equal(gate.outcome, 'duplicate');
    assert.equal(Number(gate.primary.id), Number(first.report.id));
    assert.ok(gate.evidence.some((e) => e.key === `url:https://${host}/tr/cyberstrikeai-attacks/121715`));

    const dup = await reportRow(second.report.id);
    assert.equal(Number(dup.superseded_by_report_id), Number(first.report.id));
    assert.equal(dup.supersession.reason, 'source_identity');
    assert.equal(dup.source_identity.outcome, 'duplicate');

    // From now on the bare URL resolves to the primary before any fetch.
    const third = await importUrl(tag, bare);
    assert.equal(third.duplicate, true);
    assert.equal(Number(third.report.id), Number(first.report.id));

    // One logical report in the library list and the catalog URL check.
    const list = await listThreatReports(pool, { search: tag, limit: 25, offset: 0 });
    assert.deepEqual(list.items.map((r) => Number(r.id)), [Number(first.report.id)]);
    const check = await checkReportUrls(pool, [bare, tr]);
    for (const r of check.results) {
      assert.equal(r.exists, true);
      assert.equal(r.import_would_deduplicate, true);
      assert.equal(r.matched_report_id, first.report.public_id);
    }
    // The superseded row stays resolvable and names its primary.
    const summary = await loadReportIdentitySummary(pool, dup);
    assert.equal(summary.superseded_by.report_id, first.report.public_id);
    const conflict = await supersededReportConflict(pool, dup);
    assert.equal(conflict.code, 'REPORT_SUPERSEDED');
    assert.equal(conflict.primary_report_id, first.report.public_id);
    const primarySummary = await loadReportIdentitySummary(pool, await reportRow(first.report.id));
    assert.deepEqual(primarySummary.source_variants.map((v) => v.relation).sort(), ['primary', 'superseded']);
  } finally {
    await cleanup(tag);
  }
});

test('(3/26) concurrent imports + concurrent background claims of equivalent URLs leave one logical report', opts, async () => {
  const tag = marker();
  const host = hostFor(tag);
  const bare = `https://${host}/cyberstrikeai-attacks/121715/`;
  const tr = `https://${host}/tr/cyberstrikeai-attacks/121715/`;
  const html = securelistLike(host);
  try {
    const submissions = [bare, tr, `${bare}#x`, tr.toUpperCase().replace('HTTPS://', 'https://').replace(host.toUpperCase(), host), `${tr}?utm_source=feed`, bare, tr, `https://www.${host}/cyberstrikeai-attacks/121715`];
    // Each submission = import (route) followed immediately by the worker's post-fetch claim.
    await Promise.all(submissions.map(async (u) => {
      const res = await importUrl(tag, u);
      if (!res.duplicate) await fetched(res.report.id, { url: u, finalUrl: tr, html });
    }));
    const { all, primaries } = await liveReports(tag);
    assert.equal(primaries.length, 1, `exactly one logical report (rows: ${all.length})`);
    for (const r of all) {
      if (r.superseded_by_report_id != null) assert.equal(Number(r.superseded_by_report_id), Number(primaries[0].id));
    }
    // No key is owned twice (UNIQUE) and every key resolves to the primary.
    const { rows: keys } = await pool.query(
      `SELECT k.identity_key, k.report_id FROM threat_report_identity_keys k JOIN threat_reports r ON r.id = k.report_id WHERE r.title = $1`,
      [tag]
    );
    assert.equal(new Set(keys.map((k) => k.identity_key)).size, keys.length);
    const again = await importUrl(tag, bare);
    assert.equal(Number(again.report.id), Number(primaries[0].id));
  } finally {
    await cleanup(tag);
  }
});

/**
 * Pool whose clients pause right after reading identity-key owners, so two
 * claims that were NOT serialised by the advisory locks would both read "no
 * owner" and both stay primary reports.
 */
function slowOwnerReadPool() {
  return {
    async connect() {
      const client = await pool.connect();
      return {
        async query(sql, params) {
          const res = await client.query(sql, params);
          if (/FROM threat_report_identity_keys WHERE identity_key = ANY/.test(String(sql))) {
            await client.query('SELECT pg_sleep(0.25)');
          }
          return res;
        },
        release: (...a) => client.release(...a)
      };
    },
    query: (sql, params) => pool.query(sql, params)
  };
}

test('(3b) two imported reports race in the worker on a key neither owned before fetch: one is superseded', opts, async () => {
  const tag = marker();
  const host = hostFor(tag);
  const a = `https://${host}/post/one-amp/`;
  const b = `https://${host}/post/one-old/`;
  const target = `https://${host}/post/one/`;
  try {
    const ra = await importUrl(tag, a);
    const rb = await importUrl(tag, b);
    const slow = slowOwnerReadPool();
    const outcomes = await Promise.all([
      claimFetchedReportIdentity(slow, { reportId: ra.report.id, identity: resolveSourceIdentity({ submittedUrl: a, finalUrl: target }), allowSupersede: true }),
      claimFetchedReportIdentity(slow, { reportId: rb.report.id, identity: resolveSourceIdentity({ submittedUrl: b, finalUrl: target }), allowSupersede: true })
    ]);
    assert.deepEqual(outcomes.map((o) => o.outcome).sort(), ['claimed', 'duplicate']);
    assert.equal((await liveReports(tag)).primaries.length, 1);
  } finally {
    await cleanup(tag);
  }
});

test('(5/6) safe normalisation and tracking parameters dedupe before fetch; other queries do not', opts, async () => {
  const tag = marker();
  const host = hostFor(tag);
  try {
    const first = await importUrl(tag, `https://${host}/blog/post?id=7`);
    for (const u of [`HTTPS://${host.toUpperCase()}/blog/post/?id=7#top`, `https://${host}:443/blog/post?id=7&utm_campaign=x`, `https://www.${host}/blog/post?fbclid=1&id=7`]) {
      const res = await importUrl(tag, u);
      assert.equal(res.duplicate, true, u);
      assert.equal(Number(res.report.id), Number(first.report.id));
    }
    const other = await importUrl(tag, `https://${host}/blog/post?id=8`);
    assert.equal(other.duplicate, false, 'a document-selecting parameter is a different report');
  } finally {
    await cleanup(tag);
  }
});

test('(7/8) redirect and corroborated canonical aliases; (10) WordPress post id', opts, async () => {
  const tag = marker();
  const host = hostFor(tag);
  try {
    // Redirect alias.
    const r1 = await importUrl(tag, `https://${host}/2026/11/new-slug/`);
    await fetched(r1.report.id, { url: `https://${host}/2026/11/new-slug/` });
    const r2 = await importUrl(tag, `https://${host}/old-slug/`);
    assert.equal((await fetched(r2.report.id, { url: `https://${host}/old-slug/`, finalUrl: `https://${host}/2026/11/new-slug/` })).outcome, 'duplicate');

    // Canonical alias (AMP page declaring the article, corroborated by og:url).
    const art = `https://${host}/research/apt-x/`;
    const html = page({ canonical: art, ogUrl: art });
    const c1 = await importUrl(tag, art);
    await fetched(c1.report.id, { url: art, html });
    const c2 = await importUrl(tag, `https://${host}/amp/research/apt-x/`);
    assert.equal((await fetched(c2.report.id, { url: `https://${host}/amp/research/apt-x/`, html })).outcome, 'duplicate');

    // WordPress post id under two slugs.
    const w1 = await importUrl(tag, `https://${host}/blog/first-slug/`);
    await fetched(w1.report.id, { url: `https://${host}/blog/first-slug/`, html: page({ shortlink: `https://${host}/?p=4242` }) });
    const w2 = await importUrl(tag, `https://${host}/blog/renamed-slug/`);
    const g = await fetched(w2.report.id, { url: `https://${host}/blog/renamed-slug/`, html: page({ wpRest: `https://${host}/wp-json/wp/v2/posts/4242` }) });
    assert.equal(g.outcome, 'duplicate');
    assert.equal(Number(g.primary.id), Number(w1.report.id));
    assert.equal((await liveReports(tag)).primaries.length, 3);
  } finally {
    await cleanup(tag);
  }
});

test('(9) hreflang translations merge only when both documents list each other', opts, async () => {
  const tag = marker();
  const host = hostFor(tag);
  const en = `https://${host}/post-x/`;
  const de = `https://${host}/de/beitrag-x/`;
  const fr = `https://${host}/fr/article-x/`;
  try {
    const r1 = await importUrl(tag, en);
    await fetched(r1.report.id, { url: en, html: page({ hreflang: [['de', de]] }) });
    // One-sided claim: the French page lists the English one, the English page does not list it.
    const r3 = await importUrl(tag, fr);
    assert.equal((await fetched(r3.report.id, { url: fr, html: page({ hreflang: [['en', en]] }) })).outcome, 'claimed');
    // Reciprocal: the German page lists the English page and vice versa.
    const r2 = await importUrl(tag, de);
    const gate = await fetched(r2.report.id, { url: de, html: page({ hreflang: [['en', en]] }) });
    assert.equal(gate.outcome, 'duplicate');
    assert.equal(gate.evidence[0].via, 'reciprocal_hreflang');
    assert.equal((await liveReports(tag)).primaries.length, 2);
  } finally {
    await cleanup(tag);
  }
});

// --- False-positive prevention ------------------------------------------------------

test('(11-18) look-alike articles stay separate: titles, dates, IOC sets, publishers, paths, hostile canonicals', opts, async () => {
  const tag = marker();
  const host = hostFor(tag);
  const other = `other-${host}`;
  const sameBody = page({});
  try {
    const urls = [
      [`https://${host}/apt-x-energy/`, sameBody], // same title/date/IOCs as the next three
      [`https://${host}/apt-x-energy-part-2/`, sameBody], // same campaign, different article
      [`https://${other}/apt-x-energy/`, sameBody], // different publisher, same incident
      [`https://${host}/tr/campaign/121715/`, page({ wpRest: `https://${host}/wp-json/wp/v2/threat_response/121715` })],
      [`https://${host}/tr/campaign/121716/`, page({ wpRest: `https://${host}/wp-json/wp/v2/threat_response/121716` })], // similar path, different id
      // Hostile page declaring a victim article as its canonical (cross-site, corroborated).
      [`https://${other}/copy-of-apt-x/`, page({ canonical: `https://${host}/apt-x-energy/`, ogUrl: `https://${host}/apt-x-energy/` })],
      // Same-site canonical pointing at an unrelated listing page.
      [`https://${host}/apt-y/`, page({ canonical: `https://${host}/`, ogUrl: `https://${host}/` })]
    ];
    for (const [u, html] of urls) {
      const res = await importUrl(tag, u);
      assert.equal(res.duplicate, false, u);
      const gate = await fetched(res.report.id, { url: u, html });
      assert.equal(gate.outcome, 'claimed', u);
    }
    await pool.query(`UPDATE threat_reports SET published_at = '2026-11-02T08:00:00Z' WHERE title = $1`, [tag]);
    assert.equal((await liveReports(tag)).primaries.length, urls.length);
  } finally {
    await cleanup(tag);
  }
});

test('an analysed report is never superseded automatically; ambiguity across two primaries never merges', opts, async () => {
  const tag = marker();
  const host = hostFor(tag);
  try {
    const p = await importUrl(tag, `https://${host}/a/`);
    await fetched(p.report.id, { url: `https://${host}/a/` });
    const analysed = await importUrl(tag, `https://${host}/a-old/`);
    await pool.query(
      `INSERT INTO threat_report_candidates (report_id, candidate_type, original_value, normalized_value) VALUES ($1, 'ip', '1.2.3.4', '1.2.3.4')`,
      [analysed.report.id]
    );
    const gate = await fetched(analysed.report.id, { url: `https://${host}/a-old/`, finalUrl: `https://${host}/a/` });
    assert.equal(gate.outcome, 'conflict');
    assert.equal((await reportRow(analysed.report.id)).superseded_by_report_id, null);

    const q = await importUrl(tag, `https://${host}/b/`);
    await fetched(q.report.id, { url: `https://${host}/b/` });
    const both = await importUrl(tag, `https://${host}/both/`);
    // Redirects to /a/ while its WordPress id belongs to /b/'s report: two primaries.
    await pool.query(
      `INSERT INTO threat_report_identity_keys (report_id, identity_key, evidence, origin) VALUES ($1, $2, ARRAY['wp_post'], 'fetch')`,
      [q.report.id, `wp:${host}:77`]
    );
    const amb = await fetched(both.report.id, {
      url: `https://${host}/both/`,
      finalUrl: `https://${host}/a/`,
      html: page({ shortlink: `https://${host}/?p=77` })
    });
    assert.equal(amb.outcome, 'ambiguous');
    assert.equal((await reportRow(both.report.id)).superseded_by_report_id, null);
  } finally {
    await cleanup(tag);
  }
});

// --- Reconciliation of existing duplicates ---------------------------------------------

const IOC_A = 970000001;
const IOC_B = 970000002;

async function seedAnalysedReport(tag, { url, finalUrl, finalized, decision, extraCandidate = false, iocB = IOC_B, entities = [], tags = [] }) {
  const canonical = canonicalizeReportUrl(url);
  const { rows: [r] } = await pool.query(
    `INSERT INTO threat_reports (title, source_type, source_url, source_url_canonical, source_name, import_status, analysis_status, finalized_at)
     VALUES ($1, 'url', $2, $3, 'securelist.example', $4, $4, $5) RETURNING *`,
    [tag, url, canonical, finalized ? 'ready' : 'review_required', finalized ? new Date() : null]
  );
  await pool.query(
    `INSERT INTO threat_report_artifacts (report_id, artifact_type, storage_key, source_metadata)
     VALUES ($1, 'url_fetch', $2, $3::jsonb)`,
    [r.id, `itest/${r.id}/source.html`, JSON.stringify({ url, final_url: finalUrl })]
  );
  const cands = [['md5', '09e1da2afa1216ecc55648ec8e122d2a', IOC_A], ['domain', 'fastcdn.example', iocB]];
  if (extraCandidate) cands.push(['ip', '203.0.113.9', null]);
  for (const [type, value, ioc] of cands) {
    await pool.query(
      `INSERT INTO threat_report_candidates (report_id, candidate_type, original_value, normalized_value, assessment, review_status, match_state, matched_ioc_id, matched_ioc_observable_type)
       VALUES ($1, $2, $3, $3, 'malicious', $4, $5, $6, $2)`,
      [r.id, type, value, decision, ioc ? 'existing' : 'new', ioc]
    );
  }
  for (const name of entities) {
    const { rows: [e] } = await pool.query(
      `INSERT INTO threat_entities (entity_type, name, normalized_name) VALUES ('tool', $1, $2)
       ON CONFLICT DO NOTHING RETURNING id`,
      [name, `${tag}-${name}`.toLowerCase()]
    );
    const entityId = e?.id ?? (await pool.query(`SELECT id FROM threat_entities WHERE normalized_name = $1`, [`${tag}-${name}`.toLowerCase()])).rows[0].id;
    await pool.query(`INSERT INTO threat_report_entities (report_id, entity_id) VALUES ($1, $2)`, [r.id, entityId]);
  }
  for (const name of tags) {
    const slug = `${tag}-${name}`.slice(-60);
    const { rows: [t] } = await pool.query(
      `INSERT INTO tags (name, slug, type) VALUES ($1, $1, 'threat') ON CONFLICT DO NOTHING RETURNING id`,
      [slug]
    );
    const tagId = t?.id ?? (await pool.query(`SELECT id FROM tags WHERE name = $1`, [slug])).rows[0].id;
    await pool.query(`INSERT INTO threat_report_tags (report_id, tag_id) VALUES ($1, $2)`, [r.id, tagId]);
  }
  return r;
}

async function snapshot(reportId) {
  const [cands, ents, tags, arts] = await Promise.all([
    pool.query(`SELECT id, candidate_type, normalized_value, review_status, matched_ioc_id, updated_at FROM threat_report_candidates WHERE report_id = $1 ORDER BY id`, [reportId]),
    pool.query(`SELECT entity_id FROM threat_report_entities WHERE report_id = $1 ORDER BY entity_id`, [reportId]),
    pool.query(`SELECT tag_id FROM threat_report_tags WHERE report_id = $1 ORDER BY tag_id`, [reportId]),
    pool.query(`SELECT id FROM threat_report_artifacts WHERE report_id = $1 ORDER BY id`, [reportId])
  ]);
  const r = await reportRow(reportId);
  return {
    candidates: cands.rows,
    entities: ents.rows,
    tags: tags.rows,
    artifacts: arts.rows,
    status: [r.import_status, r.analysis_status, r.finalized_at?.toISOString?.() || null]
  };
}

async function cleanupSeeded(tag) {
  await cleanup(tag);
  await pool.query(`DELETE FROM threat_entities WHERE normalized_name LIKE $1`, [`${tag.toLowerCase()}-%`]);
  await pool.query(`DELETE FROM tags WHERE name LIKE $1`, [`%${tag.slice(-20)}%`]);
  await pool.query(`DELETE FROM audit_logs WHERE entity_display = $1`, [tag]);
}

function securelistPair(tag) {
  const host = hostFor(tag);
  return {
    host,
    html: securelistLike(host),
    bare: `https://${host}/cyberstrikeai-attacks/121715/`,
    tr: `https://${host}/tr/cyberstrikeai-attacks/121715/`
  };
}

test('(19-24) reconciling the Securelist-shaped pair preserves every row, decision and reference; idempotent', opts, async () => {
  const tag = marker();
  const s = securelistPair(tag);
  const deps = { readArtifact: async () => Buffer.from(s.html) };
  const audit = createAuditLogService(pool);
  try {
    // Primary: imported first via the bare URL (301 → /tr/), finalized, decisions made.
    const primary = await seedAnalysedReport(tag, {
      url: s.bare, finalUrl: s.tr, finalized: true, decision: 'approved',
      entities: ['cyberstrikeai', 'powershell', 'sqlservr'], tags: ['llm-orchestration']
    });
    // Secondary: imported later via /tr/, pending review, fewer entities, one extra AI tag.
    const secondary = await seedAnalysedReport(tag, {
      url: s.tr, finalUrl: s.tr, finalized: false, decision: 'pending',
      entities: ['cyberstrikeai'], tags: ['llm-orchestration', 'lateral-movement']
    });
    const before = { p: await snapshot(primary.id), s: await snapshot(secondary.id) };
    const ctxBefore = await getIocThreatContext(pool, [IOC_A]);
    assert.equal(ctxBefore.claims.length, 2, 'both duplicates are IOC context before reconciliation');

    const dry = await reconcileDuplicateReports(pool, {
      primaryPublicId: primary.public_id, secondaryPublicId: secondary.public_id,
      auditLogInTransaction: audit.auditLogInTransaction, dryRun: true, deps
    });
    assert.equal(dry.status, 'dry_run');
    assert.equal((await reportRow(secondary.id)).superseded_by_report_id, null, 'dry-run writes nothing');

    const res = await reconcileDuplicateReports(pool, {
      primaryPublicId: primary.public_id, secondaryPublicId: secondary.public_id,
      auditLogInTransaction: audit.auditLogInTransaction, deps
    });
    assert.equal(res.status, 'reconciled', JSON.stringify(res.plan?.blockers));
    assert.ok(res.plan.shared_keys.some((k) => k.key === `url:https://${s.host}/tr/cyberstrikeai-attacks/121715`));
    assert.ok(res.plan.shared_keys.some((k) => k.key === `wp:${s.host}:121715`));
    assert.equal(res.plan.checks.secondary_pending_covered_by_primary, 2);
    assert.deepEqual(res.plan.secondary_only.tags.map((t) => t.replace(/^.*-(lateral-movement)$/, '$1')), ['lateral-movement']);

    // Nothing owned by either report changed: candidates, decisions, entities, tags, artifacts, status.
    assert.deepEqual(await snapshot(primary.id), before.p);
    assert.deepEqual(await snapshot(secondary.id), before.s);
    const sec = await reportRow(secondary.id);
    assert.equal(Number(sec.superseded_by_report_id), Number(primary.id));
    assert.equal(sec.supersession.reason, 'reconciliation');

    // One logical report for IOC context and the library list; old references still resolve.
    const ctxAfter = await getIocThreatContext(pool, [IOC_A]);
    assert.deepEqual(ctxAfter.claims.map((c) => c.report_public_id), [primary.public_id]);
    const list = await listThreatReports(pool, { search: tag, limit: 25, offset: 0 });
    assert.deepEqual(list.items.map((r) => r.public_id), [primary.public_id]);
    assert.equal((await loadReportIdentitySummary(pool, sec)).superseded_by.report_id, primary.public_id);
    for (const u of [s.bare, s.tr]) {
      assert.equal((await findExistingReportImport(pool, { kind: 'url', key: canonicalizeReportUrl(u) })).public_id, primary.public_id);
    }
    const { rows: audits } = await pool.query(
      `SELECT metadata FROM audit_logs WHERE action = 'threat_library.report.superseded' AND entity_id = $1`,
      [secondary.public_id]
    );
    assert.equal(audits.length, 1);
    assert.equal(audits[0].metadata.superseded_by_report_id, primary.public_id);

    // (24) Idempotent: a second run is a no-op (no second audit row, no state change).
    const again = await reconcileDuplicateReports(pool, {
      primaryPublicId: primary.public_id, secondaryPublicId: secondary.public_id,
      auditLogInTransaction: audit.auditLogInTransaction, deps
    });
    assert.equal(again.status, 'already_reconciled');
    const { rows: audits2 } = await pool.query(
      `SELECT 1 FROM audit_logs WHERE action = 'threat_library.report.superseded' AND entity_id = $1`,
      [secondary.public_id]
    );
    assert.equal(audits2.length, 1);
    assert.deepEqual(await snapshot(secondary.id), before.s);
  } finally {
    await cleanupSeeded(tag);
  }
});

test('(20/21) reconciliation refuses when the duplicate holds evidence or decisions the primary lacks', opts, async () => {
  const tag = marker();
  const s = securelistPair(tag);
  const deps = { readArtifact: async () => Buffer.from(s.html) };
  const audit = createAuditLogService(pool);
  try {
    const primary = await seedAnalysedReport(tag, { url: s.bare, finalUrl: s.tr, finalized: true, decision: 'approved' });
    const cases = [
      { name: 'extra candidate', seed: { extraCandidate: true, decision: 'pending' }, blocker: 'secondary_has_candidates_primary_lacks' },
      { name: 'different decision', seed: { decision: 'ignored' }, blocker: 'conflicting_analyst_decisions' },
      { name: 'other IOC link', seed: { decision: 'pending', iocB: 970000099 }, blocker: 'secondary_links_iocs_primary_does_not' }
    ];
    for (const c of cases) {
      const secondary = await seedAnalysedReport(tag, { url: s.tr, finalUrl: s.tr, finalized: false, ...c.seed });
      const before = await snapshot(secondary.id);
      const res = await reconcileDuplicateReports(pool, {
        primaryPublicId: primary.public_id, secondaryPublicId: secondary.public_id,
        auditLogInTransaction: audit.auditLogInTransaction, deps
      });
      assert.equal(res.status, 'blocked', c.name);
      assert.ok(res.plan.blockers.includes(c.blocker), `${c.name}: ${res.plan.blockers}`);
      assert.equal((await reportRow(secondary.id)).superseded_by_report_id, null, c.name);
      assert.deepEqual(await snapshot(secondary.id), before, c.name);
    }
    // Unrelated article (no shared identity) is refused even with identical candidates.
    const unrelated = await seedAnalysedReport(tag, { url: `https://${s.host}/other-article/`, finalUrl: `https://${s.host}/other-article/`, finalized: false, decision: 'pending' });
    const res = await reconcileDuplicateReports(pool, {
      primaryPublicId: primary.public_id, secondaryPublicId: unrelated.public_id,
      auditLogInTransaction: audit.auditLogInTransaction,
      deps: { readArtifact: async () => Buffer.from(page({})) }
    });
    assert.equal(res.status, 'blocked');
    assert.ok(res.plan.blockers.includes('no_shared_source_identity'));
  } finally {
    await cleanupSeeded(tag);
  }
});

test('(25) a failed reconciliation rolls back completely', opts, async () => {
  const tag = marker();
  const s = securelistPair(tag);
  try {
    const primary = await seedAnalysedReport(tag, { url: s.bare, finalUrl: s.tr, finalized: true, decision: 'approved' });
    const secondary = await seedAnalysedReport(tag, { url: s.tr, finalUrl: s.tr, finalized: false, decision: 'pending' });
    await assert.rejects(
      reconcileDuplicateReports(pool, {
        primaryPublicId: primary.public_id,
        secondaryPublicId: secondary.public_id,
        auditLogInTransaction: async () => { throw new Error('audit write failed'); },
        deps: { readArtifact: async () => Buffer.from(s.html) }
      }),
      /audit write failed/
    );
    const sec = await reportRow(secondary.id);
    assert.equal(sec.superseded_by_report_id, null);
    assert.equal(sec.source_identity, null);
    const { rows } = await pool.query(
      `SELECT 1 FROM threat_report_identity_keys WHERE report_id = ANY($1::bigint[]) AND origin = 'reconciliation'`,
      [[primary.id, secondary.id]]
    );
    assert.equal(rows.length, 0);
  } finally {
    await cleanupSeeded(tag);
  }
});

test('migrate backfill of submitted identity keys is idempotent and never takes a key twice', opts, async () => {
  const tag = marker();
  const host = hostFor(tag);
  try {
    const url = `https://${host}/historical/`;
    const ids = [];
    for (let i = 0; i < 2; i += 1) {
      const { rows: [r] } = await pool.query(
        `INSERT INTO threat_reports (title, source_type, source_url, source_url_canonical, created_at)
         VALUES ($1, 'url', $2, $3, NOW() - ($4 || ' minutes')::interval) RETURNING id`,
        [tag, url, canonicalizeReportUrl(url), String(10 - i)]
      );
      ids.push(Number(r.id));
    }
    const first = await backfillReportIdentityKeys(pool);
    assert.ok(first.inserted >= 1);
    assert.ok(first.conflicts.some((c) => c.report_id === ids[1] && c.owner_report_id === ids[0]), 'the oldest historical duplicate keeps the key');
    const { rows } = await pool.query(`SELECT report_id FROM threat_report_identity_keys WHERE identity_key = $1`, [`url:https://${host}/historical`]);
    assert.deepEqual(rows.map((r) => Number(r.report_id)), [ids[0]]);
    const second = await backfillReportIdentityKeys(pool);
    assert.equal(second.conflicts.filter((c) => c.report_id === ids[1]).length, 1, 'reported again, never merged');
    assert.equal((await pool.query(`SELECT 1 FROM threat_report_identity_keys WHERE identity_key = $1`, [`url:https://${host}/historical`])).rows.length, 1);
  } finally {
    await cleanup(tag);
  }
});

test('claimFetchedReportIdentity never supersedes a failed or deleted primary', opts, async () => {
  const tag = marker();
  const host = hostFor(tag);
  try {
    const failed = await importUrl(tag, `https://${host}/x/`);
    await pool.query(`UPDATE threat_reports SET import_status = 'failed' WHERE id = $1`, [failed.report.id]);
    const r = await importUrl(tag, `https://${host}/x-alias/`);
    const identity = resolveSourceIdentity({ submittedUrl: `https://${host}/x-alias/`, finalUrl: `https://${host}/x/` });
    const res = await claimFetchedReportIdentity(pool, { reportId: r.report.id, identity, allowSupersede: true });
    assert.equal(res.outcome, 'claimed');
    assert.ok(res.conflicts.some((c) => c.key === `url:https://${host}/x`), 'key owned by the failed report is reported, not taken');
  } finally {
    await cleanup(tag);
  }
});

// --- Explicit acceptances (Flying Eagle / EtherRAT shapes) ---------------------------

async function seedReport(tag, { url, finalUrl, finalized = true, rows = [], rels = [], sources = [] }) {
  const canonical = canonicalizeReportUrl(url);
  const { rows: [r] } = await pool.query(
    `INSERT INTO threat_reports (title, source_type, source_url, source_url_canonical, source_name, import_status, analysis_status, finalized_at)
     VALUES ($1, 'url', $2, $3, 'hunt.example', 'ready', 'ready', $4) RETURNING *`,
    [tag, url, canonical, finalized ? new Date() : null]
  );
  await pool.query(
    `INSERT INTO threat_report_artifacts (report_id, artifact_type, storage_key, source_metadata) VALUES ($1, 'url_fetch', $2, $3::jsonb)`,
    [r.id, `itest/${r.id}/source.html`, JSON.stringify({ url, final_url: finalUrl })]
  );
  for (const row of rows) {
    await pool.query(
      `INSERT INTO threat_report_candidates (report_id, candidate_type, original_value, normalized_value, assessment, review_status, match_state, matched_ioc_id, matched_ioc_observable_type, is_ioc)
       VALUES ($1, $2, $3, $3, $4, $5, $6, $7, $2, $8)`,
      [r.id, row.type, row.value, row.ioc ? 'malicious' : 'context_only', row.status, row.ioc ? 'existing' : 'context_only', row.ioc ?? null, Boolean(row.ioc)]
    );
  }
  const ent = async (name) => {
    const norm = `${tag}-${name}`.toLowerCase();
    await pool.query(`INSERT INTO threat_entities (entity_type, name, normalized_name) VALUES ('tool', $1, $2) ON CONFLICT DO NOTHING`, [name, norm]);
    return (await pool.query(`SELECT id FROM threat_entities WHERE normalized_name = $1`, [norm])).rows[0].id;
  };
  for (const [subject, object, objectCandidate] of rels) {
    if (objectCandidate) {
      const { rows: [c] } = await pool.query(
        `SELECT id FROM threat_report_candidates WHERE report_id = $1 AND normalized_value = $2`,
        [r.id, objectCandidate]
      );
      await pool.query(
        `INSERT INTO threat_relationships (report_id, subject_kind, subject_entity_id, relationship_type, object_kind, object_candidate_id)
         VALUES ($1, 'entity', $2, 'uses', 'candidate', $3)`,
        [r.id, await ent(subject), c.id]
      );
    } else {
      await pool.query(
        `INSERT INTO threat_relationships (report_id, subject_kind, subject_entity_id, relationship_type, object_kind, object_entity_id)
         VALUES ($1, 'entity', $2, 'uses', 'entity', $3)`,
        [r.id, await ent(subject), await ent(object)]
      );
    }
  }
  for (const src of sources) {
    await pool.query(
      `INSERT INTO threat_report_ioc_sources (report_id, original_url, canonical_url, lifecycle_status, extraction_status, content_hash)
       VALUES ($1, $2, $2, $3, $4, $5)`,
      [r.id, src.url, src.status || 'extracted', src.extraction || 'succeeded', src.hash ?? null]
    );
  }
  return r;
}

function huntPair(tag) {
  const host = hostFor(tag);
  const bare = `https://${host}/blog/flying-eagle-rat`;
  return { bare, www: bare.replace('://', '://www.'), html: page({ canonical: bare, ogUrl: bare }) };
}

async function reconcileWith(primary, secondary, html, accept = null, extra = {}) {
  const audit = createAuditLogService(pool);
  return reconcileDuplicateReports(pool, {
    primaryPublicId: primary.public_id,
    secondaryPublicId: secondary.public_id,
    auditLogInTransaction: audit.auditLogInTransaction,
    deps: { readArtifact: async () => Buffer.from(html) },
    accept,
    ...extra
  });
}

test('Flying Eagle shape: the same extracted linked source on both reports is not a blocker; a different one is', opts, async () => {
  const tag = marker();
  const h = huntPair(tag);
  const rows = [{ type: 'ip', value: '203.0.113.10', status: 'approved', ioc: 970000101 }];
  const pack = `https://${hostFor(tag)}/files/iocs.txt`;
  try {
    const primary = await seedReport(tag, { url: h.bare, finalUrl: h.bare, rows, sources: [{ url: pack, hash: 'a'.repeat(64) }] });
    const differentPack = await seedReport(tag, { url: h.www, finalUrl: h.www, rows, sources: [{ url: pack, hash: 'b'.repeat(64) }] });
    const blocked = await reconcileWith(primary, differentPack, h.html, null, { dryRun: true });
    assert.equal(blocked.status, 'blocked');
    assert.deepEqual(blocked.plan.blockers, ['secondary_has_live_linked_ioc_sources']);

    const samePack = await seedReport(tag, { url: h.www, finalUrl: h.www, rows, sources: [{ url: pack, hash: 'a'.repeat(64) }] });
    const before = await snapshot(samePack.id);
    const res = await reconcileWith(primary, samePack, h.html);
    assert.equal(res.status, 'reconciled', JSON.stringify(res.plan?.blockers));
    assert.deepEqual(res.plan.accepted.equivalent_linked_sources.map((x) => x.canonical_url), [pack]);
    assert.deepEqual(await snapshot(samePack.id), before);
  } finally {
    await cleanupSeeded(tag);
  }
});

test('EtherRAT shape: context rows, entity relationships and named decision conflicts need explicit, reasoned acceptance', opts, async () => {
  const tag = marker();
  const h = huntPair(tag);
  const reason = 'Later analyst decision on the primary supersedes the older context_only call';
  try {
    const primary = await seedReport(tag, {
      url: h.www,
      finalUrl: h.www,
      rows: [
        { type: 'ip', value: '198.51.100.33', status: 'approved', ioc: 970000201 },
        { type: 'url', value: 'https://c2.example/', status: 'approved', ioc: 970000202 }
      ]
    });
    const secondary = await seedReport(tag, {
      url: h.bare,
      finalUrl: h.bare,
      rows: [
        { type: 'ip', value: '198.51.100.33', status: 'context_only', ioc: 970000201 },
        { type: 'url', value: 'https://c2.example/', status: 'pending', ioc: null },
        { type: 'technical_artifact', value: 'deploy.cmd', status: 'pending' },
        { type: 'technical_artifact', value: 'cu.msi', status: 'pending' }
      ],
      rels: [['The Gentlemen', 'Sliver']]
    });
    const before = { p: await snapshot(primary.id), s: await snapshot(secondary.id) };

    const none = await reconcileWith(primary, secondary, h.html, null, { dryRun: true });
    assert.deepEqual(
      [...none.plan.blockers].sort(),
      ['conflicting_analyst_decisions', 'secondary_has_candidates_primary_lacks', 'secondary_has_relationships_primary_lacks']
    );

    const shortReason = await reconcileWith(
      primary, secondary, h.html,
      { secondaryOnlyContext: true, decisionConflicts: ['ip|198.51.100.33'], reason: 'ok' },
      { dryRun: true }
    );
    assert.ok(shortReason.plan.blockers.includes('acceptance_reason_required'));

    const contextOnly = await reconcileWith(primary, secondary, h.html, { secondaryOnlyContext: true, reason }, { dryRun: true });
    assert.deepEqual(contextOnly.plan.blockers, ['conflicting_analyst_decisions'], 'a decision conflict must be named individually');

    const res = await reconcileWith(primary, secondary, h.html, {
      secondaryOnlyContext: true,
      decisionConflicts: ['IP|198.51.100.33'],
      reason
    });
    assert.equal(res.status, 'reconciled', JSON.stringify(res.plan?.blockers));
    assert.deepEqual([...res.plan.accepted.context_candidates].sort(), ['technical_artifact|cu.msi', 'technical_artifact|deploy.cmd']);
    assert.deepEqual(res.plan.accepted.context_relationships, [{ relationship_type: 'uses', subject: 'The Gentlemen', object: 'Sliver' }]);
    assert.deepEqual(res.plan.accepted.decision_conflicts, [{ candidate: 'ip|198.51.100.33', secondary: 'context_only', primary: 'approved' }]);
    assert.equal(res.plan.accepted.reason, reason);
    // Nothing copied or changed on either report; the acceptances are recorded.
    assert.deepEqual(await snapshot(primary.id), before.p);
    assert.deepEqual(await snapshot(secondary.id), before.s);
    const sec = await reportRow(secondary.id);
    assert.equal(sec.supersession.accepted.reason, reason);
    const { rows: audits } = await pool.query(
      `SELECT metadata FROM audit_logs WHERE action = 'threat_library.report.superseded' AND entity_id = $1`,
      [secondary.public_id]
    );
    assert.equal(audits[0].metadata.accepted.decision_conflicts.length, 1);
  } finally {
    await cleanupSeeded(tag);
  }
});

test('acceptances never cover IOC links, IOC-naming relationships or conflicts where the primary has no decision', opts, async () => {
  const tag = marker();
  const h = huntPair(tag);
  const accept = { secondaryOnlyContext: true, decisionConflicts: ['ip|198.51.100.44'], reason: 'operator acceptance for the test' };
  try {
    const primary = await seedReport(tag, {
      url: h.www,
      finalUrl: h.www,
      rows: [{ type: 'ip', value: '198.51.100.44', status: 'pending', ioc: 970000301 }]
    });
    // The duplicate links an IOC the primary does not, decides a row the primary
    // left pending, and relates an entity to a candidate.
    const secondary = await seedReport(tag, {
      url: h.bare,
      finalUrl: h.bare,
      rows: [
        { type: 'ip', value: '198.51.100.44', status: 'approved', ioc: 970000301 },
        { type: 'domain', value: 'only-here.example', status: 'pending', ioc: 970000302 }
      ],
      rels: [['EtherRAT', null, 'only-here.example']]
    });
    const res = await reconcileWith(primary, secondary, h.html, accept, { dryRun: true });
    assert.equal(res.status, 'blocked');
    for (const b of ['secondary_links_iocs_primary_does_not', 'secondary_has_candidates_primary_lacks', 'conflicting_analyst_decisions', 'secondary_has_relationships_primary_lacks']) {
      assert.ok(res.plan.blockers.includes(b), `${b} in ${res.plan.blockers}`);
    }
    assert.equal((await reportRow(secondary.id)).superseded_by_report_id, null);
  } finally {
    await cleanupSeeded(tag);
  }
});
