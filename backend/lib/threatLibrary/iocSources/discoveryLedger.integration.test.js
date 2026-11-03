/**
 * Real-Postgres: the discovery ledger is append-only, a repository root reaches
 * "inspected" and goes no further, and nothing here touches candidates.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import { createThreatReport } from '../store.js';
import { loadSourceDiscoveryLedger, recordDiscoveryRun } from './discoveryLedger.js';
import { runIocSourceDiscoveryForReport } from './runDiscovery.js';
import { inspectIocSource } from './inspect.js';
import { loadLinkedIocSourceSummary } from './linkedSourceStatus.js';
import { dismissLinkedIocSource } from './analystActions.js';

const pool = new pg.Pool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound',
  connectionTimeoutMillis: 2000,
  max: 4
});

let hasDb = false;
if (process.env.ALLOW_THREAT_LIBRARY_DB_TESTS === '1') {
  try {
    await pool.query('SELECT 1 FROM threat_report_source_discovery_runs LIMIT 0');
    hasDb = true;
  } catch {
    hasDb = false;
  }
}
const opts = { skip: hasDb ? false : 'set ALLOW_THREAT_LIBRARY_DB_TESTS=1 with a migrated throwaway database to run' };
test.after(() => pool.end());

const newReport = (over = {}) => createThreatReport(pool, {
  title: `Vane Viper adtech ${crypto.randomUUID()}`,
  source_type: 'url',
  source_url: `https://publisher.example/blog/${crypto.randomUUID()}`,
  analysis_status: 'review_required',
  ...over
});

function githubFetch(routes) {
  return async (url) => {
    const href = String(url);
    const key = Object.keys(routes).find((k) => href.includes(k));
    if (!key) throw new Error(`not found: ${href}`);
    const body = routes[key];
    return typeof body === 'string' ? { body, contentType: 'text/csv' } : { body: JSON.stringify(body), contentType: 'application/json' };
  };
}

test('discovery records accepted and rejected references and one run', opts, async () => {
  const report = await newReport();
  const doc = {
    blocks: [
      { id: 'a', type: 'paragraph', text: 'The full IOC list is available at https://github.com/publisher/iocs/blob/main/full.csv' },
      { id: 'b', type: 'paragraph', text: 'See the vendor write-up at https://other.example/writeup for background.' }
    ]
  };
  const res = await runIocSourceDiscoveryForReport(pool, { ...report, canonical_document: doc });
  assert.equal(res.status, 'completed');
  const ledger = await loadSourceDiscoveryLedger(pool, report.id);
  assert.equal(ledger.runs.length, 1);
  assert.equal(ledger.runs[0].status, 'completed');
  const byDecision = Object.groupBy(ledger.references, (r) => r.decision);
  assert.equal(byDecision.accepted.length, 1);
  assert.ok(byDecision.accepted[0].source_public_id, 'the accepted reference names its source');
  assert.ok(byDecision.rejected.some((r) => r.url.includes('other.example') && r.rejection_reason));
});

test('a failed pass is stored as a discovery failure and analysis is not affected', opts, async () => {
  const report = await newReport();
  const res = await runIocSourceDiscoveryForReport({
    query: (sql, params) => {
      if (/FROM threat_report_artifacts/.test(sql)) throw new Error('artifact store offline');
      return pool.query(sql, params);
    }
  }, report);
  assert.equal(res.status, 'failed');
  const summary = await loadLinkedIocSourceSummary(pool, report.id);
  assert.equal(summary.package_coverage.status, 'discovery_incomplete');
});

test('ledger rows cannot be changed or deleted; deleting the report still works', opts, async () => {
  const report = await newReport();
  const run = await recordDiscoveryRun(pool, report.id, { status: 'completed' });
  await assert.rejects(pool.query(`UPDATE threat_report_source_discovery_runs SET status = 'failed' WHERE public_id = $1`, [run.public_id]), /append-only/);
  await assert.rejects(pool.query(`DELETE FROM threat_report_source_discovery_runs WHERE public_id = $1`, [run.public_id]), /append-only/);
  await pool.query(`DELETE FROM threat_reports WHERE id = $1`, [report.id]);
  const { rows } = await pool.query(`SELECT 1 FROM threat_report_source_discovery_runs WHERE public_id = $1`, [run.public_id]);
  assert.equal(rows.length, 0);
});

test('a repository root inspects to its named files and stays unapproved, with no candidates', opts, async () => {
  const report = await newReport({ title: 'Vane Viper adtech infrastructure' });
  const { rows: [source] } = await pool.query(
    `INSERT INTO threat_report_ioc_sources (report_id, original_url, canonical_url, source_type, discovery_method)
     VALUES ($1, 'https://github.com/publisher/threat-intel', 'https://github.com/publisher/threat-intel', 'github_dir', 'auto') RETURNING *`,
    [report.id]
  );
  const sha = 'a'.repeat(40);
  const fetchImpl = githubFetch({
    '/commits/HEAD': { sha },
    '/contents/indicators/csv': [
      { name: '2026-vane-viper.csv', type: 'file', path: 'indicators/csv/2026-vane-viper.csv', size: 60, sha: 'b1' },
      { name: 'hazy-hawk.csv', type: 'file', path: 'indicators/csv/hazy-hawk.csv', size: 60, sha: 'b2' }
    ],
    '/contents/indicators': [{ name: 'csv', type: 'dir', path: 'indicators/csv' }],
    '/contents/': [{ name: 'indicators', type: 'dir', path: 'indicators' }, { name: 'README.md', type: 'file', path: 'README.md', size: 10 }],
    [`${sha}/indicators/csv/2026-vane-viper.csv`]: 'indicator,type\nviper-cdn.example,domain\n'
  });
  const res = await inspectIocSource(pool, source, { fetchImpl });
  assert.equal(res.ok, true, JSON.stringify(res));

  const { rows: [after] } = await pool.query(`SELECT * FROM threat_report_ioc_sources WHERE id = $1`, [source.id]);
  assert.equal(after.lifecycle_status, 'inspected');
  assert.equal(after.approved_at, null);
  assert.equal(after.repo_revision, sha);
  assert.deepEqual(after.preview.scope.matched_files.map((f) => f.path), ['indicators/csv/2026-vane-viper.csv']);

  const { rows: files } = await pool.query(`SELECT path FROM threat_report_ioc_source_files WHERE source_id = $1`, [source.id]);
  assert.deepEqual(files.map((f) => f.path), ['indicators/csv/2026-vane-viper.csv']);
  const { rows: candidates } = await pool.query(`SELECT 1 FROM threat_report_candidates WHERE report_id = $1`, [report.id]);
  assert.equal(candidates.length, 0, 'inspection never writes candidates');

  const ledger = await loadSourceDiscoveryLedger(pool, report.id);
  assert.equal(ledger.events[0].event_type, 'inspection');
  assert.equal(ledger.events[0].outcome, 'inspected');
  assert.equal(ledger.events[0].repo_revision, sha);
  const summary = await loadLinkedIocSourceSummary(pool, report.id);
  assert.equal(summary.package_coverage.status, 'pending');
});

test('a root with nothing named for the report is unsupported, with its search recorded', opts, async () => {
  const report = await newReport({ title: 'Vane Viper adtech infrastructure' });
  const { rows: [source] } = await pool.query(
    `INSERT INTO threat_report_ioc_sources (report_id, original_url, canonical_url, source_type, discovery_method)
     VALUES ($1, 'https://github.com/publisher/other', 'https://github.com/publisher/other', 'github_dir', 'auto') RETURNING *`,
    [report.id]
  );
  const fetchImpl = githubFetch({ '/contents/': [{ name: 'all-domains.csv', type: 'file', path: 'all-domains.csv', size: 60 }] });
  const res = await inspectIocSource(pool, source, { fetchImpl });
  assert.equal(res.code, 'campaign_scope_unresolved');
  const ledger = await loadSourceDiscoveryLedger(pool, report.id);
  assert.equal(ledger.events[0].outcome, 'unsupported');
  assert.equal(ledger.events[0].evidence.file_search.files_seen, 1);
});

test('dismissing a source stores the reason on the row and in the ledger', opts, async () => {
  const report = await newReport();
  const { rows: [source] } = await pool.query(
    `INSERT INTO threat_report_ioc_sources (report_id, original_url, canonical_url, source_type, discovery_method)
     VALUES ($1, 'https://other.example/pack.csv', 'https://other.example/pack.csv', 'csv', 'auto') RETURNING *`,
    [report.id]
  );
  const res = await dismissLinkedIocSource(pool, {
    sourcePublicId: source.public_id,
    report,
    actor: { publicId: null, role: 'analyst' },
    reason: 'This CSV belongs to a different campaign of the same publisher.',
    audit: null,
    req: null
  });
  assert.equal(res.ok, true, JSON.stringify(res));
  assert.match(res.source.dismissal_reason, /different campaign/);
  const ledger = await loadSourceDiscoveryLedger(pool, report.id);
  assert.equal(ledger.events[0].event_type, 'dismissal');
  assert.match(ledger.events[0].detail, /different campaign/);
});
