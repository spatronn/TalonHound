/**
 * Real-Postgres: finalize obligations through the single finalize write path. New
 * reports must meet them, historical reports are untouched, and an exception is an
 * administrator's reasoned, audited, append-only act.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import { finalizeReport } from './reviewService.js';
import { createThreatReport } from './store.js';
import { recordDiscoveryRun } from './iocSources/discoveryLedger.js';
import { loadObligationSnapshot, reportStatusAxes } from './reportQualityStatus.js';

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
    await pool.query('SELECT 1 FROM threat_report_finalize_exceptions LIMIT 0');
    hasDb = true;
  } catch {
    hasDb = false;
  }
}
const opts = { skip: hasDb ? false : 'set ALLOW_THREAT_LIBRARY_DB_TESTS=1 with a migrated throwaway database to run' };
test.after(() => pool.end());

const analyst = { role: 'analyst' };
const admin = { role: 'admin' };

const newReport = () => createThreatReport(pool, { title: `itest-${crypto.randomUUID()}`, source_type: 'url', analysis_status: 'review_required' });

async function withFirstPass(report) {
  await pool.query(
    `INSERT INTO threat_report_extraction_runs (report_id, run_type, is_first_pass, contract_fingerprint, idempotency_key)
     VALUES ($1, 'initial', TRUE, 'itest', $2)`,
    [report.id, crypto.randomUUID()]
  );
  return report;
}

const isFinalized = async (id) => (await pool.query(`SELECT finalized_at FROM threat_reports WHERE id = $1`, [id])).rows[0].finalized_at != null;

function auditSpy() {
  const events = [];
  return {
    events,
    auditLogInTransaction: async (client, event) => { events.push(event); },
    auditLog: async () => {},
    log: async () => {}
  };
}

test('a historical report finalizes as before: no ledger, no obligations', opts, async () => {
  const report = await newReport();
  const res = await finalizeReport(pool, report.id, { user: analyst });
  assert.equal(res.ok, true, JSON.stringify(res));
  assert.equal(await isFinalized(report.id), true);
});

test('a new report without a finished discovery pass cannot finalize, and is left unchanged', opts, async () => {
  const report = await withFirstPass(await newReport());
  const res = await finalizeReport(pool, report.id, { user: analyst });
  assert.equal(res.ok, false);
  assert.equal(res.status, 409);
  assert.equal(res.code, 'finalize_obligations_unmet');
  assert.deepEqual(res.blockers[0].obligations.map((o) => o.code), ['ioc_source_discovery_incomplete']);
  assert.equal(await isFinalized(report.id), false);
});

test('a new report that meets its obligations finalizes', opts, async () => {
  const report = await withFirstPass(await newReport());
  await recordDiscoveryRun(pool, report.id, { status: 'completed' });
  const res = await finalizeReport(pool, report.id, { user: analyst });
  assert.equal(res.ok, true, JSON.stringify(res));
  assert.equal(await isFinalized(report.id), true);
});

test('a dismissed source without a reason blocks a new report', opts, async () => {
  const report = await withFirstPass(await newReport());
  await recordDiscoveryRun(pool, report.id, { status: 'completed' });
  await pool.query(
    `INSERT INTO threat_report_ioc_sources (report_id, original_url, canonical_url, lifecycle_status)
     VALUES ($1, 'https://other.example/p.csv', 'https://other.example/p.csv', 'dismissed')`,
    [report.id]
  );
  const res = await finalizeReport(pool, report.id, { user: analyst });
  assert.equal(res.code, 'finalize_obligations_unmet');
  assert.deepEqual(res.blockers[0].obligations.map((o) => o.code), ['ioc_source_dismissed_without_evidence']);
});

test('only an administrator with a written reason can record an exception', opts, async () => {
  const report = await withFirstPass(await newReport());
  const asAnalyst = await finalizeReport(pool, report.id, { user: analyst, obligationException: { reason: 'The publisher has no package here.' } });
  assert.equal(asAnalyst.status, 403);
  const noReason = await finalizeReport(pool, report.id, { user: admin, obligationException: { reason: 'short' } });
  assert.equal(noReason.status, 400);
  assert.equal(await isFinalized(report.id), false);
});

test('an exception needs the audit log, and rolls back without it', opts, async () => {
  const report = await withFirstPass(await newReport());
  const res = await finalizeReport(pool, report.id, { user: admin, obligationException: { reason: 'The publisher has no package here.' } });
  assert.equal(res.status, 503);
  assert.equal(await isFinalized(report.id), false);
  const { rows } = await pool.query(`SELECT 1 FROM threat_report_finalize_exceptions WHERE report_id = $1`, [report.id]);
  assert.equal(rows.length, 0);
});

test('an exception is stored, audited and append-only, and shows on the status axes', opts, async () => {
  const report = await withFirstPass(await newReport());
  const audit = auditSpy();
  const res = await finalizeReport(pool, report.id, { user: admin, audit, req: null, obligationException: { reason: 'The publisher has no package here.' } });
  assert.equal(res.ok, true, JSON.stringify(res));
  assert.equal(await isFinalized(report.id), true);
  assert.equal(audit.events.length, 1);
  assert.deepEqual(audit.events[0].metadata.finalize_obligation_exception.obligations, ['ioc_source_discovery_incomplete']);

  const { rows } = await pool.query(`SELECT id, obligation_code FROM threat_report_finalize_exceptions WHERE report_id = $1`, [report.id]);
  assert.deepEqual(rows.map((r) => r.obligation_code), ['ioc_source_discovery_incomplete']);
  await assert.rejects(pool.query(`UPDATE threat_report_finalize_exceptions SET reason = 'changed the reason' WHERE id = $1`, [rows[0].id]), /append-only/);
  await assert.rejects(pool.query(`DELETE FROM threat_report_finalize_exceptions WHERE id = $1`, [rows[0].id]), /append-only/);

  const fresh = (await pool.query(`SELECT * FROM threat_reports WHERE id = $1`, [report.id])).rows[0];
  const axes = reportStatusAxes(await loadObligationSnapshot(pool, fresh));
  assert.equal(axes.finalized, true);
  assert.equal(axes.package_discovery.discovery_status, 'not_recorded', 'the exception does not rewrite what was known');
  assert.equal(axes.exceptions[0].obligation_code, 'ioc_source_discovery_incomplete');
});
