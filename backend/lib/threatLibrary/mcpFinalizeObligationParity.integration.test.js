/**
 * Real-Postgres: what MCP previews about finalizing a new report matches what the
 * finalize write does, and the status axes reach MCP readers.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import { createThreatReport } from './store.js';
import { finalizeReport } from './reviewService.js';
import { recordDiscoveryRun } from './iocSources/discoveryLedger.js';
import { mcpThreatLibraryFinalizeReport, mcpThreatLibraryGetWorkflowStatus } from './mcpThreatLibraryReviewService.js';

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

async function newFirstPassReport() {
  const report = await createThreatReport(pool, { title: `itest-${crypto.randomUUID()}`, source_type: 'url', analysis_status: 'review_required', import_status: 'review_required' });
  await pool.query(
    `INSERT INTO threat_report_extraction_runs (report_id, run_type, is_first_pass, contract_fingerprint, idempotency_key)
     VALUES ($1, 'initial', TRUE, 'itest', $2)`,
    [report.id, crypto.randomUUID()]
  );
  return report;
}

const ctx = { user: { role: 'analyst' } };

test('dry run and the finalize write agree on an unmet obligation', opts, async () => {
  const report = await newFirstPassReport();
  const preview = await mcpThreatLibraryFinalizeReport(pool, { report_id: report.public_id, dry_run: true }, ctx);
  assert.equal(preview.body.would_finalize, false, JSON.stringify(preview.body));
  assert.ok(preview.body.blockers.some((b) => b.code === 'finalize_obligations_unmet'));
  const write = await finalizeReport(pool, report.id, { user: ctx.user });
  assert.equal(write.code, 'finalize_obligations_unmet');

  await recordDiscoveryRun(pool, report.id, { status: 'completed' });
  const clear = await mcpThreatLibraryFinalizeReport(pool, { report_id: report.public_id, dry_run: true }, ctx);
  assert.equal(clear.body.would_finalize, true, JSON.stringify(clear.body));
});

test('workflow status carries the status axes', opts, async () => {
  const report = await newFirstPassReport();
  const res = await mcpThreatLibraryGetWorkflowStatus(pool, { report_id: report.public_id });
  assert.equal(res.body.counts.status_axes.generation, 'first_pass_recorded');
  assert.equal(res.body.counts.status_axes.package_discovery.discovery_status, 'not_recorded');
  assert.equal(res.body.gates.finalize_permitted, false);
});
