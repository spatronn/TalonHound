#!/usr/bin/env node
/**
 * Label each pre-ledger report's current state as a `legacy_baseline` run.
 *
 * These reports' true first-pass identities were overwritten before the ledger
 * existed, so they never receive a first-pass record. The baseline is the
 * earliest state still available, clearly labelled, so later refreshes have an
 * exact-identity reference. Reads candidates; writes only ledger rows; idempotent.
 *
 *   node scripts/threat-library-legacy-baseline.js            (dry run: counts)
 *   node scripts/threat-library-legacy-baseline.js --apply
 */
import pg from 'pg';
import { linkedSourceProvenanceColumnSql } from '../lib/threatLibrary/indicatorMembership.js';
import { recordLegacyBaseline } from '../lib/threatLibrary/extractionRuns.js';

const apply = process.argv.includes('--apply');
const pool = new pg.Pool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

const { rows: reports } = await pool.query(
  `SELECT r.id, r.analysis_progress
     FROM threat_reports r
    WHERE r.deleted_at IS NULL
      AND r.analysis_status IN ('review_required', 'ready', 'skipped')
      AND NOT EXISTS (SELECT 1 FROM threat_report_extraction_runs x WHERE x.report_id = r.id)
    ORDER BY r.id`
);
console.log(`reports without a run: ${reports.length}${apply ? '' : ' (dry run, pass --apply to write)'}`);

let recorded = 0;
let candidates = 0;
for (const report of apply ? reports : []) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `SELECT c.*, ${linkedSourceProvenanceColumnSql('c')} FROM threat_report_candidates c WHERE c.report_id = $1 ORDER BY c.id`,
      [report.id]
    );
    const result = await recordLegacyBaseline(client, { report, candidates: rows });
    await client.query('COMMIT');
    if (result.recorded) {
      recorded += 1;
      candidates += rows.length;
    }
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error(`report ${report.id}: ${err.message}`);
    process.exitCode = 1;
  } finally {
    client.release();
  }
}
console.log(`recorded baselines: ${recorded}; candidate identities: ${candidates}`);
await pool.end();
