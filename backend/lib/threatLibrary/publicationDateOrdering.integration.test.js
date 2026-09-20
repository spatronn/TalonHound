import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { getIocThreatContext, createThreatReport, updateReportPublicationDate, updateReportStatus, getReportById } from './store.js';
import { loadIocThreatContext } from './iocThreatContext.js';

/**
 * Real-Postgres integration test for the Threat Context chronology rule and
 * the publication-date persistence semantics (migration 026).
 *
 * Ordering rule (store.getIocThreatContext):
 *   ORDER BY published_at DESC NULLS LAST, created_at DESC
 * i.e. newest PUBLICATION first; a report whose publication date is unknown
 * comes after every dated report and falls back to import order.
 *
 * Every test runs inside a rolled-back transaction. Skips cleanly when no
 * database is reachable (local dev without a DB).
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
  await pool.query('SELECT published_at, published_at_source, published_at_precision, published_at_raw FROM threat_reports LIMIT 0');
  hasDb = true;
} catch {
  hasDb = false;
}

const opts = { skip: hasDb ? false : 'no database available (set DB_HOST/DB_PASSWORD to run)' };
const IOC_ID = 987654321;

async function withTx(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM threat_reports');
    await fn(client);
  } finally {
    await client.query('ROLLBACK').catch(() => {});
    client.release();
  }
}

async function seedReport(client, { title, published_at, created_at, source = 'json_ld', precision = 'datetime', raw = null }) {
  const report = await createThreatReport(client, {
    title,
    source_type: 'url',
    source_name: 'seed',
    source_url: `https://seed.example/${encodeURIComponent(title)}`,
    import_status: 'ready',
    analysis_status: 'ready',
    published_at,
    published_at_source: source,
    published_at_precision: precision,
    published_at_raw: raw
  });
  await client.query('UPDATE threat_reports SET created_at = $2 WHERE id = $1', [report.id, created_at]);
  await client.query(
    `INSERT INTO threat_report_candidates (report_id, candidate_type, original_value, normalized_value, assessment, role, matched_ioc_id, matched_ioc_observable_type)
     VALUES ($1, 'domain', 'evil.example', 'evil.example', 'malicious', 'command_and_control', $2, 'domain')`,
    [report.id, IOC_ID]
  );
  return report;
}

test('threat context orders claims by publication date (newest first), not by import date', opts, async () => {
  await withTx(async (client) => {
    // Report A: published earlier, imported later.  Report B: published later, imported earlier.
    await seedReport(client, { title: 'Report A', published_at: '2026-09-15T00:00:00Z', created_at: '2026-09-20T10:00:00Z', precision: 'date', raw: '2026-09-15' });
    await seedReport(client, { title: 'Report B', published_at: '2026-09-18T00:00:00Z', created_at: '2026-09-19T10:00:00Z', precision: 'date', raw: '2026-09-18' });
    const ctx = await getIocThreatContext(client, IOC_ID);
    assert.deepEqual(ctx.claims.map((c) => c.report_title), ['Report B', 'Report A']);
    const serialized = await loadIocThreatContext(client, IOC_ID);
    assert.deepEqual(serialized.claims.map((c) => c.report.published_date), ['2026-09-18', '2026-09-15']);
    assert.deepEqual(serialized.claims.map((c) => c.report.published_at_precision), ['date', 'date']);
    assert.deepEqual(serialized.claims.map((c) => c.report.published_at_source), ['json_ld', 'json_ld']);
    // Imported stays a separate, independently exposed concept.
    assert.equal(new Date(serialized.claims[0].report.created_at).toISOString(), '2026-09-19T10:00:00.000Z');
    assert.equal(new Date(serialized.claims[1].report.created_at).toISOString(), '2026-09-20T10:00:00.000Z');
  });
});

test('unknown publication date sorts after every dated report and falls back to import order', opts, async () => {
  await withTx(async (client) => {
    await seedReport(client, { title: 'Dated old', published_at: '2026-01-05T00:00:00Z', created_at: '2026-09-21T10:00:00Z', precision: 'date' });
    await seedReport(client, { title: 'Unknown newer import', published_at: null, created_at: '2026-09-20T10:00:00Z', source: null, precision: null });
    await seedReport(client, { title: 'Unknown older import', published_at: null, created_at: '2026-09-10T10:00:00Z', source: null, precision: null });
    const ctx = await getIocThreatContext(client, IOC_ID);
    assert.deepEqual(ctx.claims.map((c) => c.report_title), ['Dated old', 'Unknown newer import', 'Unknown older import']);
    const serialized = await loadIocThreatContext(client, IOC_ID);
    assert.equal(serialized.claims[1].report.published_at, null);
    assert.equal(serialized.claims[1].report.published_date, null);
    assert.equal(serialized.claims[1].report.published_at_precision, null);
  });
});

test('date-only values persist as 00:00 UTC of the stated day and survive a status-only update (retry) untouched', opts, async () => {
  await withTx(async (client) => {
    const report = await createThreatReport(client, { title: 'Retry me', source_type: 'pdf', source_file_name: 'r.pdf' });
    assert.equal(report.published_at, null);
    await updateReportPublicationDate(client, report.id, {
      published_at: '2026-09-15T00:00:00.000Z',
      published_at_source: 'pdf_visible_date',
      published_at_precision: 'date',
      published_at_raw: 'September 15, 2026'
    });
    // A pipeline stage write (no published_at in the patch) must not clear it.
    await updateReportStatus(client, report.id, { analysis_status: 'analyzing', import_status: 'processing', clear_failure: true });
    const row = await getReportById(client, report.id);
    assert.equal(new Date(row.published_at).toISOString(), '2026-09-15T00:00:00.000Z');
    assert.equal(row.published_at_source, 'pdf_visible_date');
    assert.equal(row.published_at_precision, 'date');
    assert.equal(row.published_at_raw, 'September 15, 2026');
    // The CHECK constraints reject unknown provenance values.
    await client.query('SAVEPOINT bad');
    await assert.rejects(
      client.query('UPDATE threat_reports SET published_at_source = $2 WHERE id = $1', [report.id, 'guess']),
      /published_at_source/
    );
    await client.query('ROLLBACK TO SAVEPOINT bad');
  });
});
