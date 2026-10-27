import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import { createThreatReport } from './store.js';
import { applyCandidateReviewActions } from './reviewService.js';
import { bulkMatchCandidates } from './iocMatch.js';

/**
 * Real-Postgres Create IOCs for CIDR Indicators (ioc_items ip / ipv6 network
 * records). Against the migrated schema (partitioned ioc_items, the seeded
 * Threat_Library IOC source) it checks that:
 *
 *   - an approved IPv4 / IPv6 CIDR becomes one ip / ipv6 IOC whose observable
 *     keeps the canonical network and prefix (never expanded, never a host);
 *   - a host IP equal to the network address stays a separate IOC;
 *   - a network already in the catalog (an EmergingThreats-style ip row) is
 *     linked, not duplicated;
 *   - a second Create IOCs is idempotent (no new rows, links unchanged);
 *   - the catalog matcher finds the network IOCs for cidr candidates.
 *
 * ALLOW_THREAT_LIBRARY_DB_TESTS=1 with a migrated throwaway database.
 */

const config = {
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound',
  connectionTimeoutMillis: 2000,
  max: 4
};
const pool = new pg.Pool(config);

let hasDb = false;
if (process.env.ALLOW_THREAT_LIBRARY_DB_TESTS === '1') {
  try {
    await pool.query(`SELECT 1 FROM ioc_sources WHERE name = 'Threat_Library' LIMIT 1`);
    hasDb = true;
  } catch {
    hasDb = false;
  }
}
const opts = { skip: hasDb ? false : 'set ALLOW_THREAT_LIBRARY_DB_TESTS=1 with a migrated throwaway database to run' };

test.after(async () => {
  await pool.end();
});

const EV = { source_assertion: 'explicit_ioc', document_has_authoritative_scope: true };

async function insertCandidate(reportId, type, value) {
  const { rows } = await pool.query(
    `INSERT INTO threat_report_candidates (
       report_id, candidate_type, original_value, normalized_value, assessment, role, review_status,
       match_state, is_ioc, source_assertion, evidence, has_original_document_occurrence
     ) VALUES ($1,$2,$3,$3,'malicious','malicious_infrastructure','approved','new',true,'explicit_ioc',$4::jsonb,true)
     RETURNING id`,
    [reportId, type, value, JSON.stringify(EV)]
  );
  return Number(rows[0].id);
}

async function iocRows(values) {
  const { rows } = await pool.query(
    `SELECT id, observable_type, observable FROM ioc_items WHERE observable = ANY($1::text[]) ORDER BY id`,
    [values]
  );
  return rows;
}

async function cleanup(reportId, values) {
  const ids = (await iocRows(values)).map((r) => Number(r.id));
  await pool.query(`DELETE FROM threat_report_candidates WHERE report_id = $1`, [reportId]);
  await pool.query(`DELETE FROM audit_logs WHERE entity_id = (SELECT public_id::text FROM threat_reports WHERE id = $1)`, [reportId]);
  await pool.query(`DELETE FROM threat_reports WHERE id = $1`, [reportId]);
  if (ids.length) {
    await pool.query(`DELETE FROM ioc_observables WHERE ioc_public_id IN (SELECT public_id FROM ioc_items WHERE id = ANY($1::bigint[]))`, [ids]).catch(() => {});
    await pool.query(`DELETE FROM ioc_threat_classifications WHERE ioc_id = ANY($1::bigint[])`, [ids]).catch(() => {});
    await pool.query(`DELETE FROM ioc_items WHERE id = ANY($1::bigint[])`, [ids]);
  }
}

test('Create IOCs stores approved CIDR Indicators as ip / ipv6 network IOCs, links existing networks, and is idempotent', opts, async () => {
  const [a, b, c] = crypto.randomBytes(3);
  const v4 = `45.${a}.${b & 0xfc}.0/22`;
  const host = `45.${a}.${b & 0xfc}.0`;
  const existingNet = `46.${a}.${c}.0/24`;
  const v6 = `2a0c:${(a << 8 | b).toString(16)}::/32`;
  const values = [v4, host, existingNet, v6];
  const report = await createThreatReport(pool, {
    title: `itest-cidr-ioc-${crypto.randomUUID()}`,
    source_type: 'url',
    source_url: `https://vendor-research.example/${crypto.randomUUID()}`
  });
  await pool.query(`UPDATE threat_reports SET analysis_status = 'review_required', import_status = 'review_required' WHERE id = $1`, [report.id]);
  try {
    // An EmergingThreats-style network row already in the catalog.
    const { rows: [et] } = await pool.query(
      `INSERT INTO ioc_items (observable, observable_type, source_name, confidence)
       VALUES ($1, 'ip', 'itest:emerging-drop.rules', 'medium') RETURNING id`,
      [existingNet]
    );
    const ids = {
      v4: await insertCandidate(report.id, 'cidr', v4),
      host: await insertCandidate(report.id, 'ip', host),
      existing: await insertCandidate(report.id, 'cidr', existingNet),
      v6: await insertCandidate(report.id, 'cidr', v6)
    };
    const all = Object.values(ids);

    const preview = await applyCandidateReviewActions(pool, report.id, { action: 'create_iocs', candidateIds: all });
    assert.equal(preview.ok, true);
    assert.equal(preview.summary.unsupported, 0, 'no CIDR is left unsupported');
    assert.equal(preview.summary.eligible, 4);

    const run = await applyCandidateReviewActions(pool, report.id, { action: 'create_iocs', candidateIds: all, confirm: true });
    assert.equal(run.ok, true, JSON.stringify(run));
    assert.equal(run.summary.created, 3);
    assert.equal(run.summary.already_existing, 1);
    assert.equal(run.summary.failed, 0);

    const stored = await iocRows(values);
    const byValue = Object.fromEntries(stored.map((r) => [r.observable, r]));
    assert.equal(stored.length, 4, 'one IOC per identity: no host expansion, no duplicate of the existing network');
    assert.equal(byValue[v4].observable_type, 'ip');
    assert.equal(byValue[host].observable_type, 'ip');
    assert.notEqual(byValue[v4].id, byValue[host].id, 'host and network are distinct IOCs');
    assert.equal(byValue[v6].observable_type, 'ipv6');
    assert.equal(Number(byValue[existingNet].id), Number(et.id), 'existing network linked, not recreated');

    const { rows: cands } = await pool.query(
      `SELECT id, matched_ioc_id, matched_ioc_observable_type, promotion_outcome, review_status FROM threat_report_candidates WHERE report_id = $1`,
      [report.id]
    );
    const byId = Object.fromEntries(cands.map((r) => [Number(r.id), r]));
    assert.equal(Number(byId[ids.v4].matched_ioc_id), Number(byValue[v4].id));
    assert.equal(byId[ids.v4].matched_ioc_observable_type, 'ip');
    assert.equal(byId[ids.v4].promotion_outcome, 'created');
    assert.equal(Number(byId[ids.v6].matched_ioc_id), Number(byValue[v6].id));
    assert.equal(byId[ids.v6].matched_ioc_observable_type, 'ipv6');
    assert.equal(byId[ids.existing].promotion_outcome, 'already_existing');
    assert.ok(cands.every((r) => r.review_status === 'approved'), 'review state preserved');

    const again = await applyCandidateReviewActions(pool, report.id, { action: 'create_iocs', candidateIds: all, confirm: true });
    assert.equal(again.ok, true);
    assert.equal(again.summary.created, 0);
    assert.equal(again.summary.already_existing, 4);
    assert.equal((await iocRows(values)).length, 4, 'second run creates nothing');

    const matched = await bulkMatchCandidates(pool, [
      { candidate_type: 'cidr', normalized_value: v4, assessment: 'malicious', is_ioc: true },
      { candidate_type: 'cidr', normalized_value: v6, assessment: 'malicious', is_ioc: true },
      { candidate_type: 'ip', normalized_value: host, assessment: 'malicious', is_ioc: true }
    ]);
    assert.deepEqual(
      matched.candidates.map((m) => Number(m.matched_ioc_id)),
      [Number(byValue[v4].id), Number(byValue[v6].id), Number(byValue[host].id)]
    );
  } finally {
    await cleanup(report.id, values);
  }
});
