import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import { createThreatReport } from './store.js';
import { applyCandidateReviewActions } from './reviewService.js';
import { bulkMatchCandidates } from './iocMatch.js';
import { createManualIoc } from '../manualIocCreate.js';

/**
 * Real-Postgres email IOCs (migration 057). Against the migrated schema
 * (partitioned ioc_items, ioc_observables CHECK, the seeded Threat_Library IOC
 * source) it checks that:
 *
 *   - Create IOCs stores an approved `email` Indicator as one `email` IOC with
 *     the canonical (lower-cased, refanged) identity, in the default partition,
 *     with its ioc_observables index row;
 *   - an email IOC already in the catalog is linked, not duplicated, and a
 *     second Create IOCs is idempotent;
 *   - the catalog matcher finds the email IOC for an `email` candidate;
 *   - a manual / API create of a mixed-case defanged address resolves to the
 *     same identity, and a non-address "@" value is refused (never a domain);
 *   - Published Feeds accept the `email` category (CHECK constraints).
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

async function insertCandidate(reportId, type, original, normalized) {
  const { rows } = await pool.query(
    `INSERT INTO threat_report_candidates (
       report_id, candidate_type, original_value, normalized_value, assessment, role, review_status,
       match_state, is_ioc, source_assertion, evidence, has_original_document_occurrence
     ) VALUES ($1,$2,$3,$4,'malicious','malicious_infrastructure','approved','new',true,'explicit_ioc',$5::jsonb,true)
     RETURNING id`,
    [reportId, type, original, normalized, JSON.stringify(EV)]
  );
  return Number(rows[0].id);
}

async function iocRows(values) {
  const { rows } = await pool.query(
    `SELECT id, public_id, observable_type, observable, tableoid::regclass::text AS partition
     FROM ioc_items WHERE lower(observable) = ANY($1::text[]) ORDER BY id`,
    [values.map((v) => v.toLowerCase())]
  );
  return rows;
}

async function cleanup(reportId, values) {
  const ids = (await iocRows(values)).map((r) => Number(r.id));
  if (reportId) {
    await pool.query(`DELETE FROM threat_report_candidates WHERE report_id = $1`, [reportId]);
    await pool.query(`DELETE FROM audit_logs WHERE entity_id = (SELECT public_id::text FROM threat_reports WHERE id = $1)`, [reportId]);
    await pool.query(`DELETE FROM threat_reports WHERE id = $1`, [reportId]);
  }
  if (ids.length) {
    await pool.query(`DELETE FROM ioc_observables WHERE ioc_public_id IN (SELECT public_id FROM ioc_items WHERE id = ANY($1::bigint[]))`, [ids]).catch(() => {});
    await pool.query(`DELETE FROM ioc_threat_classifications WHERE ioc_id = ANY($1::bigint[])`, [ids]).catch(() => {});
    await pool.query(`DELETE FROM ioc_items WHERE id = ANY($1::bigint[])`, [ids]);
  }
}

test('Create IOCs stores approved email Indicators as canonical email IOCs, links existing ones, and is idempotent', opts, async () => {
  const tag = crypto.randomBytes(4).toString('hex');
  const fresh = `alex.${tag}@hr.trixauvex-itest.ink`;
  const existing = `c.laurent.${tag}@proton.me`;
  const values = [fresh, existing];
  const report = await createThreatReport(pool, {
    title: `itest-email-ioc-${crypto.randomUUID()}`,
    source_type: 'url',
    source_url: `https://vendor-research.example/${crypto.randomUUID()}`
  });
  await pool.query(`UPDATE threat_reports SET analysis_status = 'review_required', import_status = 'review_required' WHERE id = $1`, [report.id]);
  try {
    const { rows: [prior] } = await pool.query(
      `INSERT INTO ioc_items (observable, observable_type, source_name, confidence)
       VALUES ($1, 'email', 'itest:email-feed', 'medium') RETURNING id`,
      [existing]
    );
    const ids = {
      fresh: await insertCandidate(report.id, 'email', `Alex.${tag}@hr.trixauvex-itest[.]ink`, fresh),
      existing: await insertCandidate(report.id, 'email', existing.replace('@', '[@]'), existing)
    };
    const all = Object.values(ids);

    const preview = await applyCandidateReviewActions(pool, report.id, { action: 'create_iocs', candidateIds: all });
    assert.equal(preview.ok, true);
    assert.equal(preview.summary.unsupported, 0, 'email is a supported IOC type');
    assert.equal(preview.summary.eligible, 2);

    const run = await applyCandidateReviewActions(pool, report.id, { action: 'create_iocs', candidateIds: all, confirm: true });
    assert.equal(run.ok, true, JSON.stringify(run));
    assert.equal(run.summary.created, 1);
    assert.equal(run.summary.already_existing, 1);
    assert.equal(run.summary.failed, 0);

    const stored = await iocRows(values);
    assert.equal(stored.length, 2, 'one IOC per identity');
    const byValue = Object.fromEntries(stored.map((r) => [r.observable, r]));
    assert.equal(byValue[fresh].observable_type, 'email');
    assert.equal(byValue[fresh].partition, 'ioc_items_other');
    assert.equal(Number(byValue[existing].id), Number(prior.id), 'existing email IOC linked, not recreated');

    const { rows: obs } = await pool.query(
      `SELECT observable_type, observable_value FROM ioc_observables WHERE ioc_public_id = $1`,
      [byValue[fresh].public_id]
    );
    assert.deepEqual(obs, [{ observable_type: 'email', observable_value: fresh }]);

    const { rows: cands } = await pool.query(
      `SELECT id, matched_ioc_id, matched_ioc_observable_type, promotion_outcome FROM threat_report_candidates WHERE report_id = $1`,
      [report.id]
    );
    const byId = Object.fromEntries(cands.map((r) => [Number(r.id), r]));
    assert.equal(Number(byId[ids.fresh].matched_ioc_id), Number(byValue[fresh].id));
    assert.equal(byId[ids.fresh].matched_ioc_observable_type, 'email');
    assert.equal(byId[ids.fresh].promotion_outcome, 'created');
    assert.equal(byId[ids.existing].promotion_outcome, 'already_existing');

    const again = await applyCandidateReviewActions(pool, report.id, { action: 'create_iocs', candidateIds: all, confirm: true });
    assert.equal(again.ok, true);
    assert.equal(again.summary.created, 0);
    assert.equal((await iocRows(values)).length, 2, 'second run creates nothing');

    const matched = await bulkMatchCandidates(pool, [
      { candidate_type: 'email', normalized_value: fresh, assessment: 'malicious', is_ioc: true }
    ]);
    assert.equal(Number(matched.candidates[0].matched_ioc_id), Number(byValue[fresh].id));
  } finally {
    await cleanup(report.id, values);
  }
});

test('manual create: a defanged mixed-case address is one email IOC; a non-address "@" value is refused', opts, async () => {
  const tag = crypto.randomBytes(4).toString('hex');
  const canonical = `ops.${tag}@corp-mail-itest.com`;
  const { rows: [src] } = await pool.query(`SELECT id FROM ioc_sources WHERE name = 'Threat_Library' LIMIT 1`);
  try {
    const ok = await createManualIoc(pool, { observable: `Ops.${tag}@Corp-Mail-ITest[.]com`, source_id: src.id });
    assert.equal(ok.status ?? 201, 201, JSON.stringify(ok.body));
    const rows = await iocRows([canonical]);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].observable_type, 'email');
    assert.equal(rows[0].observable, canonical);

    const bad = await createManualIoc(pool, { observable: `node${tag}.example-host.net@80`, source_id: src.id });
    assert.equal(bad.status, 400);
    assert.equal((await iocRows([`node${tag}.example-host.net@80`])).length, 0, 'never stored as a domain');
  } finally {
    await cleanup(null, [canonical]);
  }
});

test('ioc_observables and published_feeds CHECK constraints admit email (migration 057)', opts, async () => {
  const { rows } = await pool.query(
    `SELECT conname, pg_get_constraintdef(oid) AS def FROM pg_constraint
     WHERE conname IN ('chk_observable_type', 'chk_published_feeds_ioc_type', 'chk_published_feeds_ioc_types') ORDER BY conname`
  );
  assert.equal(rows.length, 3);
  for (const r of rows) assert.match(r.def, /email/, r.conname);
});
