#!/usr/bin/env node
/**
 * Repair Threat Library IPv6 IOCs that the legacy create path stored as domains.
 *
 * Dry-run by default. `--apply` writes one transaction. `--expect=N` is required
 * with `--apply` and must equal the eligible row count, so a different defect
 * set cannot be repaired by accident. Idempotent: a second apply finds nothing.
 *
 *   node scripts/repair-ioc-observable-types.js
 *   node scripts/repair-ioc-observable-types.js --apply --expect=44 --snapshot=/tmp/ioc-type-snapshot.json
 *
 * Rollback (same snapshot the apply wrote):
 *   node scripts/repair-ioc-observable-types.js --rollback=/tmp/ioc-type-snapshot.json
 */
import '../lib/ensure-db-password.js';
import fs from 'node:fs';
import pg from 'pg';
import { IOC_SOURCE_NAME } from '../lib/threatLibrary/constants.js';
import {
  planHistoricalTypeRepair,
  retypeThreatLibraryIpv6,
  restoreIocTypeSnapshot
} from '../lib/iocTypeIntegrity.js';

function connectionConfig() {
  return {
    host: process.env.DB_HOST || 'db',
    port: Number(process.env.DB_PORT || 5432),
    user: process.env.DB_USER || 'talonhound',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'talonhound',
    max: 2
  };
}

function argValue(name) {
  const prefix = `--${name}=`;
  const hit = process.argv.find((a) => a.startsWith(prefix));
  return hit ? hit.slice(prefix.length) : null;
}

const ELIGIBLE_SQL = `
  SELECT i.id, i.observable, i.observable_type, i.public_id::text AS public_id,
         i.source_name, i.created_origin, i.note, i.status,
         c.id AS candidate_id, c.candidate_type, c.normalized_value, c.review_status,
         c.assessment, c.promotion_outcome, c.match_state, c.matched_ioc_id,
         c.matched_ioc_observable_type, c.report_id,
         r.public_id::text AS report_public_id, r.import_status,
         r.finalized_at
  FROM ioc_items i
  JOIN threat_report_candidates c
    ON c.matched_ioc_id = i.id
   AND c.matched_ioc_observable_type = i.observable_type
  JOIN threat_reports r ON r.id = c.report_id
  WHERE i.observable_type = 'domain'
    AND i.source_name = $1
    AND i.created_origin = 'manual_add'
    AND c.candidate_type = 'ipv6'
    AND c.review_status = 'approved'
    AND position(':' in i.observable) > 0
  ORDER BY i.id
`;

async function loadPlans(client) {
  const { rows } = await client.query(ELIGIBLE_SQL, [IOC_SOURCE_NAME]);
  const canonicals = rows.map((r) => r.observable);
  const existing = canonicals.length
    ? await client.query(
      `SELECT observable FROM ioc_items WHERE observable_type = 'ipv6' AND observable = ANY($1::text[])`,
      [canonicals]
    )
    : { rows: [] };
  const collisions = new Set(existing.rows.map((r) => r.observable));
  const plans = [];
  const skipped = [];
  for (const row of rows) {
    const plan = planHistoricalTypeRepair(row, { collision: collisions.has(row.observable) });
    if (plan.action === 'retype') {
      plans.push({
        ...plan,
        id: Number(row.id),
        observable: row.observable,
        public_id: row.public_id,
        candidate_id: Number(row.candidate_id),
        report_id: Number(row.report_id)
      });
    } else {
      skipped.push({ id: Number(row.id), action: plan.action, reason: plan.reason, observable: row.observable });
    }
  }
  return { rows: rows.length, plans, skipped };
}

async function protectedFingerprint(client) {
  const { rows } = await client.query(
    `SELECT r.id,
            r.import_status,
            COALESCE(r.finalized_at::text, '') AS finalized_at,
            md5(COALESCE(string_agg(
              c.id::text || '|' || c.review_status || '|' || c.assessment || '|' || COALESCE(c.role, '')
              || '|' || COALESCE(c.is_ioc::text, '') || '|' || c.candidate_type || '|' || c.normalized_value
              || '|' || COALESCE(c.matched_ioc_id::text, '')
              || '|' || COALESCE(c.promotion_outcome, '')
              || '|' || COALESCE(c.match_state, ''),
              E'\\n' ORDER BY c.id
            ), '')) AS fp
     FROM threat_reports r
     LEFT JOIN threat_report_candidates c ON c.report_id = r.id
     WHERE r.deleted_at IS NULL
       AND r.finalized_at IS NOT NULL
       AND r.import_status IN ('ready', 'imported')
     GROUP BY r.id
     ORDER BY r.id`
  );
  return rows.map((r) => `${r.id}|${r.import_status}|${r.finalized_at}|${r.fp}`).join('\n');
}

async function captureSnapshot(client, plans) {
  const ids = plans.map((p) => p.id);
  const publicIds = plans.map((p) => p.public_id);
  const [items, candidates, observables, projection] = await Promise.all([
    client.query(
      `SELECT id, observable, observable_type, public_id::text AS public_id, source_name, created_origin, note, status
       FROM ioc_items WHERE id = ANY($1::bigint[]) AND observable_type = 'domain' ORDER BY id`,
      [ids]
    ),
    client.query(
      `SELECT id, report_id, candidate_type, normalized_value, review_status, assessment,
              promotion_outcome, match_state, matched_ioc_id, matched_ioc_observable_type
       FROM threat_report_candidates
       WHERE matched_ioc_id = ANY($1::bigint[]) AND matched_ioc_observable_type = 'domain'
       ORDER BY id`,
      [ids]
    ),
    client.query(
      `SELECT id, ioc_public_id::text AS ioc_public_id, observable_type, observable_value
       FROM ioc_observables WHERE ioc_public_id = ANY($1::uuid[]) ORDER BY id`,
      [publicIds]
    ),
    client.query(
      `SELECT feed_id, snapshot_window, identity_key, ioc_item_id, observable, observable_type,
              recency_ts, confidence, category, confidence_rank, txt_value, item_json,
              content_fingerprint, partition_identity, chunk_key, reconciliation_bucket
       FROM published_feed_items
       WHERE ioc_item_id = ANY($1::bigint[]) AND observable_type = 'domain'
       ORDER BY feed_id, snapshot_window, identity_key`,
      [ids]
    )
  ]);
  return {
    captured_at: new Date().toISOString(),
    ioc_items: items.rows,
    candidates: candidates.rows,
    observables: observables.rows,
    published_feed_items: projection.rows
  };
}

async function main() {
  const apply = process.argv.includes('--apply');
  const expectRaw = argValue('expect');
  const snapshotPath = argValue('snapshot');
  const rollbackPath = argValue('rollback');
  const pool = new pg.Pool(connectionConfig());
  const client = await pool.connect();
  try {
    if (rollbackPath) {
      const snapshot = JSON.parse(fs.readFileSync(rollbackPath, 'utf8'));
      await client.query('BEGIN');
      const result = await restoreIocTypeSnapshot(client, snapshot);
      await client.query('COMMIT');
      process.stdout.write(`${JSON.stringify({ mode: 'rollback', ...result }, null, 2)}\n`);
      return;
    }

    await client.query('BEGIN');
    const loaded = await loadPlans(client);
    const reportIds = [...new Set(loaded.plans.map((p) => p.report_id))];
    const fingerprintBefore = await protectedFingerprint(client);
    if (!apply) {
      await client.query('ROLLBACK');
      process.stdout.write(`${JSON.stringify({
        mode: 'dry-run',
        examined: loaded.rows,
        retype: loaded.plans.length,
        skipped: loaded.skipped,
        report_ids: reportIds,
        ids: loaded.plans.map((p) => p.id)
      }, null, 2)}\n`);
      return;
    }
    if (expectRaw == null || Number(expectRaw) !== loaded.plans.length) {
      throw new Error(`--expect=${expectRaw ?? ''} does not match eligible retype count ${loaded.plans.length}`);
    }
    if (!loaded.plans.length) {
      await client.query('ROLLBACK');
      process.stdout.write(`${JSON.stringify({ mode: 'apply', retyped: 0, idempotent: true }, null, 2)}\n`);
      return;
    }
    const snapshot = await captureSnapshot(client, loaded.plans);
    if (snapshot.ioc_items.length !== loaded.plans.length) {
      throw new Error(`Snapshot captured ${snapshot.ioc_items.length} IOC rows, expected ${loaded.plans.length}`);
    }
    snapshot.protected_fingerprint = fingerprintBefore;
    snapshot.report_ids = reportIds;
    const result = await retypeThreatLibraryIpv6(client, loaded.plans, snapshot);
    const fingerprintAfter = await protectedFingerprint(client);
    if (fingerprintAfter !== fingerprintBefore) {
      throw new Error('Protected report fingerprint changed');
    }
    const verify = await client.query(
      `SELECT id, observable_type, observable, public_id::text AS public_id
       FROM ioc_items WHERE id = ANY($1::bigint[]) ORDER BY id`,
      [loaded.plans.map((p) => p.id)]
    );
    if (verify.rows.some((r) => r.observable_type !== 'ipv6')) {
      throw new Error('Verification read still has a non-ipv6 row');
    }
    await client.query('COMMIT');
    if (snapshotPath) fs.writeFileSync(snapshotPath, JSON.stringify(snapshot, null, 2));
    process.stdout.write(`${JSON.stringify({
      mode: 'apply',
      ...result,
      verified: verify.rows.length,
      protected_fingerprint_unchanged: true,
      snapshot: snapshotPath
    }, null, 2)}\n`);
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch { /* ignore */ }
    console.error(err);
    process.exit(1);
  } finally {
    client.release();
    await pool.end();
  }
}

main();
