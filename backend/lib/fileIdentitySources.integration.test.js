/**
 * Real PostgreSQL coverage for hash identity provenance.
 *
 * ThreatFox-style MD5 memberships stay on the MD5 row. A canonical SHA256
 * page must still report them, including when they are expired, without
 * rewriting the publisher assertion or counting VirusTotal as a source.
 *
 * Rows are committed under a per-run token and deleted afterwards.
 * Skips unless a migrated disposable database is configured.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import { fetchFileIdentityMembershipSummary } from './fileIdentitySources.js';
import { enrichItemsWithActiveSourceCounts } from './iocActiveSources.js';
import { dualWriteFileArtifactForObservable } from './fileArtifacts/dualWrite.js';
import { attachExactHash } from './fileArtifacts/attach.js';
import { resolveArtifactScopedIocIds } from './fileArtifacts/read.js';
import { loadRecoveredFileIdentityEvents, recordFileIdentityLinkedAudit } from './fileIdentityAudit.js';
import { AUDIT_ACTION } from './auditConstants.js';

process.env.FILE_ARTIFACTS_READ_ENABLED = '1';
process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED = '1';

const { Pool } = pg;
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound',
  connectionTimeoutMillis: 2000,
  max: 6
});

let hasDb = false;
try {
  await pool.query('SELECT 1 FROM file_artifact_ioc_links LIMIT 0');
  await pool.query('SELECT 1 FROM ioc_feed_memberships LIMIT 0');
  await pool.query('SELECT 1 FROM audit_logs LIMIT 0');
  hasDb = true;
} catch {
  hasDb = false;
}
const opts = { skip: hasDb ? false : 'no migrated database available (set DB_HOST/DB_PASSWORD to run)' };

const TOKEN = `fi${crypto.randomBytes(4).toString('hex')}`;
const md5 = () => crypto.randomBytes(16).toString('hex');
const sha1 = () => crypto.randomBytes(20).toString('hex');
const sha256 = () => crypto.randomBytes(32).toString('hex');

const created = {
  iocIds: [],
  feedIds: [],
  sourceIds: [],
  artifactIds: [],
  suppressionIds: []
};

async function feed(suffix, name) {
  const key = `itest-${suffix}-${TOKEN}`.slice(0, 80);
  const { rows } = await pool.query(
    `INSERT INTO integration_feeds (key, name, source_url, schedule_cron, active, integration_id)
     VALUES ($1, $2, 'https://example.test/itest', '0 * * * *', TRUE, gen_random_uuid())
     RETURNING integration_id`,
    [key, name]
  );
  created.feedIds.push(rows[0].integration_id);
  return rows[0].integration_id;
}

async function manualSource(name) {
  const { rows } = await pool.query(
    `INSERT INTO ioc_sources (name, source_type) VALUES ($1, 'external_report') RETURNING id`,
    [name]
  );
  created.sourceIds.push(rows[0].id);
  return rows[0].id;
}

async function insertIoc({
  type, value, sourceName, status = 'active', iocSourceId = null,
  expiresAt = null, manualOverride = false
}) {
  const { rows } = await pool.query(
    `INSERT INTO ioc_items (
       observable, observable_type, source_name, status, ioc_source_id,
       expires_at, manual_status_override, confidence
     ) VALUES ($1, $2, $3, $4, $5, $6::timestamptz, $7, 'medium')
     RETURNING id, public_id, observable, observable_type, status, manual_status_override`,
    [value, type, sourceName, status, iocSourceId, expiresAt, manualOverride]
  );
  created.iocIds.push(rows[0].id);
  return rows[0];
}

async function membership(ioc, feedId, { status = 'active', expiresAt = null, override = false } = {}) {
  const { rows } = await pool.query(
    `INSERT INTO ioc_feed_memberships (
       ioc_item_id, ioc_observable_type, feed_id, status, expires_at, policy_expires_at, override_enabled
     ) VALUES ($1, $2, $3::uuid, $4, $5::timestamptz, $5::timestamptz, $6)
     RETURNING id, status, expires_at, override_enabled, ioc_observable_type, ioc_item_id`,
    [ioc.id, ioc.observable_type, feedId, status, expiresAt, override]
  );
  return rows[0];
}

async function trackArtifacts(iocIds) {
  if (!iocIds.length) return;
  const { rows } = await pool.query(
    `SELECT DISTINCT artifact_id FROM file_artifact_ioc_links WHERE ioc_item_id = ANY($1::bigint[])
     UNION
     SELECT DISTINCT artifact_id FROM file_artifact_hashes
     WHERE normalized_hash_value IN (
       SELECT observable FROM ioc_items WHERE id = ANY($1::bigint[])
     )`,
    [iocIds]
  );
  for (const row of rows) {
    if (row.artifact_id && !created.artifactIds.includes(row.artifact_id)) {
      created.artifactIds.push(row.artifact_id);
    }
  }
}

async function writeHash(ioc, { sourceName, note = null, observationType = null, relationMethod = null }) {
  const result = await dualWriteFileArtifactForObservable(pool, {
    observable: ioc.observable,
    observableType: ioc.observable_type,
    sourceName,
    note,
    attachNoteSiblings: Boolean(note),
    providerMapping: Boolean(note),
    observationType: observationType || undefined,
    relationMethod: relationMethod || undefined,
    correlationId: `itest-${TOKEN}`,
    logger: { warn: () => {} }
  });
  await trackArtifacts([ioc.id]);
  return result;
}

test('T1/T3/T10/T12/T18 ThreatFox MD5 then VirusTotal SHA256 equivalence keeps MD5 provenance', opts, async () => {
  const tf = await feed('tf', `ThreatFox ${TOKEN}`);
  const mb = await feed('mb', `MalwareBazaar ${TOKEN}`);
  const md5Value = md5();
  const shaValue = sha256();
  const md5Ioc = await insertIoc({ type: 'md5', value: md5Value, sourceName: `ThreatFox:${TOKEN}`, status: 'expired' });
  const tfMem = await membership(md5Ioc, tf, { status: 'expired', expiresAt: '2026-06-28T16:50:56.177Z' });
  const before = { ...tfMem };

  await writeHash(md5Ioc, {
    sourceName: 'VirusTotal',
    note: `md5=${md5Value} | sha256=${shaValue}`,
    observationType: 'enrichment_derived',
    relationMethod: 'enrichment_result'
  });

  const shaIoc = await insertIoc({ type: 'sha256', value: shaValue, sourceName: `MalwareBazaar:${TOKEN}` });
  await membership(shaIoc, mb, { status: 'active' });
  await writeHash(shaIoc, { sourceName: `MalwareBazaar:${TOKEN}` });

  const summary = await fetchFileIdentityMembershipSummary(pool, {
    observable: shaValue,
    observableType: 'sha256',
    iocItemIds: [shaIoc.id],
    seedIocId: shaIoc.id
  });
  assert.equal(summary.activeSourceCount, 1);
  assert.equal(summary.activeSources[0].publisher_observable_type, 'sha256');
  assert.equal(summary.historicalSourceCount, 1);
  const fox = summary.historicalSources[0];
  assert.equal(fox.publisher_observable_type, 'md5');
  assert.equal(fox.publisher_observable, md5Value);
  assert.equal(fox.relationship, 'verified_file_identity');
  assert.equal(fox.status, 'expired');
  assert.equal(summary.activeSources.some((s) => /virustotal/i.test(s.name)), false);

  const still = await pool.query(
    `SELECT ioc_item_id, ioc_observable_type, status, expires_at, override_enabled
     FROM ioc_feed_memberships WHERE id = $1`,
    [tfMem.id]
  );
  assert.equal(still.rows[0].ioc_item_id, String(md5Ioc.id));
  assert.equal(still.rows[0].ioc_observable_type, 'md5');
  assert.equal(still.rows[0].status, before.status);
  assert.equal(Boolean(still.rows[0].override_enabled), before.override_enabled);

  const scope = await resolveArtifactScopedIocIds(pool, md5Ioc.id);
  assert.ok(scope.includes(Number(shaIoc.id)));
  assert.ok(scope.includes(Number(md5Ioc.id)));
});

test('T2/T4/T5/T6/T7/T13/T14 SHA256 source first, then MD5, repeated enrichment is idempotent', opts, async () => {
  const tf = await feed('tf2', `ThreatFoxB ${TOKEN}`);
  const mb = await feed('mb2', `MalwareBazaarB ${TOKEN}`);
  const md5Value = md5();
  const shaValue = sha256();
  const shaIoc = await insertIoc({ type: 'sha256', value: shaValue, sourceName: `MalwareBazaarB:${TOKEN}` });
  await membership(shaIoc, mb);
  await writeHash(shaIoc, { sourceName: `MalwareBazaarB:${TOKEN}`, note: `sha256=${shaValue} | md5=${md5Value}` });

  const md5Ioc = await insertIoc({ type: 'md5', value: md5Value, sourceName: `ThreatFoxB:${TOKEN}` });
  await membership(md5Ioc, tf);
  await writeHash(md5Ioc, { sourceName: `ThreatFoxB:${TOKEN}` });
  await writeHash(md5Ioc, {
    sourceName: 'VirusTotal',
    note: `md5=${md5Value} | sha256=${shaValue}`,
    observationType: 'enrichment_derived',
    relationMethod: 'enrichment_result'
  });
  await writeHash(md5Ioc, {
    sourceName: 'VirusTotal',
    note: `md5=${md5Value} | sha256=${shaValue}`,
    observationType: 'enrichment_derived',
    relationMethod: 'enrichment_result'
  });

  const summary = await fetchFileIdentityMembershipSummary(pool, {
    observable: md5Value,
    observableType: 'md5',
    seedIocId: md5Ioc.id
  });
  assert.equal(summary.activeSourceCount, 2);
  assert.equal(new Set(summary.activeSourceNames).size, 2);
  const fox = summary.activeSources.find((s) => s.publisher_observable_type === 'md5');
  assert.ok(fox);
  assert.equal(fox.publisher_observable, md5Value);
  assert.notEqual(fox.publisher_observable_type, 'sha256');

  const audits = await pool.query(
    `SELECT action, metadata
     FROM audit_logs
     WHERE action = $1
       AND metadata->>'correlation_id' = $2`,
    [AUDIT_ACTION.IOC_FILE_IDENTITY_LINKED, `itest-${TOKEN}`]
  );
  assert.ok(audits.rows.length >= 1);
  assert.equal(audits.rows.every((row) => row.metadata?.derived === false), true);
  assert.equal(audits.rows.every((row) => row.metadata?.counts_as_threat_source === false), true);
  const ops = new Set(audits.rows.map((row) => `${row.metadata.operation}:${row.metadata.observed_hash_value}`));
  assert.equal(ops.size, audits.rows.length, 'repeated enrichment does not duplicate the same transition');

  const second = await fetchFileIdentityMembershipSummary(pool, {
    observable: shaValue,
    observableType: 'sha256',
    seedIocId: shaIoc.id
  });
  assert.equal(second.activeSourceCount, summary.activeSourceCount);
});

test('T8 concurrent ingestion and enrichment leave one identity and one membership per source', opts, async () => {
  const tf = await feed('tfc', `ThreatFoxC ${TOKEN}`);
  const mb = await feed('mbc', `MalwareBazaarC ${TOKEN}`);
  const md5Value = md5();
  const shaValue = sha256();
  const md5Ioc = await insertIoc({ type: 'md5', value: md5Value, sourceName: `ThreatFoxC:${TOKEN}` });
  const shaIoc = await insertIoc({ type: 'sha256', value: shaValue, sourceName: `MalwareBazaarC:${TOKEN}` });
  await membership(md5Ioc, tf);
  await membership(shaIoc, mb);
  await Promise.all([
    writeHash(md5Ioc, { sourceName: `ThreatFoxC:${TOKEN}`, note: `md5=${md5Value} | sha256=${shaValue}` }),
    writeHash(shaIoc, { sourceName: `MalwareBazaarC:${TOKEN}`, note: `sha256=${shaValue} | md5=${md5Value}` })
  ]);
  const scope = await resolveArtifactScopedIocIds(pool, shaIoc.id);
  assert.deepEqual(scope.map(Number).sort((a, b) => a - b), [Number(md5Ioc.id), Number(shaIoc.id)].sort((a, b) => a - b));
  const mem = await pool.query(
    `SELECT COUNT(*)::int AS n FROM ioc_feed_memberships WHERE ioc_item_id = ANY($1::bigint[])`,
    [[md5Ioc.id, shaIoc.id]]
  );
  assert.equal(mem.rows[0].n, 2);
  const arts = await pool.query(
    `SELECT COUNT(DISTINCT CASE WHEN a.status = 'merged' THEN a.merged_into_artifact_id ELSE l.artifact_id END)::int AS n
     FROM file_artifact_ioc_links l
     JOIN file_artifacts a ON a.id = l.artifact_id
     WHERE l.ioc_item_id = ANY($1::bigint[])`,
    [[md5Ioc.id, shaIoc.id]]
  );
  assert.equal(arts.rows[0].n, 1);
});

test('T9/T11 canonical merge keeps every source link and both hashes resolve together', opts, async () => {
  const tf = await feed('tf9', `ThreatFoxD ${TOKEN}`);
  const mb = await feed('mb9', `MalwareBazaarD ${TOKEN}`);
  const src = await manualSource(`TL${TOKEN}`.slice(0, 32));
  const md5Value = md5();
  const shaValue = sha256();
  const sha1Value = sha1();
  const md5Ioc = await insertIoc({ type: 'md5', value: md5Value, sourceName: `ThreatFoxD:${TOKEN}`, status: 'expired' });
  const shaIoc = await insertIoc({ type: 'sha256', value: shaValue, sourceName: `MalwareBazaarD:${TOKEN}` });
  const sha1Ioc = await insertIoc({
    type: 'sha1', value: sha1Value, sourceName: `TL${TOKEN}`.slice(0, 32), iocSourceId: src, manualOverride: true
  });
  await membership(md5Ioc, tf, { status: 'expired', expiresAt: '2026-06-01T00:00:00.000Z' });
  await membership(shaIoc, mb);
  await writeHash(shaIoc, { sourceName: `MalwareBazaarD:${TOKEN}`, note: `sha256=${shaValue} | md5=${md5Value} | sha1=${sha1Value}` });
  await writeHash(md5Ioc, { sourceName: `ThreatFoxD:${TOKEN}` });
  await writeHash(sha1Ioc, { sourceName: `TL${TOKEN}`.slice(0, 32) });

  const summary = await fetchFileIdentityMembershipSummary(pool, {
    observable: shaValue, observableType: 'sha256', seedIocId: shaIoc.id
  });
  assert.equal(summary.activeSourceCount, 2);
  assert.equal(summary.historicalSourceCount, 1);
  const listed = await enrichItemsWithActiveSourceCounts(pool, [{
    id: shaIoc.id, observable: shaValue, observable_type: 'sha256'
  }], { byItemIds: true });
  assert.equal(listed[0].active_source_count, summary.activeSourceCount);
  assert.equal(listed[0].active_source_count, 2);

  for (const id of [md5Ioc.id, sha1Ioc.id, shaIoc.id]) {
    const scope = await resolveArtifactScopedIocIds(pool, id);
    assert.equal(scope.length, 3);
  }
  const override = await pool.query(
    `SELECT manual_status_override, status FROM ioc_items WHERE id = $1`,
    [sha1Ioc.id]
  );
  assert.equal(override.rows[0].manual_status_override, true);
  assert.equal(override.rows[0].status, 'active');
  const shaStatus = await pool.query(`SELECT status, manual_status_override FROM ioc_items WHERE id = $1`, [shaIoc.id]);
  assert.equal(shaStatus.rows[0].manual_status_override, false);
  assert.equal(shaStatus.rows[0].status, 'active');
});

test('T15 unverified conflicting hash does not merge artifacts', opts, async () => {
  const a = sha256();
  const b = sha256();
  const iocA = await insertIoc({ type: 'sha256', value: a, sourceName: `A${TOKEN}` });
  const iocB = await insertIoc({ type: 'sha256', value: b, sourceName: `B${TOKEN}` });
  await writeHash(iocA, { sourceName: `A${TOKEN}` });
  await writeHash(iocB, { sourceName: `B${TOKEN}` });
  const artA = (await pool.query(
    `SELECT artifact_id FROM file_artifact_ioc_links WHERE ioc_item_id = $1`,
    [iocA.id]
  )).rows[0].artifact_id;
  const artB = (await pool.query(
    `SELECT artifact_id FROM file_artifact_ioc_links WHERE ioc_item_id = $1`,
    [iocB.id]
  )).rows[0].artifact_id;
  const conflict = await attachExactHash(pool, {
    artifact_id: artB,
    hash_type: 'sha256',
    hash_value: a,
    verification_source: 'unverified'
  });
  assert.equal(conflict.ok, false);
  assert.equal(conflict.reason, 'conflict');
  const still = await pool.query(
    `SELECT artifact_id FROM file_artifact_hashes WHERE normalized_hash_value = $1`,
    [a]
  );
  assert.equal(still.rows.length, 1);
  assert.equal(still.rows[0].artifact_id, artA);
  const open = await pool.query(
    `SELECT status FROM file_artifact_merge_conflicts
     WHERE conflicting_hash_value = $1 AND status = 'open'`,
    [a]
  );
  assert.ok(open.rows.length >= 1);
});

test('T16/T17 suppression and source policy survive canonicalization', opts, async () => {
  const tf = await feed('tfp', `ThreatFoxP ${TOKEN}`);
  const md5Value = md5();
  const shaValue = sha256();
  const md5Ioc = await insertIoc({
    type: 'md5', value: md5Value, sourceName: `ThreatFoxP:${TOKEN}`, status: 'suppressed'
  });
  const mem = await membership(md5Ioc, tf, { status: 'active', override: true, expiresAt: '2027-01-01T00:00:00.000Z' });
  const sup = await pool.query(
    `INSERT INTO ioc_suppressions (ioc_value, ioc_type, reason, active)
     VALUES ($1, 'md5', 'itest false positive', TRUE) RETURNING id`,
    [md5Value]
  );
  created.suppressionIds.push(sup.rows[0].id);
  await writeHash(md5Ioc, {
    sourceName: 'VirusTotal',
    note: `md5=${md5Value} | sha256=${shaValue}`,
    observationType: 'enrichment_derived',
    relationMethod: 'enrichment_result'
  });
  const row = await pool.query(`SELECT status FROM ioc_items WHERE id = $1`, [md5Ioc.id]);
  assert.equal(row.rows[0].status, 'suppressed');
  const memAfter = await pool.query(
    `SELECT status, override_enabled, expires_at FROM ioc_feed_memberships WHERE id = $1`,
    [mem.id]
  );
  assert.equal(memAfter.rows[0].status, 'active');
  assert.equal(memAfter.rows[0].override_enabled, true);
  const supAfter = await pool.query(`SELECT active, deleted_at FROM ioc_suppressions WHERE id = $1`, [sup.rows[0].id]);
  assert.equal(supAfter.rows[0].active, true);
  assert.equal(supAfter.rows[0].deleted_at, null);
});

test('T13 recovered history is marked derived and is not inserted as an original event', opts, async () => {
  const value = sha256();
  const ioc = await insertIoc({ type: 'sha256', value, sourceName: `Solo${TOKEN}` });
  await writeHash(ioc, { sourceName: `Solo${TOKEN}` });
  const artifactId = (await pool.query(
    `SELECT artifact_id FROM file_artifact_ioc_links WHERE ioc_item_id = $1`,
    [ioc.id]
  )).rows[0].artifact_id;
  const recovered = await loadRecoveredFileIdentityEvents(pool, [ioc], []);
  assert.equal(recovered.length, 1);
  assert.equal(recovered[0].metadata.derived, true);
  assert.equal(recovered[0].metadata.not_an_original_event, true);
  assert.equal(recovered[0].metadata.recovered_from, 'file_artifact_ioc_links');
  const persisted = await pool.query(
    `SELECT COUNT(*)::int AS n FROM audit_logs WHERE action = $1 AND metadata->>'artifact_id' = $2`,
    [AUDIT_ACTION.IOC_FILE_IDENTITY_RECOVERED, artifactId]
  );
  assert.equal(persisted.rows[0].n, 0);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const written = await recordFileIdentityLinkedAudit(client, {
      artifactId,
      operation: 'hash_equivalence',
      observedHashType: 'sha256',
      observedHashValue: value,
      sourceName: 'VirusTotal',
      trigger: 'hash_enrichment',
      correlationId: `itest-${TOKEN}`
    });
    const again = await recordFileIdentityLinkedAudit(client, {
      artifactId,
      operation: 'hash_equivalence',
      observedHashType: 'sha256',
      observedHashValue: value,
      sourceName: 'VirusTotal',
      trigger: 'hash_enrichment'
    });
    assert.equal(written.written, true);
    assert.equal(again.written, false);
    await client.query('ROLLBACK');
  } finally {
    client.release();
  }
  const covered = await loadRecoveredFileIdentityEvents(pool, [ioc], [{
    action: AUDIT_ACTION.IOC_FILE_IDENTITY_LINKED,
    metadata: { artifact_id: artifactId }
  }]);
  assert.equal(covered.length, 0);
});

test.after(async () => {
  if (!hasDb) {
    await pool.end().catch(() => {});
    return;
  }
  const iocIds = created.iocIds;
  if (iocIds.length) {
    const observables = await pool.query(`SELECT observable FROM ioc_items WHERE id = ANY($1::bigint[])`, [iocIds]);
    const values = observables.rows.map((row) => row.observable);
    if (values.length) {
      await pool.query(
        `DELETE FROM file_artifact_merge_conflicts WHERE conflicting_hash_value = ANY($1::text[])`,
        [values]
      ).catch(() => {});
    }
    await trackArtifacts(iocIds);
    await pool.query(`DELETE FROM audit_logs WHERE subject_ioc_id = ANY($1::bigint[])`, [iocIds]).catch(() => {});
    await pool.query(
      `DELETE FROM audit_logs WHERE metadata->>'correlation_id' = $1`,
      [`itest-${TOKEN}`]
    ).catch(() => {});
    await pool.query(`DELETE FROM ioc_feed_memberships WHERE ioc_item_id = ANY($1::bigint[])`, [iocIds]).catch(() => {});
    await pool.query(`DELETE FROM file_artifact_ioc_links WHERE ioc_item_id = ANY($1::bigint[])`, [iocIds]).catch(() => {});
    await pool.query(`DELETE FROM ioc_items WHERE id = ANY($1::bigint[])`, [iocIds]).catch(() => {});
  }
  if (created.artifactIds.length) {
    await pool.query(`DELETE FROM file_artifact_source_observations WHERE artifact_id = ANY($1::uuid[])`, [created.artifactIds]).catch(() => {});
    await pool.query(`DELETE FROM file_artifact_hashes WHERE artifact_id = ANY($1::uuid[])`, [created.artifactIds]).catch(() => {});
    await pool.query(
      `UPDATE file_artifacts SET primary_hash_id = NULL WHERE id = ANY($1::uuid[]) OR merged_into_artifact_id = ANY($1::uuid[])`,
      [created.artifactIds]
    ).catch(() => {});
    await pool.query(
      `DELETE FROM file_artifacts WHERE status = 'merged' AND merged_into_artifact_id = ANY($1::uuid[])`,
      [created.artifactIds]
    ).catch(() => {});
    await pool.query(`DELETE FROM file_artifacts WHERE id = ANY($1::uuid[])`, [created.artifactIds]).catch(() => {});
  }
  if (created.suppressionIds.length) {
    await pool.query(`DELETE FROM ioc_suppressions WHERE id = ANY($1::bigint[])`, [created.suppressionIds]).catch(() => {});
  }
  if (created.feedIds.length) {
    await pool.query(`DELETE FROM integration_feeds WHERE integration_id = ANY($1::uuid[])`, [created.feedIds]).catch(() => {});
  }
  if (created.sourceIds.length) {
    await pool.query(`DELETE FROM ioc_sources WHERE id = ANY($1::bigint[])`, [created.sourceIds]).catch(() => {});
  }
  await pool.query(
    `DELETE FROM file_artifact_merge_conflicts WHERE evidence::text LIKE $1`,
    [`%${TOKEN}%`]
  ).catch(() => {});
  await pool.end().catch(() => {});
});
