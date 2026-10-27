/**
 * Real-Postgres proof that an IPv6 value stored as domain moves to the ipv6
 * partition without changing its id or public_id, that candidate review state
 * survives, and that the snapshot restores the previous rows.
 *
 * Opt-in: IOC_TYPE_REPAIR_ITEST=1 and a migrated database (CI after migrate,
 * or a scratch database). The test deletes its fixtures.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { retypeThreatLibraryIpv6, restoreIocTypeSnapshot } from '../iocTypeIntegrity.js';

const enabled = process.env.IOC_TYPE_REPAIR_ITEST === '1';
const observable = '2001:db8:91::1';
const reportPublicId = '11111111-2222-4333-8444-555555555555';

function poolConfig() {
  return {
    host: process.env.DB_HOST || 'localhost',
    port: Number(process.env.DB_PORT || 5432),
    user: process.env.DB_USER || 'talonhound',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'talonhound',
    max: 2
  };
}

async function cleanup(pool, state) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (state.iocId) {
      await client.query('DELETE FROM published_feed_items WHERE ioc_item_id = $1', [state.iocId]);
      await client.query('DELETE FROM ioc_observables WHERE ioc_public_id = $1', [state.publicId]);
      await client.query('DELETE FROM threat_report_candidates WHERE report_id = $1', [state.reportId]);
      await client.query('DELETE FROM published_feed_ioc_deletes WHERE ioc_item_id = $1', [state.iocId]);
      await client.query('DELETE FROM ioc_items WHERE id = $1', [state.iocId]);
      await client.query('DELETE FROM published_feed_ioc_deletes WHERE ioc_item_id = $1', [state.iocId]);
    }
    if (state.reportId) await client.query('DELETE FROM threat_reports WHERE id = $1', [state.reportId]);
    if (state.feedId) await client.query('DELETE FROM published_feeds WHERE id = $1', [state.feedId]);
    await client.query('COMMIT');
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch { /* ignore */ }
    throw err;
  } finally {
    client.release();
  }
}

test('partition retype keeps the IOC id and the snapshot restores it', { skip: !enabled }, async () => {
  const pool = new pg.Pool(poolConfig());
  const state = {};
  try {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const feed = await client.query(
        `INSERT INTO published_feeds (name, slug, ioc_type, enabled)
         VALUES ('ioc-type-repair-fixture', 'ioc-type-repair-fixture', 'domain', false)
         RETURNING id`
      );
      state.feedId = feed.rows[0].id;
      const report = await client.query(
        `INSERT INTO threat_reports (title, source_type, public_id, import_status, analysis_status, finalized_at)
         VALUES ('type integrity fixture', 'url', $1::uuid, 'ready', 'ready', NOW())
         RETURNING id`,
        [reportPublicId]
      );
      state.reportId = report.rows[0].id;
      const ioc = await client.query(
        `INSERT INTO ioc_items (
           observable, observable_type, source_name, created_origin, note, confidence
         ) VALUES (
           $1, 'domain', 'Threat_Library', 'manual_add', $2, 'medium'
         ) RETURNING id, public_id::text AS public_id`,
        [observable, `Threat Library report ${reportPublicId}: unknown (malicious)`]
      );
      state.iocId = ioc.rows[0].id;
      state.publicId = ioc.rows[0].public_id;
      await client.query(
        `INSERT INTO threat_report_candidates (
           report_id, candidate_type, original_value, normalized_value, review_status, assessment,
           matched_ioc_id, matched_ioc_observable_type, is_ioc, promotion_outcome
         ) VALUES ($1, 'ipv6', $2, $2, 'approved', 'malicious', $3, 'domain', true, 'created')`,
        [state.reportId, observable, state.iocId]
      );
      await client.query(
        `INSERT INTO ioc_observables (ioc_public_id, observable_type, observable_value)
         VALUES ($1, 'domain', $2)`,
        [state.publicId, observable]
      );
      await client.query(
        `INSERT INTO published_feed_items (
           feed_id, snapshot_window, identity_key, ioc_item_id, observable, observable_type,
           txt_value, content_fingerprint, confidence_rank
         ) VALUES ($1, 'all', $2, $3, $4, 'domain', $4, 'fixture', 0)`,
        [state.feedId, `o:domain:${observable}`, state.iocId, observable]
      );
      const snapshot = {
        ioc_items: [{
          id: state.iocId,
          observable,
          observable_type: 'domain',
          public_id: state.publicId
        }],
        candidates: (await client.query(
          `SELECT id, matched_ioc_id, matched_ioc_observable_type, review_status, assessment
           FROM threat_report_candidates WHERE report_id = $1`,
          [state.reportId]
        )).rows,
        observables: (await client.query(
          `SELECT ioc_public_id::text AS ioc_public_id, observable_type, observable_value
           FROM ioc_observables WHERE ioc_public_id = $1`,
          [state.publicId]
        )).rows,
        published_feed_items: (await client.query(
          `SELECT feed_id, snapshot_window, identity_key, ioc_item_id, observable, observable_type,
                  recency_ts, confidence, category, confidence_rank, txt_value, item_json,
                  content_fingerprint, partition_identity, chunk_key, reconciliation_bucket
           FROM published_feed_items WHERE ioc_item_id = $1`,
          [state.iocId]
        )).rows
      };
      const plan = [{
        action: 'retype',
        id: Number(state.iocId),
        observable,
        canonical: observable,
        expected_type: 'ipv6',
        public_id: state.publicId
      }];
      const applied = await retypeThreatLibraryIpv6(client, plan, snapshot);
      assert.equal(applied.retyped, 1);
      const moved = await client.query(
        `SELECT tableoid::regclass::text AS partition, id, observable_type, observable, public_id::text AS public_id
         FROM ioc_items WHERE id = $1`,
        [state.iocId]
      );
      assert.equal(moved.rows[0].partition, 'ioc_ipv6');
      assert.equal(moved.rows[0].observable_type, 'ipv6');
      assert.equal(moved.rows[0].public_id, state.publicId);
      const candidate = await client.query(
        `SELECT review_status, assessment, promotion_outcome, matched_ioc_id, matched_ioc_observable_type
         FROM threat_report_candidates WHERE report_id = $1`,
        [state.reportId]
      );
      assert.equal(candidate.rows[0].review_status, 'approved');
      assert.equal(candidate.rows[0].assessment, 'malicious');
      assert.equal(candidate.rows[0].promotion_outcome, 'created');
      assert.equal(Number(candidate.rows[0].matched_ioc_id), Number(state.iocId));
      assert.equal(candidate.rows[0].matched_ioc_observable_type, 'ipv6');
      const indexed = await client.query(
        `SELECT observable_type FROM ioc_observables WHERE ioc_public_id = $1`,
        [state.publicId]
      );
      assert.equal(indexed.rows[0].observable_type, 'ipv6');
      const projected = await client.query(
        'SELECT count(*)::int AS n FROM published_feed_items WHERE ioc_item_id = $1',
        [state.iocId]
      );
      assert.equal(projected.rows[0].n, 0);
      const tombstone = await client.query(
        `SELECT observable_type FROM published_feed_ioc_deletes WHERE ioc_item_id = $1`,
        [state.iocId]
      );
      assert.equal(tombstone.rows[0].observable_type, 'domain');

      await assert.rejects(() => retypeThreatLibraryIpv6(client, plan, { published_feed_items: [] }), /changed before repair|Locked/);

      await restoreIocTypeSnapshot(client, snapshot);
      const back = await client.query(
        `SELECT tableoid::regclass::text AS partition, observable_type, observable, public_id::text AS public_id
         FROM ioc_items WHERE id = $1`,
        [state.iocId]
      );
      assert.equal(back.rows[0].partition, 'ioc_domain');
      assert.equal(back.rows[0].observable_type, 'domain');
      assert.equal(back.rows[0].public_id, state.publicId);
      const link = await client.query(
        `SELECT matched_ioc_observable_type, review_status FROM threat_report_candidates WHERE report_id = $1`,
        [state.reportId]
      );
      assert.equal(link.rows[0].matched_ioc_observable_type, 'domain');
      assert.equal(link.rows[0].review_status, 'approved');
      const proj = await client.query(
        `SELECT identity_key, observable_type FROM published_feed_items WHERE ioc_item_id = $1`,
        [state.iocId]
      );
      assert.equal(proj.rows.length, 1);
      assert.equal(proj.rows[0].observable_type, 'domain');
      assert.equal(proj.rows[0].identity_key, `o:domain:${observable}`);
      await client.query('ROLLBACK');
      state.iocId = null;
      state.reportId = null;
      state.feedId = null;
    } finally {
      client.release();
    }
  } finally {
    if (state.iocId || state.reportId || state.feedId) await cleanup(pool, state);
    await pool.end();
  }
});
