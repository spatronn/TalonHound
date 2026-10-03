/**
 * Real-Postgres parity for canonical effective classification:
 *   detail/MCP hydrator  ===  DSL search membership  ===  SQL vocabulary fn
 *
 * Guarded by assertFileArtifactDbTestAllowed (ALLOW_FILE_ARTIFACT_DB_TESTS=1,
 * localhost, DB_NAME containing "_test"). Every fixture row is rolled back.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import { assertFileArtifactDbTestAllowed } from './fileArtifacts/dbTestGuard.js';
import {
  computeCanonicalIocClassifications,
  loadCanonicalIocClassification
} from './iocCanonicalClassifications.js';
import { hydrateIocApiMetadata } from './iocApiMetadata.js';
import { iocPairKey } from './iocThreatClassifications.js';
import { normalizeFeedTags } from './feedTagNormalization.js';
import { parseSearchQuery, buildWhereClause } from './iocSearchDsl/index.js';
import { FEED_EVIDENCE_CLASSIFICATION_FN } from './iocSearchDsl/classificationPredicate.js';

let dbConfig = null;
try {
  dbConfig = assertFileArtifactDbTestAllowed();
} catch {
  dbConfig = null;
}

const pool = dbConfig
  ? new pg.Pool({ ...dbConfig, connectionTimeoutMillis: 3000, max: 4 })
  : null;

let hasDb = false;
if (pool) {
  try {
    await pool.query(`SELECT ${FEED_EVIDENCE_CLASSIFICATION_FN}(NULL, NULL)`);
    hasDb = true;
  } catch {
    hasDb = false;
  }
}
const opts = {
  skip: hasDb
    ? false
    : 'disposable migrated test DB with migration 035 not available (ALLOW_FILE_ARTIFACT_DB_TESTS=1 + *_test DB)'
};

const MARK = `cls${crypto.randomBytes(4).toString('hex')}`;
const hex = (n) => crypto.randomBytes(n / 2).toString('hex');

async function inTx(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await fn(client);
  } finally {
    await client.query('ROLLBACK').catch(() => {});
    client.release();
  }
}

async function ensureFeed(client) {
  const key = `itest-classif-${MARK}`;
  const { rows: existing } = await client.query(
    `SELECT integration_id FROM integration_feeds WHERE key = $1`,
    [key]
  );
  if (existing[0]) return existing[0].integration_id;
  const { rows } = await client.query(
    `INSERT INTO integration_feeds (key, name, source_url, schedule_cron, active, integration_id)
     VALUES ($1, $2, 'https://example.test/itest', '0 * * * *', TRUE, gen_random_uuid())
     RETURNING integration_id`,
    [key, `ITest ${MARK}`]
  );
  return rows[0].integration_id;
}

async function insertIoc(client, {
  value,
  type,
  legacy = 'unknown',
  sourceName = 'AlienVault OTX',
  iocSourceId = null
}) {
  const { rows } = await client.query(
    `INSERT INTO ioc_items (
       public_id, observable, observable_type, source_name, confidence, category, note,
       threat_classification, status, created_at, last_seen_at, ioc_source_id
     ) VALUES (
       gen_random_uuid(), $1, $2, $3, 'medium', 'itest', $4, $5, 'active', NOW(), NOW(), $6
     ) RETURNING id, observable_type, observable, threat_classification, ioc_source_id, source_name`,
    [value, type, sourceName, `${MARK}`, legacy, iocSourceId]
  );
  return rows[0];
}

async function insertEvidence(client, ioc, feedId, { category = null, note = null, sourceName = null } = {}) {
  await client.query(
    `INSERT INTO ioc_feed_source_evidence (
       ioc_item_id, ioc_observable_type, feed_id, source_name, category, note
     ) VALUES ($1, $2, $3, $4, $5, $6)`,
    [ioc.id, ioc.observable_type, feedId, sourceName || ioc.source_name, category, note]
  );
}

async function insertJunction(client, ioc, slug, sourceType = 'analyst') {
  await client.query(
    `INSERT INTO ioc_threat_classifications
       (ioc_id, ioc_observable_type, classification_slug, source_type, source_name)
     VALUES ($1, $2, $3, $4, 'ui')`,
    [ioc.id, ioc.observable_type, slug, sourceType]
  );
}

async function insertSuppress(client, ioc, slug, sourceName = null) {
  await client.query(
    `INSERT INTO ioc_threat_classification_overrides
       (ioc_id, ioc_observable_type, classification_slug, action, source_name, created_by)
     VALUES ($1, $2, $3, 'suppress', $4, 'itest')`,
    [ioc.id, ioc.observable_type, slug, sourceName]
  );
}

async function dslMatches(client, query, ioc) {
  const { ast } = parseSearchQuery(query);
  const { sql, params } = buildWhereClause(ast, { fileArtifactsReadEnabled: false });
  const idIdx = params.length + 1;
  const typeIdx = params.length + 2;
  const { rows } = await client.query(
    `SELECT i.id FROM ioc_items i
     WHERE i.id = $${idIdx} AND i.observable_type = $${typeIdx} AND (${sql})`,
    [...params, ioc.id, ioc.observable_type]
  );
  return rows.length === 1;
}

describe('canonical classification real-Postgres parity', () => {
  after(async () => {
    if (pool) await pool.end();
  });

  it('SQL vocabulary function matches JS normalizeFeedTags for representative evidence', opts, async () => {
    await inTx(async (client) => {
      const samples = [
        { category: 'botnet_cc', note: null, expect: ['command_and_control'] },
        { category: null, note: 'x | tags=infostealer,malware_download', expect: ['credential_theft', 'dropper_downloader'] },
        { category: null, note: 'x | signature=Mirai', expect: ['botnet'] },
        { category: null, note: 'x | signature=LockBit', expect: ['ransomware'] },
        { category: 'CLOSEDQUORUM', note: 'tags=CLOSEDQUORUM,exe', expect: [] },
        { category: 'payload', note: 'threat_type=payload', expect: [] }
      ];
      for (const s of samples) {
        const { rows } = await client.query(
          `SELECT ${FEED_EVIDENCE_CLASSIFICATION_FN}($1, $2) AS slugs`,
          [s.category, s.note]
        );
        const sqlSlugs = [...(rows[0].slugs || [])].sort();
        const js = normalizeFeedTags({
          sourceName: 't',
          category: s.category,
          rawTags: [],
          signature: null,
          note: s.note
        });
        // normalizeFeedTags reads tags/signature from structured args; mirror parseNoteFields.
        const { parseNoteFields } = await import('./feedTagNormalization.js');
        const parsed = parseNoteFields(s.note);
        const rawTags = parsed.tags
          ? String(parsed.tags).split(',').map((t) => t.trim()).filter(Boolean)
          : [];
        const jsFull = normalizeFeedTags({
          sourceName: 't',
          category: s.category,
          rawTags,
          signature: parsed.signature || null
        });
        assert.deepEqual(
          sqlSlugs,
          jsFull.classifications.map((c) => c.value).sort(),
          `category=${s.category} note=${s.note}`
        );
        assert.deepEqual(sqlSlugs, [...s.expect].sort());
      }
    });
  });

  it('feed proposal: detail === MCP === DSL match', opts, async () => {
    await inTx(async (client) => {
      const feedId = await ensureFeed(client);
      const ioc = await insertIoc(client, { value: `${MARK}-feed.example`, type: 'domain' });
      await insertEvidence(client, ioc, feedId, {
        note: 'Auto-imported | tags=infostealer',
        sourceName: 'AlienVault OTX'
      });
      const canonical = await loadCanonicalIocClassification(client, ioc);
      const hydrated = await hydrateIocApiMetadata(client, [ioc]);
      const meta = hydrated.get(iocPairKey(ioc.id, ioc.observable_type));
      assert.deepEqual(canonical.classifications, ['credential_theft']);
      assert.deepEqual(meta.classifications, ['credential_theft']);
      assert.deepEqual(meta.classification_context[0].sources[0], {
        type: 'feed',
        source_name: 'AlienVault OTX'
      });
      assert.equal(await dslMatches(client, 'classification equals "credential_theft"', ioc), true);
      assert.equal(await dslMatches(client, 'classification equals "malware"', ioc), false);
    });
  });

  it('feed suppression removes DSL/detail match unless analyst re-asserts', opts, async () => {
    await inTx(async (client) => {
      const feedId = await ensureFeed(client);
      const ioc = await insertIoc(client, { value: `${MARK}-suppress.example`, type: 'domain' });
      await insertEvidence(client, ioc, feedId, {
        note: 'tags=infostealer',
        sourceName: 'AlienVault OTX'
      });
      await insertSuppress(client, ioc, 'credential_theft');
      let canonical = await loadCanonicalIocClassification(client, ioc);
      assert.deepEqual(canonical.classifications, []);
      assert.equal(await dslMatches(client, 'classification equals "credential_theft"', ioc), false);

      await insertJunction(client, ioc, 'credential_theft', 'analyst');
      canonical = await loadCanonicalIocClassification(client, ioc);
      assert.deepEqual(canonical.classifications, ['credential_theft']);
      assert.deepEqual(canonical.classification_context[0].sources, [{ type: 'analyst' }]);
      assert.equal(await dslMatches(client, 'classification equals "credential_theft"', ioc), true);
    });
  });

  it('analyst-only and feed+analyst different values are both searchable', opts, async () => {
    await inTx(async (client) => {
      const feedId = await ensureFeed(client);
      const analystOnly = await insertIoc(client, { value: `${MARK}-analyst.example`, type: 'domain' });
      await insertJunction(client, analystOnly, 'credential_theft', 'analyst');
      assert.equal(await dslMatches(client, 'classification equals "credential_theft"', analystOnly), true);

      const both = await insertIoc(client, { value: `${MARK}-both.example`, type: 'domain' });
      await insertEvidence(client, both, feedId, { note: 'tags=trojan', sourceName: 'URLhaus' });
      await insertJunction(client, both, 'credential_theft', 'analyst');
      const canonical = await loadCanonicalIocClassification(client, both);
      assert.deepEqual(canonical.classifications, ['credential_theft', 'malware']);
      assert.equal(await dslMatches(client, 'classification equals "malware"', both), true);
      assert.equal(await dslMatches(client, 'classification equals "credential_theft"', both), true);
    });
  });

  it('provider legacy column is feed provenance and DSL-searchable', opts, async () => {
    await inTx(async (client) => {
      const ioc = await insertIoc(client, {
        value: hex(32),
        type: 'md5',
        legacy: 'dropper_downloader',
        sourceName: 'ThreatFox:abuse.ch',
        iocSourceId: null
      });
      const canonical = await loadCanonicalIocClassification(client, ioc);
      assert.deepEqual(canonical.classifications, ['dropper_downloader']);
      assert.equal(canonical.classification_context[0].sources[0].type, 'feed');
      assert.equal(canonical.classification_context[0].sources[0].source_name, 'ThreatFox:abuse.ch');
      assert.deepEqual(canonical.analyst, []);
      assert.equal(await dslMatches(client, 'classification equals "dropper_downloader"', ioc), true);
    });
  });

  it('hash aliases share effective classification under file-artifact scope', opts, async () => {
    process.env.FILE_ARTIFACTS_READ_ENABLED = '1';
    try {
      await inTx(async (client) => {
        const md5 = await insertIoc(client, { value: hex(32), type: 'md5', sourceName: 'feed' });
        const sha256 = await insertIoc(client, { value: hex(64), type: 'sha256', sourceName: 'feed' });
        await insertJunction(client, md5, 'malware', 'analyst');

        const { rows: arts } = await client.query(
          `INSERT INTO file_artifacts (status) VALUES ('active') RETURNING id`
        );
        const artifactId = arts[0].id;
        await client.query(
          `INSERT INTO file_artifact_hashes (artifact_id, hash_type, normalized_hash_value, is_primary)
           VALUES ($1, 'sha256', $2, TRUE), ($1, 'md5', $3, FALSE)`,
          [artifactId, sha256.observable, md5.observable]
        );
        await client.query(
          `INSERT INTO file_artifact_ioc_links
             (artifact_id, ioc_item_id, ioc_observable_type, ioc_public_id, is_canonical_ioc)
           SELECT $1, i.id, i.observable_type, i.public_id, (i.observable_type = 'sha256')
           FROM ioc_items i WHERE i.id = ANY($2::bigint[])`,
          [artifactId, [md5.id, sha256.id]]
        );

        const fromSha = await loadCanonicalIocClassification(client, {
          id: sha256.id,
          observable_type: 'sha256'
        });
        const fromMd5 = await loadCanonicalIocClassification(client, {
          id: md5.id,
          observable_type: 'md5'
        });
        assert.deepEqual(fromSha.classifications, ['malware']);
        assert.deepEqual(fromMd5.classifications, ['malware']);
      });
    } finally {
      delete process.env.FILE_ARTIFACTS_READ_ENABLED;
    }
  });

  it('negated classification excludes the logical identity', opts, async () => {
    await inTx(async (client) => {
      const feedId = await ensureFeed(client);
      const hit = await insertIoc(client, { value: `${MARK}-neg-hit.example`, type: 'domain' });
      const miss = await insertIoc(client, { value: `${MARK}-neg-miss.example`, type: 'domain' });
      await insertEvidence(client, hit, feedId, { note: 'tags=infostealer', sourceName: 'AlienVault OTX' });
      assert.equal(await dslMatches(client, 'classification not_equals "credential_theft"', hit), false);
      assert.equal(await dslMatches(client, 'NOT classification equals "credential_theft"', hit), false);
      assert.equal(await dslMatches(client, 'classification not_equals "credential_theft"', miss), true);
    });
  });

  it('pure computeCanonical matches loader for a composed identity', opts, async () => {
    await inTx(async (client) => {
      const feedId = await ensureFeed(client);
      const ioc = await insertIoc(client, {
        value: `${MARK}-compose.example`,
        type: 'domain',
        legacy: 'phishing',
        sourceName: 'PhishTank'
      });
      await insertEvidence(client, ioc, feedId, {
        note: 'tags=infostealer',
        sourceName: 'AlienVault OTX'
      });
      await insertJunction(client, ioc, 'malware', 'analyst');
      await insertSuppress(client, ioc, 'credential_theft');
      const loaded = await loadCanonicalIocClassification(client, ioc);
      const pure = computeCanonicalIocClassifications({
        rows: [{
          threat_classification: 'phishing',
          ioc_source_id: null,
          source_name: 'PhishTank',
          feed: [{ value: 'credential_theft', source_names: ['AlienVault OTX'] }],
          junction: [{ slug: 'malware', source_type: 'analyst' }],
          suppressions: [{ classification_slug: 'credential_theft', source_name: null }]
        }]
      });
      assert.deepEqual(loaded.classifications, pure.classifications);
      assert.deepEqual(loaded.classifications, ['malware', 'phishing']);
    });
  });
});
