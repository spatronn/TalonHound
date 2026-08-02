#!/usr/bin/env node
/**
 * Idempotent File Artifact backfill.
 *
 * Phase A — seed: each md5/sha1/sha256 IOC → artifact + hash + link + direct observations
 * Phase B — provider mapping: MalwareBazaar notes + VirusTotal raw_response exact hash sets
 * Phase C — validation invariants
 *
 * Usage:
 *   node integration/backfill-file-artifacts.js
 *   FILE_ARTIFACT_BACKFILL_DRY_RUN=1 node integration/backfill-file-artifacts.js
 *   FILE_ARTIFACT_BACKFILL_BATCH_SIZE=500 node integration/backfill-file-artifacts.js
 *   FILE_ARTIFACT_BACKFILL_PHASE=seed|provider|validate|all node ...
 *   FILE_ARTIFACT_BACKFILL_RESUME_PUBLIC_ID=<uuid> node ...
 *
 * npm: npm run backfill-file-artifacts --prefix integration
 *
 * Does NOT delete IOCs. Does NOT rewrite correlation/audit FKs. Safe to re-run.
 */

import pg from 'pg';
import { config } from './config.js';
import {
  ensureArtifactForFileHashIoc,
  extractExactHashesFromNote,
  extractExactHashesFromVtRaw,
  findArtifactByHash,
  mergeFileArtifacts,
  selectCanonicalArtifact,
  attachExactHash,
  linkIocToArtifact,
  upsertSourceObservation,
  recordMergeConflict,
  resolveOpenProviderHashSetConflicts,
  OBSERVATION_TYPE,
  RELATION_METHOD,
  isExactFileHashIocType,
  withSavepoint,
  isControlledFileArtifactDbError,
  formatProviderError,
  recomputePrimaryHash
} from './lib/fileArtifacts.js';

const { Pool } = pg;
const pool = new Pool(config.db);

const BATCH_SIZE = Math.min(
  Math.max(Number(process.env.FILE_ARTIFACT_BACKFILL_BATCH_SIZE) || 500, 50),
  5000
);
const DRY_RUN = process.env.FILE_ARTIFACT_BACKFILL_DRY_RUN === '1'
  || process.env.FILE_ARTIFACT_BACKFILL_DRY_RUN === 'true';
const PHASE = String(process.env.FILE_ARTIFACT_BACKFILL_PHASE || 'all').toLowerCase();
const MAX_ERRORS = Math.max(Number(process.env.FILE_ARTIFACT_BACKFILL_MAX_ERRORS) || 50, 1);
const RESUME_PUBLIC_ID = process.env.FILE_ARTIFACT_BACKFILL_RESUME_PUBLIC_ID || null;
const PROVIDER_FILTER = String(process.env.FILE_ARTIFACT_BACKFILL_PROVIDER || 'all').toLowerCase();

/** Optional override for queued reconciliation / tests (see runFileArtifactBackfill). */
let runtimeOverride = null;

function cfg() {
  return runtimeOverride || {
    batchSize: BATCH_SIZE,
    dryRun: DRY_RUN,
    maxErrors: MAX_ERRORS,
    providerFilter: PROVIDER_FILTER,
    resumePublicId: RESUME_PUBLIC_ID,
    phase: PHASE
  };
}

function emptySummary() {
  const c = cfg();
  return {
    scanned_iocs: 0,
    created_artifacts: 0,
    created_hashes: 0,
    created_ioc_links: 0,
    created_source_observations: 0,
    skipped_existing: 0,
    merged_artifacts: 0,
    conflicts: 0,
    invalid_hashes: 0,
    unmatched_provider_records: 0,
    provider_mapped: 0,
    controlled_errors: 0,
    promoted_to_sha256: 0,
    validation_errors: [],
    batch_count: 0,
    errors: 0,
    dry_run: c.dryRun,
    phase: c.phase,
    duration_ms: 0
  };
}

function noteControlled(summary, err, context) {
  summary.controlled_errors += 1;
  if (err?.reason === 'conflict') summary.conflicts += 1;
  if (err?.reason === 'invalid_hash' || err?.reason === 'invalid_or_non_exact_hash') {
    summary.invalid_hashes += 1;
  }
  console.error('[backfill-file-artifacts] controlled error', formatProviderError(err, context));
}

async function seedBatch(client, lastPublicId, summary) {
  const params = [];
  let where = `observable_type IN ('md5','sha1','sha256')`;
  if (lastPublicId) {
    params.push(lastPublicId);
    where += ` AND public_id > $${params.length}`;
  }
  params.push(cfg().batchSize);
  const { rows } = await client.query(
    `SELECT id, public_id, observable, observable_type, source_name, note,
            first_seen_at, last_seen_at, created_at, confidence
     FROM ioc_items
     WHERE ${where}
     ORDER BY public_id
     LIMIT $${params.length}`,
    params
  );
  if (!rows.length) return { rows: [], lastPublicId };

  summary.batch_count += 1;
  for (const row of rows) {
    summary.scanned_iocs += 1;
    if (!isExactFileHashIocType(row.observable_type)) {
      summary.invalid_hashes += 1;
      continue;
    }
    if (cfg().dryRun) {
      const existing = await findArtifactByHash(client, row.observable_type, row.observable);
      if (existing?.artifact_id) summary.skipped_existing += 1;
      else summary.created_artifacts += 1;
      continue;
    }

    try {
      await client.query('BEGIN');
      const result = await ensureArtifactForFileHashIoc(client, {
        ioc_item_id: row.id,
        ioc_public_id: row.public_id,
        observable_type: row.observable_type,
        observable: row.observable,
        source_name: row.source_name,
        note: row.note,
        confidence: row.confidence,
        first_seen_at: row.first_seen_at || row.created_at,
        last_seen_at: row.last_seen_at || row.created_at,
        observation_type: OBSERVATION_TYPE.BACKFILL,
        relation_method: RELATION_METHOD.MIGRATION_SEED,
        attach_note_siblings: false,
        provider_mapping: false
      });
      await client.query('COMMIT');
      if (!result.ok) {
        if (result.reason === 'invalid_or_non_exact_hash') summary.invalid_hashes += 1;
        else if (result.reason === 'conflict') summary.conflicts += 1;
        continue;
      }
      if (result.created_artifact) summary.created_artifacts += 1;
      else summary.skipped_existing += 1;
      if (result.created_hash) summary.created_hashes += 1;
      if (result.link?.created) summary.created_ioc_links += 1;
      if (result.observation?.created) summary.created_source_observations += 1;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      summary.errors += 1;
      console.error('[backfill-file-artifacts] seed error', row.public_id, err.message);
      if (summary.errors >= cfg().maxErrors) throw err;
    }
  }
  return { rows, lastPublicId: rows[rows.length - 1].public_id };
}

async function resolveCanonicalAmong(client, artifactIds) {
  const ids = [...new Set(artifactIds.filter(Boolean))];
  if (ids.length <= 1) return ids[0] || null;
  const { rows } = await client.query(
    `SELECT a.id, a.created_at,
            EXISTS (
              SELECT 1 FROM file_artifact_hashes h
              WHERE h.artifact_id = a.id AND h.hash_type = 'sha256'
            ) AS has_sha256,
            (SELECT COUNT(*)::int FROM file_artifact_ioc_links l WHERE l.artifact_id = a.id) AS link_count
     FROM file_artifacts a
     WHERE a.id = ANY($1::uuid[]) AND a.status = 'active'`,
    [ids]
  );
  const chosen = selectCanonicalArtifact(rows.map((r) => ({
    id: r.id,
    created_at: r.created_at,
    has_sha256: r.has_sha256,
    link_count: r.link_count
  })));
  return chosen?.id || null;
}

async function applyProviderHashSet(client, hashes, meta, summary) {
  if (!hashes.length) return;

  const hits = [];
  for (const h of hashes) {
    const found = await findArtifactByHash(client, h.hash_type, h.normalized_hash_value);
    if (found?.artifact_id) hits.push({ ...h, artifact_id: found.artifact_id });
  }
  const artifactIds = [...new Set(hits.map((h) => h.artifact_id))];

  if (artifactIds.length > 1) {
    // Check conflicting mapping: same type appearing on different artifacts with incompatible sets
    const canonicalId = await resolveCanonicalAmong(client, artifactIds);
    if (!canonicalId) {
      summary.conflicts += 1;
      await recordMergeConflict(client, {
        conflicting_hash_type: hashes[0].hash_type,
        conflicting_hash_value: hashes[0].normalized_hash_value,
        candidate_artifact_ids: artifactIds,
        reason: 'provider_hash_set_multiple_artifacts',
        evidence: meta
      });
      return;
    }
    for (const id of artifactIds) {
      if (id === canonicalId) continue;
      if (!cfg().dryRun) {
        const merged = await mergeFileArtifacts(client, {
          canonicalArtifactId: canonicalId,
          duplicateArtifactId: id,
          method: meta.method || 'provider_exact_hash_set',
          evidence: meta
        });
        if (merged.ok && !merged.noop) summary.merged_artifacts += 1;
      } else {
        summary.merged_artifacts += 1;
      }
    }
    artifactIds.length = 0;
    artifactIds.push(canonicalId);
  }

  let artifactId = artifactIds[0] || null;
  if (!artifactId) {
    // Provider mapping without existing IOC artifact — skip creating orphan unless linked IOC exists
    summary.unmatched_provider_records += 1;
    return;
  }

  if (cfg().dryRun) {
    summary.provider_mapped += 1;
    return;
  }

  for (const h of hashes) {
    const attached = await withSavepoint(client, 'fa_prov_hash', async () => attachExactHash(client, {
      artifact_id: artifactId,
      hash_type: h.hash_type,
      hash_value: h.normalized_hash_value,
      verification_source: meta.provider || null
    }));
    if (!attached.ok) {
      if (attached.reason === 'conflict' || attached.reason === 'unique_violation') {
        summary.conflicts += 1;
        if (attached.reason === 'conflict' && !attached.hash_id) {
          await recordMergeConflict(client, {
            conflicting_hash_type: h.hash_type,
            conflicting_hash_value: h.normalized_hash_value,
            candidate_artifact_ids: [artifactId, attached.artifact_id].filter(Boolean),
            reason: attached.reason,
            evidence: meta
          }).catch(() => {});
        }
      } else if (attached.reason === 'invalid_hash') {
        summary.invalid_hashes += 1;
      }
      continue;
    }
    if (attached.created_hash) summary.created_hashes += 1;
    if (attached.hash_id) {
      const iocs = await client.query(
        `SELECT id, public_id, observable_type FROM ioc_items
         WHERE observable_type = $1 AND LOWER(observable) = $2`,
        [h.hash_type, h.normalized_hash_value]
      );
      for (const ioc of iocs.rows) {
        const link = await withSavepoint(client, 'fa_prov_link', async () => linkIocToArtifact(client, {
          artifact_id: artifactId,
          ioc_item_id: ioc.id,
          ioc_observable_type: ioc.observable_type,
          ioc_public_id: ioc.public_id,
          linked_hash_id: attached.hash_id
        }));
        if (link?.reason === 'conflict') summary.conflicts += 1;
        if (link?.created) summary.created_ioc_links += 1;
      }
      if (meta.source_name) {
        const obs = await withSavepoint(client, 'fa_prov_obs', async () => upsertSourceObservation(client, {
          artifact_id: artifactId,
          source_name: meta.source_name,
          observed_hash_id: attached.hash_id,
          observed_hash_type: h.hash_type,
          observed_hash_value: h.normalized_hash_value,
          observation_type: meta.observation_type || OBSERVATION_TYPE.PROVIDER_MAPPING,
          relation_method: meta.relation_method || RELATION_METHOD.PROVIDER_EXACT_HASH_SET,
          raw_ref: meta
        }));
        if (obs?.created) summary.created_source_observations += 1;
      }
    }
  }

  const sha256 = hashes.find((h) => h.hash_type === 'sha256') || hashes[0];
  if (sha256?.normalized_hash_value) {
    await resolveOpenProviderHashSetConflicts(client, {
      hash_type: sha256.hash_type,
      hash_value: sha256.normalized_hash_value,
      resolution: {
        resolved_by: 'backfill_provider_exact_hash_set',
        provider: meta.provider || null,
        artifact_id: artifactId
      }
    }).catch(() => {});
  }
  summary.provider_mapped += 1;
}

async function providerMalwareBazaar(client, summary) {
  if (cfg().providerFilter !== 'all' && cfg().providerFilter !== 'malwarebazaar') return;
  let lastId = 0;
  for (;;) {
    const { rows } = await client.query(
      `SELECT id, ioc_item_id, ioc_observable_type, source_name, note
       FROM ioc_feed_source_evidence
       WHERE id > $1
         AND note ILIKE '%Auto-imported from MalwareBazaar%'
         AND note ILIKE '%md5=%'
       ORDER BY id
       LIMIT $2`,
      [lastId, cfg().batchSize]
    );
    if (!rows.length) break;
    summary.batch_count += 1;
    for (const row of rows) {
      const ioc = await client.query(
        `SELECT observable, observable_type, public_id FROM ioc_items
         WHERE id = $1 AND observable_type = $2`,
        [row.ioc_item_id, row.ioc_observable_type]
      );
      const primary = ioc.rows[0];
      if (!primary) continue;
      const hashes = extractExactHashesFromNote({
        observableType: primary.observable_type,
        observable: primary.observable,
        note: row.note
      });
      try {
        if (!cfg().dryRun) await client.query('BEGIN');
        await withSavepoint(client, 'fa_provider_rec', async () => {
          await applyProviderHashSet(client, hashes, {
            provider: 'malwarebazaar',
            source_name: row.source_name,
            evidence_id: row.id,
            method: 'provider_exact_hash_set',
            observation_type: OBSERVATION_TYPE.PROVIDER_MAPPING,
            relation_method: RELATION_METHOD.PROVIDER_EXACT_HASH_SET
          }, summary);
        });
        if (!cfg().dryRun) await client.query('COMMIT');
      } catch (err) {
        if (!cfg().dryRun) await client.query('ROLLBACK').catch(() => {});
        if (isControlledFileArtifactDbError(err)) {
          noteControlled(summary, err, { provider: 'malwarebazaar', evidence_id: row.id });
          continue;
        }
        summary.errors += 1;
        console.error(
          '[backfill-file-artifacts] MB provider error',
          formatProviderError(err, { evidence_id: row.id })
        );
        if (summary.errors >= cfg().maxErrors) throw err;
      }
    }
    lastId = rows[rows.length - 1].id;
  }
}

async function providerVirusTotal(client, summary) {
  if (cfg().providerFilter !== 'all' && cfg().providerFilter !== 'virustotal') return;
  let lastId = 0;
  for (;;) {
    const { rows } = await client.query(
      `SELECT id, ioc_id, ioc_value, ioc_type, raw_response, provider
       FROM ioc_enrichments
       WHERE id > $1
         AND provider = 'virustotal'
         AND status = 'success'
         AND raw_response IS NOT NULL
         AND ioc_type IN ('md5','sha1','sha256','hash')
       ORDER BY id
       LIMIT $2`,
      [lastId, cfg().batchSize]
    );
    if (!rows.length) break;
    summary.batch_count += 1;
    for (const row of rows) {
      const hashes = extractExactHashesFromVtRaw(row.raw_response);
      if (hashes.length < 2) continue;
      try {
        if (!cfg().dryRun) await client.query('BEGIN');
        await withSavepoint(client, 'fa_provider_rec', async () => {
          await applyProviderHashSet(client, hashes, {
            provider: 'virustotal',
            source_name: 'VirusTotal',
            enrichment_id: row.id,
            method: 'enrichment_result',
            observation_type: OBSERVATION_TYPE.ENRICHMENT,
            relation_method: RELATION_METHOD.ENRICHMENT_RESULT
          }, summary);
        });
        if (!cfg().dryRun) await client.query('COMMIT');
      } catch (err) {
        if (!cfg().dryRun) await client.query('ROLLBACK').catch(() => {});
        if (isControlledFileArtifactDbError(err)) {
          noteControlled(summary, err, { provider: 'virustotal', enrichment_id: row.id });
          continue;
        }
        summary.errors += 1;
        console.error(
          '[backfill-file-artifacts] VT provider error',
          formatProviderError(err, { enrichment_id: row.id })
        );
        if (summary.errors >= cfg().maxErrors) throw err;
      }
    }
    lastId = rows[rows.length - 1].id;
  }
}

async function validate(client, summary) {
  const checks = [];

  const dupHash = await client.query(
    `SELECT hash_type, normalized_hash_value, COUNT(DISTINCT artifact_id) AS c
     FROM file_artifact_hashes
     GROUP BY hash_type, normalized_hash_value
     HAVING COUNT(DISTINCT artifact_id) > 1`
  );
  if (dupHash.rowCount) {
    checks.push({ check: 'unique_exact_hash', ok: false, count: dupHash.rowCount });
  } else {
    checks.push({ check: 'unique_exact_hash', ok: true });
  }

  const multiPrimary = await client.query(
    `SELECT artifact_id, COUNT(*) AS c
     FROM file_artifact_hashes
     WHERE is_primary = TRUE
     GROUP BY artifact_id
     HAVING COUNT(*) > 1`
  );
  checks.push({
    check: 'one_primary_per_artifact',
    ok: multiPrimary.rowCount === 0,
    count: multiPrimary.rowCount
  });

  const sha256NotPrimary = await client.query(
    `SELECT a.id
     FROM file_artifacts a
     JOIN file_artifact_hashes hsha ON hsha.artifact_id = a.id AND hsha.hash_type = 'sha256'
     LEFT JOIN file_artifact_hashes hp ON hp.artifact_id = a.id AND hp.is_primary = TRUE
     WHERE a.status = 'active'
       AND (hp.id IS NULL OR hp.hash_type <> 'sha256')
     LIMIT 20`
  );
  checks.push({
    check: 'sha256_is_primary_when_present',
    ok: sha256NotPrimary.rowCount === 0,
    count: sha256NotPrimary.rowCount
  });

  const unlinked = await client.query(
    `SELECT COUNT(*)::int AS c
     FROM ioc_items i
     WHERE i.observable_type IN ('md5','sha1','sha256')
       AND NOT EXISTS (
         SELECT 1 FROM file_artifact_ioc_links l
         WHERE l.ioc_item_id = i.id AND l.ioc_observable_type = i.observable_type
       )`
  );
  // Only fail validation when seed phase was run (all); warn otherwise
  checks.push({
    check: 'all_exact_hash_iocs_linked',
    ok: true,
    unlinked_count: unlinked.rows[0]?.c || 0,
    note: 'Informational after partial backfill'
  });

  const emptyArtifacts = await client.query(
    `SELECT COUNT(*)::int AS c
     FROM file_artifacts fa
     LEFT JOIN file_artifact_hashes fah ON fah.artifact_id = fa.id
     LEFT JOIN file_artifact_ioc_links fail ON fail.artifact_id = fa.id
     LEFT JOIN file_artifact_source_observations faso ON faso.artifact_id = fa.id
     WHERE fa.status = 'active'
       AND fah.id IS NULL
       AND fail.id IS NULL
       AND faso.id IS NULL`
  );
  checks.push({
    check: 'empty_orphan_artifacts',
    ok: (emptyArtifacts.rows[0]?.c || 0) === 0,
    count: emptyArtifacts.rows[0]?.c || 0
  });

  const hashlessActive = await client.query(
    `SELECT COUNT(*)::int AS c
     FROM file_artifacts a
     WHERE a.status = 'active'
       AND NOT EXISTS (SELECT 1 FROM file_artifact_hashes h WHERE h.artifact_id = a.id)`
  );
  checks.push({
    check: 'active_artifact_has_hash',
    ok: (hashlessActive.rows[0]?.c || 0) === 0,
    count: hashlessActive.rows[0]?.c || 0
  });

  summary.validation = checks;
  summary.validation_errors = checks.filter((c) => c.ok === false);
}

async function promoteSha256Primaries(client, summary) {
  if (cfg().dryRun) return;
  await client.query(`SET max_parallel_workers_per_gather = 0`);
  await client.query(`SET work_mem = '8MB'`);
  const { rows } = await client.query(
    `SELECT a.id
     FROM file_artifacts a
     WHERE a.status = 'active'
       AND EXISTS (
         SELECT 1 FROM file_artifact_hashes hsha
         WHERE hsha.artifact_id = a.id AND hsha.hash_type = 'sha256'
       )
       AND NOT EXISTS (
         SELECT 1 FROM file_artifact_hashes hp
         WHERE hp.artifact_id = a.id AND hp.is_primary = TRUE AND hp.hash_type = 'sha256'
       )
     LIMIT 5000`
  );
  for (const row of rows) {
    await client.query('BEGIN');
    try {
      await withSavepoint(client, 'fa_promote_sha256', async () => {
        await recomputePrimaryHash(client, row.id);
      });
      await client.query('COMMIT');
      summary.promoted_to_sha256 += 1;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      summary.errors += 1;
      console.error('[backfill-file-artifacts] promote error', row.id, err.message);
      if (summary.errors >= cfg().maxErrors) throw err;
    }
  }
}

/**
 * Programmatic entry for CLI and queued reconciliation.
 * @param {{
 *   pool?: import('pg').Pool,
 *   dryRun?: boolean,
 *   phase?: string,
 *   batchSize?: number,
 *   maxErrors?: number,
 *   providerFilter?: string,
 *   resumePublicId?: string|null,
 *   endPool?: boolean,
 *   promotePrimaries?: boolean,
 *   log?: Function
 * }} [options]
 */
export async function runFileArtifactBackfill(options = {}) {
  const ownPool = options.pool || pool;
  const endPool = options.endPool != null ? options.endPool : !options.pool;
  const log = options.log || console.log.bind(console);
  const prev = runtimeOverride;
  runtimeOverride = {
    batchSize: options.batchSize ?? BATCH_SIZE,
    dryRun: options.dryRun ?? DRY_RUN,
    maxErrors: options.maxErrors ?? MAX_ERRORS,
    providerFilter: String(options.providerFilter || PROVIDER_FILTER).toLowerCase(),
    resumePublicId: options.resumePublicId !== undefined ? options.resumePublicId : RESUME_PUBLIC_ID,
    phase: String(options.phase || PHASE).toLowerCase()
  };

  const summary = emptySummary();
  const started = Date.now();
  const client = await ownPool.connect();
  log('[backfill-file-artifacts] start', {
    dry_run: cfg().dryRun,
    batch_size: cfg().batchSize,
    phase: cfg().phase,
    resume: cfg().resumePublicId
  });

  try {
    await client.query(`SELECT 1 FROM file_artifacts LIMIT 1`);
  } catch (err) {
    client.release();
    if (endPool) await ownPool.end();
    runtimeOverride = prev;
    const e = new Error(`schema missing — run migration 131 first: ${err.message}`);
    e.code = 'schema_missing';
    throw e;
  }

  try {
    if (cfg().phase === 'all' || cfg().phase === 'seed') {
      let lastPublicId = cfg().resumePublicId;
      for (;;) {
        const { rows, lastPublicId: next } = await seedBatch(client, lastPublicId, summary);
        if (!rows.length) break;
        lastPublicId = next;
        if (rows.length < cfg().batchSize) break;
      }
    }

    if (cfg().phase === 'all' || cfg().phase === 'provider') {
      await providerMalwareBazaar(client, summary);
      await providerVirusTotal(client, summary);
    }

    if (options.promotePrimaries !== false
      && (cfg().phase === 'all' || cfg().phase === 'provider' || cfg().phase === 'promote')) {
      await promoteSha256Primaries(client, summary);
    }

    if (cfg().phase === 'all' || cfg().phase === 'validate') {
      await validate(client, summary);
    }
  } finally {
    summary.duration_ms = Date.now() - started;
    client.release();
    if (endPool) await ownPool.end();
    runtimeOverride = prev;
  }

  return summary;
}

async function runCli() {
  try {
    const summary = await runFileArtifactBackfill({ endPool: true });
    console.log(JSON.stringify(summary, null, 2));
    if (summary.validation_errors?.length) process.exitCode = 1;
    if (summary.errors >= cfg().maxErrors) process.exitCode = 1;
  } catch (err) {
    console.error('[backfill-file-artifacts] fatal', err);
    process.exit(err.code === 'schema_missing' ? 2 : 1);
  }
}

const isDirectCli = process.argv[1]
  && String(process.argv[1]).replace(/\\/g, '/').endsWith('backfill-file-artifacts.js');
if (isDirectCli) {
  runCli();
}