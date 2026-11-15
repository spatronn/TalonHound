#!/usr/bin/env node
/**
 * Narrow, idempotent repair: re-apply VirusTotal exact hash sets from stored
 * ioc_enrichments.raw_response onto file artifacts that are missing the VT MD5.
 *
 * Does NOT call VirusTotal. Uses persisted provider evidence only.
 *
 * Usage (on host with DB access):
 *   node backend/scripts/repairVtMissingMd5Hashes.js --dry-run
 *   node backend/scripts/repairVtMissingMd5Hashes.js --apply
 *   node backend/scripts/repairVtMissingMd5Hashes.js --apply --artifact-id <uuid>
 */
import pg from 'pg';
import { dualWriteVirusTotalFileArtifact } from '../lib/virustotalFileArtifactDualWrite.js';

const { Pool } = pg;

function argFlag(name) {
  return process.argv.includes(name);
}
function argValue(name) {
  const idx = process.argv.indexOf(name);
  return idx >= 0 ? process.argv[idx + 1] : null;
}

const dryRun = !argFlag('--apply');
const onlyArtifact = argValue('--artifact-id');

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound'
});

const sql = `
WITH vt AS (
  SELECT
    e.id AS enrichment_id,
    e.ioc_id,
    e.ioc_type,
    e.ioc_value,
    e.raw_response,
    e.fetched_at,
    lower(COALESCE(
      e.raw_response->'data'->'attributes'->>'md5',
      e.normalized_summary->'file'->>'md5'
    )) AS vt_md5
  FROM ioc_enrichments e
  WHERE e.provider = 'virustotal'
    AND e.status = 'success'
    AND e.raw_response IS NOT NULL
    AND COALESCE(
      e.raw_response->'data'->'attributes'->>'md5',
      e.normalized_summary->'file'->>'md5'
    ) IS NOT NULL
),
linked AS (
  SELECT
    vt.*,
    i.id AS resolved_ioc_id,
    i.observable_type AS resolved_type,
    i.observable AS resolved_observable,
    COALESCE(a.merged_into_artifact_id, l.artifact_id) AS artifact_id
  FROM vt
  JOIN ioc_items i
    ON i.id = vt.ioc_id
    OR (i.observable_type = vt.ioc_type AND lower(i.observable) = lower(vt.ioc_value))
  JOIN file_artifact_ioc_links l
    ON l.ioc_item_id = i.id AND l.ioc_observable_type = i.observable_type
  JOIN file_artifacts a ON a.id = l.artifact_id
),
dedup AS (
  SELECT DISTINCT ON (artifact_id, vt_md5)
    enrichment_id, resolved_ioc_id, resolved_type, resolved_observable,
    fetched_at, vt_md5, artifact_id, raw_response
  FROM linked
  WHERE artifact_id IS NOT NULL
    AND vt_md5 ~ '^[0-9a-f]{32}$'
    AND ($1::uuid IS NULL OR artifact_id = $1::uuid)
  ORDER BY artifact_id, vt_md5, fetched_at DESC
)
SELECT d.*
FROM dedup d
WHERE NOT EXISTS (
  SELECT 1 FROM file_artifact_hashes h
  WHERE h.artifact_id = d.artifact_id
    AND h.hash_type = 'md5'
    AND h.normalized_hash_value = d.vt_md5
)
ORDER BY d.fetched_at DESC
`;

async function main() {
  const { rows } = await pool.query(sql, [onlyArtifact]);
  console.log(JSON.stringify({
    mode: dryRun ? 'dry-run' : 'apply',
    affected: rows.length,
    artifact_ids: rows.map((r) => r.artifact_id)
  }, null, 2));

  if (dryRun || !rows.length) {
    await pool.end();
    return;
  }

  let repaired = 0;
  let failed = 0;
  for (const row of rows) {
    const out = await dualWriteVirusTotalFileArtifact(pool, {
      iocId: Number(row.resolved_ioc_id),
      iocType: row.resolved_type,
      observable: row.resolved_observable,
      raw: row.raw_response
    });
    if (out?.ok) {
      repaired += 1;
      console.log(JSON.stringify({
        repaired: true,
        artifact_id: row.artifact_id,
        enrichment_id: row.enrichment_id,
        vt_md5: row.vt_md5
      }));
    } else {
      failed += 1;
      console.error(JSON.stringify({
        repaired: false,
        artifact_id: row.artifact_id,
        enrichment_id: row.enrichment_id
      }));
    }
  }
  console.log(JSON.stringify({ repaired, failed }, null, 2));
  await pool.end();
  if (failed) process.exitCode = 1;
}

main().catch(async (err) => {
  console.error(err);
  await pool.end().catch(() => {});
  process.exit(1);
});
