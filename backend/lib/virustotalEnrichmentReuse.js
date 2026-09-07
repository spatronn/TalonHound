/**
 * Reuse a single VirusTotal file result across exact-hash aliases of one file.
 *
 * A VirusTotal file report describes a FILE ARTIFACT and carries every hash of
 * that file (md5/sha1/sha256). TalonHound may hold several linked `ioc_items`
 * rows for the same file (a canonical SHA256 plus SHA1/MD5 aliases), but a VT
 * enrichment row in `ioc_enrichments` is persisted against the single `ioc_id`
 * that was enriched. When the detail page then canonicalizes to a different
 * linked IOC, a lookup by that IOC's own `ioc_id` misses the stored result and
 * the UI wrongly shows "enrichment has not been run yet" — tempting a second,
 * quota-consuming provider request.
 *
 * This resolver looks up the VT row for an IOC and, only when the IOC has no row
 * of its own, reuses a successful VT result stored against a proven exact-hash
 * alias of the SAME file artifact. It performs NO provider request — it is a pure
 * database read — so one VT lookup suffices for every hash of the file.
 *
 * Reuse is limited to `status='success'` rows from artifact-linked aliases (exact
 * hashes proven to belong to the same file). It never reaches across unrelated
 * hashes, never does fuzzy matching, and never creates IOC rows.
 */

import { VT_PROVIDER } from './virustotalEnrichment.js';
import { findArtifactLinkedIocsByIocId } from './fileArtifacts/read.js';

const VT_ROW_COLUMNS = 'ioc_id, status, ioc_type, normalized_summary, error_message, fetched_at, expires_at';

/**
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {number|string} iocId
 * @param {{ findLinked?: (db:any, id:number|string)=>Promise<{linked_ioc_ids:number[]}|null> }} [opts]
 * @returns {Promise<{ row: object|null, reusedFromAlias: boolean }>}
 */
export async function resolveVtEnrichmentRow(db, iocId, opts = {}) {
  const findLinked = opts.findLinked || findArtifactLinkedIocsByIocId;

  // 1) The IOC's own VT row wins (any status — success/not_found/error), so direct
  //    enrichment and the existing refresh policy are completely unchanged.
  const direct = await db.query(
    `SELECT ${VT_ROW_COLUMNS} FROM ioc_enrichments WHERE provider=$1 AND ioc_id=$2 LIMIT 1`,
    [VT_PROVIDER, iocId]
  );
  if (direct.rowCount) return { row: direct.rows[0], reusedFromAlias: false };

  // 2) No own row — reuse a successful VT result from an exact-hash alias of the
  //    same file artifact, if any. Read-only; no provider call.
  const linked = await findLinked(db, iocId);
  const otherIds = (linked?.linked_ioc_ids || [])
    .map((n) => Number(n))
    .filter((n) => Number.isFinite(n) && n !== Number(iocId));
  if (!otherIds.length) return { row: null, reusedFromAlias: false };

  const alt = await db.query(
    `SELECT ${VT_ROW_COLUMNS}
     FROM ioc_enrichments
     WHERE provider=$1 AND ioc_id = ANY($2::bigint[]) AND status='success'
     ORDER BY fetched_at DESC NULLS LAST
     LIMIT 1`,
    [VT_PROVIDER, otherIds]
  );
  if (alt.rowCount) return { row: alt.rows[0], reusedFromAlias: true };
  return { row: null, reusedFromAlias: false };
}
