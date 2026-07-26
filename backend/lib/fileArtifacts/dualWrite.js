/**
 * Dual-write helpers after IOC insert/update.
 *
 * When dual-write runs inside an open import transaction, SQL failures must not
 * leave the outer transaction aborted (25P02). Work runs under a SAVEPOINT;
 * unexpected schema/integrity errors are rethrown with the original SQLSTATE so
 * job results show the root cause instead of a follow-on aborted-transaction message.
 */

import { isExactFileHashIocType } from './hashNormalize.js';
import { isFileArtifactsDualWriteEnabled } from './flags.js';
import { ensureArtifactForFileHashIoc } from './attach.js';
import { mergeFileArtifacts } from './merge.js';
import { selectCanonicalArtifact } from './metadataPolicy.js';
import { OBSERVATION_TYPE, RELATION_METHOD } from './observations.js';
import { resolveFeedIdBySourceName } from '../iocExpiration.js';
import {
  withSavepoint,
  isControlledFileArtifactDbError,
  formatProviderError
} from './txSavepoint.js';

/**
 * @param {any} err
 */
export function shouldRethrowDualWriteError(err) {
  if (!err) return false;
  if (isControlledFileArtifactDbError(err)) return false;
  return true;
}

/**
 * @param {{ warn?: Function }|undefined} logger
 * @param {string} label
 * @param {any} err
 * @param {object} [extra]
 */
function logDualWriteFailure(logger, label, err, extra = {}) {
  logger?.warn?.(label, {
    ...formatProviderError(err, extra),
    sqlState: err?.code || null,
    table: err?.table || null,
    column: err?.column || null
  });
}

/**
 * Safe dual-write wrapper for hash IOC rows already in hand.
 * @param {import('pg').Pool|import('pg').PoolClient} client
 * @param {object} input - ensureArtifactForFileHashIoc input
 * @param {{ logger?: { warn?: Function } }} opts
 */
export async function dualWriteFileArtifact(client, input, opts = {}) {
  if (!isFileArtifactsDualWriteEnabled()) {
    return { skipped: true, reason: 'dual_write_disabled' };
  }
  try {
    return await withSavepoint(client, 'fa_dual_write', () => ensureArtifactForFileHashIoc(client, input));
  } catch (err) {
    logDualWriteFailure(opts.logger, '[file-artifacts] dualWriteFileArtifact failed', err, {
      ioc_public_id: input?.ioc_public_id,
      observable: input?.observable
    });
    if (shouldRethrowDualWriteError(err)) throw err;
    return {
      ok: false,
      error: err?.message || String(err),
      code: err?.code || null
    };
  }
}

/**
 * Look up IOC row and dual-write artifact representation.
 *
 * @param {import('pg').Pool|import('pg').PoolClient} client
 * @param {{
 *   observable: string,
 *   observableType: string,
 *   sourceName?: string|null,
 *   feedId?: string|null,
 *   note?: string|null,
 *   confidence?: string|null,
 *   firstSeenAt?: string|Date|null,
 *   lastSeenAt?: string|Date|null,
 *   attachNoteSiblings?: boolean,
 *   providerMapping?: boolean,
 *   observationType?: string,
 *   relationMethod?: string,
 *   logger?: { warn?: Function }
 * }} input
 */
export async function dualWriteFileArtifactForObservable(client, input) {
  if (!isFileArtifactsDualWriteEnabled()) {
    return { skipped: true, reason: 'dual_write_disabled' };
  }
  if (!isExactFileHashIocType(input.observableType)) {
    return { skipped: true, reason: 'not_exact_hash' };
  }

  try {
    return await withSavepoint(client, 'fa_dual_write_obs', async () => {
      let row = null;
      const q = `SELECT id, public_id, observable, observable_type, note,
                        first_seen_at, last_seen_at, created_at, source_name
                 FROM ioc_items
                 WHERE observable = $1 AND observable_type = $2
                 ORDER BY created_at ASC
                 LIMIT 1`;
      const lower = await client.query(q, [
        String(input.observable || '').toLowerCase(),
        String(input.observableType || '').toLowerCase()
      ]);
      row = lower.rows[0] || null;
      if (!row) {
        const again = await client.query(q, [input.observable, input.observableType]);
        row = again.rows[0] || null;
      }
      if (!row) return { skipped: true, reason: 'ioc_not_found' };

      let feedId = input.feedId || null;
      if (!feedId && input.sourceName) {
        // integration_feeds has key/name — never source_name. Resolve via feed source rules.
        feedId = await resolveFeedIdBySourceName(client, input.sourceName);
      }

      const result = await ensureArtifactForFileHashIoc(client, {
        ioc_item_id: row.id,
        ioc_public_id: row.public_id,
        observable_type: row.observable_type,
        observable: row.observable,
        source_name: input.sourceName || row.source_name || null,
        feed_id: feedId,
        note: input.note != null ? input.note : row.note,
        confidence: input.confidence || null,
        first_seen_at: input.firstSeenAt || row.first_seen_at || row.created_at,
        last_seen_at: input.lastSeenAt || row.last_seen_at || row.created_at,
        attach_note_siblings: Boolean(input.attachNoteSiblings),
        provider_mapping: Boolean(input.providerMapping),
        observation_type: input.observationType || OBSERVATION_TYPE.DIRECT,
        relation_method: input.relationMethod || RELATION_METHOD.SAME_SOURCE_RECORD
      });

      const needsMerge = result?.siblings?.needs_merge_with;
      if (needsMerge && result?.artifact_id && needsMerge !== result.artifact_id) {
        const { rows: cands } = await client.query(
          `SELECT a.id,
                  a.created_at,
                  EXISTS (
                    SELECT 1 FROM file_artifact_hashes h
                    WHERE h.artifact_id = a.id AND h.hash_type = 'sha256'
                  ) AS has_sha256,
                  (SELECT COUNT(*)::int FROM file_artifact_ioc_links l WHERE l.artifact_id = a.id) AS link_count
           FROM file_artifacts a
           WHERE a.id = ANY($1::uuid[])`,
          [[result.artifact_id, needsMerge]]
        );
        const canonical = selectCanonicalArtifact(cands.map((r) => ({
          id: r.id,
          created_at: r.created_at,
          has_sha256: r.has_sha256,
          link_count: r.link_count
        })));
        if (canonical) {
          const duplicateId = canonical.id === result.artifact_id ? needsMerge : result.artifact_id;
          await mergeFileArtifacts(client, {
            canonicalArtifactId: canonical.id,
            duplicateArtifactId: duplicateId,
            method: 'provider_exact_hash_set',
            evidence: { source: input.sourceName || null }
          });
          result.merged_into = canonical.id;
        }
      }

      return result;
    });
  } catch (err) {
    logDualWriteFailure(
      input.logger,
      '[file-artifacts] dualWriteFileArtifactForObservable failed',
      err,
      {
        observable: input.observable,
        observableType: input.observableType,
        sourceName: input.sourceName || null
      }
    );
    if (shouldRethrowDualWriteError(err)) throw err;
    return {
      ok: false,
      error: err?.message || String(err),
      code: err?.code || null
    };
  }
}
