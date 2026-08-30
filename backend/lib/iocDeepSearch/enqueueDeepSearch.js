// Shared "enqueue a Deep Search" helper, used by both the interactive search route (when a
// query is classified expensive) and the statement-timeout fallback in the search handler
// (when an interactive query is cancelled by the DB). Keeping it in one place guarantees the
// classified path and the fallback path create identical jobs: same de-dup, same concurrency
// guard, same audit + structured log.

import { AUDIT_ACTION, AUDIT_SEVERITY } from '../auditConstants.js';
import { getDeepSearchConfig, DEEP_SEARCH_QUEUE_NAME } from './deepSearchConfig.js';
import { queryFingerprint } from './deepSearchStatus.js';
import {
  createDeepSearch,
  findActiveDuplicate,
  countActiveForUser,
  setJobId
} from './deepSearchStore.js';

/**
 * @returns {Promise<{ row: object, deduped: boolean }>}
 * @throws  {Error & { status?: number }} 401 when no actor email; 429 when over concurrency.
 */
export async function enqueueDeepSearch(pool, deepSearchQueue, {
  originalQuery,
  normalizedQuery,
  normalizedAst,
  classificationReason,
  origin = 'classified',
  requestedById = null,
  requestedByEmail,
  auditLogService = null,
  logger = null,
  req = null
}) {
  const cfg = getDeepSearchConfig();
  const email = String(requestedByEmail || '').trim();
  const ownerId = Number.isFinite(Number(requestedById)) ? Number(requestedById) : null;
  if (!email || !ownerId) {
    const err = new Error('Authentication required');
    err.status = 401;
    throw err;
  }

  const fingerprint = queryFingerprint(normalizedQuery);

  // Per-user in-flight de-dup: reuse an identical queued/running search instead of spawning a
  // duplicate. Scoped by immutable user id — never across users / recycled emails.
  const existing = await findActiveDuplicate(pool, { userId: ownerId, queryFingerprint: fingerprint });
  if (existing) {
    logger?.info?.('deep_search queued (deduped)', {
      event: 'deep_search.queued',
      deep_search_id: existing.id,
      deduped: true,
      origin,
      reason: classificationReason || null,
      query_fingerprint: fingerprint
    });
    return { row: existing, deduped: true };
  }

  const active = await countActiveForUser(pool, ownerId);
  if (active >= cfg.maxConcurrentPerUser) {
    const err = new Error(
      `You already have ${active} active deep search(es). Wait for one to finish (limit ${cfg.maxConcurrentPerUser}).`
    );
    err.status = 429;
    throw err;
  }

  const row = await createDeepSearch(pool, {
    originalQuery,
    normalizedQuery,
    normalizedAst,
    queryFingerprint: fingerprint,
    classificationReason: classificationReason || null,
    origin,
    requestedById: Number.isFinite(Number(requestedById)) ? Number(requestedById) : null,
    requestedByEmail: email
  });

  const job = await deepSearchQueue.add(
    'deep-search',
    { deepSearchId: row.id },
    { removeOnComplete: 100, removeOnFail: 200, attempts: 1 }
  );
  await setJobId(pool, row.id, String(job.id));

  if (auditLogService) {
    const event = {
      action: AUDIT_ACTION.IOC_DEEP_SEARCH_CREATED,
      entityType: 'ioc_deep_search',
      entityId: row.id,
      entityDisplay: String(normalizedQuery).slice(0, 200),
      severity: AUDIT_SEVERITY.INFO,
      metadata: {
        deep_search_id: row.id,
        normalized_query: normalizedQuery,
        origin,
        classification_reason: classificationReason || null
      }
    };
    if (req) event.req = req;
    else { event.actorEmail = email; event.actorUsername = email; }
    await auditLogService.auditSuccess(event);
  }

  logger?.info?.('deep_search queued', {
    event: 'deep_search.queued',
    deep_search_id: row.id,
    deduped: false,
    origin,
    reason: classificationReason || null,
    queue: DEEP_SEARCH_QUEUE_NAME,
    query_fingerprint: fingerprint
  });

  return { row, deduped: false };
}
