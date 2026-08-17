/**
 * Query-wide IOC bulk triage.
 *
 * PAGE mode stays on the explicit-ID routes (max 100). This module never accepts
 * a client ID list or a client-supplied match count. The backend re-parses the
 * executed DSL, rejects empty/unfiltered/expensive queries, and resolves the
 * canonical IOC List match set at execution time.
 */

import {
  parseSearchQuery,
  buildWhereClause,
  buildCanonicalResultSelectSql,
  classifyQuery,
  isDslError,
  getQueryTimeoutMs
} from './iocSearchDsl/index.js';
import { isFileArtifactsReadEnabled } from './fileArtifacts/flags.js';
import {
  bulkAddTag,
  bulkAddClassification,
  bulkSuppress,
  bulkExpire,
  BULK_TRIAGE_MAX_ITEMS
} from './iocBulkTriage.js';
import { getBulkQueryConfig } from './iocBulkQueryJob/config.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from './auditConstants.js';

export const QUERY_WIDE_ACTIONS = Object.freeze(['tag', 'classification', 'suppress', 'expire']);
const QUERY_CANCELED = '57014';

export function parseQueryWideRequest(body, action) {
  if (!QUERY_WIDE_ACTIONS.includes(action)) {
    return { ok: false, status: 400, code: 'INVALID_ACTION', message: 'Invalid bulk action' };
  }
  const mode = String(body?.selection_mode || '').trim();
  if (mode && mode !== 'all_matching') {
    return {
      ok: false,
      status: 400,
      code: 'INVALID_SELECTION_MODE',
      message: 'selection_mode must be all_matching'
    };
  }
  const query = String(body?.query ?? '');
  if (!query.trim()) {
    return {
      ok: false,
      status: 400,
      code: 'EMPTY_QUERY',
      message: 'Query-wide bulk requires a non-empty executed search query'
    };
  }
  return { ok: true, action, query };
}

export function compileQueryWideTarget(rawQuery) {
  const query = String(rawQuery ?? '');
  if (!query.trim()) {
    return {
      ok: false,
      status: 400,
      code: 'EMPTY_QUERY',
      message: 'Query-wide bulk requires a non-empty executed search query'
    };
  }
  let parsed;
  try {
    parsed = parseSearchQuery(query);
  } catch (err) {
    if (isDslError(err)) {
      return {
        ok: false,
        status: 400,
        code: err.code || 'INVALID_QUERY',
        message: err.message || 'Invalid search query'
      };
    }
    throw err;
  }
  const classified = classifyQuery(parsed.ast);
  if (classified.mode === 'deep_search') {
    return {
      ok: false,
      status: 409,
      code: 'QUERY_TOO_EXPENSIVE',
      message: 'This search is too broad for query-wide bulk. Narrow the query or use Deep Search, then act on a page.'
    };
  }
  const built = buildWhereClause(parsed.ast);
  return {
    ok: true,
    originalQuery: query,
    normalizedQuery: parsed.normalizedQuery,
    ast: parsed.ast,
    whereSql: built.sql,
    params: built.params,
    fileArtifactsReadEnabled: isFileArtifactsReadEnabled()
  };
}

export function canonicalMatchSql(compiled) {
  const inner = buildCanonicalResultSelectSql({
    fileArtifactsReadEnabled: compiled.fileArtifactsReadEnabled,
    whereSql: compiled.whereSql
  });
  return `SELECT c.id FROM (${inner}) c`;
}

export async function countMatchingIocs(pool, compiled, { timeoutMs } = {}) {
  const cfgTimeout = timeoutMs ?? getQueryTimeoutMs();
  const safeTimeout = Math.max(100, Math.min(Math.trunc(cfgTimeout), 120000));
  const sql = `SELECT COUNT(*)::bigint AS n FROM (${canonicalMatchSql(compiled)}) q`;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SET LOCAL statement_timeout = ${safeTimeout}`);
    await client.query('SET LOCAL max_parallel_workers_per_gather = 0');
    const { rows } = await client.query(sql, compiled.params);
    await client.query('COMMIT');
    const n = Number(rows[0]?.n || 0);
    return { ok: true, matchCount: Number.isFinite(n) ? n : 0 };
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch { /* ignore */ }
    if (err?.code === QUERY_CANCELED) {
      return {
        ok: false,
        status: 409,
        code: 'COUNT_UNAVAILABLE',
        message: 'Exact match count could not be computed for this search. Narrow the query before running a query-wide action.'
      };
    }
    throw err;
  } finally {
    client.release();
  }
}

export async function streamMatchingIocIds(pool, compiled, {
  chunkSize = BULK_TRIAGE_MAX_ITEMS,
  hardLimit,
  onChunk
} = {}) {
  const fetchSize = Math.max(1, Math.min(Math.trunc(chunkSize) || BULK_TRIAGE_MAX_ITEMS, BULK_TRIAGE_MAX_ITEMS));
  const cap = Number.isFinite(Number(hardLimit)) ? Number(hardLimit) : null;
  const sql = `${canonicalMatchSql(compiled)} ORDER BY c.id`;
  const client = await pool.connect();
  let collected = 0;
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ');
    await client.query('SET LOCAL max_parallel_workers_per_gather = 0');
    await client.query('DECLARE bulk_query_cur NO SCROLL CURSOR FOR ' + sql, compiled.params);
    for (;;) {
      const remaining = cap == null ? fetchSize : cap - collected;
      if (remaining <= 0) {
        await client.query('COMMIT');
        return { ok: false, status: 400, code: 'HARD_LIMIT', message: `Query matches more than ${cap} IOCs` };
      }
      const { rows } = await client.query(
        `FETCH FORWARD ${Math.min(fetchSize, remaining)} FROM bulk_query_cur`
      );
      if (!rows.length) break;
      const ids = rows.map((r) => Number(r.id)).filter((id) => Number.isInteger(id) && id > 0);
      collected += ids.length;
      if (typeof onChunk === 'function') await onChunk(ids);
    }
    await client.query('COMMIT');
    return { ok: true, matchCount: collected };
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch { /* ignore */ }
    throw err;
  } finally {
    client.release();
  }
}

export function extraAuditMetadata(compiled, action) {
  return {
    selection_mode: 'all_matching',
    query: compiled.normalizedQuery,
    bulk_action: action
  };
}

async function applyChunk(pool, {
  action,
  ids,
  payload,
  user,
  req,
  audit,
  extraMetadata
}) {
  if (action === 'tag') {
    return bulkAddTag(pool, {
      iocIds: ids,
      tagId: payload.tag_id,
      user,
      req,
      audit,
      extraMetadata
    });
  }
  if (action === 'classification') {
    return bulkAddClassification(pool, {
      iocIds: ids,
      slug: payload.classification_slug,
      user,
      req,
      audit,
      extraMetadata
    });
  }
  if (action === 'suppress') {
    return bulkSuppress(pool, {
      iocIds: ids,
      reason: payload.reason,
      expiresAt: payload.expires_at,
      user,
      req,
      audit,
      extraMetadata
    });
  }
  return bulkExpire(pool, {
    iocIds: ids,
    reason: payload.reason,
    user,
    req,
    audit,
    extraMetadata
  });
}

function emptyOutcome() {
  return { requested: 0, succeeded: 0, skipped: 0, failed: 0, results: [] };
}

export function mergeOutcomes(a, b) {
  const left = a || emptyOutcome();
  const right = b || emptyOutcome();
  return {
    requested: (left.requested || 0) + (right.requested || 0),
    succeeded: (left.succeeded || 0) + (right.succeeded || 0),
    skipped: (left.skipped || 0) + (right.skipped || 0),
    failed: (left.failed || 0) + (right.failed || 0),
    results: [...(left.results || []), ...(right.results || [])]
  };
}

export function errorSampleFromResults(results, max = 20) {
  const out = [];
  for (const row of results || []) {
    if (row?.status === 'error') {
      out.push({ id: row.id, message: row.message || 'Failed' });
      if (out.length >= max) break;
    }
  }
  return out;
}

export async function executeQueryWideBulk(pool, {
  compiled,
  action,
  payload,
  user,
  req,
  audit,
  includeResults = true,
  onProgress = null
}) {
  const cfg = getBulkQueryConfig();
  const extraMetadata = extraAuditMetadata(compiled, action);
  let totals = emptyOutcome();
  const streamed = await streamMatchingIocIds(pool, compiled, {
    chunkSize: cfg.chunkSize,
    hardLimit: cfg.hardLimit,
    onChunk: async (ids) => {
      const outcome = await applyChunk(pool, {
        action,
        ids,
        payload,
        user,
        req,
        audit,
        extraMetadata
      });
      if (!outcome.ok) {
        const err = new Error(outcome.message || 'Bulk action failed');
        err.status = outcome.status || 400;
        err.code = 'ACTION_REJECTED';
        throw err;
      }
      totals = mergeOutcomes(totals, outcome);
      if (onProgress) {
        await onProgress({
          matchCount: totals.requested,
          succeeded: totals.succeeded,
          skipped: totals.skipped,
          failed: totals.failed
        });
      }
    }
  });
  if (!streamed.ok) return streamed;
  return {
    ok: true,
    matchCount: streamed.matchCount,
    requested: totals.requested,
    succeeded: totals.succeeded,
    skipped: totals.skipped,
    failed: totals.failed,
    results: includeResults ? totals.results : undefined,
    errorSample: errorSampleFromResults(totals.results)
  };
}

export function decideExecutionMode(matchCount, cfg = getBulkQueryConfig()) {
  const n = Number(matchCount) || 0;
  if (n > cfg.hardLimit) {
    return {
      ok: false,
      status: 400,
      code: 'HARD_LIMIT',
      message: `Query matches ${n} IOCs, which exceeds the query-wide limit of ${cfg.hardLimit}`
    };
  }
  return { ok: true, mode: n <= cfg.syncMax ? 'sync' : 'async', matchCount: n };
}

export async function auditQueryWideOperation(audit, {
  req,
  action,
  compiled,
  matchCount,
  succeeded,
  skipped,
  failed,
  mode,
  reason,
  jobId = null,
  outcome = 'completed'
}) {
  const auditAction = outcome === 'enqueued'
    ? AUDIT_ACTION.IOC_BULK_QUERY_ENQUEUED
    : outcome === 'failed'
      ? AUDIT_ACTION.IOC_BULK_QUERY_FAILED
      : AUDIT_ACTION.IOC_BULK_QUERY_COMPLETED;
  await audit?.auditSuccess?.({
    req,
    action: auditAction,
    entityType: AUDIT_ENTITY.IOC_BULK_QUERY,
    entityId: jobId || compiled.normalizedQuery,
    entityDisplay: compiled.normalizedQuery,
    severity: failed > 0 || outcome === 'failed' ? AUDIT_SEVERITY.WARNING : AUDIT_SEVERITY.INFO,
    metadata: {
      selection_mode: 'all_matching',
      bulk_action: action,
      query: compiled.normalizedQuery,
      original_query: compiled.originalQuery,
      match_count: matchCount,
      succeeded,
      skipped,
      failed,
      mode,
      ...(reason ? { reason } : {}),
      ...(jobId ? { job_id: jobId } : {})
    }
  }).catch(() => {});
}

export function payloadFromBody(action, body) {
  if (action === 'tag') return { tag_id: body?.tag_id };
  if (action === 'classification') return { classification_slug: body?.classification_slug };
  if (action === 'suppress') {
    return { reason: body?.reason, expires_at: body?.expires_at ?? null };
  }
  return { reason: body?.reason };
}
