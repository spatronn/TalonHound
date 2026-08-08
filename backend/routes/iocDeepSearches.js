import { requireRole, ROLES, isAdminRole, normalizeAppRole } from '../lib/rbac.js';
import { AUDIT_ACTION, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import { parseSearchQuery, isDslError } from '../lib/iocSearchDsl/index.js';
import { clampDeepSearchPageSize } from '../lib/iocDeepSearch/deepSearchConfig.js';
import {
  getDeepSearchById,
  listDeepSearches,
  countDeepSearches,
  getResultsPage,
  requestCancel,
  markExpired
} from '../lib/iocDeepSearch/deepSearchStore.js';
import {
  serializeDeepSearch,
  effectiveDeepSearchStatus,
  isBrowsable,
  parseListStatusFilter
} from '../lib/iocDeepSearch/deepSearchStatus.js';
import { enqueueDeepSearch } from '../lib/iocDeepSearch/enqueueDeepSearch.js';

function actorEmail(req) {
  return String(req.user?.email || req.user?.username || '').trim();
}

function canAccess(req, row) {
  if (isAdminRole(normalizeAppRole(req.user?.role))) return true;
  return row.requested_by_email && row.requested_by_email === actorEmail(req);
}

function encodeCursor(cursor) {
  return Buffer.from(JSON.stringify(cursor), 'utf8').toString('base64url');
}

function decodeCursor(raw) {
  if (!raw) return null;
  try {
    const obj = JSON.parse(Buffer.from(String(raw), 'base64url').toString('utf8'));
    if (obj && typeof obj.t === 'string' && obj.id != null) {
      return { t: obj.t, id: String(obj.id) };
    }
  } catch {
    /* invalid cursor */
  }
  return null;
}

// Re-parse the stored normalized query so the response can show query summary chips without
// trusting a client-supplied AST. Returns { normalized_query, conditions } (best-effort).
function summarizeQuery(row) {
  try {
    const parsed = parseSearchQuery(row.normalized_query || row.original_query);
    return { normalized_query: parsed.normalizedQuery, conditions: parsed.conditions };
  } catch {
    return { normalized_query: row.normalized_query || '', conditions: [] };
  }
}

async function ensureNotPastExpiry(pool, row) {
  if (!row) return row;
  if (effectiveDeepSearchStatus(row) !== 'expired') return row;
  if (row.status === 'completed') {
    try {
      const marked = await markExpired(pool, row.id);
      if (marked) return marked;
    } catch {
      /* still treated as expired via effectiveDeepSearchStatus */
    }
    return { ...row, status: 'expired' };
  }
  return row;
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {{
 *   deepSearchQueue: import('bullmq').Queue,
 *   auditLogService: any,
 *   logger?: any,
 *   mapPageItems: (pool: any, pageItems: any[]) => Promise<any[]>
 * }} deps
 */
export function registerIocDeepSearchRoutes(app, pool, { deepSearchQueue, auditLogService, logger = null, mapPageItems }) {
  // List the caller's deep searches (admins may pass ?scope=all). Shares Action Center
  // filter buckets with exports.
  app.get('/api/iocs/deep-searches', async (req, res) => {
    const email = actorEmail(req);
    const wantAll = req.query.scope === 'all' && isAdminRole(normalizeAppRole(req.user?.role));
    const statuses = parseListStatusFilter(req.query.status);
    if (statuses === undefined) {
      return res.status(400).json({ message: 'Invalid status filter. Allowed: all, processing, ready, failed, expired, or a concrete status.' });
    }
    const pageRaw = Number(req.query.page);
    const page = Math.max(Number.isFinite(pageRaw) ? Math.trunc(pageRaw) : 1, 1);
    const sizeRaw = Number(req.query.page_size ?? req.query.pageSize);
    const pageSize = Math.min(Math.max(Number.isFinite(sizeRaw) ? Math.trunc(sizeRaw) : 25, 1), 100);
    try {
      const [rows, total] = await Promise.all([
        listDeepSearches(pool, { email, includeAll: wantAll, limit: pageSize, offset: (page - 1) * pageSize, statuses }),
        countDeepSearches(pool, { email, includeAll: wantAll, statuses })
      ]);
      return res.json({ items: rows.map((r) => serializeDeepSearch(r)), total, page, page_size: pageSize });
    } catch {
      return res.status(500).json({ message: 'Failed to list deep searches' });
    }
  });

  // Read one deep search's status + query summary.
  app.get('/api/iocs/deep-searches/:id', async (req, res) => {
    try {
      let row = await getDeepSearchById(pool, req.params.id);
      if (!row) return res.status(404).json({ message: 'Deep search not found' });
      if (!canAccess(req, row)) return res.status(403).json({ message: 'Forbidden' });
      row = await ensureNotPastExpiry(pool, row);
      const summary = summarizeQuery(row);
      return res.json({ ...serializeDeepSearch(row), ...summary });
    } catch {
      return res.status(500).json({ message: 'Failed to read deep search' });
    }
  });

  // Browse a page of a completed deep search's results (keyset pagination over the spool).
  app.get('/api/iocs/deep-searches/:id/results', async (req, res) => {
    try {
      let row = await getDeepSearchById(pool, req.params.id);
      if (!row) return res.status(404).json({ message: 'Deep search not found' });
      if (!canAccess(req, row)) return res.status(403).json({ message: 'Forbidden' });
      row = await ensureNotPastExpiry(pool, row);

      const summary = summarizeQuery(row);
      const status = effectiveDeepSearchStatus(row);

      // Non-error states: still processing, or the result set was cleaned up. The result view
      // must never silently re-run the expensive query, so we return an explicit state.
      if (!isBrowsable(row)) {
        return res.json({
          deep_search_id: row.id,
          status,
          result_state: status === 'expired' ? 'expired' : (status === 'completed' ? 'ready' : status),
          normalized_query: summary.normalized_query,
          conditions: summary.conditions,
          match_count: row.match_count == null ? null : Number(row.match_count),
          items: [],
          has_more: false,
          next_cursor: null
        });
      }

      const pageSize = clampDeepSearchPageSize(req.query.page_size);
      const cursor = decodeCursor(req.query.cursor);
      const spool = await getResultsPage(pool, row.id, { cursor, limit: pageSize + 1 });

      const hasMore = spool.length > pageSize;
      const pageRows = spool.slice(0, pageSize);

      const pageItems = pageRows.map((r) => ({
        id: r.ioc_item_id,
        public_id: r.public_id,
        observable: r.observable,
        observable_type: r.ioc_observable_type,
        ip: r.observable,
        status: r.status || 'active',
        created_at: r.created_at,
        imported_at: r.created_at,
        first_seen_at: r.first_seen_at || r.created_at,
        last_seen_at: r.created_at,
        artifact_id: r.artifact_id || null,
        source_count: 0,
        source_names: [],
        confidence_set: [],
        category_set: []
      }));

      const items = await mapPageItems(pool, pageItems);

      const lastRow = pageRows[pageRows.length - 1];
      const nextCursor = hasMore && lastRow
        ? encodeCursor({ t: new Date(lastRow.created_at).toISOString(), id: String(lastRow.ioc_item_id) })
        : null;

      return res.json({
        deep_search_id: row.id,
        status,
        result_state: 'ready',
        normalized_query: summary.normalized_query,
        conditions: summary.conditions,
        match_count: row.match_count == null ? null : Number(row.match_count),
        items,
        has_more: hasMore,
        next_cursor: nextCursor,
        page_size: pageSize
      });
    } catch {
      return res.status(500).json({ message: 'Failed to read deep search results' });
    }
  });

  // Cancel a queued/running deep search.
  app.post('/api/iocs/deep-searches/:id/cancel', async (req, res) => {
    try {
      const existing = await getDeepSearchById(pool, req.params.id);
      if (!existing) return res.status(404).json({ message: 'Deep search not found' });
      if (!canAccess(req, existing)) return res.status(403).json({ message: 'Forbidden' });
      const row = await requestCancel(pool, req.params.id);
      if (!row) return res.status(409).json({ message: `Deep search cannot be cancelled (status: ${existing.status})` });
      await auditLogService.auditSuccess({
        req,
        action: AUDIT_ACTION.IOC_DEEP_SEARCH_CANCELLED,
        entityType: 'ioc_deep_search',
        entityId: row.id,
        severity: AUDIT_SEVERITY.INFO,
        metadata: { deep_search_id: row.id, previous_status: existing.status }
      });
      return res.json(serializeDeepSearch(row));
    } catch {
      return res.status(500).json({ message: 'Failed to cancel deep search' });
    }
  });

  // Re-run a terminal (expired/failed/cancelled) deep search as a brand-new job with the same
  // query. Used by Action Center "Run again". The source row is never mutated.
  app.post('/api/iocs/deep-searches/:id/create-again', requireRole(ROLES.ADMIN, ROLES.ANALYST), async (req, res) => {
    try {
      let existing = await getDeepSearchById(pool, req.params.id);
      if (!existing) return res.status(404).json({ message: 'Deep search not found' });
      if (!canAccess(req, existing)) return res.status(403).json({ message: 'Forbidden' });
      existing = await ensureNotPastExpiry(pool, existing);
      const status = effectiveDeepSearchStatus(existing);
      if (!['expired', 'failed', 'cancelled'].includes(status)) {
        return res.status(409).json({ message: `Deep search cannot be recreated (status: ${status})` });
      }

      let parsed;
      try {
        parsed = parseSearchQuery(existing.normalized_query || existing.original_query);
      } catch (err) {
        if (isDslError(err)) return res.status(400).json({ error: err.toJSON(), message: err.message });
        return res.status(400).json({ message: 'Invalid search query on source deep search' });
      }

      const { row, deduped } = await enqueueDeepSearch(pool, deepSearchQueue, {
        originalQuery: existing.original_query || parsed.normalizedQuery,
        normalizedQuery: parsed.normalizedQuery,
        normalizedAst: parsed.ast,
        classificationReason: existing.classification_reason,
        origin: 'classified',
        requestedById: Number.isFinite(Number(req.user?.id)) ? Number(req.user.id) : null,
        requestedByEmail: actorEmail(req),
        auditLogService,
        logger,
        req
      });
      return res.status(deduped ? 200 : 201).json(serializeDeepSearch(row));
    } catch (err) {
      if (err.status === 401) return res.status(401).json({ message: err.message });
      if (err.status === 429) return res.status(429).json({ message: err.message });
      return res.status(500).json({ message: 'Failed to recreate deep search' });
    }
  });
}
