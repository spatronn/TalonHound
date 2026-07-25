import fs from 'node:fs';
import { createReadStream } from 'node:fs';
import { requireRole, ROLES, isAdminRole, normalizeAppRole } from '../lib/rbac.js';
import { AUDIT_ACTION, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import { parseSearchQuery, isDslError } from '../lib/iocSearchDsl/index.js';
import { sanitizeColumns } from '../lib/iocSearchExport/columns.js';
import { getExportConfig, resolveExportFilePath } from '../lib/iocSearchExport/exportConfig.js';
import {
  createExport,
  getExportById,
  listExports,
  countExports,
  countActiveForUser,
  setJobId,
  requestCancel,
  markExpired
} from '../lib/iocSearchExport/exportStore.js';
import {
  EXPORT_TASK_TYPE,
  EXPORT_TASK_TYPE_LABEL,
  effectiveExportStatus,
  publicFailureReason,
  parseListStatusFilter,
  parseListPagination
} from '../lib/iocSearchExport/exportStatus.js';

const VALID_FORMATS = new Set(['csv', 'csv_gz']);
const VALID_SCOPES = new Set(['all', 'preview']);

function actorEmail(req) {
  return String(req.user?.email || req.user?.username || '').trim();
}

function canAccessExport(req, row) {
  if (isAdminRole(normalizeAppRole(req.user?.role))) return true;
  return row.requested_by_email && row.requested_by_email === actorEmail(req);
}

// Present an export row to the client without leaking the on-disk path.
function serializeExport(row, now = new Date()) {
  const status = effectiveExportStatus(row, now);
  return {
    id: row.id,
    task_type: EXPORT_TASK_TYPE,
    task_type_label: EXPORT_TASK_TYPE_LABEL,
    original_query: row.original_query,
    normalized_query: row.normalized_query,
    format: row.format,
    selected_columns: row.selected_columns,
    scope: row.scope,
    status,
    requested_by_email: row.requested_by_email,
    requested_at: row.requested_at,
    started_at: row.started_at,
    completed_at: row.completed_at,
    ready_at: row.completed_at,
    record_count: row.record_count == null ? null : Number(row.record_count),
    file_size: row.file_size == null ? null : Number(row.file_size),
    progress: row.progress,
    expires_at: row.expires_at,
    failure_reason: publicFailureReason(row.failure_reason),
    cancelled_at: row.cancelled_at,
    retry_count: row.retry_count,
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

async function enqueueExport(pool, exportQueue, auditLogService, req, {
  originalQuery,
  normalizedQuery,
  normalizedAst,
  format,
  columns,
  scope,
  sourceExportId = null,
  sourceAction = null
}) {
  const cfg = getExportConfig();
  const email = actorEmail(req);
  if (!email) {
    const err = new Error('Authentication required');
    err.status = 401;
    throw err;
  }

  const active = await countActiveForUser(pool, email);
  if (active >= cfg.maxConcurrentPerUser) {
    const err = new Error(
      `You already have ${active} active export(s). Wait for one to finish (limit ${cfg.maxConcurrentPerUser}).`
    );
    err.status = 429;
    throw err;
  }

  const row = await createExport(pool, {
    originalQuery,
    normalizedQuery,
    normalizedAst,
    format,
    selectedColumns: columns,
    scope,
    requestedById: Number.isFinite(Number(req.user?.id)) ? Number(req.user.id) : null,
    requestedByEmail: email
  });

  const job = await exportQueue.add(
    'export',
    { exportId: row.id },
    { removeOnComplete: 100, removeOnFail: 200, attempts: 1 }
  );
  await setJobId(pool, row.id, String(job.id));

  await auditLogService.auditSuccess({
    req,
    action: AUDIT_ACTION.IOC_SEARCH_EXPORT_CREATED,
    entityType: 'ioc_search_export',
    entityId: row.id,
    entityDisplay: normalizedQuery.slice(0, 200),
    metadata: {
      export_id: row.id,
      normalized_query: normalizedQuery,
      format,
      scope,
      columns,
      ...(sourceExportId ? { source_export_id: sourceExportId, source_action: sourceAction } : {})
    }
  });

  return row;
}

/**
 * Clone a prior export into a brand-new queued task. Never mutates the source row.
 */
async function cloneExportTask(pool, exportQueue, auditLogService, req, source, sourceAction) {
  // Prefer re-parsing the stored normalized query so the worker and API share validators.
  let parsed;
  try {
    parsed = parseSearchQuery(source.normalized_query || source.original_query);
  } catch (err) {
    if (isDslError(err)) {
      const e = new Error(err.message);
      e.status = 400;
      e.payload = { error: err.toJSON(), message: err.message };
      throw e;
    }
    const e = new Error('Invalid search query on source export');
    e.status = 400;
    throw e;
  }

  const format = VALID_FORMATS.has(source.format) ? source.format : 'csv';
  const scope = VALID_SCOPES.has(source.scope) ? source.scope : 'all';
  const columns = sanitizeColumns(source.selected_columns);

  return enqueueExport(pool, exportQueue, auditLogService, req, {
    originalQuery: source.original_query || parsed.normalizedQuery,
    normalizedQuery: parsed.normalizedQuery,
    normalizedAst: parsed.ast,
    format,
    columns,
    scope,
    sourceExportId: source.id,
    sourceAction
  });
}

/**
 * If a ready row is past expires_at, flip it to expired (best-effort) and treat as expired.
 */
async function ensureNotPastExpiry(pool, row) {
  if (!row) return row;
  if (effectiveExportStatus(row) !== 'expired') return row;
  if (row.status === 'ready') {
    try {
      const marked = await markExpired(pool, row.id);
      if (marked) return marked;
    } catch {
      /* list/download still treat as expired via effectiveExportStatus */
    }
    return { ...row, status: 'expired', storage_path: null };
  }
  return row;
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {{ exportQueue: import('bullmq').Queue, auditLogService: any }} deps
 */
export function registerIocSearchExportRoutes(app, pool, { exportQueue, auditLogService }) {
  const cfg = getExportConfig();

  // Create an asynchronous export job for a DSL search.
  app.post('/api/iocs/search-exports', requireRole(ROLES.ADMIN, ROLES.ANALYST), async (req, res) => {
    const body = req.body || {};
    const rawQuery = body.query;
    const format = String(body.format || 'csv');
    const scope = String(body.scope || 'all');

    if (!VALID_FORMATS.has(format)) {
      return res.status(400).json({ message: `Invalid format. Allowed: ${[...VALID_FORMATS].join(', ')}` });
    }
    if (!VALID_SCOPES.has(scope)) {
      return res.status(400).json({ message: `Invalid scope. Allowed: ${[...VALID_SCOPES].join(', ')}` });
    }

    let parsed;
    try {
      parsed = parseSearchQuery(rawQuery);
    } catch (err) {
      if (isDslError(err)) return res.status(400).json({ error: err.toJSON(), message: err.message });
      return res.status(400).json({ message: 'Invalid search query', detail: err.message });
    }

    const columns = sanitizeColumns(body.columns);

    try {
      const row = await enqueueExport(pool, exportQueue, auditLogService, req, {
        originalQuery: String(rawQuery),
        normalizedQuery: parsed.normalizedQuery,
        normalizedAst: parsed.ast,
        format,
        columns,
        scope
      });
      return res.status(201).json({ export_id: row.id, status: 'queued', task_type: EXPORT_TASK_TYPE });
    } catch (err) {
      if (err.status === 401) return res.status(401).json({ message: err.message });
      if (err.status === 429) return res.status(429).json({ message: err.message });
      return res.status(500).json({ message: 'Failed to create export' });
    }
  });

  // List the caller's exports (admins may pass ?scope=all to see every user's exports).
  // Action Center uses page/page_size/status; legacy limit/offset still accepted.
  app.get('/api/iocs/search-exports', async (req, res) => {
    const email = actorEmail(req);
    const wantAll = req.query.scope === 'all' && isAdminRole(normalizeAppRole(req.user?.role));
    const statuses = parseListStatusFilter(req.query.status);
    if (statuses === undefined) {
      return res.status(400).json({
        message: 'Invalid status filter. Allowed: all, processing, ready, failed, expired, or a concrete status.'
      });
    }
    const paging = parseListPagination({
      page: req.query.page,
      pageSize: req.query.page_size ?? req.query.pageSize,
      limit: req.query.limit,
      offset: req.query.offset
    });
    try {
      const [rows, total] = await Promise.all([
        listExports(pool, {
          email,
          includeAll: wantAll,
          limit: paging.limit,
          offset: paging.offset,
          statuses
        }),
        countExports(pool, { email, includeAll: wantAll, statuses })
      ]);
      return res.json({
        items: rows.map((r) => serializeExport(r)),
        total,
        page: paging.page,
        page_size: paging.pageSize
      });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to list exports' });
    }
  });

  // Read a single export's status.
  app.get('/api/iocs/search-exports/:id', async (req, res) => {
    try {
      let row = await getExportById(pool, req.params.id);
      if (!row) return res.status(404).json({ message: 'Export not found' });
      if (!canAccessExport(req, row)) return res.status(403).json({ message: 'Forbidden' });
      row = await ensureNotPastExpiry(pool, row);
      return res.json(serializeExport(row));
    } catch (err) {
      return res.status(500).json({ message: 'Failed to read export' });
    }
  });

  // Download a ready export. Authorization + retention + path-traversal safety enforced.
  app.get('/api/iocs/search-exports/:id/download', async (req, res) => {
    try {
      let row = await getExportById(pool, req.params.id);
      if (!row) return res.status(404).json({ message: 'Export not found' });
      if (!canAccessExport(req, row)) return res.status(403).json({ message: 'Forbidden' });

      row = await ensureNotPastExpiry(pool, row);
      const status = effectiveExportStatus(row);
      if (status === 'expired') {
        return res.status(410).json({ message: 'Export has expired' });
      }
      if (status !== 'ready' || !row.storage_path) {
        return res.status(409).json({ message: `Export is not ready (status: ${status})` });
      }

      // Re-resolve the file path under the configured storage dir; never trust the
      // stored path blindly for traversal.
      let filePath;
      try {
        filePath = resolveExportFilePath(cfg.storageDir, basenameOnly(row.storage_path));
      } catch {
        return res.status(500).json({ message: 'Invalid export storage path' });
      }
      if (!fs.existsSync(filePath)) {
        return res.status(410).json({ message: 'Export file is no longer available' });
      }

      const isGz = row.format === 'csv_gz';
      const fileName = `ioc-export-${row.id}.csv${isGz ? '.gz' : ''}`;
      res.setHeader('Content-Type', isGz ? 'application/gzip' : 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Cache-Control', 'no-store');

      await auditLogService.auditSuccess({
        req,
        action: AUDIT_ACTION.IOC_SEARCH_EXPORT_DOWNLOADED,
        entityType: 'ioc_search_export',
        entityId: row.id,
        metadata: { export_id: row.id, record_count: row.record_count == null ? null : Number(row.record_count) }
      });

      const stream = createReadStream(filePath);
      stream.on('error', () => {
        if (!res.headersSent) res.status(500).json({ message: 'Failed to read export file' });
        else res.destroy();
      });
      return stream.pipe(res);
    } catch (err) {
      return res.status(500).json({ message: 'Failed to download export' });
    }
  });

  // Cancel a queued/processing export.
  app.post('/api/iocs/search-exports/:id/cancel', async (req, res) => {
    try {
      const existing = await getExportById(pool, req.params.id);
      if (!existing) return res.status(404).json({ message: 'Export not found' });
      if (!canAccessExport(req, existing)) return res.status(403).json({ message: 'Forbidden' });

      const row = await requestCancel(pool, req.params.id);
      if (!row) {
        return res.status(409).json({ message: `Export cannot be cancelled (status: ${existing.status})` });
      }
      await auditLogService.auditSuccess({
        req,
        action: AUDIT_ACTION.IOC_SEARCH_EXPORT_CANCELLED,
        entityType: 'ioc_search_export',
        entityId: row.id,
        severity: AUDIT_SEVERITY.INFO,
        metadata: { export_id: row.id, previous_status: existing.status }
      });
      return res.json(serializeExport(row));
    } catch (err) {
      return res.status(500).json({ message: 'Failed to cancel export' });
    }
  });

  // Retry a failed export by creating a NEW queued task (source row stays failed).
  app.post('/api/iocs/search-exports/:id/retry', requireRole(ROLES.ADMIN, ROLES.ANALYST), async (req, res) => {
    try {
      const existing = await getExportById(pool, req.params.id);
      if (!existing) return res.status(404).json({ message: 'Export not found' });
      if (!canAccessExport(req, existing)) return res.status(403).json({ message: 'Forbidden' });
      if (effectiveExportStatus(existing) !== 'failed') {
        return res.status(409).json({ message: `Export cannot be retried (status: ${existing.status})` });
      }

      const row = await cloneExportTask(pool, exportQueue, auditLogService, req, existing, 'retry');
      return res.status(201).json(serializeExport(row));
    } catch (err) {
      if (err.status === 401) return res.status(401).json({ message: err.message });
      if (err.status === 429) return res.status(429).json({ message: err.message });
      if (err.status === 400) return res.status(400).json(err.payload || { message: err.message });
      return res.status(500).json({ message: 'Failed to retry export' });
    }
  });

  // Create-again for expired (or cancelled) exports — new task, same query payload.
  app.post('/api/iocs/search-exports/:id/create-again', requireRole(ROLES.ADMIN, ROLES.ANALYST), async (req, res) => {
    try {
      let existing = await getExportById(pool, req.params.id);
      if (!existing) return res.status(404).json({ message: 'Export not found' });
      if (!canAccessExport(req, existing)) return res.status(403).json({ message: 'Forbidden' });
      existing = await ensureNotPastExpiry(pool, existing);
      const status = effectiveExportStatus(existing);
      if (status !== 'expired' && status !== 'cancelled') {
        return res.status(409).json({ message: `Export cannot be recreated (status: ${status})` });
      }

      const row = await cloneExportTask(pool, exportQueue, auditLogService, req, existing, 'create_again');
      return res.status(201).json(serializeExport(row));
    } catch (err) {
      if (err.status === 401) return res.status(401).json({ message: err.message });
      if (err.status === 429) return res.status(429).json({ message: err.message });
      if (err.status === 400) return res.status(400).json(err.payload || { message: err.message });
      return res.status(500).json({ message: 'Failed to recreate export' });
    }
  });
}

// Extract just the basename of a stored path so the download re-resolve cannot be
// tricked into walking outside the storage dir even if storage_path were tampered.
function basenameOnly(p) {
  const norm = String(p).replace(/\\/g, '/');
  const parts = norm.split('/');
  return parts[parts.length - 1] || '';
}
