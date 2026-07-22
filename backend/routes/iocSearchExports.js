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
  countActiveForUser,
  setJobId,
  requestCancel,
  prepareRetry
} from '../lib/iocSearchExport/exportStore.js';

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
function serializeExport(row) {
  return {
    id: row.id,
    original_query: row.original_query,
    normalized_query: row.normalized_query,
    format: row.format,
    selected_columns: row.selected_columns,
    scope: row.scope,
    status: row.status,
    requested_by_email: row.requested_by_email,
    requested_at: row.requested_at,
    started_at: row.started_at,
    completed_at: row.completed_at,
    record_count: row.record_count == null ? null : Number(row.record_count),
    file_size: row.file_size == null ? null : Number(row.file_size),
    progress: row.progress,
    expires_at: row.expires_at,
    failure_reason: row.failure_reason,
    cancelled_at: row.cancelled_at,
    retry_count: row.retry_count,
    created_at: row.created_at
  };
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
    const email = actorEmail(req);
    if (!email) return res.status(401).json({ message: 'Authentication required' });

    try {
      const active = await countActiveForUser(pool, email);
      if (active >= cfg.maxConcurrentPerUser) {
        return res.status(429).json({
          message: `You already have ${active} active export(s). Wait for one to finish (limit ${cfg.maxConcurrentPerUser}).`
        });
      }

      const row = await createExport(pool, {
        originalQuery: String(rawQuery),
        normalizedQuery: parsed.normalizedQuery,
        normalizedAst: parsed.ast,
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
        entityDisplay: parsed.normalizedQuery.slice(0, 200),
        metadata: { export_id: row.id, normalized_query: parsed.normalizedQuery, format, scope, columns }
      });

      return res.status(201).json({ export_id: row.id, status: 'queued' });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to create export', detail: err.message });
    }
  });

  // List the caller's exports (admins may pass ?scope=all to see every user's exports).
  app.get('/api/iocs/search-exports', async (req, res) => {
    const email = actorEmail(req);
    const wantAll = req.query.scope === 'all' && isAdminRole(normalizeAppRole(req.user?.role));
    const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200);
    const offset = Math.max(Number(req.query.offset) || 0, 0);
    try {
      const rows = await listExports(pool, { email, includeAll: wantAll, limit, offset });
      return res.json({ items: rows.map(serializeExport) });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to list exports', detail: err.message });
    }
  });

  // Read a single export's status.
  app.get('/api/iocs/search-exports/:id', async (req, res) => {
    try {
      const row = await getExportById(pool, req.params.id);
      if (!row) return res.status(404).json({ message: 'Export not found' });
      if (!canAccessExport(req, row)) return res.status(403).json({ message: 'Forbidden' });
      return res.json(serializeExport(row));
    } catch (err) {
      return res.status(500).json({ message: 'Failed to read export', detail: err.message });
    }
  });

  // Download a ready export. Authorization + retention + path-traversal safety enforced.
  app.get('/api/iocs/search-exports/:id/download', async (req, res) => {
    try {
      const row = await getExportById(pool, req.params.id);
      if (!row) return res.status(404).json({ message: 'Export not found' });
      if (!canAccessExport(req, row)) return res.status(403).json({ message: 'Forbidden' });
      if (row.status !== 'ready' || !row.storage_path) {
        return res.status(409).json({ message: `Export is not ready (status: ${row.status})` });
      }
      if (row.expires_at && new Date(row.expires_at) <= new Date()) {
        return res.status(410).json({ message: 'Export has expired' });
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
      return res.status(500).json({ message: 'Failed to download export', detail: err.message });
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
      return res.status(500).json({ message: 'Failed to cancel export', detail: err.message });
    }
  });

  // Retry a failed export (bounded by IOC_EXPORT_MAX_RETRIES).
  app.post('/api/iocs/search-exports/:id/retry', requireRole(ROLES.ADMIN, ROLES.ANALYST), async (req, res) => {
    try {
      const existing = await getExportById(pool, req.params.id);
      if (!existing) return res.status(404).json({ message: 'Export not found' });
      if (!canAccessExport(req, existing)) return res.status(403).json({ message: 'Forbidden' });

      const row = await prepareRetry(pool, req.params.id, cfg.maxRetries);
      if (!row) {
        return res.status(409).json({
          message: `Export cannot be retried (status: ${existing.status}, retries: ${existing.retry_count}/${cfg.maxRetries})`
        });
      }
      const job = await exportQueue.add(
        'export',
        { exportId: row.id },
        { removeOnComplete: 100, removeOnFail: 200, attempts: 1 }
      );
      await setJobId(pool, row.id, String(job.id));
      return res.json(serializeExport(row));
    } catch (err) {
      return res.status(500).json({ message: 'Failed to retry export', detail: err.message });
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
