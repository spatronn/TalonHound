import { requireRole, ROLES } from '../lib/rbac.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import {
  actorUserId,
  actorEmail,
  canAccessSavedSearch,
  parseSavedSearchWrite,
  toPublicSavedSearch,
  listSavedSearches,
  getSavedSearchRow,
  insertSavedSearch,
  updateSavedSearch,
  deleteSavedSearch
} from '../lib/iocSavedSearchStore.js';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function sendDslError(res, err) {
  return res.status(400).json({ error: err.toJSON?.() || { message: err.message }, message: err.message });
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {{ auditSuccess?: Function }} [audit]
 */
export function registerIocSavedSearchRoutes(app, pool, audit) {
  const writeRole = requireRole(ROLES.ADMIN, ROLES.ANALYST);

  app.get('/api/iocs/saved-searches', async (req, res) => {
    const ownerId = actorUserId(req);
    if (!ownerId) return res.status(401).json({ message: 'Authentication required' });
    try {
      const items = await listSavedSearches(pool, ownerId);
      return res.json({ saved_searches: items });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to list saved searches', detail: err.message });
    }
  });

  app.post('/api/iocs/saved-searches', writeRole, async (req, res) => {
    const ownerId = actorUserId(req);
    if (!ownerId) return res.status(401).json({ message: 'Authentication required' });
    const parsedWrite = parseSavedSearchWrite(req.body || {}, { requireQuery: true });
    if (!parsedWrite.ok) {
      if (parsedWrite.dslError) return sendDslError(res, parsedWrite.dslError);
      return res.status(400).json({ message: parsedWrite.message || 'Invalid saved search', errors: parsedWrite.errors });
    }
    try {
      const result = await insertSavedSearch(pool, {
        name: parsedWrite.name,
        description: parsedWrite.description ?? null,
        originalQuery: parsedWrite.originalQuery,
        parsed: parsedWrite.parsed,
        ownerId,
        ownerUsername: actorEmail(req) || String(req.user?.username || '')
      });
      if (result.duplicate) {
        return res.status(409).json({
          code: 'SAVED_SEARCH_NAME_DUPLICATE',
          message: 'A saved search with this name already exists.'
        });
      }
      const body = toPublicSavedSearch(result.row);
      audit?.auditSuccess?.({
        req,
        action: AUDIT_ACTION.IOC_SAVED_SEARCH_CREATED,
        entityType: AUDIT_ENTITY.IOC_SAVED_SEARCH,
        entityId: String(body.id),
        entityDisplay: body.name,
        severity: AUDIT_SEVERITY.INFO,
        after: { id: body.id, name: body.name },
        metadata: { normalized_query: String(body.normalized_query || '').slice(0, 200) }
      });
      return res.status(201).json({ saved_search: body });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to save search', detail: err.message });
    }
  });

  app.get('/api/iocs/saved-searches/:id', async (req, res) => {
    const id = String(req.params.id || '').trim();
    if (!UUID_RE.test(id)) return res.status(400).json({ message: 'Invalid saved search id' });
    try {
      const row = await getSavedSearchRow(pool, id);
      if (!row) return res.status(404).json({ message: 'Saved search not found' });
      if (!canAccessSavedSearch(req, row)) return res.status(403).json({ message: 'Forbidden' });
      return res.json({ saved_search: toPublicSavedSearch(row) });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to load saved search', detail: err.message });
    }
  });

  app.patch('/api/iocs/saved-searches/:id', writeRole, async (req, res) => {
    const id = String(req.params.id || '').trim();
    if (!UUID_RE.test(id)) return res.status(400).json({ message: 'Invalid saved search id' });
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    if (body.name === undefined && body.query === undefined && body.description === undefined) {
      return res.status(400).json({ message: 'No fields to update' });
    }
    const parsedWrite = parseSavedSearchWrite(
      {
        name: body.name,
        query: body.query,
        description: body.description
      },
      { requireQuery: body.query !== undefined, requireName: body.name !== undefined }
    );
    if (!parsedWrite.ok) {
      if (parsedWrite.dslError) return sendDslError(res, parsedWrite.dslError);
      return res.status(400).json({ message: parsedWrite.message || 'Invalid saved search', errors: parsedWrite.errors });
    }
    try {
      const existing = await getSavedSearchRow(pool, id);
      if (!existing) return res.status(404).json({ message: 'Saved search not found' });
      if (!canAccessSavedSearch(req, existing)) return res.status(403).json({ message: 'Forbidden' });
      const fields = {};
      if (body.name !== undefined) fields.name = parsedWrite.name;
      if (body.description !== undefined) fields.description = parsedWrite.description;
      if (body.query !== undefined) {
        fields.originalQuery = parsedWrite.originalQuery;
        fields.parsed = parsedWrite.parsed;
      }
      const result = await updateSavedSearch(pool, id, fields);
      if (result.duplicate) {
        return res.status(409).json({
          code: 'SAVED_SEARCH_NAME_DUPLICATE',
          message: 'A saved search with this name already exists.'
        });
      }
      const pub = toPublicSavedSearch(result.row);
      audit?.auditSuccess?.({
        req,
        action: AUDIT_ACTION.IOC_SAVED_SEARCH_UPDATED,
        entityType: AUDIT_ENTITY.IOC_SAVED_SEARCH,
        entityId: String(pub.id),
        entityDisplay: pub.name,
        severity: AUDIT_SEVERITY.INFO,
        before: { id: existing.id, name: existing.name },
        after: { id: pub.id, name: pub.name },
        metadata: { normalized_query: String(pub.normalized_query || '').slice(0, 200) }
      });
      return res.json({ saved_search: pub });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to update saved search', detail: err.message });
    }
  });

  app.delete('/api/iocs/saved-searches/:id', writeRole, async (req, res) => {
    const id = String(req.params.id || '').trim();
    if (!UUID_RE.test(id)) return res.status(400).json({ message: 'Invalid saved search id' });
    try {
      const existing = await getSavedSearchRow(pool, id);
      if (!existing) return res.status(404).json({ message: 'Saved search not found' });
      if (!canAccessSavedSearch(req, existing)) return res.status(403).json({ message: 'Forbidden' });
      await deleteSavedSearch(pool, id);
      audit?.auditSuccess?.({
        req,
        action: AUDIT_ACTION.IOC_SAVED_SEARCH_DELETED,
        entityType: AUDIT_ENTITY.IOC_SAVED_SEARCH,
        entityId: String(existing.id),
        entityDisplay: existing.name,
        severity: AUDIT_SEVERITY.INFO,
        before: { id: existing.id, name: existing.name }
      });
      return res.json({ ok: true, id: existing.id });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to delete saved search', detail: err.message });
    }
  });
}
