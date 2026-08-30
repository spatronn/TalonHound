import { requireRole, ROLES } from '../lib/rbac.js';
import { AUDIT_ACTION, AUDIT_ENTITY } from '../lib/auditConstants.js';
import { normalizeTagSlug } from '../lib/tagHelpers.js';
import { listAdminThreatActors } from '../lib/threatActorAdminList.js';
import {
  CATALOG_SOURCE_MANUAL,
  canConfirmBundledCatalogIdentity,
  confirmBundledCatalogEquivalence,
  resolveCatalogSources
} from '../lib/threatActors/catalogSources.js';

function isAdmin(req) {
  return String(req.user?.role || '').trim().toLowerCase() === ROLES.ADMIN;
}

function parseAliases(raw) {
  if (raw == null || raw === '') return [];
  if (Array.isArray(raw)) {
    return raw.map((x) => String(x || '').trim()).filter(Boolean);
  }
  return String(raw).split(',').map((x) => x.trim()).filter(Boolean);
}

function serializeThreatActor(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    aliases: row.aliases || [],
    description: row.description || null,
    active: Boolean(row.active),
    catalog_sources: row.catalog_sources || resolveCatalogSources(row),
    bundled_catalog_collision_pending: Boolean(row.bundled_catalog_collision_pending),
    created_at: row.created_at,
    updated_at: row.updated_at,
    created_by: row.created_by || null,
    updated_by: row.updated_by || null
  };
}

function actorAuditSnapshot(row) {
  return serializeThreatActor(row);
}

async function fetchActorById(pool, id) {
  const { rows } = await pool.query('SELECT * FROM threat_actors WHERE id = $1::uuid', [id]);
  return rows[0] || null;
}

async function findDuplicate(pool, { name, slug, excludeId = null }) {
  const params = [name, slug];
  let sql = `SELECT id FROM threat_actors WHERE (lower(name) = lower($1) OR slug = $2)`;
  if (excludeId) {
    params.push(excludeId);
    sql += ` AND id <> $3::uuid`;
  }
  sql += ' LIMIT 1';
  const { rows } = await pool.query(sql, params);
  return rows[0] || null;
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {{ auditSuccess: Function }} audit
 */
export function registerThreatActorRoutes(app, pool, audit) {
  app.get('/api/threat-actors', async (_req, res) => {
    try {
      const rows = await fetchActiveThreatActors(pool);
      return res.json({
        threat_actors: rows.map((row) => ({
          id: row.id,
          name: row.name,
          slug: row.slug,
          aliases: row.aliases || [],
          active: Boolean(row.active)
        }))
      });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  });

  app.get('/api/admin/threat-actors', requireRole(ROLES.ADMIN), async (req, res) => {
    try {
      const result = await listAdminThreatActors(pool, req.query || {});
      return res.json({
        threat_actors: result.items.map(serializeThreatActor),
        pagination: result.pagination
      });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  });

  app.post('/api/admin/threat-actors', requireRole(ROLES.ADMIN), async (req, res) => {
    const body = req.body || {};
    const name = String(body.name || '').trim();
    if (!name) return res.status(400).json({ success: false, error: 'name is required' });
    const slug = normalizeTagSlug(body.slug || name);
    if (!slug) return res.status(400).json({ success: false, error: 'slug could not be generated' });
    const aliases = parseAliases(body.aliases);
    const description = body.description != null ? String(body.description).trim() || null : null;
    const active = body.active !== false;
    const userLabel = req.user?.email || req.user?.username || req.user?.publicId || null;

    try {
      const dup = await findDuplicate(pool, { name, slug });
      if (dup) return res.status(409).json({ success: false, error: 'Threat actor name or slug already exists' });

      const { rows } = await pool.query(
        `INSERT INTO threat_actors (name, slug, aliases, description, active, catalog_sources, created_by, updated_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
         RETURNING *`,
        [name, slug, aliases.length ? aliases : null, description, active, [CATALOG_SOURCE_MANUAL], userLabel]
      );
      const actor = rows[0];
      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.THREAT_ACTOR_CREATED,
        entityType: AUDIT_ENTITY.THREAT_ACTOR,
        entityId: String(actor.id),
        entityDisplay: actor.name,
        after: actorAuditSnapshot(actor),
        metadata: { slug: actor.slug }
      });
      return res.status(201).json({ success: true, threat_actor: serializeThreatActor(actor) });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  });

  app.patch('/api/admin/threat-actors/:id', requireRole(ROLES.ADMIN), async (req, res) => {
    const id = String(req.params.id || '').trim();
    if (!/^[0-9a-f-]{36}$/i.test(id)) {
      return res.status(400).json({ success: false, error: 'Invalid threat actor id' });
    }
    const prev = await fetchActorById(pool, id);
    if (!prev) return res.status(404).json({ success: false, error: 'Threat actor not found' });

    const body = req.body || {};
    const name = body.name !== undefined ? String(body.name || '').trim() : prev.name;
    if (!name) return res.status(400).json({ success: false, error: 'name cannot be empty' });
    const slug = body.slug !== undefined ? normalizeTagSlug(body.slug || name) : prev.slug;
    const aliases = body.aliases !== undefined ? parseAliases(body.aliases) : (prev.aliases || []);
    const description = body.description !== undefined
      ? (String(body.description || '').trim() || null)
      : prev.description;
    const active = body.active !== undefined ? Boolean(body.active) : prev.active;
    const userLabel = req.user?.email || req.user?.username || req.user?.publicId || null;
    const confirmBundledCatalog = body.confirm_bundled_catalog === true;
    if (confirmBundledCatalog) {
      const eligibility = canConfirmBundledCatalogIdentity(prev);
      if (!eligibility.ok) {
        const messages = {
          unknown_sentinel: 'Unknown sentinel cannot confirm bundled identity',
          already_confirmed: 'Threat actor is already a confirmed bundled equivalent',
          no_pending_collision: 'No pending manual/bundled collision to confirm'
        };
        return res.status(400).json({
          success: false,
          error: messages[eligibility.reason] || 'Cannot confirm bundled identity'
        });
      }
    }

    const prevSources = resolveCatalogSources(prev);
    const prevCollisionPending = Boolean(prev.bundled_catalog_collision_pending);
    const nextCatalogSources = confirmBundledCatalog
      ? confirmBundledCatalogEquivalence(prevSources)
      : prevSources;
    const nextCollisionPending = confirmBundledCatalog ? false : prevCollisionPending;
    const auditAction = confirmBundledCatalog
      ? AUDIT_ACTION.THREAT_ACTOR_BUNDLED_IDENTITY_CONFIRMED
      : AUDIT_ACTION.THREAT_ACTOR_UPDATED;

    try {
      const dup = await findDuplicate(pool, { name, slug, excludeId: id });
      if (dup) return res.status(409).json({ success: false, error: 'Threat actor name or slug already exists' });

      const { rows } = await pool.query(
        `UPDATE threat_actors
         SET name = $2, slug = $3, aliases = $4, description = $5, active = $6,
             catalog_sources = $7, bundled_catalog_collision_pending = $8,
             updated_by = $9, updated_at = NOW()
         WHERE id = $1::uuid
         RETURNING *`,
        [id, name, slug, aliases.length ? aliases : null, description, active, nextCatalogSources, nextCollisionPending, userLabel]
      );
      const actor = rows[0];
      await audit.auditSuccess({
        req,
        action: auditAction,
        entityType: AUDIT_ENTITY.THREAT_ACTOR,
        entityId: String(actor.id),
        entityDisplay: actor.name,
        before: actorAuditSnapshot(prev),
        after: actorAuditSnapshot(actor),
        metadata: confirmBundledCatalog ? {
          slug: actor.slug,
          previous_catalog_sources: prevSources,
          resulting_catalog_sources: nextCatalogSources,
          previous_collision_pending: prevCollisionPending,
          resulting_collision_pending: nextCollisionPending
        } : { slug: actor.slug }
      });
      return res.json({ success: true, threat_actor: serializeThreatActor(actor) });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  });

  async function setActorActive(req, res, active) {
    const id = String(req.params.id || '').trim();
    if (!/^[0-9a-f-]{36}$/i.test(id)) {
      return res.status(400).json({ success: false, error: 'Invalid threat actor id' });
    }
    const prev = await fetchActorById(pool, id);
    if (!prev) return res.status(404).json({ success: false, error: 'Threat actor not found' });
    const userLabel = req.user?.email || req.user?.username || req.user?.publicId || null;
    try {
      const { rows } = await pool.query(
        `UPDATE threat_actors SET active = $2, updated_by = $3, updated_at = NOW()
         WHERE id = $1::uuid RETURNING *`,
        [id, active, userLabel]
      );
      const actor = rows[0];
      await audit.auditSuccess({
        req,
        action: active ? AUDIT_ACTION.THREAT_ACTOR_ENABLED : AUDIT_ACTION.THREAT_ACTOR_DISABLED,
        entityType: AUDIT_ENTITY.THREAT_ACTOR,
        entityId: String(actor.id),
        entityDisplay: actor.name,
        before: actorAuditSnapshot(prev),
        after: actorAuditSnapshot(actor)
      });
      return res.json({ success: true, threat_actor: serializeThreatActor(actor) });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  }

  app.patch('/api/admin/threat-actors/:id/disable', requireRole(ROLES.ADMIN), (req, res) => setActorActive(req, res, false));
  app.patch('/api/admin/threat-actors/:id/enable', requireRole(ROLES.ADMIN), (req, res) => setActorActive(req, res, true));
}

export async function fetchActiveThreatActors(pool) {
  const { rows } = await pool.query(
    `SELECT id, name, slug, aliases, active FROM threat_actors WHERE active = TRUE ORDER BY name ASC`
  );
  return rows;
}

export async function resolveThreatActorById(pool, id) {
  if (!id) return null;
  const { rows } = await pool.query(
    `SELECT id, name, slug, aliases, active FROM threat_actors WHERE id = $1::uuid`,
    [id]
  );
  return rows[0] || null;
}
