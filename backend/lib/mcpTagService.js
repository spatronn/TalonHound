/**
 * MCP IOC tag tools — the IOC Details "Tags" panel over MCP.
 *
 * list_tags      the enabled tag catalog (what the IOC Details tag picker offers
 *                through GET /api/tags).
 * add_ioc_tags   analyst (origin='manual') assignments of existing, enabled
 *                catalog tags via ensureIocTagAssignment — the same write as
 *                POST /api/ioc/:id/tags. Never creates catalog tags, never
 *                re-enables disabled ones.
 * remove_ioc_tags  deletes analyst assignments only — the same rule as
 *                DELETE /api/ioc/:id/tags/:tagId. Source (feed/integration) and
 *                Threat Library report tags are never removed here.
 *
 * Every change writes the same ioc.tag.added / ioc.tag.removed audit event as
 * the GUI, with MCP provenance (API key id/name, owner user, tool).
 */

import { normalizeTagName, MAX_TAG_NAME_LENGTH } from './tagHelpers.js';
import { ensureIocTagAssignment } from './tagCatalogService.js';
import { resolveEnrichmentIocs } from './enrichmentOrchestrator.js';
import { hydrateIocApiMetadata, EMPTY_IOC_API_METADATA } from './iocApiMetadata.js';
import { iocPairKey } from './iocThreatClassifications.js';
import { mcpActorAuditFields } from './mcpIocService.js';
import { getMcpConfig } from './mcpConfig.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from './auditConstants.js';

function validationError(message) {
  return { error: { code: 'VALIDATION_ERROR', message } };
}

/**
 * Normalize + dedupe requested tag names with the canonical catalog rule
 * (trim, lowercase, collapse whitespace — `-`, `_` and space stay distinct).
 * @returns {{ ok: true, names: string[] } | { ok: false, message: string }}
 */
export function normalizeRequestedTagNames(raw, max) {
  if (!Array.isArray(raw) || !raw.length) {
    return { ok: false, message: 'tags must be a non-empty array of tag names' };
  }
  const names = [];
  for (const value of raw) {
    if (typeof value !== 'string') return { ok: false, message: 'tags must be an array of tag names' };
    const name = normalizeTagName(value);
    if (!name) return { ok: false, message: 'tags must not contain empty names' };
    if (name.length > MAX_TAG_NAME_LENGTH) {
      return { ok: false, message: `tag names are at most ${MAX_TAG_NAME_LENGTH} characters` };
    }
    if (!names.includes(name)) names.push(name);
  }
  if (names.length > max) return { ok: false, message: `at most ${max} tags per call` };
  return { ok: true, names };
}

async function resolveTargetIoc(pool, ref) {
  const key = String(ref ?? '').trim();
  const { found, invalid } = await resolveEnrichmentIocs(pool, [key]);
  if (invalid.length) {
    return validationError('ioc_id must be an IOC public_id (UUID) or numeric id');
  }
  const ioc = found.get(key.toLowerCase()) || found.get(key);
  if (!ioc) return { error: { code: 'IOC_NOT_FOUND', message: 'IOC not found' } };
  return { ioc };
}

async function loadIocTagView(pool, ioc) {
  const meta = (await hydrateIocApiMetadata(pool, [{ id: ioc.id, observable_type: ioc.observable_type }]))
    .get(iocPairKey(ioc.id, ioc.observable_type)) || EMPTY_IOC_API_METADATA;
  return { tags: meta.tags, tags_detail: meta.tags_detail };
}

function iocIdentity(ioc) {
  return {
    ioc_id: ioc.public_id || String(ioc.id),
    observable: ioc.observable,
    observable_type: ioc.observable_type
  };
}

async function auditTagChange(ctx, { action, ioc, tag, tool }) {
  if (!ctx.audit?.auditSuccess || !ctx.req) return;
  const actor = mcpActorAuditFields(ctx.mcpAuth || ctx.req.mcpAuth, ctx.req.user);
  // Same event shape as POST/DELETE /api/ioc/:id/tags, plus MCP provenance.
  await ctx.audit.auditSuccess({
    req: ctx.req,
    action,
    entityType: AUDIT_ENTITY.IOC,
    entityId: ioc.public_id ? String(ioc.public_id) : String(ioc.id),
    entityDisplay: ioc.observable || String(ioc.id),
    subjectIocId: ioc.id,
    subjectIocType: ioc.observable_type || null,
    subjectIocValue: ioc.observable || null,
    severity: AUDIT_SEVERITY.INFO,
    actorUsername: actor.actorUsername,
    actorEmail: actor.actorEmail,
    actorRole: actor.actorRole,
    actorPublicId: actor.actorPublicId,
    source: 'mcp',
    metadata: {
      ...actor.metadataExtras,
      tool,
      ioc_id: String(ioc.id),
      subject_ioc_id: String(ioc.id),
      subject_ioc_type: ioc.observable_type || null,
      subject_ioc_value: ioc.observable || null,
      tag_id: Number(tag.id),
      tag_name: tag.name,
      tag_type: tag.type || null,
      tag_category: tag.category || null
    }
  }).catch(() => {});
}

/**
 * @param {import('pg').Pool} pool
 * @param {{ query?: string, limit?: number }} args
 */
export async function mcpListTags(pool, args = {}, ctx = {}) {
  const config = ctx.config || getMcpConfig();
  const limit = Math.min(Math.max(Number(args.limit) || config.tagListMax, 1), config.tagListMax);
  const query = String(args.query || '').trim().slice(0, MAX_TAG_NAME_LENGTH);
  const params = [];
  const where = ['enabled = TRUE'];
  if (query) {
    params.push(`%${query.replace(/[\\%_]/g, (c) => `\\${c}`)}%`);
    where.push(`name ILIKE $${params.length}`);
  }
  params.push(limit + 1);
  const { rows } = await pool.query(
    `SELECT name, category, description
     FROM tags
     WHERE ${where.join(' AND ')}
     ORDER BY name ASC
     LIMIT $${params.length}`,
    params
  );
  return {
    body: {
      tags: rows.slice(0, limit).map((r) => ({
        name: r.name,
        category: r.category || null,
        description: r.description || null
      })),
      truncated: rows.length > limit
    }
  };
}

/**
 * @param {import('pg').Pool} pool
 * @param {{ ioc_id: string|number, tags: string[] }} args
 * @param {{ req?: object, mcpAuth?: object, audit?: object, config?: object }} ctx
 */
export async function mcpAddIocTags(pool, args = {}, ctx = {}) {
  const config = ctx.config || getMcpConfig();
  const requested = normalizeRequestedTagNames(args.tags, config.tagWriteMax);
  if (!requested.ok) return validationError(requested.message);
  const target = await resolveTargetIoc(pool, args.ioc_id);
  if (target.error) return target;
  const { ioc } = target;

  const { rows: catalog } = await pool.query(
    `SELECT id, name, type, category, enabled
     FROM tags
     WHERE name = ANY($1::text[])`,
    [requested.names]
  );
  const byName = new Map(catalog.map((r) => [r.name, r]));
  const unknown = requested.names.filter((n) => !byName.has(n));
  const disabled = requested.names.filter((n) => byName.get(n)?.enabled === false);
  if (unknown.length || disabled.length) {
    // All-or-nothing: the analyst picker only offers enabled catalog tags.
    const parts = [];
    if (unknown.length) parts.push(`not in the TalonHound tag catalog: ${unknown.join(', ')}`);
    if (disabled.length) parts.push(`disabled in the tag catalog: ${disabled.join(', ')}`);
    return {
      error: {
        code: 'TAG_NOT_ALLOWED',
        message: `No tags were changed. Tags ${parts.join('; ')}. Use list_tags to find catalog tags; MCP never creates or re-enables tags.`
      }
    };
  }

  const added = [];
  const alreadyPresent = [];
  const createdBy = ctx.req?.user?.id ?? null;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const name of requested.names) {
      const tag = byName.get(name);
      const { inserted } = await ensureIocTagAssignment(client, {
        iocId: ioc.id,
        observableType: ioc.observable_type,
        tagId: tag.id,
        origin: 'manual',
        createdBy
      });
      (inserted ? added : alreadyPresent).push(tag);
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }

  for (const tag of added) {
    await auditTagChange(ctx, { action: AUDIT_ACTION.IOC_TAG_ADDED, ioc, tag, tool: 'add_ioc_tags' });
  }

  return {
    body: {
      ...iocIdentity(ioc),
      added: added.map((t) => t.name),
      already_present: alreadyPresent.map((t) => t.name),
      ...(await loadIocTagView(pool, ioc))
    }
  };
}

/**
 * @param {import('pg').Pool} pool
 * @param {{ ioc_id: string|number, tags: string[] }} args
 * @param {{ req?: object, mcpAuth?: object, audit?: object, config?: object }} ctx
 */
export async function mcpRemoveIocTags(pool, args = {}, ctx = {}) {
  const config = ctx.config || getMcpConfig();
  const requested = normalizeRequestedTagNames(args.tags, config.tagWriteMax);
  if (!requested.ok) return validationError(requested.message);
  const target = await resolveTargetIoc(pool, args.ioc_id);
  if (target.error) return target;
  const { ioc } = target;

  // Analyst assignments on this IOC only — same predicate as the GUI delete.
  const { rows: removed } = await pool.query(
    `DELETE FROM ioc_tags it
     USING tags t
     WHERE t.id = it.tag_id
       AND it.ioc_id = $1
       AND it.ioc_observable_type = $2
       AND it.origin = 'manual'
       AND t.name = ANY($3::text[])
     RETURNING t.id, t.name, t.type, t.category`,
    [ioc.id, ioc.observable_type, requested.names]
  );

  for (const tag of removed) {
    await auditTagChange(ctx, { action: AUDIT_ACTION.IOC_TAG_REMOVED, ioc, tag, tool: 'remove_ioc_tags' });
  }

  const view = await loadIocTagView(pool, ioc);
  const removedNames = new Set(removed.map((t) => t.name));
  const remainingByName = new Map((view.tags_detail || []).map((t) => [t.name, t]));
  const notAssigned = [];
  const notRemovable = [];
  for (const name of requested.names) {
    if (removedNames.has(name)) continue;
    const still = remainingByName.get(name);
    if (!still) {
      notAssigned.push(name);
      continue;
    }
    const origins = still.origins?.length ? still.origins : [still.origin].filter(Boolean);
    notRemovable.push({
      tag: name,
      origins,
      reason: origins.includes('manual')
        // Analyst tag on another hash of the same file artifact (shown via alias scope).
        ? 'manual tag belongs to a file-artifact alias IOC, not this record'
        : 'source/feed or Threat Library report tag — not an analyst tag'
    });
  }

  return {
    body: {
      ...iocIdentity(ioc),
      removed: removed.map((t) => t.name),
      not_assigned: notAssigned,
      not_removable: notRemovable,
      ...view
    }
  };
}
