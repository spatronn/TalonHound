import { AUDIT_ACTION, AUDIT_ENTITY } from '../lib/auditConstants.js';
import { ROLES, normalizeAppRole, requireRole } from '../lib/rbac.js';
import {
  CATALOG_LINK_MODE,
  CATALOG_LINK_OUTCOME,
  CatalogLinkError,
  linkSourceLabelToCatalog,
  loadCatalogLinkContext
} from '../lib/attributionCatalogLinking.js';
import {
  buildMultiThreatClassificationResponseFields,
  diffThreatClassificationSlugs,
  loadIocThreatClassificationDetails,
  mergeIocThreatMetadataItem,
  normalizeIocThreatClassificationSlugs,
  validateIocThreatClassificationSlugs
} from '../lib/iocThreatClassifications.js';
import {
  planThreatClassificationEffectiveSave,
  syncThreatClassificationOverrides
} from '../lib/iocThreatClassificationOverrides.js';

export {
  batchLoadFeedClassifications,
  batchLoadThreatClassificationSuppressions
} from '../lib/iocThreatClassificationOverrides.js';
import {
  canonicalClassificationResponseFields,
  loadCanonicalIocClassification,
  loadCanonicalIocClassifications
} from '../lib/iocCanonicalClassifications.js';
import { resolveThreatActorById } from './threatActors.js';
import {
  buildMultiThreatActorResponseFields,
  fetchIocThreatActors,
  loadIocThreatActorDetails,
  parseThreatActorBody,
  replaceIocThreatActors,
  validateIocThreatActorIds,
  diffThreatActorIds
} from '../lib/iocThreatActors.js';
import {
  emptyAttributionResponseFields,
  fetchEffectiveIocAttributions,
  loadEffectiveIocAttributions
} from '../lib/iocSourceAttributions.js';
import {
  parseMalwareFamilyBody,
  replaceIocMalwareFamilies,
  validateIocMalwareFamilyIds,
  diffMalwareFamilyIds,
  ensureMalwareFamilyByName
} from '../lib/iocMalwareFamilies.js';

async function fetchIocRow(pool, iocId, observableType) {
  const { rows } = await pool.query(
    `SELECT i.id, i.public_id, i.observable, i.observable_type, i.threat_classification, i.threat_actor_id,
            ta.name AS threat_actor_name
     FROM ioc_items i
     LEFT JOIN threat_actors ta ON ta.id = i.threat_actor_id
     WHERE i.id = $1 AND i.observable_type = $2`,
    [iocId, observableType]
  );
  return rows[0] || null;
}

function isThreatActorsTableMissing(err) {
  return String(err?.message || '').includes('ioc_threat_actors');
}

/** Effective attributions (analyst ∪ source-reported) with provenance. */
async function resolveThreatActorFields(pool, iocId, observableType, legacyRow = null) {
  try {
    const fields = await fetchEffectiveIocAttributions(pool, iocId, observableType);
    if (fields.threat_actors?.length || fields.malware_families?.length) return fields;
    // Fall through for legacy single-column actor when junction/attributions empty.
    if (!legacyRow?.threat_actor_id) return fields;
  } catch (err) {
    if (!isThreatActorsTableMissing(err)
      && !String(err?.message || '').includes('ioc_source_attributions')) {
      throw err;
    }
  }
  if (legacyRow?.threat_actor_id) {
    const actor = await resolveThreatActorById(pool, legacyRow.threat_actor_id);
    if (actor) {
      return {
        ...emptyAttributionResponseFields(),
        ...buildMultiThreatActorResponseFields([{
          id: actor.id,
          name: actor.name,
          slug: actor.slug,
          aliases: actor.aliases,
          active: actor.active
        }]),
        analyst_threat_actor_ids: [actor.id],
        malware_families: [],
        malware_family_ids: [],
        analyst_malware_family_ids: []
      };
    }
    return {
      ...emptyAttributionResponseFields(),
      ...buildMultiThreatActorResponseFields([{
        id: legacyRow.threat_actor_id,
        name: legacyRow.threat_actor_name || null,
        active: true
      }]),
      analyst_threat_actor_ids: [legacyRow.threat_actor_id]
    };
  }
  return emptyAttributionResponseFields();
}

/** Analyst-only threat actor IDs for edit/no-op comparison. */
async function loadAnalystThreatActorIds(pool, iocId, observableType) {
  try {
    const fields = await fetchIocThreatActors(pool, iocId, observableType);
    return fields.threat_actor_ids || [];
  } catch (err) {
    if (!isThreatActorsTableMissing(err)) throw err;
    return [];
  }
}

function userLabel(req) {
  return req.user?.email || req.user?.username || req.user?.publicId || null;
}

function parseClassificationBody(body) {
  if (Array.isArray(body?.threat_classifications)) return body.threat_classifications;
  if (Array.isArray(body?.classifications)) return body.classifications;
  if (Array.isArray(body?.effective_threat_classifications)) return body.effective_threat_classifications;
  if (body?.threat_classification != null || body?.primary_threat_classification != null) {
    return [body?.threat_classification ?? body?.primary_threat_classification];
  }
  return body?.threat_classifications;
}

function isOverridesTableMissing(err) {
  return String(err?.message || '').includes('ioc_threat_classification_overrides');
}

/**
 * IOC Details classification bundle = the canonical effective classification
 * (lib/iocCanonicalClassifications.js), same as list / REST / MCP / DSL / exports.
 */
async function buildEffectiveClassificationBundle(pool, iocId, observableType) {
  const canonical = await loadCanonicalIocClassification(pool, { id: iocId, observable_type: observableType });
  return canonicalClassificationResponseFields(canonical);
}

async function buildIocClassificationResponse(pool, iocId, observableType, baseRow = null) {
  const row = baseRow || await fetchIocRow(pool, iocId, observableType);
  if (!row) return null;
  const fields = await buildEffectiveClassificationBundle(pool, iocId, observableType);
  const actorFields = await resolveThreatActorFields(pool, iocId, observableType, row);
  return {
    public_id: row.public_id,
    ...actorFields,
    ...fields
  };
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {{ auditSuccess: Function }} audit
 * @param {{ invalidateDetailsCache?: (publicId: string) => void }} [opts]
 */
export function registerIocThreatMetadataRoutes(app, pool, audit, opts = {}) {
  const invalidateDetailsCache = typeof opts.invalidateDetailsCache === 'function'
    ? opts.invalidateDetailsCache
    : () => {};
  // Injectable for route tests; production uses lib/attributionCatalogLinking.js.
  const catalogLinking = {
    loadContext: loadCatalogLinkContext,
    link: linkSourceLabelToCatalog,
    loadAttributionFields: (iocId, observableType) => resolveThreatActorFields(pool, iocId, observableType),
    ...(opts.catalogLinking || {})
  };

  async function applyIocThreatClassifications(req, res, { auditAction }) {
    const iocId = Number(req.params.id);
    if (!Number.isFinite(iocId) || iocId <= 0) {
      return res.status(400).json({ success: false, error: 'Invalid IOC id' });
    }
    const observableType = String(req.body?.observable_type || req.query?.observable_type || '').trim();
    if (!observableType) {
      return res.status(400).json({ success: false, error: 'observable_type is required' });
    }

    try {
      const prev = await fetchIocRow(pool, iocId, observableType);
      if (!prev) return res.status(404).json({ success: false, error: 'IOC not found' });

      // Plan against the canonical identity: feed classifications (evidence and
      // importer-stored values, all aliases) are kept by leaving them checked and
      // hidden by unchecking (suppression); everything else checked becomes an
      // analyst assertion. Existing analyst assertions stay analyst even when a
      // feed also proposes the same slug.
      const canonicalBefore = await loadCanonicalIocClassification(pool, { id: iocId, observable_type: observableType });
      const feedClassifications = canonicalBefore.feed;
      const planned = planThreatClassificationEffectiveSave({
        desiredEffectiveSlugs: parseClassificationBody(req.body),
        feedClassifications
      });
      const keptAnalyst = canonicalBefore.analyst.filter((slug) => planned.desired.includes(slug));
      planned.additions = [...new Set([...planned.additions, ...keptAnalyst])];

      const check = await validateIocThreatClassificationSlugs(pool, planned.additions, {
        requireActive: true
      });
      if (!check.ok) return res.status(400).json({ success: false, error: check.error });

      const beforeBundle = canonicalClassificationResponseFields(canonicalBefore);
      const beforeEffective = (beforeBundle.effective_threat_classifications || [])
        .map((x) => x.value)
        .filter((v) => v && v !== 'unknown');

      const sortKey = (arr) => [...arr].map((x) => String(x).toLowerCase()).sort().join('|');
      if (sortKey(beforeEffective) === sortKey(planned.desired)) {
        const unchanged = await buildIocClassificationResponse(pool, iocId, observableType, prev);
        return res.json({ success: true, ...unchanged });
      }

      const client = await pool.connect();
      let syncResult;
      try {
        await client.query('BEGIN');
        syncResult = await syncThreatClassificationOverrides(client, {
          iocId,
          observableType,
          additions: planned.additions,
          suppressions: planned.suppressions,
          actor: userLabel(req)
        });
        await client.query('COMMIT');
      } catch (err) {
        try { await client.query('ROLLBACK'); } catch { /* ignore */ }
        throw err;
      } finally {
        client.release();
      }

      invalidateDetailsCache(prev.public_id);

      const afterBundle = await buildEffectiveClassificationBundle(pool, iocId, observableType);
      const afterEffective = (afterBundle.effective_threat_classifications || [])
        .map((x) => x.value)
        .filter((v) => v && v !== 'unknown');
      const diff = diffThreatClassificationSlugs(beforeEffective, afterEffective);

      await audit.auditSuccess({
        req,
        action: auditAction,
        entityType: AUDIT_ENTITY.IOC,
        entityId: String(iocId),
        entityDisplay: `${observableType} · ${prev.observable}`,
        metadata: {
          observable_type: observableType,
          ioc_value: prev.observable,
          old_classification: beforeEffective[0] || 'unknown',
          new_classification: afterEffective[0] || 'unknown',
          ...diff,
          created_adds: syncResult.created_adds,
          cleared_adds: syncResult.cleared_adds,
          created_suppressions: syncResult.created_suppressions,
          restored_suppressions: syncResult.restored_suppressions
        },
        before: {
          effective_threat_classifications: beforeEffective,
          analyst_additions: beforeBundle.analyst_threat_classifications?.map((x) => x.value) || [],
          suppressions: beforeBundle.suppressed_threat_classifications?.map((x) => x.value) || []
        },
        after: {
          effective_threat_classifications: afterEffective,
          analyst_additions: afterBundle.analyst_threat_classifications?.map((x) => x.value) || [],
          suppressions: afterBundle.suppressed_threat_classifications?.map((x) => x.value) || []
        }
      });

      for (const slug of syncResult.created_suppressions || []) {
        await audit.auditSuccess({
          req,
          action: AUDIT_ACTION.IOC_THREAT_CLASSIFICATION_SUPPRESSED,
          entityType: AUDIT_ENTITY.IOC,
          entityId: String(iocId),
          entityDisplay: `${observableType} · ${prev.observable}`,
          metadata: { observable_type: observableType, classification: slug, action: 'suppress' }
        });
      }
      for (const slug of syncResult.restored_suppressions || []) {
        await audit.auditSuccess({
          req,
          action: AUDIT_ACTION.IOC_THREAT_CLASSIFICATION_RESTORED,
          entityType: AUDIT_ENTITY.IOC,
          entityId: String(iocId),
          entityDisplay: `${observableType} · ${prev.observable}`,
          metadata: { observable_type: observableType, classification: slug, action: 'restore' }
        });
      }

      const response = await buildIocClassificationResponse(pool, iocId, observableType, prev);
      return res.json({ success: true, ...response });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  }

  app.patch('/api/ioc/:id/threat-classifications', (req, res) =>
    applyIocThreatClassifications(req, res, { auditAction: AUDIT_ACTION.IOC_THREAT_CLASSIFICATIONS_UPDATED })
  );

  app.patch('/api/ioc/:id/threat-classification', (req, res) =>
    applyIocThreatClassifications(req, res, { auditAction: AUDIT_ACTION.IOC_THREAT_CLASSIFICATION_UPDATED })
  );

  async function applyIocThreatActors(req, res, { auditAction }) {
    const iocId = Number(req.params.id);
    if (!Number.isFinite(iocId) || iocId <= 0) {
      return res.status(400).json({ success: false, error: 'Invalid IOC id' });
    }
    const observableType = String(req.body?.observable_type || req.query?.observable_type || '').trim();
    if (!observableType) {
      return res.status(400).json({ success: false, error: 'observable_type is required' });
    }

    const parsed = parseThreatActorBody(req.body);
    if (parsed === undefined) {
      return res.status(400).json({
        success: false,
        error: 'threat_actor_ids (array) or threat_actor_id is required'
      });
    }

    const check = await validateIocThreatActorIds(pool, parsed, { requireActive: true });
    if (!check.ok) return res.status(400).json({ success: false, error: check.error });
    const nextIds = check.value;

    try {
      const prev = await fetchIocRow(pool, iocId, observableType);
      if (!prev) return res.status(404).json({ success: false, error: 'IOC not found' });

      const beforeFields = await resolveThreatActorFields(pool, iocId, observableType, prev);
      const beforeIds = beforeFields.analyst_threat_actor_ids?.length
        ? beforeFields.analyst_threat_actor_ids
        : await loadAnalystThreatActorIds(pool, iocId, observableType);
      const sortKey = (arr) => [...arr].map((x) => String(x).toLowerCase()).sort().join('|');
      if (sortKey(beforeIds) === sortKey(nextIds)) {
        return res.json({
          success: true,
          public_id: prev.public_id,
          ...beforeFields
        });
      }

      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await replaceIocThreatActors(client, {
          iocId,
          observableType,
          threatActorIds: nextIds,
          sourceType: 'analyst',
          actor: userLabel(req),
          manageTransaction: false
        });
        await client.query('COMMIT');
      } catch (err) {
        try { await client.query('ROLLBACK'); } catch { /* ignore */ }
        throw err;
      } finally {
        client.release();
      }

      invalidateDetailsCache(prev.public_id);
      const afterFields = await resolveThreatActorFields(pool, iocId, observableType);
      const afterAnalystIds = afterFields.analyst_threat_actor_ids || nextIds;
      const diff = diffThreatActorIds(beforeIds, afterAnalystIds);
      const beforeNames = (beforeFields.threat_actors || [])
        .filter((a) => a.attribution === 'analyst' || a.attribution === 'mixed' || !a.attribution)
        .map((a) => a.name).filter(Boolean);
      const afterNames = (afterFields.threat_actors || [])
        .filter((a) => a.attribution === 'analyst' || a.attribution === 'mixed')
        .map((a) => a.name).filter(Boolean);

      await audit.auditSuccess({
        req,
        action: auditAction,
        entityType: AUDIT_ENTITY.IOC,
        entityId: String(iocId),
        entityDisplay: `${observableType} · ${prev.observable}`,
        metadata: {
          observable_type: observableType,
          ioc_value: prev.observable,
          old_threat_actor: beforeNames[0] || null,
          new_threat_actor: afterNames[0] || null,
          old_threat_actors: beforeNames,
          new_threat_actors: afterNames,
          old_threat_actor_id: beforeFields.threat_actor_id || null,
          new_threat_actor_id: afterFields.threat_actor_id || null,
          ...diff
        },
        before: {
          threat_actor_id: beforeFields.threat_actor_id || null,
          threat_actor_name: beforeFields.threat_actor_name || null,
          threat_actor_ids: beforeIds,
          threat_actors: beforeNames
        },
        after: {
          threat_actor_id: afterFields.threat_actor_id || null,
          threat_actor_name: afterFields.threat_actor_name || null,
          threat_actor_ids: afterFields.threat_actor_ids || [],
          threat_actors: afterNames
        }
      });

      return res.json({
        success: true,
        public_id: prev.public_id,
        ...afterFields
      });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  }

  app.patch('/api/ioc/:id/threat-actors', (req, res) =>
    applyIocThreatActors(req, res, { auditAction: AUDIT_ACTION.IOC_THREAT_ACTORS_UPDATED })
  );

  app.patch('/api/ioc/:id/threat-actor', (req, res) =>
    applyIocThreatActors(req, res, { auditAction: AUDIT_ACTION.IOC_THREAT_ACTOR_UPDATED })
  );

  async function applyIocMalwareFamilies(req, res) {
    const iocId = Number(req.params.id);
    if (!Number.isFinite(iocId) || iocId <= 0) {
      return res.status(400).json({ success: false, error: 'Invalid IOC id' });
    }
    const observableType = String(req.body?.observable_type || req.query?.observable_type || '').trim();
    if (!observableType) {
      return res.status(400).json({ success: false, error: 'observable_type is required' });
    }

    const parsed = parseMalwareFamilyBody(req.body);
    if (parsed === undefined) {
      return res.status(400).json({
        success: false,
        error: 'malware_family_ids (array), malware_families, or malware_family_names is required'
      });
    }

    const resolvedIds = [];
    for (const name of parsed.names || []) {
      const row = await ensureMalwareFamilyByName(pool, name);
      if (!row?.id) {
        return res.status(400).json({
          success: false,
          error: `Unknown malware family: ${name}. Create it under Threat Intelligence → Malware Families first.`
        });
      }
      if (row.active === false) {
        return res.status(400).json({
          success: false,
          error: `Malware family is inactive: ${row.name || name}`
        });
      }
      resolvedIds.push(row.id);
    }
    const candidateIds = [...(parsed.ids || []), ...resolvedIds];
    const check = await validateIocMalwareFamilyIds(pool, candidateIds, { requireActive: true });
    if (!check.ok) return res.status(400).json({ success: false, error: check.error });
    const nextIds = check.value;

    try {
      const prev = await fetchIocRow(pool, iocId, observableType);
      if (!prev) return res.status(404).json({ success: false, error: 'IOC not found' });

      const beforeFields = await resolveThreatActorFields(pool, iocId, observableType, prev);
      const beforeIds = beforeFields.analyst_malware_family_ids || [];
      const sortKey = (arr) => [...arr].map((x) => String(x).toLowerCase()).sort().join('|');
      if (sortKey(beforeIds) === sortKey(nextIds)) {
        return res.json({ success: true, public_id: prev.public_id, ...beforeFields });
      }

      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await replaceIocMalwareFamilies(client, {
          iocId,
          observableType,
          malwareFamilyIds: nextIds,
          sourceType: 'analyst',
          actor: userLabel(req),
          manageTransaction: false
        });
        await client.query('COMMIT');
      } catch (err) {
        try { await client.query('ROLLBACK'); } catch { /* ignore */ }
        throw err;
      } finally {
        client.release();
      }

      invalidateDetailsCache(prev.public_id);
      const afterFields = await resolveThreatActorFields(pool, iocId, observableType);
      const diff = diffMalwareFamilyIds(beforeIds, afterFields.analyst_malware_family_ids || nextIds);
      const beforeNames = (beforeFields.malware_families || [])
        .filter((f) => f.attribution === 'analyst' || f.attribution === 'mixed')
        .map((f) => f.name).filter(Boolean);
      const afterNames = (afterFields.malware_families || [])
        .filter((f) => f.attribution === 'analyst' || f.attribution === 'mixed')
        .map((f) => f.name).filter(Boolean);

      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.IOC_MALWARE_FAMILIES_UPDATED,
        entityType: AUDIT_ENTITY.IOC,
        entityId: String(iocId),
        entityDisplay: `${observableType} · ${prev.observable}`,
        metadata: {
          observable_type: observableType,
          ioc_value: prev.observable,
          old_malware_families: beforeNames,
          new_malware_families: afterNames,
          ...diff
        },
        before: { malware_family_ids: beforeIds, malware_families: beforeNames },
        after: {
          malware_family_ids: afterFields.analyst_malware_family_ids || nextIds,
          malware_families: afterNames
        }
      });

      return res.json({ success: true, public_id: prev.public_id, ...afterFields });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  }

  app.patch('/api/ioc/:id/malware-families', (req, res) => applyIocMalwareFamilies(req, res));

  // ---------------------------------------------------------------------------
  // Source-reported Threat Actor / Malware Family → local catalog identity
  // (IOC Details "+" on an unlinked chip). Catalog resolution only: the source
  // assertion stays a source claim; analyst attribution (Edit) is untouched.
  // ---------------------------------------------------------------------------

  function sendCatalogLinkError(res, err) {
    if (err instanceof CatalogLinkError) {
      return res.status(err.status).json({ success: false, error: err.message, code: err.code, ...err.details });
    }
    return res.status(500).json({ success: false, error: err?.message || 'Request failed' });
  }

  app.get('/api/ioc/:id/source-attributions/catalog-candidates', async (req, res) => {
    try {
      const ctx = await catalogLinking.loadContext(pool, {
        iocId: req.params.id,
        observableType: req.query?.observable_type,
        entityKind: req.query?.entity_kind,
        sourceLabel: req.query?.source_label,
        q: req.query?.q || ''
      });
      const role = normalizeAppRole(req.user?.role);
      const { ioc, ...rest } = ctx;
      return res.json({
        success: true,
        public_id: ioc.public_id,
        ...rest,
        permissions: {
          can_link: role === ROLES.ADMIN || role === ROLES.ANALYST,
          // Catalog writes are admin-only (same boundary as the catalog pages).
          can_create: role === ROLES.ADMIN
        }
      });
    } catch (err) {
      return sendCatalogLinkError(res, err);
    }
  });

  app.post('/api/ioc/:id/source-attributions/catalog-link',
    requireRole(ROLES.ADMIN, ROLES.ANALYST),
    async (req, res) => {
      const body = req.body || {};
      const mode = String(body.mode || '').trim();
      try {
        const result = await catalogLinking.link(pool, {
          iocId: req.params.id,
          observableType: body.observable_type,
          entityKind: body.entity_kind,
          sourceLabel: body.source_label,
          mode,
          entityId: mode === CATALOG_LINK_MODE.LINK ? body.entity_id : null,
          create: mode === CATALOG_LINK_MODE.CREATE ? body.create : null,
          confirmDistinct: body.confirm_distinct === true,
          canCreate: normalizeAppRole(req.user?.role) === ROLES.ADMIN,
          actorLabel: userLabel(req)
        });
        const { ioc, entity, created_entity: createdEntity } = result;
        const kind = String(body.entity_kind);
        const isActor = kind === 'threat_actor';

        if (result.outcome !== CATALOG_LINK_OUTCOME.ALREADY_LINKED) {
          invalidateDetailsCache(ioc.public_id);
          if (createdEntity) {
            // Same catalog event the admin catalog pages emit, with its origin.
            await audit.auditSuccess({
              req,
              action: isActor ? AUDIT_ACTION.THREAT_ACTOR_CREATED : AUDIT_ACTION.MALWARE_FAMILY_CREATED,
              entityType: isActor ? AUDIT_ENTITY.THREAT_ACTOR : AUDIT_ENTITY.MALWARE_FAMILY,
              entityId: String(createdEntity.id),
              entityDisplay: createdEntity.name,
              after: {
                id: createdEntity.id,
                name: createdEntity.name,
                slug: createdEntity.slug,
                aliases: createdEntity.aliases || [],
                description: createdEntity.description || null,
                active: createdEntity.active !== false,
                catalog_sources: createdEntity.catalog_sources || ['manual']
              },
              metadata: {
                slug: createdEntity.slug,
                origin: 'ioc_source_label_link',
                source_label: result.source_label,
                // What the provider called it vs. where TalonHound put it.
                provider_entity_types: [...new Set(result.evidence.map((e) => e.provider_entity_type).filter(Boolean))],
                local_entity_kind: kind,
                classification_basis: 'source_reported_metadata_unverified',
                cross_catalog_matches: (result.cross_catalog_matches || []).map((m) => ({
                  entity_kind: m.entity_kind, id: m.id, name: m.name, match: m.match
                })),
                ioc_id: Number(ioc.id),
                ioc_observable_type: ioc.observable_type
              }
            });
          }
          const created = result.outcome === CATALOG_LINK_OUTCOME.CREATED_AND_LINKED;
          await audit.auditSuccess({
            req,
            action: isActor
              ? (created ? AUDIT_ACTION.IOC_THREAT_ACTOR_CATALOG_CREATED_AND_LINKED : AUDIT_ACTION.IOC_THREAT_ACTOR_CATALOG_LINKED)
              : (created ? AUDIT_ACTION.IOC_MALWARE_FAMILY_CATALOG_CREATED_AND_LINKED : AUDIT_ACTION.IOC_MALWARE_FAMILY_CATALOG_LINKED),
            entityType: AUDIT_ENTITY.IOC,
            entityId: String(ioc.id),
            entityDisplay: `${ioc.observable_type} · ${ioc.observable}`,
            metadata: {
              observable_type: ioc.observable_type,
              ioc_value: ioc.observable,
              ioc_public_id: ioc.public_id,
              operation: created ? 'create_and_link' : 'link',
              entity_kind: kind,
              entity_id: entity.id,
              entity_name: entity.name,
              source_label: result.source_label,
              // The analyst confirmed what the label means, not the source's claim.
              resolution_method: 'analyst',
              attribution: 'source_reported',
              linked_assertions: result.linked_assertions,
              sources: result.evidence.map((e) => ({
                source_name: e.source_name,
                feed_key: e.feed_key,
                provider_field: e.provider_field || null,
                evidence_ref_type: e.evidence_ref_type,
                evidence_ref_id: e.evidence_ref_id,
                evidence_title: e.evidence_title,
                assertion_status: e.assertion_status
              }))
            },
            after: { entity_id: entity.id, entity_name: entity.name, source_label: result.source_label }
          });
        }

        const fields = await catalogLinking.loadAttributionFields(Number(ioc.id), ioc.observable_type);
        return res.json({
          success: true,
          outcome: result.outcome,
          entity_kind: kind,
          entity,
          created: Boolean(createdEntity),
          linked_assertions: result.linked_assertions,
          source_label: result.source_label,
          evidence: result.evidence,
          cross_catalog_matches: result.cross_catalog_matches || [],
          public_id: ioc.public_id,
          ...fields
        });
      } catch (err) {
        return sendCatalogLinkError(res, err);
      }
    });
}

export async function buildThreatMetadataFields(pool, row) {
  if (!row) {
    return {
      ...buildMultiThreatClassificationResponseFields([]),
      ...emptyAttributionResponseFields()
    };
  }
  const actorFields = Number.isFinite(Number(row.id)) && row.observable_type
    ? await resolveThreatActorFields(pool, row.id, row.observable_type, row)
    : (row.threat_actor_id
      ? {
        ...emptyAttributionResponseFields(),
        ...buildMultiThreatActorResponseFields([{
          id: row.threat_actor_id,
          name: row.threat_actor_name || null,
          active: true
        }]),
        analyst_threat_actor_ids: [row.threat_actor_id]
      }
      : emptyAttributionResponseFields());

  if (Number.isFinite(Number(row.id)) && row.observable_type) {
    try {
      const fields = await buildEffectiveClassificationBundle(pool, row.id, row.observable_type);
      return { ...fields, ...actorFields };
    } catch (err) {
      if (!isOverridesTableMissing(err)) {
        console.warn('[threat-metadata] effective bundle failed:', err.message);
      }
    }
    const detailMap = await loadIocThreatClassificationDetails(pool, [{
      id: row.id,
      observable_type: row.observable_type
    }]);
    const key = `${Number(row.id)}|${String(row.observable_type || '')}`;
    const fields = detailMap.get(key);
    if (fields) {
      return { ...fields, ...actorFields };
    }
  }
  const slugs = normalizeIocThreatClassificationSlugs(row.threat_classification);
  return {
    ...buildMultiThreatClassificationResponseFields(slugs.length ? slugs : []),
    ...actorFields
  };
}

export async function enrichItemsWithThreatMetadata(pool, items) {
  const map = new Map();
  if (!items?.length) return map;

  const pairs = items
    .map((it) => ({
      id: Number(it?.id),
      observable_type: String(it?.observable_type || '').trim()
    }))
    .filter((p) => Number.isFinite(p.id) && p.id > 0 && p.observable_type);
  if (!pairs.length) return map;

  const values = pairs.map((_, i) => `($${i * 2 + 1}::int, $${i * 2 + 2}::text)`).join(', ');
  const params = pairs.flatMap((p) => [p.id, p.observable_type]);
  const { rows } = await pool.query(
    `SELECT i.id, i.observable_type, i.threat_classification, i.threat_actor_id, ta.name AS threat_actor_name
     FROM ioc_items i
     LEFT JOIN threat_actors ta ON ta.id = i.threat_actor_id
     WHERE (i.id, i.observable_type) IN (VALUES ${values})`,
    params
  );

  const detailMap = await loadIocThreatClassificationDetails(pool, pairs);
  let attributionMap = new Map();
  try {
    attributionMap = await loadEffectiveIocAttributions(pool, pairs, { compact: true });
  } catch (err) {
    if (!String(err?.message || '').includes('ioc_source_attributions')) {
      console.warn('[threat-metadata] attribution load failed:', err.message);
    }
    attributionMap = await loadIocThreatActorDetails(pool, pairs);
  }
  for (const row of rows) {
    const key = `${Number(row.id)}|${String(row.observable_type)}`;
    let fields = detailMap.get(key);
    if (!fields) {
      const slugs = normalizeIocThreatClassificationSlugs(row.threat_classification);
      fields = buildMultiThreatClassificationResponseFields(slugs.length ? slugs : []);
    }
    let actorFields = attributionMap.get(key);
    if (!actorFields?.threat_actor_ids?.length && !actorFields?.threat_actors?.length && row.threat_actor_id) {
      actorFields = {
        ...emptyAttributionResponseFields(),
        ...buildMultiThreatActorResponseFields([{
          id: row.threat_actor_id,
          name: row.threat_actor_name || null,
          active: true
        }]),
        analyst_threat_actor_ids: [row.threat_actor_id]
      };
    }
    if (!actorFields) actorFields = emptyAttributionResponseFields();
    map.set(key, {
      ...fields,
      ...actorFields
    });
  }
  return map;
}

export function mergeThreatMetadataItem(item, metaMap) {
  const key = `${Number(item?.id)}|${String(item?.observable_type || '')}`;
  const meta = metaMap?.get(key);
  if (meta) return { ...item, ...meta };
  return mergeIocThreatMetadataItem(item, null, null);
}

/**
 * Canonical classifications for an IOC list page (one batched load; see
 * lib/iocCanonicalClassifications.js). `scopeBySeed` reuses the page's artifact
 * alias expansion.
 */
export function loadListCanonicalClassifications(pool, items, { scopeBySeed = null } = {}) {
  return loadCanonicalIocClassifications(pool, items, scopeBySeed ? { scopeBySeed } : {});
}

/** Overlay the canonical classification fields on a list item. */
export function mergeCanonicalClassificationsIntoItem(item, canonicalMap) {
  const key = `${Number(item?.id)}|${String(item?.observable_type || '')}`;
  const canonical = canonicalMap?.get(key);
  if (!canonical) return item;
  return { ...item, ...canonicalClassificationResponseFields(canonical) };
}
