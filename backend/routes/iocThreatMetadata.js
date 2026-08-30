import { AUDIT_ACTION, AUDIT_ENTITY } from '../lib/auditConstants.js';
import {
  buildMultiThreatClassificationResponseFields,
  diffThreatClassificationSlugs,
  fetchIocThreatClassificationSlugs,
  loadIocThreatClassificationDetails,
  mergeIocThreatMetadataItem,
  normalizeIocThreatClassificationSlugs,
  validateIocThreatClassificationSlugs
} from '../lib/iocThreatClassifications.js';
import {
  buildThreatClassificationEffectiveFields,
  computeEffectiveThreatClassifications,
  listActiveThreatClassificationSuppressions,
  planThreatClassificationEffectiveSave,
  syncThreatClassificationOverrides
} from '../lib/iocThreatClassificationOverrides.js';
import { resolveThreatActorById } from './threatActors.js';
import { parseNoteFields, normalizeFeedTags } from '../lib/feedTagNormalization.js';
import {
  buildMultiThreatActorResponseFields,
  emptyThreatActorResponseFields,
  fetchIocThreatActors,
  loadIocThreatActorDetails,
  parseThreatActorBody,
  replaceIocThreatActors,
  validateIocThreatActorIds,
  diffThreatActorIds
} from '../lib/iocThreatActors.js';

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

/** Junction first; fall back to legacy ioc_items.threat_actor_id. */
async function resolveThreatActorFields(pool, iocId, observableType, legacyRow = null) {
  try {
    const fields = await fetchIocThreatActors(pool, iocId, observableType);
    if (fields.threat_actor_ids?.length) return fields;
  } catch (err) {
    if (!isThreatActorsTableMissing(err)) throw err;
  }
  if (legacyRow?.threat_actor_id) {
    const actor = await resolveThreatActorById(pool, legacyRow.threat_actor_id);
    if (actor) {
      return buildMultiThreatActorResponseFields([{
        id: actor.id,
        name: actor.name,
        slug: actor.slug,
        aliases: actor.aliases,
        active: actor.active
      }]);
    }
    return buildMultiThreatActorResponseFields([{
      id: legacyRow.threat_actor_id,
      name: legacyRow.threat_actor_name || null,
      active: true
    }]);
  }
  return emptyThreatActorResponseFields();
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

async function loadFeedClassificationsForIoc(pool, iocId, observableType) {
  const map = await batchLoadFeedClassifications(pool, [{ id: iocId, observable_type: observableType }]);
  return map.get(`${Number(iocId)}|${String(observableType)}`) || [];
}

/**
 * Analyst additions come from the junction table. When junction is empty (pre-multi /
 * feed-import rows), fall back to ioc_items.threat_classification so details matches
 * the list path (`enrichItemsWithThreatMetadata` + `mergeFeedClassificationsIntoItem`).
 */
async function resolveAnalystAdditionSlugs(pool, iocId, observableType, {
  analystSlugs = null,
  legacyThreatClassification = null
} = {}) {
  if (analystSlugs != null) {
    return normalizeIocThreatClassificationSlugs(analystSlugs);
  }
  const junction = await fetchIocThreatClassificationSlugs(pool, iocId, observableType);
  if (junction.length) return junction;

  let legacy = legacyThreatClassification;
  if (legacy == null) {
    const { rows } = await pool.query(
      `SELECT threat_classification
       FROM ioc_items
       WHERE id = $1 AND observable_type = $2
       LIMIT 1`,
      [iocId, observableType]
    );
    legacy = rows[0]?.threat_classification ?? null;
  }
  return normalizeIocThreatClassificationSlugs(legacy);
}

async function buildEffectiveClassificationBundle(pool, iocId, observableType, {
  analystSlugs = null,
  feedClassifications = null,
  legacyThreatClassification = null
} = {}) {
  const feed = feedClassifications
    || await loadFeedClassificationsForIoc(pool, iocId, observableType);
  const additions = await resolveAnalystAdditionSlugs(pool, iocId, observableType, {
    analystSlugs,
    legacyThreatClassification
  });
  let suppressions = [];
  try {
    suppressions = await listActiveThreatClassificationSuppressions(pool, iocId, observableType);
  } catch (err) {
    if (!isOverridesTableMissing(err)) throw err;
  }
  const computed = computeEffectiveThreatClassifications({
    feedClassifications: feed,
    analystAdditionSlugs: additions,
    activeSuppressions: suppressions
  });
  return buildThreatClassificationEffectiveFields(computed);
}

async function buildIocClassificationResponse(pool, iocId, observableType, baseRow = null) {
  const row = baseRow || await fetchIocRow(pool, iocId, observableType);
  if (!row) return null;
  const fields = await buildEffectiveClassificationBundle(pool, iocId, observableType, {
    legacyThreatClassification: row.threat_classification
  });
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

      const feedClassifications = await loadFeedClassificationsForIoc(pool, iocId, observableType);
      const planned = planThreatClassificationEffectiveSave({
        desiredEffectiveSlugs: parseClassificationBody(req.body),
        feedClassifications
      });

      const check = await validateIocThreatClassificationSlugs(pool, planned.additions, {
        requireActive: true
      });
      if (!check.ok) return res.status(400).json({ success: false, error: check.error });

      const beforeBundle = await buildEffectiveClassificationBundle(pool, iocId, observableType, {
        feedClassifications,
        legacyThreatClassification: prev.threat_classification
      });
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

      const afterBundle = await buildEffectiveClassificationBundle(pool, iocId, observableType, {
        feedClassifications
      });
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
      const beforeIds = beforeFields.threat_actor_ids || [];
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
      const diff = diffThreatActorIds(beforeIds, afterFields.threat_actor_ids || []);
      const beforeNames = (beforeFields.threat_actors || []).map((a) => a.name).filter(Boolean);
      const afterNames = (afterFields.threat_actors || []).map((a) => a.name).filter(Boolean);

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
}

export async function buildThreatMetadataFields(pool, row, { feedClassifications = null } = {}) {
  if (!row) {
    return {
      ...buildMultiThreatClassificationResponseFields([]),
      ...emptyThreatActorResponseFields()
    };
  }
  const actorFields = Number.isFinite(Number(row.id)) && row.observable_type
    ? await resolveThreatActorFields(pool, row.id, row.observable_type, row)
    : (row.threat_actor_id
      ? buildMultiThreatActorResponseFields([{
        id: row.threat_actor_id,
        name: row.threat_actor_name || null,
        active: true
      }])
      : emptyThreatActorResponseFields());

  if (Number.isFinite(Number(row.id)) && row.observable_type) {
    try {
      const fields = await buildEffectiveClassificationBundle(pool, row.id, row.observable_type, {
        feedClassifications,
        legacyThreatClassification: row.threat_classification
      });
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
  const actorDetailMap = await loadIocThreatActorDetails(pool, pairs);
  for (const row of rows) {
    const key = `${Number(row.id)}|${String(row.observable_type)}`;
    let fields = detailMap.get(key);
    if (!fields) {
      const slugs = normalizeIocThreatClassificationSlugs(row.threat_classification);
      fields = buildMultiThreatClassificationResponseFields(slugs.length ? slugs : []);
    }
    let actorFields = actorDetailMap.get(key);
    if (!actorFields?.threat_actor_ids?.length && row.threat_actor_id) {
      actorFields = buildMultiThreatActorResponseFields([{
        id: row.threat_actor_id,
        name: row.threat_actor_name || null,
        active: true
      }]);
    }
    if (!actorFields) actorFields = emptyThreatActorResponseFields();
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

export async function batchLoadFeedClassifications(pool, items) {
  const feedMap = new Map();
  if (!items?.length) return feedMap;

  const pairs = items
    .map((it) => ({ id: Number(it?.id), observable_type: String(it?.observable_type || '').trim() }))
    .filter((p) => Number.isFinite(p.id) && p.id > 0 && p.observable_type);
  if (!pairs.length) return feedMap;

  const values = pairs.map((_, i) => `($${i * 2 + 1}::bigint, $${i * 2 + 2}::text)`).join(', ');
  const params = pairs.flatMap((p) => [p.id, p.observable_type]);
  const { rows } = await pool.query(
    `SELECT e.ioc_item_id, e.ioc_observable_type, e.source_name, e.category, e.note, f.key AS feed_key
     FROM ioc_feed_source_evidence e
     JOIN integration_feeds f ON f.integration_id = e.feed_id
     WHERE (e.ioc_item_id, e.ioc_observable_type) IN (VALUES ${values})`,
    params
  );

  const evidenceByKey = new Map();
  for (const row of rows) {
    const key = `${Number(row.ioc_item_id)}|${String(row.ioc_observable_type)}`;
    if (!evidenceByKey.has(key)) evidenceByKey.set(key, []);
    evidenceByKey.get(key).push(row);
  }

  for (const [key, evRows] of evidenceByKey.entries()) {
    const seenSlugs = new Set();
    const feedClassifications = [];
    for (const evRow of evRows) {
      const noteFields = parseNoteFields(evRow.note);
      const rawTagsStr = noteFields.tags || '';
      const rawTags = rawTagsStr ? rawTagsStr.split(',').map((t) => t.trim()).filter(Boolean) : [];
      const { classifications } = normalizeFeedTags({
        sourceName: evRow.source_name,
        rawTags,
        category: evRow.category,
        signature: noteFields.signature || null
      });
      for (const c of classifications) {
        if (!seenSlugs.has(c.value)) {
          feedClassifications.push(c);
          seenSlugs.add(c.value);
        }
      }
    }
    if (feedClassifications.length) feedMap.set(key, feedClassifications);
  }
  return feedMap;
}

export async function batchLoadThreatClassificationSuppressions(pool, items) {
  const map = new Map();
  if (!items?.length) return map;
  const pairs = items
    .map((it) => ({ id: Number(it?.id), observable_type: String(it?.observable_type || '').trim() }))
    .filter((p) => Number.isFinite(p.id) && p.id > 0 && p.observable_type);
  if (!pairs.length) return map;

  try {
    const values = pairs.map((_, i) => `($${i * 2 + 1}::bigint, $${i * 2 + 2}::text)`).join(', ');
    const params = pairs.flatMap((p) => [p.id, p.observable_type]);
    const { rows } = await pool.query(
      `SELECT ioc_id, ioc_observable_type, classification_slug, source_name, created_at, created_by
       FROM ioc_threat_classification_overrides
       WHERE action = 'suppress'
         AND cleared_at IS NULL
         AND (ioc_id, ioc_observable_type) IN (VALUES ${values})`,
      params
    );
    for (const row of rows) {
      const key = `${Number(row.ioc_id)}|${String(row.ioc_observable_type)}`;
      if (!map.has(key)) map.set(key, []);
      map.get(key).push(row);
    }
  } catch (err) {
    if (!isOverridesTableMissing(err)) throw err;
  }
  return map;
}

/**
 * Merge feed-derived classifications with analyst additions, applying suppressions.
 */
export function mergeFeedClassificationsIntoItem(item, feedMap, suppressMap = null) {
  const key = `${Number(item?.id)}|${String(item?.observable_type || '')}`;
  const feedClasses = feedMap?.get(key) || [];
  const suppressions = suppressMap?.get(key) || [];
  const analystSlugs = (item.threat_classifications || [])
    .map((c) => c?.value)
    .filter((v) => v && v !== 'unknown');
  const computed = computeEffectiveThreatClassifications({
    feedClassifications: feedClasses,
    analystAdditionSlugs: analystSlugs,
    activeSuppressions: suppressions
  });
  return { ...item, ...buildThreatClassificationEffectiveFields(computed) };
}
