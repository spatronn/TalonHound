import { AUDIT_ACTION, AUDIT_ENTITY } from '../lib/auditConstants.js';
import {
  buildMultiThreatClassificationResponseFields,
  diffThreatClassificationSlugs,
  fetchIocThreatClassificationSlugs,
  loadIocThreatClassificationDetails,
  mergeIocThreatMetadataItem,
  normalizeIocThreatClassificationSlugs,
  replaceIocThreatClassifications,
  validateIocThreatClassificationSlugs
} from '../lib/iocThreatClassifications.js';
import { normalizeClassificationSlug } from '../lib/threatClassification.js';
import { parseNoteFields, normalizeFeedTags } from '../lib/feedTagNormalization.js';
import { resolveThreatActorById } from './threatActors.js';

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

function actorDisplayName(row) {
  return row?.threat_actor_name || null;
}

function userLabel(req) {
  return req.user?.email || req.user?.username || req.user?.publicId || null;
}

function parseClassificationBody(body) {
  if (Array.isArray(body?.threat_classifications)) return body.threat_classifications;
  if (Array.isArray(body?.classifications)) return body.classifications;
  if (body?.threat_classification != null || body?.primary_threat_classification != null) {
    return [body?.threat_classification ?? body?.primary_threat_classification];
  }
  return body?.threat_classifications;
}

async function buildIocClassificationResponse(pool, iocId, observableType, baseRow = null) {
  const row = baseRow || await fetchIocRow(pool, iocId, observableType);
  if (!row) return null;
  const slugs = await fetchIocThreatClassificationSlugs(pool, iocId, observableType);
  const detailMap = await loadIocThreatClassificationDetails(pool, [{ id: iocId, observable_type: observableType }]);
  const key = `${Number(iocId)}|${String(observableType || '')}`;
  const fields = detailMap.get(key) || buildMultiThreatClassificationResponseFields(slugs);
  return {
    public_id: row.public_id,
    threat_actor_id: row.threat_actor_id || null,
    threat_actor_name: actorDisplayName(row),
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

    const check = await validateIocThreatClassificationSlugs(pool, parseClassificationBody(req.body), {
      requireActive: true
    });
    if (!check.ok) return res.status(400).json({ success: false, error: check.error });

    try {
      const prev = await fetchIocRow(pool, iocId, observableType);
      if (!prev) return res.status(404).json({ success: false, error: 'IOC not found' });

      const oldSlugs = await fetchIocThreatClassificationSlugs(pool, iocId, observableType);
      const legacyOld = oldSlugs.length
        ? oldSlugs
        : (normalizeClassificationSlug(prev.threat_classification) === 'unknown' ? [] : [normalizeClassificationSlug(prev.threat_classification)]);

      const newSlugs = check.value;
      const sortKey = (arr) => [...arr].sort().join('|');
      const same = sortKey(legacyOld) === sortKey(newSlugs);
      if (same) {
        const unchanged = await buildIocClassificationResponse(pool, iocId, observableType, prev);
        return res.json({ success: true, ...unchanged });
      }

      await replaceIocThreatClassifications(pool, {
        iocId,
        observableType,
        slugs: newSlugs,
        sourceType: 'analyst',
        sourceName: 'ui',
        actor: userLabel(req)
      });
      invalidateDetailsCache(prev.public_id);

      const diff = diffThreatClassificationSlugs(legacyOld, newSlugs);
      await audit.auditSuccess({
        req,
        action: auditAction,
        entityType: AUDIT_ENTITY.IOC,
        entityId: String(iocId),
        entityDisplay: `${observableType} · ${prev.observable}`,
        metadata: {
          observable_type: observableType,
          ioc_value: prev.observable,
          old_classification: legacyOld[0] || 'unknown',
          new_classification: newSlugs[0] || 'unknown',
          ...diff
        },
        before: { threat_classifications: legacyOld },
        after: { threat_classifications: newSlugs }
      });

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

  app.patch('/api/ioc/:id/threat-actor', async (req, res) => {
    const iocId = Number(req.params.id);
    if (!Number.isFinite(iocId) || iocId <= 0) {
      return res.status(400).json({ success: false, error: 'Invalid IOC id' });
    }
    const observableType = String(req.body?.observable_type || req.query?.observable_type || '').trim();
    if (!observableType) {
      return res.status(400).json({ success: false, error: 'observable_type is required' });
    }

    const rawActorId = req.body?.threat_actor_id;
    const clear = rawActorId === null || rawActorId === '' || rawActorId === false;
    let nextActorId = null;
    if (!clear) {
      nextActorId = String(rawActorId || '').trim();
      if (!/^[0-9a-f-]{36}$/i.test(nextActorId)) {
        return res.status(400).json({ success: false, error: 'threat_actor_id must be a UUID or null' });
      }
      const actor = await resolveThreatActorById(pool, nextActorId);
      if (!actor || actor.active === false) {
        return res.status(400).json({ success: false, error: 'Threat actor not found or inactive' });
      }
    }

    try {
      const prev = await fetchIocRow(pool, iocId, observableType);
      if (!prev) return res.status(404).json({ success: false, error: 'IOC not found' });

      const oldActorId = prev.threat_actor_id || null;
      const oldActorName = actorDisplayName(prev);
      if (String(oldActorId || '') === String(nextActorId || '')) {
        return res.json({
          success: true,
          threat_actor_id: oldActorId,
          threat_actor_name: oldActorName,
          public_id: prev.public_id
        });
      }

      const { rows } = await pool.query(
        `UPDATE ioc_items SET threat_actor_id = $3::uuid
         WHERE id = $1 AND observable_type = $2
         RETURNING public_id, threat_actor_id`,
        [iocId, observableType, nextActorId]
      );
      const updated = rows[0];
      let newActorName = null;
      if (updated.threat_actor_id) {
        const actor = await resolveThreatActorById(pool, updated.threat_actor_id);
        newActorName = actor?.name || null;
      }
      invalidateDetailsCache(updated.public_id);

      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.IOC_THREAT_ACTOR_UPDATED,
        entityType: AUDIT_ENTITY.IOC,
        entityId: String(iocId),
        entityDisplay: `${observableType} · ${prev.observable}`,
        metadata: {
          observable_type: observableType,
          ioc_value: prev.observable,
          old_threat_actor: oldActorName,
          new_threat_actor: newActorName,
          old_threat_actor_id: oldActorId,
          new_threat_actor_id: updated.threat_actor_id
        },
        before: { threat_actor_id: oldActorId, threat_actor_name: oldActorName },
        after: { threat_actor_id: updated.threat_actor_id, threat_actor_name: newActorName }
      });

      return res.json({
        success: true,
        public_id: updated.public_id,
        threat_actor_id: updated.threat_actor_id,
        threat_actor_name: newActorName
      });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  });
}

export async function buildThreatMetadataFields(pool, row) {
  if (!row) return buildMultiThreatClassificationResponseFields([]);
  if (Number.isFinite(Number(row.id)) && row.observable_type) {
    const detailMap = await loadIocThreatClassificationDetails(pool, [{
      id: row.id,
      observable_type: row.observable_type
    }]);
    const key = `${Number(row.id)}|${String(row.observable_type || '')}`;
    const fields = detailMap.get(key);
    if (fields) {
      return {
        ...fields,
        threat_actor_id: row.threat_actor_id || null,
        threat_actor_name: row.threat_actor_name || null
      };
    }
  }
  const slugs = normalizeIocThreatClassificationSlugs(row.threat_classification);
  return {
    ...buildMultiThreatClassificationResponseFields(slugs.length ? slugs : []),
    threat_actor_id: row.threat_actor_id || null,
    threat_actor_name: row.threat_actor_name || null
  };
}

/** Batch-load classification + actor display fields for IOC list/hot rows. */
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
  for (const row of rows) {
    const key = `${Number(row.id)}|${String(row.observable_type)}`;
    let fields = detailMap.get(key);
    if (!fields) {
      const slugs = normalizeIocThreatClassificationSlugs(row.threat_classification);
      fields = buildMultiThreatClassificationResponseFields(slugs.length ? slugs : []);
    }
    map.set(key, {
      ...fields,
      threat_actor_id: row.threat_actor_id || null,
      threat_actor_name: row.threat_actor_name || null
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
 * Batch-load feed-derived classifications from ioc_feed_source_evidence for list items.
 * Returns a Map of "id|observable_type" → [{value, label, active, origin, source_name}].
 * Single query for the whole page — no N+1.
 */
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

/**
 * Merge feed-derived classifications into an item's threat_classifications array.
 * Feed entries are appended after stored ones; duplicates by slug are skipped.
 */
export function mergeFeedClassificationsIntoItem(item, feedMap) {
  const key = `${Number(item?.id)}|${String(item?.observable_type || '')}`;
  const feedClasses = feedMap?.get(key);
  if (!feedClasses?.length) return item;

  const existing = new Set((item.threat_classifications || []).map((c) => c?.value).filter(Boolean));
  const toAdd = feedClasses.filter((c) => !existing.has(c.value));
  if (!toAdd.length) return item;

  return { ...item, threat_classifications: [...(item.threat_classifications || []), ...toAdd] };
}
