import { AUDIT_ACTION, AUDIT_ENTITY } from '../lib/auditConstants.js';
import {
  normalizeThreatClassification,
  threatClassificationResponseFields,
  validateThreatClassification
} from '../lib/threatClassification.js';
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

  app.patch('/api/ioc/:id/threat-classification', async (req, res) => {
    const iocId = Number(req.params.id);
    if (!Number.isFinite(iocId) || iocId <= 0) {
      return res.status(400).json({ success: false, error: 'Invalid IOC id' });
    }
    const observableType = String(req.body?.observable_type || req.query?.observable_type || '').trim();
    if (!observableType) {
      return res.status(400).json({ success: false, error: 'observable_type is required' });
    }

    const check = validateThreatClassification(req.body?.threat_classification ?? req.body?.primary_threat_classification);
    if (!check.ok) return res.status(400).json({ success: false, error: check.error });

    try {
      const prev = await fetchIocRow(pool, iocId, observableType);
      if (!prev) return res.status(404).json({ success: false, error: 'IOC not found' });

      const oldClass = normalizeThreatClassification(prev.threat_classification);
      if (oldClass === check.value) {
        return res.json({
          success: true,
          ...threatClassificationResponseFields(check.value),
          public_id: prev.public_id
        });
      }

      const { rows } = await pool.query(
        `UPDATE ioc_items SET threat_classification = $3
         WHERE id = $1 AND observable_type = $2
         RETURNING public_id, threat_classification`,
        [iocId, observableType, check.value]
      );
      const updated = rows[0];
      invalidateDetailsCache(updated.public_id);

      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.IOC_THREAT_CLASSIFICATION_UPDATED,
        entityType: AUDIT_ENTITY.IOC,
        entityId: String(iocId),
        entityDisplay: `${observableType} · ${prev.observable}`,
        metadata: {
          observable_type: observableType,
          ioc_value: prev.observable,
          old_classification: oldClass,
          new_classification: check.value
        },
        before: { threat_classification: oldClass },
        after: { threat_classification: check.value }
      });

      return res.json({
        success: true,
        public_id: updated.public_id,
        ...threatClassificationResponseFields(updated.threat_classification)
      });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  });

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

export function buildThreatMetadataFields(row) {
  if (!row) return threatClassificationResponseFields('unknown');
  return {
    ...threatClassificationResponseFields(row.threat_classification),
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
  for (const row of rows) {
    map.set(`${Number(row.id)}|${String(row.observable_type)}`, buildThreatMetadataFields(row));
  }
  return map;
}

export function mergeThreatMetadataItem(item, metaMap) {
  const key = `${Number(item?.id)}|${String(item?.observable_type || '')}`;
  const meta = metaMap?.get(key);
  if (meta) return { ...item, ...meta };
  return { ...item, ...buildThreatMetadataFields(item) };
}
