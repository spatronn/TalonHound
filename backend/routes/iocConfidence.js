import { AUDIT_ACTION, AUDIT_ENTITY } from '../lib/auditConstants.js';
import { pickSafeFields } from '../lib/auditRedaction.js';
import {
  buildIocConfidenceSummary,
  computeEffectiveConfidence,
  fetchFeedNamesByKey,
  normalizeConfidence,
  resolveConfidenceSourceKind,
  validateConfidenceInput,
  validateConfidenceReason
} from '../lib/iocConfidence.js';

const CONFIDENCE_AUDIT_FIELDS = [
  'confidence',
  'source_confidence',
  'feed_default_confidence',
  'analyst_confidence_override',
  'analyst_confidence_override_reason',
  'analyst_confidence_overridden_at'
];

function tsField(v) {
  if (v == null) return null;
  return v instanceof Date ? v.toISOString() : v;
}

async function fetchIocConfidenceRow(pool, iocId, observableType) {
  const { rows } = await pool.query(
    `SELECT i.id, i.public_id, i.observable, i.observable_type, i.source_name,
            i.confidence, i.source_confidence, i.feed_default_confidence,
            i.analyst_confidence_override, i.analyst_confidence_override_reason,
            i.analyst_confidence_overridden_by, i.analyst_confidence_overridden_at,
            u.username AS overridden_by_email
     FROM ioc_items i
     LEFT JOIN users u ON u.public_id = i.analyst_confidence_overridden_by
     WHERE i.id = $1 AND i.observable_type = $2`,
    [iocId, observableType]
  );
  return rows[0] || null;
}

async function fetchSiblingRows(pool, observable, observableType) {
  const { rows } = await pool.query(
    `SELECT i.id, i.public_id, i.observable, i.observable_type, i.source_name,
            i.confidence, i.source_confidence, i.feed_default_confidence,
            i.analyst_confidence_override, i.analyst_confidence_override_reason,
            i.analyst_confidence_overridden_by, i.analyst_confidence_overridden_at,
            u.username AS overridden_by_email
     FROM ioc_items i
     LEFT JOIN users u ON u.public_id = i.analyst_confidence_overridden_by
     WHERE i.observable = $1 AND i.observable_type = $2
     ORDER BY i.created_at DESC`,
    [observable, observableType]
  );
  return rows;
}

function serializeConfidenceAuditRow(row) {
  if (!row) return null;
  return {
    confidence: row.confidence,
    source_confidence: row.source_confidence,
    feed_default_confidence: row.feed_default_confidence,
    analyst_confidence_override: row.analyst_confidence_override,
    analyst_confidence_override_reason: row.analyst_confidence_override_reason,
    analyst_confidence_overridden_at: tsField(row.analyst_confidence_overridden_at)
  };
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {ReturnType<import('../lib/auditLogService.js').createAuditLogService>} audit
 * @param {{ invalidateDetailsCache?: (publicId: string) => void }} [opts]
 */
export function registerIocConfidenceRoutes(app, pool, audit, opts = {}) {
  const invalidateDetailsCache = typeof opts.invalidateDetailsCache === 'function'
    ? opts.invalidateDetailsCache
    : () => {};

  async function buildResponseForIoc(row) {
    const siblings = await fetchSiblingRows(pool, row.observable, row.observable_type);
    const feedNamesByKey = await fetchFeedNamesByKey(pool);
    const confidence = buildIocConfidenceSummary({
      rows: siblings.map((s) => (s.public_id === row.public_id ? row : s)),
      seedPublicId: row.public_id,
      feedNamesByKey
    });
    return { confidence, public_id: row.public_id };
  }

  app.patch('/api/ioc/:id/confidence', async (req, res) => {
    const iocId = Number(req.params.id);
    if (!Number.isFinite(iocId) || iocId <= 0) {
      return res.status(400).json({ success: false, error: 'Invalid IOC id' });
    }

    const observableType = String(req.body?.observable_type || req.query?.observable_type || '').trim();
    if (!observableType) {
      return res.status(400).json({ success: false, error: 'observable_type is required in body or query' });
    }

    const clearOverride = req.body?.clear_override === true || req.body?.confidence === null;

    try {
      const prev = await fetchIocConfidenceRow(pool, iocId, observableType);
      if (!prev) return res.status(404).json({ success: false, error: 'IOC not found' });

      const reasonCheck = validateConfidenceReason(req.body?.reason);
      if (!reasonCheck.ok) {
        return res.status(400).json({ success: false, error: reasonCheck.error });
      }

      const userId = req.user?.publicId && /^[0-9a-f-]{36}$/i.test(req.user.publicId)
        ? req.user.publicId
        : null;
      const actorEmail = String(req.user?.email || req.user?.username || '').trim() || null;

      const oldSummary = buildIocConfidenceSummary({
        rows: [prev],
        seedPublicId: prev.public_id,
        feedNamesByKey: new Map()
      });

      if (clearOverride) {
        await pool.query(
          `UPDATE ioc_items
           SET analyst_confidence_override = NULL,
               analyst_confidence_override_reason = $3,
               analyst_confidence_overridden_by = $4::uuid,
               analyst_confidence_overridden_at = NOW(),
               confidence = $5
           WHERE id = $1 AND observable_type = $2`,
          [
            iocId,
            observableType,
            reasonCheck.value,
            userId,
            computeEffectiveConfidence({
              sourceConfidence: prev.source_confidence ?? prev.confidence,
              feedDefaultConfidence: prev.feed_default_confidence,
              analystOverride: null,
              fallback: prev.confidence
            })
          ]
        );

        const after = await fetchIocConfidenceRow(pool, iocId, observableType);
        const payload = await buildResponseForIoc(after);
        invalidateDetailsCache(after.public_id);

        await audit.auditSuccess({
          req,
          action: AUDIT_ACTION.IOC_CONFIDENCE_OVERRIDE_CLEARED,
          entityType: AUDIT_ENTITY.IOC,
          entityId: String(iocId),
          entityDisplay: after.observable,
          before: pickSafeFields(serializeConfidenceAuditRow(prev), CONFIDENCE_AUDIT_FIELDS),
          after: pickSafeFields(serializeConfidenceAuditRow(after), CONFIDENCE_AUDIT_FIELDS),
          metadata: {
            observable_type: observableType,
            ioc_value: after.observable,
            feed_name: after.source_name,
            old_effective_confidence: oldSummary.effective,
            new_effective_confidence: payload.confidence.effective,
            restored_source: payload.confidence.source,
            reason: reasonCheck.value,
            user: actorEmail
          }
        });

        return res.status(200).json({ success: true, ...payload });
      }

      const confCheck = validateConfidenceInput(req.body?.confidence);
      if (!confCheck.ok) {
        return res.status(400).json({ success: false, error: confCheck.error });
      }

      await pool.query(
        `UPDATE ioc_items
         SET analyst_confidence_override = $3,
             analyst_confidence_override_reason = $4,
             analyst_confidence_overridden_by = $5::uuid,
             analyst_confidence_overridden_at = NOW(),
             confidence = $3
         WHERE id = $1 AND observable_type = $2`,
        [iocId, observableType, confCheck.value, reasonCheck.value, userId]
      );

      const after = await fetchIocConfidenceRow(pool, iocId, observableType);
      const payload = await buildResponseForIoc(after);
      invalidateDetailsCache(after.public_id);

      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.IOC_CONFIDENCE_OVERRIDE_SET,
        entityType: AUDIT_ENTITY.IOC,
        entityId: String(iocId),
        entityDisplay: after.observable,
        before: pickSafeFields(serializeConfidenceAuditRow(prev), CONFIDENCE_AUDIT_FIELDS),
        after: pickSafeFields(serializeConfidenceAuditRow(after), CONFIDENCE_AUDIT_FIELDS),
        metadata: {
          observable_type: observableType,
          ioc_value: after.observable,
          feed_name: after.source_name,
          old_effective_confidence: oldSummary.effective,
          new_effective_confidence: payload.confidence.effective,
          old_source: oldSummary.source,
          new_source: 'analyst_override',
          reason: reasonCheck.value,
          user: actorEmail
        }
      });

      return res.status(200).json({ success: true, ...payload });
    } catch (err) {
      console.error('[ioc-confidence] PATCH failed', err?.message || err);
      return res.status(500).json({ success: false, error: 'Failed to update IOC confidence', detail: err.message });
    }
  });

  app.delete('/api/ioc/:id/confidence-override', async (req, res) => {
    req.body = { ...(req.body || {}), clear_override: true, confidence: null };
    const iocId = Number(req.params.id);
    if (!Number.isFinite(iocId) || iocId <= 0) {
      return res.status(400).json({ success: false, error: 'Invalid IOC id' });
    }

    const observableType = String(req.body?.observable_type || req.query?.observable_type || '').trim();
    if (!observableType) {
      return res.status(400).json({ success: false, error: 'observable_type is required in body or query' });
    }

    try {
      const prev = await fetchIocConfidenceRow(pool, iocId, observableType);
      if (!prev) return res.status(404).json({ success: false, error: 'IOC not found' });

      const reasonCheck = validateConfidenceReason(req.body?.reason);
      if (!reasonCheck.ok) {
        return res.status(400).json({ success: false, error: reasonCheck.error });
      }

      const userId = req.user?.publicId && /^[0-9a-f-]{36}$/i.test(req.user.publicId)
        ? req.user.publicId
        : null;
      const actorEmail = String(req.user?.email || req.user?.username || '').trim() || null;

      const oldSummary = buildIocConfidenceSummary({
        rows: [prev],
        seedPublicId: prev.public_id,
        feedNamesByKey: new Map()
      });

      await pool.query(
        `UPDATE ioc_items
         SET analyst_confidence_override = NULL,
             analyst_confidence_override_reason = $3,
             analyst_confidence_overridden_by = $4::uuid,
             analyst_confidence_overridden_at = NOW(),
             confidence = $5
         WHERE id = $1 AND observable_type = $2`,
        [
          iocId,
          observableType,
          reasonCheck.value,
          userId,
          computeEffectiveConfidence({
            sourceConfidence: prev.source_confidence ?? prev.confidence,
            feedDefaultConfidence: prev.feed_default_confidence,
            analystOverride: null,
            fallback: prev.confidence
          })
        ]
      );

      const after = await fetchIocConfidenceRow(pool, iocId, observableType);
      const payload = await buildResponseForIoc(after);
      invalidateDetailsCache(after.public_id);

      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.IOC_CONFIDENCE_OVERRIDE_CLEARED,
        entityType: AUDIT_ENTITY.IOC,
        entityId: String(iocId),
        entityDisplay: after.observable,
        before: pickSafeFields(serializeConfidenceAuditRow(prev), CONFIDENCE_AUDIT_FIELDS),
        after: pickSafeFields(serializeConfidenceAuditRow(after), CONFIDENCE_AUDIT_FIELDS),
        metadata: {
          observable_type: observableType,
          ioc_value: after.observable,
          feed_name: after.source_name,
          old_effective_confidence: oldSummary.effective,
          new_effective_confidence: payload.confidence.effective,
          restored_source: payload.confidence.source,
          reason: reasonCheck.value,
          user: actorEmail
        }
      });

      return res.status(200).json({ success: true, ...payload });
    } catch (err) {
      console.error('[ioc-confidence] DELETE failed', err?.message || err);
      return res.status(500).json({ success: false, error: 'Failed to clear IOC confidence override', detail: err.message });
    }
  });
}
