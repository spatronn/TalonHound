import { requireTriageRole } from '../lib/rbac.js';
import {
  parseIocIdList,
  bulkAddTag,
  bulkAddClassification,
  bulkSuppress,
  bulkExpire
} from '../lib/iocBulkTriage.js';

function sendBulkOutcome(res, outcome) {
  if (!outcome.ok) {
    return res.status(outcome.status || 400).json({ message: outcome.message });
  }
  return res.status(200).json({
    ok: outcome.failed === 0,
    requested: outcome.requested,
    succeeded: outcome.succeeded,
    skipped: outcome.skipped,
    failed: outcome.failed,
    results: outcome.results
  });
}

function parseIdsOrReject(req, res) {
  const parsed = parseIocIdList(req.body?.ioc_ids);
  if (!parsed.ok) {
    res.status(parsed.status).json({ message: parsed.message });
    return null;
  }
  return parsed.ids;
}

/**
 * Explicit-ID bulk triage. Never accepts a search query / "all matching".
 */
export function registerIocBulkTriageRoutes(app, pool, audit) {
  const triage = requireTriageRole();

  app.post('/api/iocs/bulk/tags', triage, async (req, res) => {
    const iocIds = parseIdsOrReject(req, res);
    if (!iocIds) return;
    try {
      const outcome = await bulkAddTag(pool, {
        iocIds,
        tagId: req.body?.tag_id,
        user: req.user,
        req,
        audit
      });
      return sendBulkOutcome(res, outcome);
    } catch (err) {
      return res.status(500).json({ message: 'Bulk tag failed', detail: err.message });
    }
  });

  app.post('/api/iocs/bulk/classifications', triage, async (req, res) => {
    const iocIds = parseIdsOrReject(req, res);
    if (!iocIds) return;
    try {
      const outcome = await bulkAddClassification(pool, {
        iocIds,
        slug: req.body?.classification_slug,
        user: req.user,
        req,
        audit
      });
      return sendBulkOutcome(res, outcome);
    } catch (err) {
      return res.status(500).json({ message: 'Bulk classification failed', detail: err.message });
    }
  });

  app.post('/api/iocs/bulk/suppress', triage, async (req, res) => {
    const iocIds = parseIdsOrReject(req, res);
    if (!iocIds) return;
    try {
      const outcome = await bulkSuppress(pool, {
        iocIds,
        reason: req.body?.reason,
        expiresAt: req.body?.expires_at,
        user: req.user,
        req,
        audit
      });
      return sendBulkOutcome(res, outcome);
    } catch (err) {
      return res.status(500).json({ message: 'Bulk suppress failed', detail: err.message });
    }
  });

  app.post('/api/iocs/bulk/expire', triage, async (req, res) => {
    const iocIds = parseIdsOrReject(req, res);
    if (!iocIds) return;
    try {
      const outcome = await bulkExpire(pool, {
        iocIds,
        reason: req.body?.reason,
        user: req.user,
        req,
        audit
      });
      return sendBulkOutcome(res, outcome);
    } catch (err) {
      return res.status(500).json({ message: 'Bulk expire failed', detail: err.message });
    }
  });
}
