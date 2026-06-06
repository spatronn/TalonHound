import { requireTriageRole } from '../lib/rbac.js';
import { parseActionReason } from '../lib/reasonValidation.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import {
  emptyBulkResponse,
  normalizeDetectionBulkVerdict,
  normalizeIncidentBulkVerdict,
  parseBulkIds,
  parseIncidentBulkIds,
  pushBulkResult
} from '../lib/bulkTriageHelpers.js';

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {{ auditLogService: { auditSuccess: Function }, findIncidentRow: (id: string) => Promise<{ id: string, incident_id?: number } | null> }} deps
 */
export function registerBulkTriageRoutes(app, pool, deps) {
  const { auditLogService, findIncidentRow } = deps;

  app.patch('/api/ioc/match-events/bulk/verdict', requireTriageRole(), async (req, res) => {
    const idParse = parseBulkIds(req.body?.ids);
    if (!idParse.ok) return res.status(400).json({ message: idParse.message });

    const verdictNorm = normalizeDetectionBulkVerdict(req.body?.verdict);
    if (!verdictNorm) {
      return res.status(400).json({ message: 'Invalid verdict. Use fp, tp, suspicious, in_progress, or security_test.' });
    }

    const reasonCheck = parseActionReason(req.body);
    if (!reasonCheck.ok) return res.status(400).json({ message: reasonCheck.message });

    const assignTo = req.body?.assigned_to == null ? null : String(req.body.assigned_to).trim() || null;
    const reviewedBy = String(req.user?.username || req.user?.email || '').trim() || null;
    const results = [];
    let succeeded = 0;
    let failed = 0;

    for (const id of idParse.ids) {
      try {
        const beforeQ = await pool.query('SELECT * FROM ioc_match_events WHERE id = $1 LIMIT 1', [id]);
        if (!beforeQ.rowCount) {
          failed += 1;
          pushBulkResult(results, id, false, 'not found');
          continue;
        }
        const beforeRow = beforeQ.rows[0];
        const verdict = verdictNorm.verdict;
        const verdictChanging = String(beforeRow.verdict || '') !== String(verdict || '');
        if (!verdictChanging) {
          succeeded += 1;
          pushBulkResult(results, id, true);
          continue;
        }

        const note = reasonCheck.reason;
        const q = await pool.query(
          `UPDATE ioc_match_events
           SET verdict = $2::text,
               reviewed_at = NOW(),
               reviewed_by = $3::text,
               note = $4,
               assigned_to = COALESCE($5::text, assigned_to),
               assigned_at = CASE WHEN $5::text IS NULL THEN assigned_at ELSE NOW() END
           WHERE id = $1
           RETURNING *`,
          [id, verdict, reviewedBy, note, assignTo]
        );
        const afterRow = q.rows[0];
        await auditLogService.auditSuccess({
          req,
          action: AUDIT_ACTION.IOC_MATCH_EVENT_VERDICT_CHANGED,
          entityType: AUDIT_ENTITY.IOC_MATCH_EVENT,
          entityId: String(id),
          entityDisplay: String(afterRow.matched_ioc || id),
          severity: AUDIT_SEVERITY.INFO,
          before: { verdict: beforeRow.verdict, assigned_to: beforeRow.assigned_to },
          after: { verdict: afterRow.verdict, assigned_to: afterRow.assigned_to },
          metadata: {
            bulk: true,
            bulk_count: idParse.ids.length,
            security_test: verdictNorm.securityTest,
            reason: reasonCheck.reason
          }
        }).catch(() => {});
        succeeded += 1;
        pushBulkResult(results, id, true);
      } catch (err) {
        failed += 1;
        pushBulkResult(results, id, false, err?.message || 'update failed');
      }
    }

    return res.json({ ...emptyBulkResponse(idParse.ids.length), succeeded, failed, results });
  });

  app.patch('/api/incidents/bulk', requireTriageRole(), async (req, res) => {
    const idParse = parseIncidentBulkIds(req.body?.ids);
    if (!idParse.ok) return res.status(400).json({ message: idParse.message });

    const reasonCheck = parseActionReason(req.body);
    if (!reasonCheck.ok) return res.status(400).json({ message: reasonCheck.message });

    const hasVerdict = req.body?.verdict != null && String(req.body.verdict).trim() !== '';
    const hasAssignee = req.body?.assigned_to != null && String(req.body.assigned_to).trim() !== '';
    const closeRequested = Boolean(req.body?.close);
    if (!hasVerdict && !hasAssignee && !closeRequested) {
      return res.status(400).json({ message: 'Provide verdict, assigned_to, or close=true' });
    }

    let verdictNorm = null;
    if (hasVerdict || closeRequested) {
      const rawVerdict = hasVerdict ? req.body.verdict : req.body?.close_verdict;
      verdictNorm = normalizeIncidentBulkVerdict(rawVerdict);
      if (!verdictNorm) {
        return res.status(400).json({ message: 'Invalid verdict. Use TP, FP, Suspicious, or security_test for close/bulk verdict.' });
      }
      if (closeRequested && !['TP', 'FP', 'Suspicious'].includes(verdictNorm.verdict)) {
        return res.status(400).json({ message: 'close requires verdict TP, FP, Suspicious, or security_test' });
      }
    }

    const assignTo = hasAssignee ? String(req.body.assigned_to).trim() : null;
    const reviewer = String(req.user?.username || req.user?.email || '').trim() || null;
    const results = [];
    let succeeded = 0;
    let failed = 0;

    for (const idRaw of idParse.ids) {
      const tx = await pool.connect();
      try {
        const incident = await findIncidentRow(idRaw);
        if (!incident?.id) {
          failed += 1;
          pushBulkResult(results, idRaw, false, 'not found');
          continue;
        }

        await tx.query('BEGIN');
        const curQ = await tx.query('SELECT * FROM ioc_activity WHERE id = $1::uuid FOR UPDATE', [incident.id]);
        if (!curQ.rowCount) {
          await tx.query('ROLLBACK');
          failed += 1;
          pushBulkResult(results, idRaw, false, 'not found');
          continue;
        }
        const current = curQ.rows[0];
        const nextVerdict = verdictNorm ? verdictNorm.verdict : (current.verdict || 'Unreviewed');
        const nextStatus = ['TP', 'FP', 'Suspicious'].includes(nextVerdict) ? 'closed' : (current.status || 'open');
        const nextAssignee = assignTo ?? current.assigned_to;

        const updQ = await tx.query(
          `UPDATE ioc_activity
           SET verdict = $2::text,
               status = $3::text,
               note = $4::text,
               assigned_to = $5::text,
               assigned_at = CASE WHEN $5::text IS DISTINCT FROM assigned_to THEN NOW() ELSE assigned_at END,
               updated_at = NOW()
           WHERE id = $1::uuid
           RETURNING *`,
          [incident.id, nextVerdict, nextStatus, reasonCheck.reason, nextAssignee]
        );
        await tx.query('COMMIT');
        const updated = updQ.rows[0];

        if (verdictNorm && String(current.verdict || '') !== String(updated.verdict || '')) {
          await auditLogService.auditSuccess({
            req,
            action: AUDIT_ACTION.INCIDENT_VERDICT_CHANGED,
            entityType: AUDIT_ENTITY.INCIDENT,
            entityId: String(updated.incident_id || updated.id),
            entityDisplay: String(updated.ioc_value || updated.incident_id),
            severity: AUDIT_SEVERITY.INFO,
            before: { verdict: current.verdict, status: current.status },
            after: { verdict: updated.verdict, status: updated.status },
            metadata: { bulk: true, bulk_count: idParse.ids.length, security_test: verdictNorm.securityTest, reason: reasonCheck.reason }
          }).catch(() => {});
        }
        if (String(current.status || '') !== 'closed' && updated.status === 'closed') {
          await auditLogService.auditSuccess({
            req,
            action: AUDIT_ACTION.INCIDENT_CLOSED,
            entityType: AUDIT_ENTITY.INCIDENT,
            entityId: String(updated.incident_id || updated.id),
            entityDisplay: String(updated.ioc_value || updated.incident_id),
            severity: AUDIT_SEVERITY.INFO,
            before: { status: current.status },
            after: { status: updated.status },
            metadata: { bulk: true, reason: reasonCheck.reason }
          }).catch(() => {});
        }
        if (assignTo && String(current.assigned_to || '') !== String(updated.assigned_to || '')) {
          await auditLogService.auditSuccess({
            req,
            action: AUDIT_ACTION.INCIDENT_ASSIGNED,
            entityType: AUDIT_ENTITY.INCIDENT,
            entityId: String(updated.incident_id || updated.id),
            entityDisplay: String(updated.ioc_value || updated.incident_id),
            severity: AUDIT_SEVERITY.INFO,
            before: { assigned_to: current.assigned_to },
            after: { assigned_to: updated.assigned_to },
            metadata: { bulk: true, reason: reasonCheck.reason }
          }).catch(() => {});
        }

        succeeded += 1;
        pushBulkResult(results, idRaw, true);
      } catch (err) {
        try { await tx.query('ROLLBACK'); } catch { /* ignore */ }
        failed += 1;
        pushBulkResult(results, idRaw, false, err?.message || 'update failed');
      } finally {
        tx.release();
      }
    }

    return res.json({ ...emptyBulkResponse(idParse.ids.length), succeeded, failed, results });
  });
}
