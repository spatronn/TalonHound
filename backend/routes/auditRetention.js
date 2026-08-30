import { requireRole, ROLES } from '../lib/rbac.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import { isCallerSystemAdmin } from '../lib/systemAdminAuth.js';
import {
  AUDIT_LOG_RETENTION_PRESET_DAYS,
  AUDIT_LOG_RETENTION_MAX_DAYS,
  AUDIT_LOG_RETENTION_DEFAULT_DAYS,
  getAuditLogRetentionConfig,
  setAuditLogRetention,
  parseAuditLogRetentionInput
} from '../lib/auditLogRetention.js';

export { isCallerSystemAdmin };

function publicRetentionPayload(cfg, { canEdit }) {
  return {
    retention_days: cfg.retentionDays,
    keep_forever: cfg.keepForever,
    default_days: AUDIT_LOG_RETENTION_DEFAULT_DAYS,
    preset_days: [...AUDIT_LOG_RETENTION_PRESET_DAYS],
    max_days: AUDIT_LOG_RETENTION_MAX_DAYS,
    updated_at: cfg.updatedAt,
    updated_by: cfg.updatedBy,
    last_cleanup_at: cfg.lastRunAt,
    can_edit: Boolean(canEdit)
  };
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {{ audit?: { auditSuccess: Function, auditLog: Function } }} [deps]
 */
export function registerAuditRetentionRoutes(app, pool, deps = {}) {
  const audit = deps.audit || null;

  // Read: any admin may view the configured retention (Settings page convention).
  app.get('/api/settings/audit-log-retention', requireRole(ROLES.ADMIN), async (req, res) => {
    try {
      const cfg = await getAuditLogRetentionConfig(pool);
      const canEdit = await isCallerSystemAdmin(pool, req);
      return res.json(publicRetentionPayload(cfg, { canEdit }));
    } catch {
      return res.status(500).json({ message: 'Failed to load audit log retention setting' });
    }
  });

  // Write: only the System Administrator may change retention. Enforced
  // server-side regardless of the frontend control state.
  app.put('/api/settings/audit-log-retention', requireRole(ROLES.ADMIN), async (req, res) => {
    let systemAdmin = false;
    try {
      systemAdmin = await isCallerSystemAdmin(pool, req);
    } catch {
      systemAdmin = false;
    }
    if (!systemAdmin) {
      return res.status(403).json({
        code: 'FORBIDDEN',
        message: 'Only the System Administrator can change audit log retention'
      });
    }

    const parsed = parseAuditLogRetentionInput(req.body);
    if (!parsed.ok) {
      return res.status(400).json({ code: 'INVALID_RETENTION', message: parsed.error });
    }

    try {
      const before = await getAuditLogRetentionConfig(pool);
      const after = await setAuditLogRetention(pool, {
        days: parsed.keepForever ? null : parsed.days,
        updatedBy: req.user?.email || req.user?.username || null
      });

      const isReduction = before.keepForever
        ? !after.keepForever
        : (!after.keepForever && after.retentionDays < before.retentionDays);

      if (audit?.auditLog) {
        await audit.auditLog({
          req,
          action: AUDIT_ACTION.SETTINGS_UPDATED,
          entityType: AUDIT_ENTITY.SETTINGS,
          entityId: 'audit_log_retention',
          entityDisplay: 'Audit Log Retention',
          severity: isReduction ? AUDIT_SEVERITY.WARNING : AUDIT_SEVERITY.INFO,
          before: {
            audit_log_retention_days: before.retentionDays,
            keep_forever: before.keepForever
          },
          after: {
            audit_log_retention_days: after.retentionDays,
            keep_forever: after.keepForever
          },
          metadata: {
            setting: 'audit_log_retention_days',
            previous_retention_days: before.retentionDays,
            new_retention_days: after.retentionDays,
            previous_keep_forever: before.keepForever,
            new_keep_forever: after.keepForever,
            reduction: isReduction
          }
        });
      }

      const canEdit = await isCallerSystemAdmin(pool, req);
      return res.json({
        ...publicRetentionPayload(after, { canEdit }),
        message: 'Audit log retention updated'
      });
    } catch {
      return res.status(500).json({ message: 'Failed to update audit log retention setting' });
    }
  });
}
