import { requireRole, ROLES } from '../lib/rbac.js';
import { requireSystemAdmin } from '../lib/systemAdminAuth.js';
import { AUDIT_ACTION, AUDIT_ENTITY } from '../lib/auditConstants.js';
import { updateCheckService } from '../lib/updateCheckService.js';

const UPDATES_FORBIDDEN_MESSAGE = 'Only the System Administrator can manage product updates';

/**
 * Product update status and manual check. System Administrator only.
 *
 * Background polling (updateCheckService.startBackgroundChecks) is internal and
 * does not use these HTTP routes or require a user session.
 *
 * @param {import('express').Express} app
 * @param {{
 *   pool?: import('pg').Pool,
 *   auditLogService?: any,
 *   updateCheck?: typeof updateCheckService
 * }} [deps]
 */
export function registerSystemUpdatesRoutes(app, deps = {}) {
  const admin = requireRole(ROLES.ADMIN);
  const systemAdmin = requireSystemAdmin(deps.pool, UPDATES_FORBIDDEN_MESSAGE);
  const service = deps.updateCheck || updateCheckService;
  const audit = deps.auditLogService || null;

  app.get('/api/system/updates', admin, systemAdmin, (_req, res) => {
    return res.json(service.getStatus());
  });

  app.post('/api/system/updates/check', admin, systemAdmin, async (req, res) => {
    try {
      const status = await service.check({ force: true });
      if (audit?.auditSuccess) {
        await audit.auditSuccess({
          req,
          action: AUDIT_ACTION.UPDATE_CHECK_REQUESTED,
          entityType: AUDIT_ENTITY.SETTINGS,
          entityId: null,
          entityDisplay: 'update-check',
          metadata: {
            status: status.status,
            current_version: status.currentVersion,
            latest_version: status.latestVersion,
            channel: status.channel
          }
        });
      }
      return res.json(status);
    } catch {
      return res.status(500).json({
        code: 'UPDATE_CHECK_FAILED',
        message: 'Failed to check for updates'
      });
    }
  });
}
