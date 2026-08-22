import { requireRole, ROLES } from '../lib/rbac.js';
import { removeIocManualSource } from '../lib/iocSourceRemoval.js';

/**
 * Source-level IOC removal route.
 *
 * DELETE /api/ioc/:publicId/sources/manual/:sourceId
 *   Detaches a single manual/custom source membership from an IOC. This is
 *   deliberately distinct from DELETE /api/ioc/:publicId (global IOC deletion)
 *   and from DELETE /api/admin/ioc-sources/:id (source catalog deletion). Only
 *   manual/custom sources are removable; feed-managed sources are rejected by
 *   the service using authoritative DB state.
 *
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {{ auditSuccess: Function }} auditLogService
 * @param {{ invalidateDetailsCache?: (publicId: string) => void }} [opts]
 */
export function registerIocSourceRemovalRoute(app, pool, auditLogService, { invalidateDetailsCache = () => {} } = {}) {
  // Admin-only, consistent with the other IOC-source lifecycle actions (move /
  // archive / catalog delete) and with global IOC deletion. requireRole also
  // rejects the machine ingest principal and read-only users.
  app.delete(
    '/api/ioc/:publicId/sources/manual/:sourceId',
    requireRole(ROLES.ADMIN),
    async (req, res) => {
      const publicId = String(req.params?.publicId || '').trim();
      const sourceId = Number(req.params?.sourceId);

      try {
        const result = await removeIocManualSource(
          pool,
          { publicId, sourceId },
          { req, user: req.user, audit: auditLogService }
        );

        if (result.status === 200) {
          if (publicId) invalidateDetailsCache(publicId);
          if (result.body?.removed_public_id) invalidateDetailsCache(result.body.removed_public_id);
          if (result.body?.canonical_public_id) invalidateDetailsCache(result.body.canonical_public_id);
        }

        return res.status(result.status).json(result.body);
      } catch (err) {
        return res.status(500).json({ error: 'removal_failed', message: 'Failed to remove IOC from source', detail: err.message });
      }
    }
  );
}
