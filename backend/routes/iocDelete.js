import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import { isHumanAdmin } from '../lib/ingestPrincipal.js';

function isAdminUser(req) {
  return isHumanAdmin(req);
}

export function registerIocDeleteRoute(app, pool, auditLogService, { invalidateDetailsCache = () => {} } = {}) {
  app.delete('/api/ioc/:publicId', async (req, res) => {
    if (!isAdminUser(req)) return res.status(403).json({ message: 'Forbidden' });

    const publicId = String(req.params?.publicId || '').trim();
    if (!publicId) {
      return res.status(400).json({ message: 'valid publicId is required' });
    }

    const confirmation = String(req.body?.confirmation || '').trim().toLowerCase();
    if (confirmation !== 'delete') {
      return res.status(400).json({ message: 'Confirmation text is invalid. Type "delete" to confirm.' });
    }

    try {
      const prev = await pool.query(
        `SELECT i.id, i.public_id, i.observable, i.observable_type, i.ioc_source_id,
                0 AS match_event_count,
                (SELECT COUNT(*) FROM ioc_manual_source_memberships WHERE ioc_item_id = i.id) AS manual_membership_count
         FROM ioc_items i WHERE i.public_id = $1::uuid LIMIT 1`,
        [publicId]
      );
      if (!prev.rows.length) {
        return res.status(404).json({ message: 'IOC not found' });
      }
      const row = prev.rows[0];
      const hadMatchEvents = Number(row.match_event_count) > 0;

      await pool.query('DELETE FROM ioc_enrichments WHERE ioc_id = $1', [row.id]).catch(() => {});
      await pool.query('DELETE FROM ioc_manual_source_memberships WHERE ioc_item_id = $1', [row.id]).catch(() => {});
      await pool.query('DELETE FROM ioc_items WHERE id = $1', [row.id]);

      invalidateDetailsCache(row.public_id);

      await auditLogService.auditSuccess({
        req,
        action: AUDIT_ACTION.IOC_DELETED,
        entityType: AUDIT_ENTITY.IOC,
        entityId: String(row.public_id),
        entityDisplay: `${row.observable} (${row.observable_type})`,
        severity: AUDIT_SEVERITY.WARNING,
        metadata: {
          ioc_id: row.id,
          ioc_value: row.observable,
          ioc_type: row.observable_type,
          ioc_source_id: row.ioc_source_id || null,
          had_match_events: hadMatchEvents,
          delete_mode: 'hard_delete'
        }
      }).catch(() => {});

      return res.json({ ok: true, deleted_public_id: row.public_id });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to delete IOC', detail: err.message });
    }
  });
}
