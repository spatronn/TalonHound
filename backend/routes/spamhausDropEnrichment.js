import { requireRole, ROLES } from '../lib/rbac.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import { parseActionReason } from '../lib/reasonValidation.js';
import {
  SPAMHAUS_DROP_PROVIDER,
  getSpamhausDropConfig,
  getSpamhausDropSyncState,
  lookupIpInSpamhausDrop,
  buildSpamhausLookupResponse,
  validateSyncIntervalHours
} from '../lib/spamhausDropSync.js';
import {
  getSpamhausDropEnrichmentByIp,
  persistSpamhausLookupResult,
  rowToSpamhausApiPayload
} from '../services/spamhausDropEnrichmentService.js';

export function extractIpFromIoc(iocValue, iocType) {
  const type = String(iocType || '').trim().toLowerCase();
  if (type === 'ip' || type === 'ipv4' || type === 'ipv6' || type === 'ip6') {
    return String(iocValue || '').trim().split('/')[0].trim() || null;
  }
  if (type === 'url') {
    try {
      const u = new URL(String(iocValue || '').trim());
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
      const host = u.hostname;
      if (!host) return null;
      // Only IP hosts — no DNS resolve for domain hosts
      const IPV4_RE = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
      const hostClean = host.replace(/^\[|\]$/g, ''); // strip IPv6 brackets
      const isIp = IPV4_RE.test(hostClean) || hostClean.includes(':');
      if (!isIp) return null;
      return hostClean;
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {ReturnType<import('../lib/auditLogService.js').createAuditLogService>} audit
 * @param {{ importQueue?: import('bullmq').Queue }} options
 */
export function registerSpamhausDropEnrichmentRoutes(app, pool, audit, options = {}) {
  const { importQueue } = options;
  // -------------------------------------------------------------------------
  // IOC Detail: hydrate persisted enrichment (no live CIDR re-lookup)
  // -------------------------------------------------------------------------
  app.get('/api/enrichment/spamhaus-drop/ioc', async (req, res) => {
    try {
      const iocValue = String(req.query?.ioc_value || req.query?.value || '').trim();
      const iocType = String(req.query?.ioc_type || req.query?.type || '').trim();

      if (!iocValue || !iocType) {
        return res.status(400).json({ message: 'ioc_value and ioc_type are required' });
      }

      const config = await getSpamhausDropConfig(pool);

      if (!config.enabled) {
        return res.json({ provider: SPAMHAUS_DROP_PROVIDER, status: 'disabled', listed: null });
      }

      const targetIp = extractIpFromIoc(iocValue, iocType);
      if (targetIp === null) {
        return res.json({ provider: SPAMHAUS_DROP_PROVIDER, status: 'not_applicable', listed: null });
      }

      const row = await getSpamhausDropEnrichmentByIp(pool, targetIp);
      return res.json(rowToSpamhausApiPayload(row));
    } catch (err) {
      console.error('[spamhaus-drop] GET ioc lookup failed', err?.message || err);
      return res.status(500).json({ message: 'Spamhaus DROP lookup failed' });
    }
  });

  // -------------------------------------------------------------------------
  // IOC Detail: refresh = re-lookup from local dataset + persist result
  // -------------------------------------------------------------------------
  app.post('/api/enrichment/spamhaus-drop/ioc/refresh', async (req, res) => {
    try {
      const iocValue = String(req.body?.ioc_value || req.body?.value || '').trim();
      const iocType = String(req.body?.ioc_type || req.body?.type || '').trim();

      if (!iocValue || !iocType) {
        return res.status(400).json({ message: 'ioc_value and ioc_type are required' });
      }

      const config = await getSpamhausDropConfig(pool);
      const syncState = await getSpamhausDropSyncState(pool);
      const targetIp = extractIpFromIoc(iocValue, iocType);

      if (targetIp === null) {
        const resp = buildSpamhausLookupResponse({ lookup: null, syncState, config, targetIp: null, notApplicable: true });
        return res.json(resp);
      }

      let lookup;
      try {
        lookup = await lookupIpInSpamhausDrop(pool, targetIp);
      } catch (err) {
        if (err?.code === 'invalid_ip') {
          return res.status(400).json({ message: err.message, code: 'invalid_ip' });
        }
        const failResp = {
          provider: SPAMHAUS_DROP_PROVIDER,
          status: 'error',
          listed: null,
          target_ip: targetIp,
          error_message: err?.message || 'Spamhaus DROP lookup failed'
        };
        await persistSpamhausLookupResult(pool, {
          targetIp,
          iocValue,
          iocType,
          response: failResp
        }).catch(() => {});
        throw err;
      }

      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.SPAMHAUS_DROP_ENRICHMENT_REFRESH,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: iocValue,
        entityDisplay: iocValue,
        severity: AUDIT_SEVERITY.INFO,
        metadata: { ioc_value: iocValue, ioc_type: iocType, target_ip: targetIp, provider: SPAMHAUS_DROP_PROVIDER }
      }).catch(() => {});

      const resp = buildSpamhausLookupResponse({ lookup, syncState, config, targetIp });
      await persistSpamhausLookupResult(pool, {
        targetIp,
        iocValue,
        iocType,
        response: resp
      }).catch((persistErr) => {
        console.error('[spamhaus-drop] persist failed', persistErr?.message || persistErr);
      });

      const enrichedAt = resp.status === 'listed' || resp.status === 'not_listed'
        ? new Date().toISOString()
        : null;
      return res.json(enrichedAt ? { ...resp, last_enriched_at: enrichedAt } : resp);
    } catch (err) {
      console.error('[spamhaus-drop] POST refresh failed', err?.message || err);
      return res.status(500).json({ message: 'Spamhaus DROP refresh failed' });
    }
  });

  // -------------------------------------------------------------------------
  // Admin: GET provider config + sync state
  // -------------------------------------------------------------------------
  app.get('/api/admin/enrichment-providers/spamhaus-drop', requireRole(ROLES.ADMIN), async (req, res) => {
    try {
      const config = await getSpamhausDropConfig(pool);
      const syncState = await getSpamhausDropSyncState(pool);
      return res.json({
        provider: SPAMHAUS_DROP_PROVIDER,
        display_name: 'Spamhaus DROP',
        enabled: config.enabled,
        sync_interval_hours: config.sync_interval_hours,
        timeout_ms: config.timeout_ms,
        sync_state: syncState
      });
    } catch (err) {
      console.error('[spamhaus-drop] GET admin config failed', err?.message || err);
      return res.status(500).json({ message: 'Failed to load Spamhaus DROP config' });
    }
  });

  // -------------------------------------------------------------------------
  // Admin: PUT update provider config
  // -------------------------------------------------------------------------
  app.put('/api/admin/enrichment-providers/spamhaus-drop', requireRole(ROLES.ADMIN), async (req, res) => {
    const reasonCheck = parseActionReason(req.body);
    if (!reasonCheck.ok) {
      return res.status(400).json({ message: reasonCheck.message });
    }

    const enabled = req.body?.enabled === true;
    const syncIntervalRaw = req.body?.sync_interval_hours ?? 24;
    const intervalCheck = validateSyncIntervalHours(syncIntervalRaw);
    if (!intervalCheck.ok) {
      return res.status(400).json({ message: intervalCheck.error });
    }
    const syncIntervalHours = intervalCheck.value;
    const timeoutMs = Math.max(5000, Number(req.body?.timeout_ms ?? 30000));

    try {
      await pool.query(
        `INSERT INTO threat_intel_provider_configs (provider, enabled, ttl_hours, timeout_ms, config, updated_at)
         VALUES ($1, $2, 24, $3, $4::jsonb, NOW())
         ON CONFLICT (provider) DO UPDATE SET
           enabled      = $2,
           timeout_ms   = $3,
           config       = $4::jsonb,
           updated_at   = NOW()`,
        [SPAMHAUS_DROP_PROVIDER, enabled, timeoutMs, JSON.stringify({ sync_interval_hours: syncIntervalHours })]
      );

      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.ENRICHMENT_PROVIDER_CONFIG_UPDATED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: SPAMHAUS_DROP_PROVIDER,
        entityDisplay: 'Spamhaus DROP',
        severity: AUDIT_SEVERITY.INFO,
        after: { enabled, sync_interval_hours: syncIntervalHours, timeout_ms: timeoutMs },
        metadata: { provider: SPAMHAUS_DROP_PROVIDER, reason: reasonCheck.reason }
      }).catch(() => {});

      const config = await getSpamhausDropConfig(pool);
      const syncState = await getSpamhausDropSyncState(pool);
      return res.json({ ok: true, enabled: config.enabled, sync_interval_hours: config.sync_interval_hours, timeout_ms: config.timeout_ms, sync_state: syncState });
    } catch (err) {
      console.error('[spamhaus-drop] PUT admin config failed', err?.message || err);
      return res.status(500).json({ message: 'Failed to update Spamhaus DROP config' });
    }
  });

  // -------------------------------------------------------------------------
  // Admin: POST run sync now (enqueues an immediate BullMQ job)
  // -------------------------------------------------------------------------
  app.post('/api/admin/enrichment-providers/spamhaus-drop/sync', requireRole(ROLES.ADMIN), async (req, res) => {
    try {
      const config = await getSpamhausDropConfig(pool);
      if (!config.enabled) {
        return res.status(409).json({ message: 'Spamhaus DROP provider is disabled. Enable it before running a sync.' });
      }

      if (!importQueue) {
        return res.status(503).json({ message: 'Import queue not available' });
      }

      const jobId = `spamhaus-drop-manual-${Date.now()}`;
      await importQueue.add(
        'spamhaus-drop-sync',
        { triggeredBy: 'admin', integration_key: 'spamhaus-drop' },
        { jobId, priority: 10 }
      );

      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.SPAMHAUS_DROP_SYNC_TRIGGERED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: SPAMHAUS_DROP_PROVIDER,
        entityDisplay: 'Spamhaus DROP',
        severity: AUDIT_SEVERITY.INFO,
        metadata: { provider: SPAMHAUS_DROP_PROVIDER, job_id: jobId, triggered_by: 'admin' }
      }).catch(() => {});

      return res.json({ ok: true, job_id: jobId });
    } catch (err) {
      console.error('[spamhaus-drop] POST sync failed', err?.message || err);
      return res.status(500).json({ message: 'Failed to enqueue Spamhaus DROP sync' });
    }
  });
}
