import { normalizeAppRole, ROLES } from '../lib/rbac.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import { validatePublicIp } from '../lib/publicIp.js';
import {
  enrichIpWithIpinfoLite,
  getEnrichmentByIp,
  getIpinfoLiteConfig,
  rowToApiPayload,
  testIpinfoLiteConnection,
  maskToken
} from '../services/ipinfoLiteService.js';

const IPINFO_PROVIDER = 'ipinfo_lite';

function decodeRouteIp(raw) {
  try {
    return decodeURIComponent(String(raw || '').trim());
  } catch {
    return String(raw || '').trim();
  }
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {ReturnType<import('../lib/auditLogService.js').createAuditLogService>} audit
 */
export function registerIpEnrichmentRoutes(app, pool, audit) {
  app.get('/api/enrichment/ip/:ip', async (req, res) => {
    try {
      const ip = decodeRouteIp(req.params.ip);
      const publicIp = validatePublicIp(ip);
      if (!publicIp) {
        return res.json({ enriched: false, ip, provider: IPINFO_PROVIDER, provider_status: 'skipped' });
      }
      const row = await getEnrichmentByIp(pool, publicIp);
      if (!row) {
        return res.json({ enriched: false, ip: publicIp, provider: IPINFO_PROVIDER });
      }
      return res.json(rowToApiPayload(row, { enriched: row.provider_status === 'success', cached: false }));
    } catch (err) {
      console.error('[ip-enrichment] GET failed', err?.message || err);
      return res.status(500).json({ error: 'Failed to load IP enrichment', message: 'Failed to load IP enrichment' });
    }
  });

  app.post('/api/enrichment/ip/:ip/refresh', async (req, res) => {
    const ip = decodeRouteIp(req.params.ip);
    const force = String(req.query?.force || '').toLowerCase() === 'true'
      || req.body?.force === true;
    const role = normalizeAppRole(req.user?.role) || ROLES.ADMIN;

    if (force && role !== ROLES.ADMIN) {
      return res.status(403).json({ error: 'Force refresh requires admin role', message: 'Force refresh requires admin role' });
    }

    const publicIp = validatePublicIp(ip);
    if (!publicIp) {
      return res.status(422).json({
        error: 'Private or reserved IP — external lookup not supported',
        message: 'Private or reserved IP — external lookup not supported',
        enriched: false,
        ip,
        provider_status: 'skipped'
      });
    }

    try {
      const cfg = await getIpinfoLiteConfig(pool);
      if (!cfg.configured) {
        return res.status(409).json({
          error: 'IPinfo Lite provider is not configured',
          message: 'IPinfo Lite provider is not configured'
        });
      }
      if (!cfg.enabled) {
        return res.status(409).json({
          error: 'IPinfo Lite provider is disabled',
          message: 'IPinfo Lite provider is disabled'
        });
      }

      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.IP_ENRICHMENT_REQUESTED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: publicIp,
        entityDisplay: publicIp,
        severity: AUDIT_SEVERITY.INFO,
        metadata: { ip: publicIp, provider: IPINFO_PROVIDER, force, cached: false }
      }).catch(() => {});

      const result = await enrichIpWithIpinfoLite(pool, publicIp, { force });
      const payload = rowToApiPayload(result.row, {
        enriched: result.row?.provider_status === 'success',
        cached: result.cached
      });

      if (result.row?.provider_status === 'success') {
        await audit.auditSuccess({
          req,
          action: AUDIT_ACTION.IP_ENRICHMENT_COMPLETED,
          entityType: AUDIT_ENTITY.ENRICHMENT,
          entityId: publicIp,
          entityDisplay: publicIp,
          severity: AUDIT_SEVERITY.INFO,
          metadata: {
            ip: publicIp,
            provider: IPINFO_PROVIDER,
            cached: result.cached,
            force,
            status: result.row.provider_status
          }
        }).catch(() => {});
        return res.json(payload);
      }

      await audit.auditFailure({
        req,
        action: AUDIT_ACTION.IP_ENRICHMENT_FAILED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: publicIp,
        entityDisplay: publicIp,
        severity: AUDIT_SEVERITY.WARNING,
        metadata: {
          ip: publicIp,
          provider: IPINFO_PROVIDER,
          cached: result.cached,
          status: result.row?.provider_status,
          error_message: result.row?.error_message
        }
      }).catch(() => {});

      return res.status(result.row?.provider_status === 'unavailable' ? 404 : 502).json({
        ...payload,
        error: result.row?.error_message || 'IP enrichment failed',
        message: result.row?.error_message || 'IP enrichment failed'
      });
    } catch (err) {
      console.error('[ip-enrichment] POST refresh failed', err?.message || err);
      if (err?.code === 'not_configured') {
        return res.status(409).json({ error: err.message, message: err.message });
      }
      if (err?.code === 'auth') {
        return res.status(401).json({ error: err.message, message: err.message });
      }
      if (err?.code === 'rate_limit') {
        return res.status(429).json({
          error: err.message,
          message: err.message,
          retry_after: err.retryAfter || null
        });
      }
      await audit.auditFailure({
        req,
        action: AUDIT_ACTION.IP_ENRICHMENT_FAILED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: publicIp,
        entityDisplay: publicIp,
        severity: AUDIT_SEVERITY.WARNING,
        metadata: { error_message: String(err?.message || err) }
      }).catch(() => {});
      return res.status(500).json({ error: 'IP enrichment failed', message: 'IP enrichment failed' });
    }
  });

  app.get('/api/admin/enrichment-providers/ipinfo-lite', async (req, res) => {
    try {
      const cfg = await getIpinfoLiteConfig(pool);
      return res.json({
        provider_key: cfg.provider_key,
        display_name: cfg.display_name,
        enabled: cfg.enabled,
        configured: cfg.configured,
        token_masked: cfg.token_masked,
        base_url: cfg.base_url,
        timeout_seconds: cfg.timeout_seconds,
        usage_note: cfg.usage_note,
        source: cfg.source,
        last_test_at: cfg.last_test_at,
        last_success_at: cfg.last_success_at,
        last_error_at: cfg.last_error_at,
        last_error_message: cfg.last_error_message
      });
    } catch {
      return res.status(500).json({ message: 'Failed to load IPinfo Lite config' });
    }
  });

  app.put('/api/admin/enrichment-providers/ipinfo-lite', async (req, res) => {
    try {
      const enabled = req.body?.enabled !== false;
      const token = typeof req.body?.token === 'string' ? req.body.token.trim() : undefined;
      const baseUrl = typeof req.body?.base_url === 'string' && req.body.base_url.trim()
        ? req.body.base_url.trim().replace(/\/$/, '')
        : undefined;
      const timeoutSeconds = Number(req.body?.timeout_seconds);
      const usageNote = typeof req.body?.usage_note === 'string' ? req.body.usage_note.trim() : undefined;

      const existing = await getIpinfoLiteConfig(pool);
      const config = {
        base_url: baseUrl || existing.base_url,
        timeout_seconds: Number.isFinite(timeoutSeconds) && timeoutSeconds >= 3
          ? Math.min(timeoutSeconds, 30)
          : existing.timeout_seconds,
        ...(usageNote !== undefined ? { usage_note: usageNote } : { usage_note: existing.usage_note })
      };
      const timeoutMs = config.timeout_seconds * 1000;

      await pool.query(
        `INSERT INTO threat_intel_provider_configs (provider, enabled, ttl_hours, timeout_ms, api_key, config, updated_at)
         VALUES ($1, $2, 24, $3, $4, $5::jsonb, NOW())
         ON CONFLICT (provider) DO UPDATE SET
           enabled = $2,
           timeout_ms = $3,
           api_key = COALESCE(NULLIF($4, ''), threat_intel_provider_configs.api_key),
           config = $5::jsonb,
           updated_at = NOW()`,
        [IPINFO_PROVIDER, enabled, timeoutMs, token, JSON.stringify(config)]
      );

      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.ENRICHMENT_PROVIDER_CONFIG_UPDATED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: IPINFO_PROVIDER,
        entityDisplay: 'IPinfo Lite',
        severity: AUDIT_SEVERITY.INFO,
        after: { enabled, base_url: config.base_url, timeout_seconds: config.timeout_seconds, token_updated: Boolean(token) },
        metadata: { provider: IPINFO_PROVIDER }
      }).catch(() => {});

      const cfg = await getIpinfoLiteConfig(pool);
      return res.json({
        ok: true,
        provider_key: cfg.provider_key,
        display_name: cfg.display_name,
        enabled: cfg.enabled,
        configured: cfg.configured,
        token_masked: cfg.token_masked,
        base_url: cfg.base_url,
        timeout_seconds: cfg.timeout_seconds
      });
    } catch {
      return res.status(500).json({ message: 'Failed to update IPinfo Lite config' });
    }
  });

  app.post('/api/admin/enrichment-providers/ipinfo-lite/test', async (req, res) => {
    const now = new Date().toISOString();
    try {
      const row = await testIpinfoLiteConnection(pool);
      await pool.query(
        `UPDATE threat_intel_provider_configs SET last_test_at=$2, last_success_at=$2, last_error_message=NULL, updated_at=NOW() WHERE provider=$1`,
        [IPINFO_PROVIDER, now]
      );
      return res.json({
        ok: true,
        message: 'Connection successful',
        asn: row.asn,
        as_name: row.as_name,
        country_code: row.country_code
      });
    } catch (err) {
      const msg = String(err?.message || 'IPinfo Lite test failed');
      await pool.query(
        `UPDATE threat_intel_provider_configs SET last_test_at=$2, last_error_at=$2, last_error_message=$3, updated_at=NOW() WHERE provider=$1`,
        [IPINFO_PROVIDER, now, msg.slice(0, 500)]
      ).catch(() => {});
      if (err?.code === 'not_configured') return res.status(400).json({ message: msg });
      if (err?.code === 'auth') return res.status(401).json({ message: msg });
      if (err?.code === 'rate_limit') return res.status(429).json({ message: msg });
      return res.status(502).json({ message: msg });
    }
  });

  app.post('/api/admin/enrichment-providers/ipinfo-lite/remove-key', async (req, res) => {
    try {
      await pool.query(
        `UPDATE threat_intel_provider_configs SET api_key=NULL, updated_at=NOW() WHERE provider=$1`,
        [IPINFO_PROVIDER]
      );
      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.ENRICHMENT_KEY_REMOVED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: IPINFO_PROVIDER,
        entityDisplay: 'IPinfo Lite',
        severity: AUDIT_SEVERITY.WARNING,
        metadata: { provider: IPINFO_PROVIDER }
      }).catch(() => {});
      return res.json({ ok: true });
    } catch {
      return res.status(500).json({ message: 'Failed to remove token' });
    }
  });
}

export { maskToken };
