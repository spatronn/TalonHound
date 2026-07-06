import { requireRole, ROLES } from '../lib/rbac.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import { parseActionReason } from '../lib/reasonValidation.js';

const DEFAULT_TTL_HOURS = 24;
const DEFAULT_TIMEOUT_MS = 15000;
const DEFAULT_RATE_LIMIT_PER_MINUTE = 10;
import {
  enrichIocWithFilescan,
  getFilescanConfig,
  getEnrichmentByIoc,
  rowToApiPayload,
  testFilescanConnection,
  isFilescanSupportedType,
  maskApiKey,
  FILESCAN_PROVIDER,
  TEST_IOC_VALUE,
  TEST_IOC_TYPE
} from '../services/filescanService.js';

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {ReturnType<import('../lib/auditLogService.js').createAuditLogService>} audit
 */
export function registerFilescanEnrichmentRoutes(app, pool, audit) {
  // GET /api/enrichment/filescan?ioc_type=hash&ioc_value=<value>
  app.get('/api/enrichment/filescan', async (req, res) => {
    try {
      const iocType = String(req.query?.ioc_type || '').trim();
      const iocValue = String(req.query?.ioc_value || '').trim();

      if (!iocType || !iocValue) {
        return res.status(400).json({
          error: 'ioc_type and ioc_value query parameters are required',
          message: 'ioc_type and ioc_value query parameters are required',
          enriched: false,
          provider: FILESCAN_PROVIDER,
          provider_status: 'invalid_input'
        });
      }

      if (!isFilescanSupportedType(iocType)) {
        return res.json({
          enriched: false,
          ioc_type: iocType,
          ioc_value: iocValue,
          provider: FILESCAN_PROVIDER,
          provider_status: 'unsupported_type',
          message: 'IOC type not supported by Filescan.io'
        });
      }

      const config = await getFilescanConfig(pool);
      if (!config.enabled) {
        return res.json(rowToApiPayload(null, {
          enriched: false,
          iocType,
          iocValue,
          providerStatus: 'disabled'
        }));
      }

      const row = await getEnrichmentByIoc(pool, iocType, iocValue);
      if (!row) {
        return res.json(rowToApiPayload(null, { enriched: false, iocType, iocValue }));
      }
      return res.json(rowToApiPayload(row, { enriched: row.provider_status === 'success', cached: true }));
    } catch (err) {
      console.error('[filescan-enrichment] GET failed', err?.message || err);
      return res.status(500).json({ error: 'Failed to load Filescan.io enrichment', message: 'Failed to load Filescan.io enrichment' });
    }
  });

  // POST /api/enrichment/filescan/refresh
  app.post('/api/enrichment/filescan/refresh', async (req, res) => {
    const iocType = String(req.body?.ioc_type || req.query?.ioc_type || '').trim();
    const iocValue = String(req.body?.ioc_value || req.query?.ioc_value || '').trim();
    const force = String(req.query?.force || '').toLowerCase() === 'true' || req.body?.force === true;

    if (!iocType || !iocValue) {
      return res.status(400).json({
        error: 'ioc_type and ioc_value are required',
        message: 'ioc_type and ioc_value are required',
        provider_status: 'invalid_input'
      });
    }

    if (!isFilescanSupportedType(iocType)) {
      return res.status(422).json({
        error: 'IOC type not supported by Filescan.io',
        message: 'IOC type not supported by Filescan.io',
        provider_status: 'unsupported_type'
      });
    }

    try {
      const result = await enrichIocWithFilescan(pool, iocType, iocValue, { force });

      if (result.skipped && result.provider_status === 'disabled') {
        return res.status(409).json({
          error: 'Filescan.io provider is disabled',
          message: 'Filescan.io provider is disabled',
          provider_status: 'disabled'
        });
      }

      if (!result.cached || force) {
        await audit.auditSuccess({
          req,
          action: AUDIT_ACTION.FILESCAN_ENRICHMENT_REFRESH,
          entityType: AUDIT_ENTITY.ENRICHMENT,
          entityId: `${iocType}:${iocValue}`,
          entityDisplay: iocValue,
          severity: AUDIT_SEVERITY.INFO,
          metadata: {
            ioc_type: iocType,
            ioc_value: iocValue,
            provider: FILESCAN_PROVIDER,
            cache_bypass: force || !result.cached,
            cached: result.cached,
            force,
            provider_status: result.provider_status
          }
        }).catch(() => {});
      }

      const payload = rowToApiPayload(result.row, {
        enriched: result.provider_status === 'success',
        cached: result.cached,
        iocType,
        iocValue
      });

      if (result.provider_status === 'success') {
        return res.json(payload);
      }

      const httpStatus = result.provider_status === 'rate_limited' ? 429
        : (result.provider_status === 'auth_error' ? 401 : 502);

      return res.status(httpStatus).json({
        ...payload,
        error: result.row?.error_message || 'Filescan.io enrichment failed',
        message: result.row?.error_message || 'Filescan.io enrichment failed'
      });
    } catch (err) {
      console.error('[filescan-enrichment] POST refresh failed', err?.message || err);
      if (err?.code === 'invalid_input') {
        return res.status(400).json({ error: err.message, message: err.message, provider_status: 'invalid_input' });
      }
      if (err?.code === 'auth') {
        return res.status(401).json({ error: err.message, message: err.message, provider_status: 'auth_error' });
      }
      if (err?.code === 'rate_limit') {
        return res.status(429).json({
          error: err.message,
          message: err.message,
          provider_status: 'rate_limited',
          retry_after: err.retryAfter || null
        });
      }
      return res.status(500).json({ error: 'Filescan.io enrichment failed', message: 'Filescan.io enrichment failed' });
    }
  });

  app.get('/api/admin/enrichment-providers/filescan', requireRole(ROLES.ADMIN), async (req, res) => {
    try {
      const cfg = await getFilescanConfig(pool);
      return res.json({
        provider_key: cfg.provider_key,
        display_name: cfg.display_name,
        enabled: cfg.enabled,
        configured: cfg.configured,
        api_key_masked: cfg.api_key_masked,
        api_key_set: cfg.api_key_set,
        cache_ttl_hours: cfg.cache_ttl_hours,
        timeout_ms: cfg.timeout_ms,
        rate_limit_per_minute: cfg.rate_limit_per_minute,
        source: cfg.source,
        last_test_at: cfg.last_test_at,
        last_success_at: cfg.last_success_at,
        last_error_at: cfg.last_error_at,
        last_error_message: cfg.last_error_message
      });
    } catch {
      return res.status(500).json({ message: 'Failed to load Filescan.io config' });
    }
  });

  app.put('/api/admin/enrichment-providers/filescan', requireRole(ROLES.ADMIN), async (req, res) => {
    const reasonCheck = parseActionReason(req.body);
    if (!reasonCheck.ok) {
      return res.status(400).json({ message: reasonCheck.message });
    }
    try {
      const enabled = req.body?.enabled === true;
      const apiKey = typeof req.body?.api_key === 'string' ? req.body.api_key.trim() : undefined;
      const ttlHours = Math.max(1, Number(req.body?.cache_ttl_hours ?? req.body?.ttl_hours ?? DEFAULT_TTL_HOURS));
      const timeoutMs = Math.max(3000, Number(req.body?.timeout_ms ?? DEFAULT_TIMEOUT_MS));
      const rateLimitPerMinute = Math.max(1, Number(req.body?.rate_limit_per_minute ?? DEFAULT_RATE_LIMIT_PER_MINUTE));

      const config = { rate_limit_per_minute: rateLimitPerMinute };

      await pool.query(
        `INSERT INTO threat_intel_provider_configs (provider, enabled, ttl_hours, timeout_ms, api_key, config, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6::jsonb, NOW())
         ON CONFLICT (provider) DO UPDATE SET
           enabled    = $2,
           ttl_hours  = $3,
           timeout_ms = $4,
           api_key    = COALESCE(NULLIF($5, ''), threat_intel_provider_configs.api_key),
           config     = $6::jsonb,
           updated_at = NOW()`,
        [FILESCAN_PROVIDER, enabled, ttlHours, timeoutMs, apiKey, JSON.stringify(config)]
      );

      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.ENRICHMENT_PROVIDER_CONFIG_UPDATED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: FILESCAN_PROVIDER,
        entityDisplay: 'Filescan.io',
        severity: AUDIT_SEVERITY.INFO,
        after: {
          enabled,
          cache_ttl_hours: ttlHours,
          timeout_ms: timeoutMs,
          rate_limit_per_minute: rateLimitPerMinute,
          api_key_updated: Boolean(apiKey)
        },
        metadata: { provider: FILESCAN_PROVIDER, reason: reasonCheck.reason }
      }).catch(() => {});

      const cfg = await getFilescanConfig(pool);
      return res.json({
        ok: true,
        provider_key: cfg.provider_key,
        display_name: cfg.display_name,
        enabled: cfg.enabled,
        configured: cfg.configured,
        api_key_masked: cfg.api_key_masked,
        api_key_set: cfg.api_key_set,
        cache_ttl_hours: cfg.cache_ttl_hours,
        timeout_ms: cfg.timeout_ms,
        rate_limit_per_minute: cfg.rate_limit_per_minute
      });
    } catch {
      return res.status(500).json({ message: 'Failed to update Filescan.io config' });
    }
  });

  app.post('/api/admin/enrichment-providers/filescan/test', requireRole(ROLES.ADMIN), async (req, res) => {
    const now = new Date().toISOString();
    try {
      const result = await testFilescanConnection(pool);

      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.FILESCAN_CONNECTION_TEST,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: FILESCAN_PROVIDER,
        entityDisplay: 'Filescan.io',
        severity: AUDIT_SEVERITY.INFO,
        metadata: { provider: FILESCAN_PROVIDER, test_ioc: TEST_IOC_VALUE, verdict: result.verdict }
      }).catch(() => {});

      await pool.query(
        `UPDATE threat_intel_provider_configs SET last_test_at=$2, last_success_at=$2, last_error_message=NULL, updated_at=NOW() WHERE provider=$1`,
        [FILESCAN_PROVIDER, now]
      );
      return res.json({
        ok: true,
        message: 'Connection successful',
        ioc_value: result.ioc_value,
        verdict: result.verdict,
        report_count: result.report_count
      });
    } catch (err) {
      const msg = String(err?.message || 'Filescan.io test failed');
      await pool.query(
        `UPDATE threat_intel_provider_configs SET last_test_at=$2, last_error_at=$2, last_error_message=$3, updated_at=NOW() WHERE provider=$1`,
        [FILESCAN_PROVIDER, now, msg.slice(0, 500)]
      ).catch(() => {});
      if (err?.code === 'disabled') return res.status(409).json({ message: msg });
      if (err?.code === 'auth') return res.status(401).json({ message: msg });
      if (err?.code === 'rate_limit') return res.status(429).json({ message: msg });
      return res.status(502).json({ message: msg });
    }
  });

  app.post('/api/admin/enrichment-providers/filescan/remove-key', requireRole(ROLES.ADMIN), async (req, res) => {
    try {
      await pool.query(
        `UPDATE threat_intel_provider_configs SET api_key=NULL, updated_at=NOW() WHERE provider=$1`,
        [FILESCAN_PROVIDER]
      );
      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.ENRICHMENT_KEY_REMOVED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: FILESCAN_PROVIDER,
        entityDisplay: 'Filescan.io',
        severity: AUDIT_SEVERITY.WARNING,
        metadata: { provider: FILESCAN_PROVIDER }
      }).catch(() => {});
      return res.json({ ok: true });
    } catch {
      return res.status(500).json({ message: 'Failed to remove API key' });
    }
  });
}

export { maskApiKey };
