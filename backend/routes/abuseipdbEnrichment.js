import { normalizeAppRole, requireRole, ROLES } from '../lib/rbac.js';
import { isValidIpAddress, validatePublicIp } from '../lib/publicIp.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import { parseActionReason } from '../lib/reasonValidation.js';
import { buildEnrichmentAuditScope, resolveSubjectIocFromRequest } from '../lib/enrichmentAuditScope.js';
import {
  enrichIpWithAbuseIpdb,
  getAbuseIpdbConfig,
  getEnrichmentByIp,
  rowToApiPayload,
  testAbuseIpdbConnection,
  maskApiKey,
  ABUSEIPDB_PROVIDER,
  TEST_IP
} from '../services/abuseipdbService.js';
import { guardProviderEnabled } from '../lib/enrichmentProviderRegistry.js';
import { auditProviderConfigUpdate } from '../lib/enrichmentProviderConfigAudit.js';
import { recordEnrichmentUsage } from '../lib/enrichmentUsageTelemetry.js';

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
export function registerAbuseIpdbEnrichmentRoutes(app, pool, audit) {
  app.get('/api/enrichment/abuseipdb/ip/:ip', async (req, res) => {
    try {
      const ip = decodeRouteIp(req.params.ip);
      if (!isValidIpAddress(ip)) {
        return res.status(400).json({
          error: 'Invalid IP address',
          message: 'Invalid IP address',
          enriched: false,
          ip,
          provider: ABUSEIPDB_PROVIDER,
          provider_status: 'invalid_ip'
        });
      }

      const publicIp = validatePublicIp(ip);
      if (!publicIp) {
        return res.json({
          enriched: false,
          ip: ip.split('/')[0].trim(),
          provider: ABUSEIPDB_PROVIDER,
          provider_status: 'unsupported_private_ip',
          message: 'AbuseIPDB only supports public IP reputation checks'
        });
      }

      const config = await getAbuseIpdbConfig(pool);
      if (!config.configured) {
        return res.json(rowToApiPayload(null, {
          enriched: false,
          ip: publicIp,
          providerStatus: 'not_configured'
        }));
      }
      if (!config.enabled) {
        return res.json(rowToApiPayload(null, {
          enriched: false,
          ip: publicIp,
          providerStatus: 'disabled'
        }));
      }

      const row = await getEnrichmentByIp(pool, publicIp);
      if (!row) {
        return res.json(rowToApiPayload(null, { enriched: false, ip: publicIp }));
      }
      const fresh = row.provider_status === 'success';
      return res.json(rowToApiPayload(row, { enriched: fresh, cached: true }));
    } catch (err) {
      console.error('[abuseipdb-enrichment] GET failed', err?.message || err);
      return res.status(500).json({ error: 'Failed to load AbuseIPDB enrichment', message: 'Failed to load AbuseIPDB enrichment' });
    }
  });

  app.post('/api/enrichment/abuseipdb/ip/:ip/refresh', async (req, res) => {
    const ip = decodeRouteIp(req.params.ip);
    const force = String(req.query?.force || '').toLowerCase() === 'true'
      || req.body?.force === true;
    const role = normalizeAppRole(req.user?.role) || ROLES.ADMIN;

    if (force && role !== ROLES.ADMIN) {
      return res.status(403).json({ error: 'Force refresh requires admin role', message: 'Force refresh requires admin role' });
    }

    if (!isValidIpAddress(ip)) {
      return res.status(400).json({
        error: 'Invalid IP address',
        message: 'Invalid IP address',
        enriched: false,
        ip,
        provider_status: 'invalid_ip'
      });
    }

    const publicIp = validatePublicIp(ip);
    if (!publicIp) {
      return res.status(422).json({
        error: 'Private or reserved IP — external lookup not supported',
        message: 'AbuseIPDB only supports public IP reputation checks',
        enriched: false,
        ip: ip.split('/')[0].trim(),
        provider_status: 'unsupported_private_ip'
      });
    }

    try {
      // Central disable guard: no external call for a disabled provider.
      if (!(await guardProviderEnabled(pool, ABUSEIPDB_PROVIDER, res))) return;

      const abuseStartedAt = Date.now();
      const result = await enrichIpWithAbuseIpdb(pool, publicIp, { force });
      const abuseExternal = result.cached !== true && !result.skipped;

      if (result.skipped && result.provider_status === 'not_configured') {
        return res.status(409).json({
          error: 'AbuseIPDB API key is not configured',
          message: 'AbuseIPDB API key is not configured',
          provider_status: 'not_configured'
        });
      }
      if (result.skipped && result.provider_status === 'disabled') {
        return res.status(409).json({
          error: 'AbuseIPDB provider is disabled',
          message: 'AbuseIPDB provider is disabled',
          provider_status: 'disabled'
        });
      }

      if (!result.cached || force) {
        const subject = await resolveSubjectIocFromRequest(pool, req);
        const scope = buildEnrichmentAuditScope({
          subject,
          subjectIocValue: subject?.observable || req.body?.value || publicIp,
          subjectIocType: subject?.observable_type || req.body?.ioc_type || null,
          targetType: 'ip',
          targetValue: publicIp,
          provider: ABUSEIPDB_PROVIDER,
          extraMetadata: {
            ip: publicIp,
            original_value: subject?.observable || req.body?.value || publicIp,
            observable_value: subject?.observable || req.body?.value || publicIp,
            cache_bypass: force || !result.cached,
            cached: result.cached,
            force,
            provider_status: result.provider_status,
            abuse_confidence_score: result.row?.normalized_summary?.abuseConfidenceScore ?? null
          }
        });
        await audit.auditSuccess({
          req,
          action: AUDIT_ACTION.ABUSEIPDB_ENRICHMENT_REFRESH,
          entityType: AUDIT_ENTITY.ENRICHMENT,
          entityId: scope.entityId,
          entityDisplay: scope.entityDisplay,
          subjectIocId: scope.subjectIocId,
          subjectIocType: scope.subjectIocType,
          subjectIocValue: scope.subjectIocValue,
          targetType: scope.targetType,
          targetValue: scope.targetValue,
          severity: AUDIT_SEVERITY.INFO,
          metadata: scope.metadata
        }).catch(() => {});
      }

      const payload = rowToApiPayload(result.row, {
        enriched: result.provider_status === 'success',
        cached: result.cached,
        ip: publicIp
      });

      if (result.provider_status === 'success') {
        recordEnrichmentUsage(pool, {
          provider: ABUSEIPDB_PROVIDER,
          iocType: 'ip',
          outcome: 'success',
          external: abuseExternal,
          cacheHit: !abuseExternal,
          responseTimeMs: abuseExternal ? Date.now() - abuseStartedAt : null
        });
        return res.json(payload);
      }

      recordEnrichmentUsage(pool, {
        provider: ABUSEIPDB_PROVIDER,
        iocType: 'ip',
        outcome: 'failure',
        external: abuseExternal,
        rateLimited: result.provider_status === 'rate_limited',
        responseTimeMs: abuseExternal ? Date.now() - abuseStartedAt : null
      });

      const httpStatus = result.provider_status === 'rate_limited' ? 429
        : (result.provider_status === 'auth_error' ? 401 : 502);

      return res.status(httpStatus).json({
        ...payload,
        error: result.row?.error_message || 'AbuseIPDB enrichment failed',
        message: result.row?.error_message || 'AbuseIPDB enrichment failed'
      });
    } catch (err) {
      console.error('[abuseipdb-enrichment] POST refresh failed', err?.message || err);
      if (err?.code === 'invalid_ip') {
        return res.status(400).json({ error: err.message, message: err.message, provider_status: 'invalid_ip' });
      }
      if (err?.code === 'auth') {
        recordEnrichmentUsage(pool, { provider: ABUSEIPDB_PROVIDER, iocType: 'ip', outcome: 'failure', external: true });
        return res.status(401).json({ error: err.message, message: err.message, provider_status: 'auth_error' });
      }
      if (err?.code === 'rate_limit') {
        recordEnrichmentUsage(pool, { provider: ABUSEIPDB_PROVIDER, iocType: 'ip', outcome: 'failure', external: true, rateLimited: true });
        return res.status(429).json({
          error: err.message,
          message: err.message,
          provider_status: 'rate_limited',
          retry_after: err.retryAfter || null
        });
      }
      recordEnrichmentUsage(pool, { provider: ABUSEIPDB_PROVIDER, iocType: 'ip', outcome: 'failure', external: true });
      return res.status(500).json({ error: 'AbuseIPDB enrichment failed', message: 'AbuseIPDB enrichment failed' });
    }
  });

  app.get('/api/admin/enrichment-providers/abuseipdb', requireRole(ROLES.ADMIN), async (req, res) => {
    try {
      const cfg = await getAbuseIpdbConfig(pool);
      return res.json({
        provider_key: cfg.provider_key,
        display_name: cfg.display_name,
        enabled: cfg.enabled,
        configured: cfg.configured,
        api_key_masked: cfg.api_key_masked,
        cache_ttl_hours: cfg.cache_ttl_hours,
        timeout_ms: cfg.timeout_ms,
        max_age_days: cfg.max_age_days,
        verbose: cfg.verbose,
        source: cfg.source,
        last_test_at: cfg.last_test_at,
        last_success_at: cfg.last_success_at,
        last_error_at: cfg.last_error_at,
        last_error_message: cfg.last_error_message
      });
    } catch {
      return res.status(500).json({ message: 'Failed to load AbuseIPDB config' });
    }
  });

  app.put('/api/admin/enrichment-providers/abuseipdb', requireRole(ROLES.ADMIN), async (req, res) => {
    const reasonCheck = parseActionReason(req.body);
    if (!reasonCheck.ok) {
      return res.status(400).json({ message: reasonCheck.message });
    }
    try {
      const enabled = req.body?.enabled === true;
      const apiKey = typeof req.body?.api_key === 'string' ? req.body.api_key.trim() : undefined;
      const ttlHours = Math.max(1, Number(req.body?.cache_ttl_hours ?? req.body?.ttl_hours ?? 24));
      const timeoutMs = Math.max(3000, Number(req.body?.timeout_ms ?? 8000));
      const maxAgeDays = Math.min(365, Math.max(1, Number(req.body?.max_age_days ?? 90)));
      const verbose = req.body?.verbose === true;

      const existing = await getAbuseIpdbConfig(pool);
      const config = {
        max_age_days: maxAgeDays,
        verbose
      };

      await pool.query(
        `INSERT INTO threat_intel_provider_configs (provider, enabled, ttl_hours, timeout_ms, api_key, config, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6::jsonb, NOW())
         ON CONFLICT (provider) DO UPDATE SET
           enabled = $2,
           ttl_hours = $3,
           timeout_ms = $4,
           api_key = COALESCE(NULLIF($5, ''), threat_intel_provider_configs.api_key),
           config = $6::jsonb,
           updated_at = NOW()`,
        [ABUSEIPDB_PROVIDER, enabled, ttlHours, timeoutMs, apiKey, JSON.stringify(config)]
      );

      await auditProviderConfigUpdate(audit, req, {
        provider: ABUSEIPDB_PROVIDER,
        displayName: 'AbuseIPDB',
        previousEnabled: existing.enabled,
        newEnabled: enabled,
        after: {
          cache_ttl_hours: ttlHours,
          timeout_ms: timeoutMs,
          max_age_days: maxAgeDays,
          verbose,
          api_key_updated: Boolean(apiKey)
        },
        metadata: { reason: reasonCheck.reason }
      });

      const cfg = await getAbuseIpdbConfig(pool);
      return res.json({
        ok: true,
        provider_key: cfg.provider_key,
        display_name: cfg.display_name,
        enabled: cfg.enabled,
        configured: cfg.configured,
        api_key_masked: cfg.api_key_masked,
        cache_ttl_hours: cfg.cache_ttl_hours,
        timeout_ms: cfg.timeout_ms,
        max_age_days: cfg.max_age_days,
        verbose: cfg.verbose
      });
    } catch {
      return res.status(500).json({ message: 'Failed to update AbuseIPDB config' });
    }
  });

  app.post('/api/admin/enrichment-providers/abuseipdb/test', requireRole(ROLES.ADMIN), async (req, res) => {
    const now = new Date().toISOString();
    const testIp = typeof req.body?.ip === 'string' && req.body.ip.trim()
      ? req.body.ip.trim()
      : TEST_IP;
    try {
      const result = await testAbuseIpdbConnection(pool, testIp);
      await pool.query(
        `UPDATE threat_intel_provider_configs SET last_test_at=$2, last_success_at=$2, last_error_message=NULL, updated_at=NOW() WHERE provider=$1`,
        [ABUSEIPDB_PROVIDER, now]
      );
      return res.json({
        ok: true,
        message: 'Connection successful',
        ip: result.ip,
        abuse_confidence_score: result.abuseConfidenceScore,
        country_code: result.countryCode
      });
    } catch (err) {
      const msg = String(err?.message || 'AbuseIPDB test failed');
      await pool.query(
        `UPDATE threat_intel_provider_configs SET last_test_at=$2, last_error_at=$2, last_error_message=$3, updated_at=NOW() WHERE provider=$1`,
        [ABUSEIPDB_PROVIDER, now, msg.slice(0, 500)]
      ).catch(() => {});
      if (err?.code === 'not_configured') return res.status(400).json({ message: msg });
      if (err?.code === 'disabled') return res.status(409).json({ message: msg });
      if (err?.code === 'unsupported_private_ip' || err?.code === 'invalid_ip') {
        return res.status(422).json({ message: msg });
      }
      if (err?.code === 'auth') return res.status(401).json({ message: msg });
      if (err?.code === 'rate_limit') return res.status(429).json({ message: msg });
      return res.status(502).json({ message: msg });
    }
  });

  app.post('/api/admin/enrichment-providers/abuseipdb/remove-key', requireRole(ROLES.ADMIN), async (req, res) => {
    try {
      await pool.query(
        `UPDATE threat_intel_provider_configs SET api_key=NULL, updated_at=NOW() WHERE provider=$1`,
        [ABUSEIPDB_PROVIDER]
      );
      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.ENRICHMENT_KEY_REMOVED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: ABUSEIPDB_PROVIDER,
        entityDisplay: 'AbuseIPDB',
        severity: AUDIT_SEVERITY.WARNING,
        metadata: { provider: ABUSEIPDB_PROVIDER }
      }).catch(() => {});
      return res.json({ ok: true });
    } catch {
      return res.status(500).json({ message: 'Failed to remove API key' });
    }
  });
}

export { maskApiKey };
