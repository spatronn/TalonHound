import { normalizeAppRole, requireRole, ROLES } from '../lib/rbac.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import { parseActionReason } from '../lib/reasonValidation.js';
import { redactUrlSecrets } from '../lib/auditRedaction.js';
import {
  enrichIocWithUrlscan,
  getUrlscanConfig,
  getUrlscanEnrichmentByIoc,
  rowToApiPayload,
  testUrlscanConnection,
  maskApiKey,
  URLSCAN_PROVIDER,
  URLSCAN_DISPLAY_NAME
} from '../services/urlscanService.js';
import {
  URLSCAN_ASSESSMENT,
  URLSCAN_UNSUPPORTED_TYPE_MESSAGE,
  isSupportedUrlscanIocType,
  clampLookbackDays,
  clampSearchSize,
  clampDetailLimit
} from '../lib/urlscanEnrichment.js';
import { providerDisabledOutcome, registerEnrichmentExecutor } from '../lib/enrichmentProviderRegistry.js';
import { noteProviderRateLimited } from '../lib/enrichmentProviderGuard.js';
import { auditProviderConfigUpdate } from '../lib/enrichmentProviderConfigAudit.js';
import { recordEnrichmentUsage } from '../lib/enrichmentUsageTelemetry.js';
import { recordHealthProbeResult, classifyProbeError } from '../lib/enrichmentProviderHealthCheck.js';

/**
 * Standard refusal for an IOC whose stored observable type urlscan.io does not
 * apply to (anything but domain/url). Same 422 shape as the other providers'
 * unsupported-target responses; no provider call is made.
 */
function unsupportedTypeOutcome() {
  return {
    status: 422,
    body: {
      error: 'IOC type not supported for urlscan enrichment',
      message: URLSCAN_UNSUPPORTED_TYPE_MESSAGE,
      provider: URLSCAN_PROVIDER,
      provider_status: 'unsupported',
      status: 'unsupported'
    }
  };
}

/** The IOC's canonical observable type from the DB — never a client-supplied type. */
async function loadIocForUrlscan(pool, id) {
  const itemRes = await pool.query(
    `SELECT id, observable AS ioc_value, lower(observable_type) AS ioc_type
     FROM ioc_items WHERE id = $1 LIMIT 1`,
    [id]
  );
  return itemRes.rows[0] || null;
}

/**
 * Canonical urlscan refresh — shared by IOC Details and MCP enrichment executor.
 */
export async function runUrlscanRefresh(pool, audit, req, { iocId, force = false } = {}) {
  const role = normalizeAppRole(req.user?.role) || ROLES.ADMIN;
  const id = Number(iocId);
  if (!Number.isFinite(id) || id <= 0) {
    return { status: 400, body: { error: 'Invalid IOC id', message: 'Invalid IOC id', provider: URLSCAN_PROVIDER } };
  }

  if (force && role !== ROLES.ADMIN) {
    return {
      status: 403,
      body: {
        error: 'Force refresh requires admin role',
        message: 'Force refresh requires admin role',
        provider: URLSCAN_PROVIDER
      }
    };
  }

  try {
    const disabled = await providerDisabledOutcome(pool, URLSCAN_PROVIDER);
    if (disabled) return disabled;

    const item = await loadIocForUrlscan(pool, id);
    if (!item) {
      return { status: 404, body: { message: 'IOC not found', provider: URLSCAN_PROVIDER } };
    }
    const category = isSupportedUrlscanIocType(item.ioc_type);
    if (!category) return unsupportedTypeOutcome();

    const startedAt = Date.now();
    const result = await enrichIocWithUrlscan(pool, {
      iocId: id,
      iocValue: item.ioc_value,
      iocType: category,
      force
    });
    const external = result.cached !== true && !result.skipped;

    if (result.skipped && result.provider_status === 'not_configured') {
      return {
        status: 409,
        body: {
          error: 'urlscan.io API key is not configured',
          message: 'urlscan.io API key is not configured',
          provider: URLSCAN_PROVIDER,
          provider_status: 'not_configured',
          status: 'not_configured'
        }
      };
    }
    if (result.skipped && result.provider_status === 'disabled') {
      return {
        status: 409,
        body: {
          error: 'urlscan.io provider is disabled',
          message: 'urlscan.io provider is disabled',
          provider: URLSCAN_PROVIDER,
          provider_status: 'disabled',
          status: 'disabled'
        }
      };
    }
    if (result.skipped && result.provider_status === 'unsupported') return unsupportedTypeOutcome();

    if (!result.cached || force) {
      const auditValue = category === 'url'
        ? redactUrlSecrets(item.ioc_value)
        : item.ioc_value;
      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.URLSCAN_ENRICHMENT_REFRESH,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: String(id),
        entityDisplay: auditValue,
        subjectIocId: id,
        subjectIocType: category,
        subjectIocValue: auditValue,
        targetType: category,
        targetValue: auditValue,
        severity: AUDIT_SEVERITY.INFO,
        metadata: {
          provider: URLSCAN_PROVIDER,
          observable_type: category,
          observable_value: auditValue,
          ioc_id: id,
          cache_bypass: force || !result.cached,
          cached: result.cached === true,
          force,
          provider_status: result.provider_status,
          evidence_assessment: result.assessment,
          privacy_restricted: result.assessment === URLSCAN_ASSESSMENT.PRIVACY_RESTRICTED
        }
      }).catch(() => {});
    }

    const payload = rowToApiPayload(result.row, {
      cached: result.cached === true,
      iocId: id,
      message: result.row?.error_message || null
    });

    if (result.provider_status === 'rate_limited') {
      noteProviderRateLimited(URLSCAN_PROVIDER, result.error?.retryAfter);
      recordEnrichmentUsage(pool, {
        provider: URLSCAN_PROVIDER,
        iocType: category,
        outcome: 'failure',
        external,
        rateLimited: true,
        responseTimeMs: external ? Date.now() - startedAt : null
      });
      return {
        status: 429,
        body: {
          ...payload,
          error: result.row?.error_message || 'urlscan.io rate limit reached',
          message: result.row?.error_message || 'urlscan.io rate limit reached',
          retry_after: result.error?.retryAfter || null
        }
      };
    }

    if (result.provider_status === 'error' || result.provider_status === 'auth_error') {
      recordEnrichmentUsage(pool, {
        provider: URLSCAN_PROVIDER,
        iocType: category,
        outcome: 'failure',
        external,
        responseTimeMs: external ? Date.now() - startedAt : null
      });
      const httpStatus = result.provider_status === 'auth_error' ? 401 : 502;
      return {
        status: httpStatus,
        body: {
          ...payload,
          error: result.row?.error_message || 'urlscan.io enrichment failed',
          message: result.row?.error_message || 'urlscan.io enrichment failed'
        }
      };
    }

    recordEnrichmentUsage(pool, {
      provider: URLSCAN_PROVIDER,
      iocType: category,
      outcome: 'success',
      external,
      cacheHit: !external,
      responseTimeMs: external ? Date.now() - startedAt : null
    });

    return { status: 200, body: payload };
  } catch (err) {
    console.error('[urlscan-enrichment] refresh failed', err?.code || err?.message || err);
    if (err?.code === 'invalid_url' || err?.code === 'invalid_domain') {
      return {
        status: 400,
        body: {
          error: err.message,
          message: err.message,
          provider: URLSCAN_PROVIDER,
          provider_status: 'unsupported'
        }
      };
    }
    if (err?.code === 'auth') {
      recordEnrichmentUsage(pool, { provider: URLSCAN_PROVIDER, iocType: 'url', outcome: 'failure', external: true });
      return {
        status: 401,
        body: {
          error: err.message,
          message: err.message,
          provider: URLSCAN_PROVIDER,
          provider_status: 'auth_error'
        }
      };
    }
    if (err?.code === 'rate_limit') {
      recordEnrichmentUsage(pool, {
        provider: URLSCAN_PROVIDER,
        iocType: 'url',
        outcome: 'failure',
        external: true,
        rateLimited: true
      });
      noteProviderRateLimited(URLSCAN_PROVIDER, err.retryAfter);
      return {
        status: 429,
        body: {
          error: err.message,
          message: err.message,
          provider: URLSCAN_PROVIDER,
          provider_status: 'rate_limited',
          retry_after: err.retryAfter || null
        }
      };
    }
    recordEnrichmentUsage(pool, { provider: URLSCAN_PROVIDER, iocType: 'url', outcome: 'failure', external: true });
    return {
      status: 500,
      body: {
        error: 'urlscan.io enrichment failed',
        message: 'urlscan.io enrichment failed',
        provider: URLSCAN_PROVIDER
      }
    };
  }
}

export function registerUrlscanEnrichmentRoutes(app, pool, audit) {
  registerEnrichmentExecutor(URLSCAN_PROVIDER, (ctx) => runUrlscanRefresh(
    ctx.pool || pool,
    ctx.audit || audit,
    ctx.req,
    { iocId: ctx.ioc?.id, force: ctx.force === true }
  ));

  app.get('/api/ioc/:id/enrichments/urlscan', async (req, res) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isFinite(id) || id <= 0) {
        return res.status(400).json({ message: 'Invalid IOC id', provider: URLSCAN_PROVIDER });
      }
      // Stored rows for a non-applicable type (e.g. IP rows written before urlscan
      // was limited to domain/url) are never served.
      const item = await loadIocForUrlscan(pool, id);
      if (!item) {
        return res.status(404).json({ message: 'IOC not found', provider: URLSCAN_PROVIDER });
      }
      if (!isSupportedUrlscanIocType(item.ioc_type)) {
        const out = unsupportedTypeOutcome();
        return res.status(out.status).json(out.body);
      }
      const config = await getUrlscanConfig(pool);
      if (!config.configured) {
        return res.json(rowToApiPayload(null, {
          iocId: id,
          providerStatus: 'not_configured',
          message: 'urlscan.io API key is not configured'
        }));
      }
      if (!config.enabled) {
        return res.json(rowToApiPayload(null, {
          iocId: id,
          providerStatus: 'disabled',
          message: 'urlscan.io provider is disabled'
        }));
      }
      const row = await getUrlscanEnrichmentByIoc(pool, id);
      if (!row) {
        return res.json(rowToApiPayload(null, { iocId: id }));
      }
      return res.json(rowToApiPayload(row, { cached: true, iocId: id }));
    } catch (err) {
      console.error('[urlscan-enrichment] GET failed', err?.message || err);
      return res.status(500).json({
        message: 'Failed to load urlscan enrichment',
        provider: URLSCAN_PROVIDER
      });
    }
  });

  app.post('/api/ioc/:id/enrichments/urlscan/refresh', async (req, res) => {
    const force = String(req.query?.force || '').toLowerCase() === 'true'
      || req.body?.force === true;
    const out = await runUrlscanRefresh(pool, audit, req, { iocId: req.params.id, force });
    return res.status(out.status).json(out.body);
  });

  app.get('/api/admin/enrichment-providers/urlscan', requireRole(ROLES.ADMIN), async (req, res) => {
    try {
      const cfg = await getUrlscanConfig(pool);
      return res.json({
        provider_key: cfg.provider_key,
        display_name: cfg.display_name,
        enabled: cfg.enabled,
        configured: cfg.configured,
        api_key_masked: cfg.api_key_masked,
        cache_ttl_hours: cfg.cache_ttl_hours,
        timeout_ms: cfg.timeout_ms,
        lookback_days: cfg.lookback_days,
        search_size: cfg.search_size,
        detail_limit: cfg.detail_limit,
        no_result_ttl_hours: cfg.no_result_ttl_hours,
        source: cfg.source,
        last_test_at: cfg.last_test_at,
        last_success_at: cfg.last_success_at,
        last_error_at: cfg.last_error_at,
        last_error_message: cfg.last_error_message,
        read_only: true,
        scan_submission_enabled: false
      });
    } catch {
      return res.status(500).json({ message: 'Failed to load urlscan.io config' });
    }
  });

  app.put('/api/admin/enrichment-providers/urlscan', requireRole(ROLES.ADMIN), async (req, res) => {
    const reasonCheck = parseActionReason(req.body);
    if (!reasonCheck.ok) {
      return res.status(400).json({ message: reasonCheck.message });
    }
    try {
      const enabled = req.body?.enabled === true;
      const apiKey = typeof req.body?.api_key === 'string' ? req.body.api_key.trim() : undefined;
      const ttlHours = Math.max(1, Number(req.body?.cache_ttl_hours ?? req.body?.ttl_hours ?? 24));
      const timeoutMs = Math.max(3000, Number(req.body?.timeout_ms ?? 12000));
      const lookbackDays = clampLookbackDays(req.body?.lookback_days ?? 30);
      const searchSize = clampSearchSize(req.body?.search_size ?? 20);
      const detailLimit = clampDetailLimit(req.body?.detail_limit ?? 3);
      const noResultTtl = Math.min(48, Math.max(1, Number(req.body?.no_result_ttl_hours ?? 6)));

      const existing = await getUrlscanConfig(pool);
      const config = {
        lookback_days: lookbackDays,
        search_size: searchSize,
        detail_limit: detailLimit,
        no_result_ttl_hours: noResultTtl,
        read_only: true,
        scan_submission_enabled: false
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
        [URLSCAN_PROVIDER, enabled, ttlHours, timeoutMs, apiKey, JSON.stringify(config)]
      );

      await auditProviderConfigUpdate(audit, req, {
        provider: URLSCAN_PROVIDER,
        displayName: URLSCAN_DISPLAY_NAME,
        previousEnabled: existing.enabled,
        newEnabled: enabled,
        after: {
          cache_ttl_hours: ttlHours,
          timeout_ms: timeoutMs,
          lookback_days: lookbackDays,
          search_size: searchSize,
          detail_limit: detailLimit,
          no_result_ttl_hours: noResultTtl,
          api_key_updated: Boolean(apiKey),
          read_only: true
        },
        metadata: { reason: reasonCheck.reason }
      });

      const cfg = await getUrlscanConfig(pool);
      return res.json({
        ok: true,
        provider_key: cfg.provider_key,
        display_name: cfg.display_name,
        enabled: cfg.enabled,
        configured: cfg.configured,
        api_key_masked: cfg.api_key_masked,
        cache_ttl_hours: cfg.cache_ttl_hours,
        timeout_ms: cfg.timeout_ms,
        lookback_days: cfg.lookback_days,
        search_size: cfg.search_size,
        detail_limit: cfg.detail_limit,
        no_result_ttl_hours: cfg.no_result_ttl_hours,
        read_only: true,
        scan_submission_enabled: false
      });
    } catch {
      return res.status(500).json({ message: 'Failed to update urlscan.io config' });
    }
  });

  app.post('/api/admin/enrichment-providers/urlscan/test', requireRole(ROLES.ADMIN), async (req, res) => {
    try {
      const result = await testUrlscanConnection(pool);
      await recordHealthProbeResult(pool, {
        provider: URLSCAN_PROVIDER,
        source: 'manual',
        outcome: 'success',
        evidence: 'Manual connection test succeeded (quotas + search)'
      }).catch(() => {});
      return res.json({
        ok: true,
        message: 'Connection successful',
        quotas: result.quotas,
        search_total: result.search_total,
        read_only: true
      });
    } catch (err) {
      const msg = String(err?.message || 'urlscan.io test failed');
      if (err?.code !== 'not_configured' && err?.code !== 'disabled') {
        const { category, evidence } = classifyProbeError(err);
        if (category !== 'not_configured') {
          await recordHealthProbeResult(pool, {
            provider: URLSCAN_PROVIDER,
            source: 'manual',
            outcome: 'failure',
            category,
            evidence
          }).catch(() => {});
        }
      }
      if (err?.code === 'not_configured') return res.status(400).json({ message: msg });
      if (err?.code === 'disabled') return res.status(409).json({ message: msg });
      if (err?.code === 'auth') return res.status(401).json({ message: msg });
      if (err?.code === 'rate_limit') return res.status(429).json({ message: msg });
      return res.status(502).json({ message: msg });
    }
  });

  app.post('/api/admin/enrichment-providers/urlscan/remove-key', requireRole(ROLES.ADMIN), async (req, res) => {
    try {
      await pool.query(
        `UPDATE threat_intel_provider_configs SET api_key = NULL, updated_at = NOW() WHERE provider = $1`,
        [URLSCAN_PROVIDER]
      );
      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.ENRICHMENT_KEY_REMOVED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: URLSCAN_PROVIDER,
        entityDisplay: URLSCAN_DISPLAY_NAME,
        severity: AUDIT_SEVERITY.WARNING,
        metadata: { provider: URLSCAN_PROVIDER }
      }).catch(() => {});
      return res.json({ ok: true });
    } catch {
      return res.status(500).json({ message: 'Failed to remove API key' });
    }
  });
}

export { maskApiKey };
