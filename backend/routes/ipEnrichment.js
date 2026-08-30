import { normalizeAppRole, requireRole, ROLES } from '../lib/rbac.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import { validatePublicIp } from '../lib/publicIp.js';
import { buildEnrichmentAuditScope, resolveSubjectIocFromRequest } from '../lib/enrichmentAuditScope.js';
import {
  enrichIpWithIpinfoLite,
  enrichIpsWithIpinfoLite,
  getEnrichmentByIp,
  getEnrichmentsByIps,
  getIpinfoLiteConfig,
  MAX_BULK_IPS,
  rowToApiPayload,
  maskToken,
  IPINFO_LITE_TRUSTED_BASE_URL
} from '../services/ipinfoLiteService.js';
import { parseActionReason } from '../lib/reasonValidation.js';
import { guardProviderEnabled } from '../lib/enrichmentProviderRegistry.js';
import { runProviderHealthProbe } from '../lib/enrichmentProviderHealthCheck.js';
import { auditProviderConfigUpdate } from '../lib/enrichmentProviderConfigAudit.js';
import {
  recordEnrichmentUsage,
  writeEnrichmentUsage,
  buildUsageDelta,
  sumUsageDeltas
} from '../lib/enrichmentUsageTelemetry.js';

const IPINFO_PROVIDER = 'ipinfo_lite';

function decodeRouteIp(raw) {
  try {
    return decodeURIComponent(String(raw || '').trim());
  } catch {
    return String(raw || '').trim();
  }
}

function parseBulkIps(value) {
  const values = Array.isArray(value) ? value : String(value || '').split(',');
  return values.map((ip) => String(ip || '').trim()).filter(Boolean);
}

function bulkStateForRow(row) {
  if (!row) return 'not_found';
  if (row.provider_status === 'success') return 'cached';
  if (row.provider_status === 'unavailable') return 'not_found';
  return 'provider_error';
}

function bulkSummary(results) {
  return results.reduce((summary, item) => {
    summary[item.state] = (summary[item.state] || 0) + 1;
    return summary;
  }, { cached: 0, enriched: 0, not_found: 0, provider_error: 0, invalid_ip: 0 });
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {ReturnType<import('../lib/auditLogService.js').createAuditLogService>} audit
 */
export function registerIpEnrichmentRoutes(app, pool, audit) {
  app.get('/api/enrichment/ips', async (req, res) => {
    const requestedIps = parseBulkIps(req.query?.ips);
    if (!requestedIps.length) {
      return res.status(400).json({ error: 'ips is required', message: 'ips is required' });
    }
    if (requestedIps.length > MAX_BULK_IPS) {
      return res.status(400).json({
        error: `A maximum of ${MAX_BULK_IPS} IPs is allowed`,
        message: `A maximum of ${MAX_BULK_IPS} IPs is allowed`
      });
    }

    try {
      const valid = [];
      const invalid = [];
      const seen = new Set();
      for (const requestedIp of requestedIps) {
        const normalizedIp = validatePublicIp(requestedIp);
        if (!normalizedIp) {
          invalid.push({
            requested_ip: requestedIp,
            normalized_ip: null,
            state: 'invalid_ip',
            data: null,
            error: 'Invalid, private, or reserved IP'
          });
        } else if (!seen.has(normalizedIp)) {
          seen.add(normalizedIp);
          valid.push(normalizedIp);
        }
      }

      const byIp = await getEnrichmentsByIps(pool, valid);
      const results = [
        ...invalid,
        ...valid.map((normalizedIp) => {
          const row = byIp.get(normalizedIp) || null;
          return {
            requested_ip: normalizedIp,
            normalized_ip: normalizedIp,
            state: bulkStateForRow(row),
            data: row
              ? rowToApiPayload(row, {
                cached: true,
                enriched: row.provider_status === 'success'
              })
              : null,
            error: row?.error_message || null
          };
        })
      ];
      return res.json({
        provider: IPINFO_PROVIDER,
        results,
        summary: bulkSummary(results)
      });
    } catch (err) {
      console.error('[ip-enrichment] bulk GET failed', err?.message || err);
      return res.status(500).json({ error: 'Failed to load IP enrichments', message: 'Failed to load IP enrichments' });
    }
  });

  app.post('/api/enrichment/ips/enrich', async (req, res) => {
    const requestedIps = parseBulkIps(req.body?.ips);
    const force = req.body?.force === true;
    const role = normalizeAppRole(req.user?.role) || ROLES.ADMIN;
    if (!requestedIps.length) {
      return res.status(400).json({ error: 'ips is required', message: 'ips is required' });
    }
    if (requestedIps.length > MAX_BULK_IPS) {
      return res.status(400).json({
        error: `A maximum of ${MAX_BULK_IPS} IPs is allowed`,
        message: `A maximum of ${MAX_BULK_IPS} IPs is allowed`
      });
    }
    if (force && role !== ROLES.ADMIN) {
      return res.status(403).json({ error: 'Force refresh requires admin role', message: 'Force refresh requires admin role' });
    }

    const normalizedTargets = [...new Set(requestedIps.map((ip) => validatePublicIp(ip)).filter(Boolean))];
    const subject = await resolveSubjectIocFromRequest(pool, req);
    const subjectValue = subject?.observable || req.body?.value || normalizedTargets[0] || null;
    const targetValue = normalizedTargets.join(',').slice(0, 2000);
    const requestedScope = buildEnrichmentAuditScope({
      subject,
      subjectIocValue: subjectValue,
      subjectIocType: subject?.observable_type || req.body?.ioc_type || null,
      targetType: normalizedTargets.length === 1 ? 'ip' : 'ip_batch',
      targetValue,
      provider: IPINFO_PROVIDER,
      extraMetadata: {
        ips: normalizedTargets,
        count: normalizedTargets.length,
        force,
        source_page: 'ioc_detail_intelligence'
      }
    });

    try {
      // Central disable guard: block bulk enrichment for a disabled provider
      // before any external call or audit write.
      if (!(await guardProviderEnabled(pool, IPINFO_PROVIDER, res))) return;

      const results = await enrichIpsWithIpinfoLite(pool, requestedIps, { force });
      const summary = bulkSummary(results);

      // Usage telemetry: fold the bulk outcome into one atomic upsert. invalid_ip is
      // never a provider request; cached => cache hit; enriched/not_found => successful
      // external calls; provider_error => failed external calls. Per-item latency is
      // not available for the bulk path, so no provider-latency is recorded here.
      writeEnrichmentUsage(pool, {
        provider: IPINFO_PROVIDER,
        iocType: 'ip',
        delta: sumUsageDeltas([
          buildUsageDelta({ outcome: 'success', cacheHit: true, count: summary.cached }),
          buildUsageDelta({ outcome: 'success', external: true, count: summary.enriched }),
          buildUsageDelta({ outcome: 'success', external: true, count: summary.not_found }),
          buildUsageDelta({ outcome: 'failure', external: true, count: summary.provider_error })
        ])
      });

      const attempted = results.some((item) => item.state !== 'cached' && item.state !== 'invalid_ip');
      if (!attempted) {
        return res.json({ provider: IPINFO_PROVIDER, results, summary });
      }
      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.IP_ENRICHMENT_REQUESTED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: requestedScope.entityId,
        entityDisplay: requestedScope.entityDisplay,
        subjectIocId: requestedScope.subjectIocId,
        subjectIocType: requestedScope.subjectIocType,
        subjectIocValue: requestedScope.subjectIocValue,
        targetType: requestedScope.targetType,
        targetValue: requestedScope.targetValue,
        severity: AUDIT_SEVERITY.INFO,
        metadata: requestedScope.metadata
      }).catch(() => {});

      const hasSuccess = summary.enriched > 0 || summary.not_found > 0;
      const hasFailure = summary.provider_error > 0;
      const auditArgs = {
        req,
        action: hasSuccess ? AUDIT_ACTION.IP_ENRICHMENT_COMPLETED : AUDIT_ACTION.IP_ENRICHMENT_FAILED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: requestedScope.entityId,
        entityDisplay: requestedScope.entityDisplay,
        subjectIocId: requestedScope.subjectIocId,
        subjectIocType: requestedScope.subjectIocType,
        subjectIocValue: requestedScope.subjectIocValue,
        targetType: requestedScope.targetType,
        targetValue: requestedScope.targetValue,
        severity: hasFailure ? AUDIT_SEVERITY.WARNING : AUDIT_SEVERITY.INFO,
        metadata: { ...requestedScope.metadata, summary, success: !hasFailure }
      };
      if (hasSuccess) await audit.auditSuccess(auditArgs).catch(() => {});
      else await audit.auditFailure(auditArgs).catch(() => {});
      return res.json({ provider: IPINFO_PROVIDER, results, summary });
    } catch (err) {
      const message = String(err?.message || 'IP enrichment failed');
      await audit.auditFailure({
        req,
        action: AUDIT_ACTION.IP_ENRICHMENT_FAILED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: requestedScope.entityId,
        entityDisplay: requestedScope.entityDisplay,
        subjectIocId: requestedScope.subjectIocId,
        subjectIocType: requestedScope.subjectIocType,
        subjectIocValue: requestedScope.subjectIocValue,
        targetType: requestedScope.targetType,
        targetValue: requestedScope.targetValue,
        severity: AUDIT_SEVERITY.WARNING,
        metadata: { ...requestedScope.metadata, error_message: message, success: false }
      }).catch(() => {});
      return res.status(500).json({ error: 'IP enrichment failed', message: 'IP enrichment failed' });
    }
  });

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
      return res.json(rowToApiPayload(row, { enriched: row.provider_status === 'success', cached: true }));
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
      // Central disable guard first: a disabled provider blocks refresh entirely,
      // even when a cached row exists, without any external call.
      if (!(await guardProviderEnabled(pool, IPINFO_PROVIDER, res))) return;

      if (!force) {
        const existing = await getEnrichmentByIp(pool, publicIp);
        if (existing?.provider_status === 'success') {
          // Served from cache — a logical request with no external provider call.
          recordEnrichmentUsage(pool, { provider: IPINFO_PROVIDER, iocType: 'ip', outcome: 'success', cacheHit: true });
          return res.json(rowToApiPayload(existing, { enriched: true, cached: true }));
        }
      }

      const cfg = await getIpinfoLiteConfig(pool);
      if (!cfg.configured) {
        return res.status(409).json({
          error: 'IPinfo Lite provider is not configured',
          message: 'IPinfo Lite provider is not configured'
        });
      }

      const subject = await resolveSubjectIocFromRequest(pool, req);
      const requestedScope = buildEnrichmentAuditScope({
        subject,
        subjectIocValue: subject?.observable || req.body?.value || publicIp,
        subjectIocType: subject?.observable_type || req.body?.ioc_type || null,
        targetType: 'ip',
        targetValue: publicIp,
        provider: IPINFO_PROVIDER,
        extraMetadata: {
          ip: publicIp,
          original_value: subject?.observable || req.body?.value || publicIp,
          observable_value: subject?.observable || req.body?.value || publicIp,
          force,
          cached: false
        }
      });

      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.IP_ENRICHMENT_REQUESTED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: requestedScope.entityId,
        entityDisplay: requestedScope.entityDisplay,
        subjectIocId: requestedScope.subjectIocId,
        subjectIocType: requestedScope.subjectIocType,
        subjectIocValue: requestedScope.subjectIocValue,
        targetType: requestedScope.targetType,
        targetValue: requestedScope.targetValue,
        severity: AUDIT_SEVERITY.INFO,
        metadata: requestedScope.metadata
      }).catch(() => {});

      const ipStartedAt = Date.now();
      const result = await enrichIpWithIpinfoLite(pool, publicIp, { force });
      const ipExternal = result.cached !== true;
      const payload = rowToApiPayload(result.row, {
        enriched: result.row?.provider_status === 'success',
        cached: result.cached
      });

      if (result.row?.provider_status === 'success' && !result.error) {
        // success — external call unless the service short-circuited to cache.
        recordEnrichmentUsage(pool, {
          provider: IPINFO_PROVIDER,
          iocType: 'ip',
          outcome: 'success',
          external: ipExternal,
          cacheHit: !ipExternal,
          responseTimeMs: ipExternal ? Date.now() - ipStartedAt : null
        });
        const completedScope = buildEnrichmentAuditScope({
          subject,
          subjectIocValue: subject?.observable || req.body?.value || publicIp,
          subjectIocType: subject?.observable_type || req.body?.ioc_type || null,
          targetType: 'ip',
          targetValue: publicIp,
          provider: IPINFO_PROVIDER,
          extraMetadata: {
            ip: publicIp,
            original_value: subject?.observable || req.body?.value || publicIp,
            observable_value: subject?.observable || req.body?.value || publicIp,
            cached: result.cached,
            force,
            status: result.row.provider_status
          }
        });
        await audit.auditSuccess({
          req,
          action: AUDIT_ACTION.IP_ENRICHMENT_COMPLETED,
          entityType: AUDIT_ENTITY.ENRICHMENT,
          entityId: completedScope.entityId,
          entityDisplay: completedScope.entityDisplay,
          subjectIocId: completedScope.subjectIocId,
          subjectIocType: completedScope.subjectIocType,
          subjectIocValue: completedScope.subjectIocValue,
          targetType: completedScope.targetType,
          targetValue: completedScope.targetValue,
          severity: AUDIT_SEVERITY.INFO,
          metadata: completedScope.metadata
        }).catch(() => {});
        return res.json(payload);
      }

      const failedScope = buildEnrichmentAuditScope({
        subject,
        subjectIocValue: subject?.observable || req.body?.value || publicIp,
        subjectIocType: subject?.observable_type || req.body?.ioc_type || null,
        targetType: 'ip',
        targetValue: publicIp,
        provider: IPINFO_PROVIDER,
        extraMetadata: {
          ip: publicIp,
          original_value: subject?.observable || req.body?.value || publicIp,
          observable_value: subject?.observable || req.body?.value || publicIp,
          cached: result.cached,
          force,
          status: result.row?.provider_status,
          error_message: result.error_message || result.row?.error_message
        }
      });
      await audit.auditFailure({
        req,
        action: AUDIT_ACTION.IP_ENRICHMENT_FAILED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: failedScope.entityId,
        entityDisplay: failedScope.entityDisplay,
        subjectIocId: failedScope.subjectIocId,
        subjectIocType: failedScope.subjectIocType,
        subjectIocValue: failedScope.subjectIocValue,
        targetType: failedScope.targetType,
        targetValue: failedScope.targetValue,
        severity: AUDIT_SEVERITY.WARNING,
        metadata: failedScope.metadata
      }).catch(() => {});

      // 'unavailable' is a completed lookup with no dataset match (not an error);
      // anything else here is a failed external attempt.
      const ipUnavailable = result.row?.provider_status === 'unavailable';
      recordEnrichmentUsage(pool, {
        provider: IPINFO_PROVIDER,
        iocType: 'ip',
        outcome: ipUnavailable ? 'success' : 'failure',
        external: ipExternal,
        cacheHit: !ipExternal,
        responseTimeMs: ipExternal ? Date.now() - ipStartedAt : null
      });

      return res.status(result.row?.provider_status === 'unavailable' ? 404 : 502).json({
        ...payload,
        state: result.state || 'provider_error',
        refresh_error: Boolean(result.error),
        error: result.error_message || result.row?.error_message || 'IP enrichment failed',
        message: result.error_message || result.row?.error_message || 'IP enrichment failed'
      });
    } catch (err) {
      console.error('[ip-enrichment] POST refresh failed', err?.message || err);
      if (err?.code === 'not_configured') {
        return res.status(409).json({ error: err.message, message: err.message });
      }
      if (err?.code === 'auth') {
        recordEnrichmentUsage(pool, { provider: IPINFO_PROVIDER, iocType: 'ip', outcome: 'failure', external: true });
        return res.status(401).json({ error: err.message, message: err.message });
      }
      if (err?.code === 'rate_limit') {
        recordEnrichmentUsage(pool, { provider: IPINFO_PROVIDER, iocType: 'ip', outcome: 'failure', external: true, rateLimited: true });
        return res.status(429).json({
          error: err.message,
          message: err.message,
          retry_after: err.retryAfter || null
        });
      }
      recordEnrichmentUsage(pool, { provider: IPINFO_PROVIDER, iocType: 'ip', outcome: 'failure', external: true });
      const subject = await resolveSubjectIocFromRequest(pool, req).catch(() => null);
      const failedScope = buildEnrichmentAuditScope({
        subject,
        subjectIocValue: subject?.observable || req.body?.value || publicIp,
        subjectIocType: subject?.observable_type || req.body?.ioc_type || null,
        targetType: 'ip',
        targetValue: publicIp,
        provider: IPINFO_PROVIDER,
        extraMetadata: { error_message: String(err?.message || err), ip: publicIp, force }
      });
      await audit.auditFailure({
        req,
        action: AUDIT_ACTION.IP_ENRICHMENT_FAILED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: failedScope.entityId,
        entityDisplay: failedScope.entityDisplay,
        subjectIocId: failedScope.subjectIocId,
        subjectIocType: failedScope.subjectIocType,
        subjectIocValue: failedScope.subjectIocValue,
        targetType: failedScope.targetType,
        targetValue: failedScope.targetValue,
        severity: AUDIT_SEVERITY.WARNING,
        metadata: failedScope.metadata
      }).catch(() => {});
      return res.status(500).json({ error: 'IP enrichment failed', message: 'IP enrichment failed' });
    }
  });

  app.get('/api/admin/enrichment-providers/ipinfo-lite', requireRole(ROLES.ADMIN), async (req, res) => {
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

  app.put('/api/admin/enrichment-providers/ipinfo-lite', requireRole(ROLES.ADMIN), async (req, res) => {
    const reasonCheck = parseActionReason(req.body);
    if (!reasonCheck.ok) {
      return res.status(400).json({ message: reasonCheck.message });
    }
    try {
      const enabled = req.body?.enabled !== false;
      const token = typeof req.body?.token === 'string' ? req.body.token.trim() : undefined;
      // base_url is not user-configurable (SSRF-03). Always persist the trusted origin.
      const timeoutSeconds = Number(req.body?.timeout_seconds);
      const usageNote = typeof req.body?.usage_note === 'string' ? req.body.usage_note.trim() : undefined;

      const existing = await getIpinfoLiteConfig(pool);
      const config = {
        base_url: IPINFO_LITE_TRUSTED_BASE_URL,
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

      await auditProviderConfigUpdate(audit, req, {
        provider: IPINFO_PROVIDER,
        displayName: 'IPinfo Lite',
        previousEnabled: existing.enabled,
        newEnabled: enabled,
        after: { base_url: config.base_url, timeout_seconds: config.timeout_seconds, token_updated: Boolean(token) },
        metadata: { reason: reasonCheck.reason }
      });

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

  // Manual "Test Connection" — runs the canonical IPinfo Lite health probe so
  // manual and scheduled checks share one implementation and one health store.
  app.post('/api/admin/enrichment-providers/ipinfo-lite/test', requireRole(ROLES.ADMIN), async (req, res) => {
    const cfg = await getIpinfoLiteConfig(pool).catch(() => ({ configured: false }));
    if (!cfg.configured) return res.status(400).json({ message: 'IPinfo Lite token is not configured' });
    const result = await runProviderHealthProbe(pool, IPINFO_PROVIDER, { source: 'manual' });
    if (result.ok) {
      return res.json({
        ok: true,
        message: 'Connection successful',
        asn: result.detail?.asn,
        as_name: result.detail?.as_name,
        country_code: result.detail?.country_code
      });
    }
    if (result.category === 'auth') return res.status(401).json({ message: 'IPinfo Lite authentication failed' });
    if (result.category === 'rate_limit') return res.status(429).json({ message: 'IPinfo Lite rate limit reached' });
    if (result.category === 'timeout') return res.status(504).json({ message: 'IPinfo Lite test timeout' });
    return res.status(502).json({ message: 'IPinfo Lite test failed' });
  });

  app.post('/api/admin/enrichment-providers/ipinfo-lite/remove-key', requireRole(ROLES.ADMIN), async (req, res) => {
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
