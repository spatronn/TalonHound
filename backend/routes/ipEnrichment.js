import { normalizeAppRole, ROLES } from '../lib/rbac.js';
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
  testIpinfoLiteConnection,
  maskToken
} from '../services/ipinfoLiteService.js';
import { parseActionReason } from '../lib/reasonValidation.js';

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
      const results = await enrichIpsWithIpinfoLite(pool, requestedIps, { force });
      const summary = bulkSummary(results);
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
      if (!force) {
        const existing = await getEnrichmentByIp(pool, publicIp);
        if (existing?.provider_status === 'success') {
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
      if (!cfg.enabled) {
        return res.status(409).json({
          error: 'IPinfo Lite provider is disabled',
          message: 'IPinfo Lite provider is disabled'
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

      const result = await enrichIpWithIpinfoLite(pool, publicIp, { force });
      const payload = rowToApiPayload(result.row, {
        enriched: result.row?.provider_status === 'success',
        cached: result.cached
      });

      if (result.row?.provider_status === 'success' && !result.error) {
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
        return res.status(401).json({ error: err.message, message: err.message });
      }
      if (err?.code === 'rate_limit') {
        return res.status(429).json({
          error: err.message,
          message: err.message,
          retry_after: err.retryAfter || null
        });
      }
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
    const reasonCheck = parseActionReason(req.body);
    if (!reasonCheck.ok) {
      return res.status(400).json({ message: reasonCheck.message });
    }
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
        metadata: { provider: IPINFO_PROVIDER, reason: reasonCheck.reason }
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
