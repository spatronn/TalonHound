import { parseDomainOrUrlInput, isRdapSupportedIocType } from '../lib/domainRoot.js';
import { normalizeAppRole, ROLES } from '../lib/rbac.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import {
  getEnrichmentByRootDomain,
  refreshRdapEnrichment,
  rowToApiPayload
} from '../services/rdapEnrichmentService.js';

function decodeRouteValue(raw) {
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
export function registerRdapEnrichmentRoutes(app, pool, audit) {
  app.get('/api/enrichment/rdap/:value', async (req, res) => {
    try {
      const value = decodeRouteValue(req.params.value);
      const hintType = String(req.query?.ioc_type || req.query?.type || '').trim() || null;
      const parsed = parseDomainOrUrlInput(value, hintType);
      if (!parsed.ok) {
        const status = parsed.code === 'unsupported' ? 400 : 400;
        return res.status(status).json({ message: parsed.message, code: parsed.code });
      }

      if (hintType && !isRdapSupportedIocType(hintType)) {
        return res.status(400).json({ message: 'IOC type is not supported for RDAP enrichment', code: 'unsupported' });
      }

      const row = await getEnrichmentByRootDomain(pool, parsed.root_domain);
      if (!row) {
        return res.json(rowToApiPayload(null, {
          enriched: false,
          observableValue: parsed.observable_value,
          rootDomain: parsed.root_domain,
          iocType: parsed.ioc_type
        }));
      }

      const enriched = row.rdap_status === 'success';
      return res.json(rowToApiPayload(row, {
        enriched,
        cached: false,
        observableValue: parsed.observable_value,
        rootDomain: parsed.root_domain,
        iocType: parsed.ioc_type
      }));
    } catch (err) {
      console.error('[rdap-enrichment] GET failed', err?.message || err);
      return res.status(500).json({ message: 'Failed to load RDAP enrichment' });
    }
  });

  app.post('/api/enrichment/rdap/:value/refresh', async (req, res) => {
    const value = decodeRouteValue(req.params.value);
    const hintType = String(req.query?.ioc_type || req.query?.type || '').trim() || null;
    const force = String(req.query?.force || '').toLowerCase() === 'true';

    const role = normalizeAppRole(req.user?.role) || ROLES.ADMIN;
    if (force && role !== ROLES.ADMIN) {
      return res.status(403).json({ message: 'Force refresh requires admin role' });
    }

    const parsed = parseDomainOrUrlInput(value, hintType);
    if (!parsed.ok) {
      return res.status(400).json({ message: parsed.message, code: parsed.code });
    }

    if (hintType && !isRdapSupportedIocType(hintType)) {
      return res.status(400).json({ message: 'IOC type is not supported for RDAP enrichment', code: 'unsupported' });
    }

    try {
      audit.auditSuccess({
        req,
        action: AUDIT_ACTION.RDAP_ENRICHMENT_REQUESTED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: parsed.root_domain,
        entityDisplay: parsed.root_domain,
        severity: AUDIT_SEVERITY.INFO,
        metadata: {
          root_domain: parsed.root_domain,
          observable_value: parsed.observable_value,
          force,
          source_page: 'ioc_detail_intelligence'
        }
      }).catch(() => {});

      const result = await refreshRdapEnrichment(pool, parsed, { force });
      const row = result.row;
      const payload = rowToApiPayload(row, {
        enriched: row.rdap_status === 'success',
        cached: result.cached,
        observableValue: parsed.observable_value,
        rootDomain: parsed.root_domain,
        iocType: parsed.ioc_type
      });

      if (row.rdap_status === 'success') {
        audit.auditSuccess({
          req,
          action: AUDIT_ACTION.RDAP_ENRICHMENT_COMPLETED,
          entityType: AUDIT_ENTITY.ENRICHMENT,
          entityId: parsed.root_domain,
          entityDisplay: parsed.root_domain,
          severity: AUDIT_SEVERITY.INFO,
          metadata: {
            root_domain: parsed.root_domain,
            cached: result.cached,
            force,
            from_lookup: result.fromLookup
          }
        }).catch(() => {});
        return res.json(payload);
      }

      audit.auditFailure({
        req,
        action: AUDIT_ACTION.RDAP_ENRICHMENT_FAILED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: parsed.root_domain,
        entityDisplay: parsed.root_domain,
        severity: AUDIT_SEVERITY.WARNING,
        metadata: {
          root_domain: parsed.root_domain,
          cached: result.cached,
          error_message: row.error_message
        }
      }).catch(() => {});

      return res.status(502).json({
        ...payload,
        message: row.error_message || 'RDAP lookup failed'
      });
    } catch (err) {
      console.error('[rdap-enrichment] POST failed', err?.message || err);
      if (err?.code === 'rate_limit') {
        return res.status(429).json({
          message: err.message || 'RDAP rate limit reached',
          retry_after: err.retryAfter || null
        });
      }
      audit.auditFailure({
        req,
        action: AUDIT_ACTION.RDAP_ENRICHMENT_FAILED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: parsed.root_domain,
        entityDisplay: parsed.root_domain,
        severity: AUDIT_SEVERITY.WARNING,
        metadata: { error_message: String(err?.message || err) }
      }).catch(() => {});
      return res.status(500).json({ message: 'RDAP enrichment failed' });
    }
  });
}
