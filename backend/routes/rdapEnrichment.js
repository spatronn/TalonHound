import { normalizeRdapTarget, isRdapSupportedIocType } from '../lib/domainRoot.js';
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

function resolveRequestValue(req) {
  if (req.body?.value != null && String(req.body.value).trim()) {
    return String(req.body.value).trim();
  }
  if (req.query?.value != null && String(req.query.value).trim()) {
    return String(req.query.value).trim();
  }
  if (req.params?.value != null && String(req.params.value).trim()) {
    return decodeRouteValue(req.params.value);
  }
  return '';
}

function validationStatus(code) {
  if (code === 'unsupported') return 422;
  return 400;
}

function sendValidationError(res, parsed) {
  const status = validationStatus(parsed.code);
  return res.status(status).json({
    error: parsed.message,
    message: parsed.message,
    code: parsed.code
  });
}

function targetFields(parsed) {
  return {
    original_value: parsed.original_value,
    normalized_host: parsed.normalized_host,
    rdap_domain: parsed.rdap_domain,
    input_type: parsed.input_type
  };
}

async function handleRdapGet(pool, parsed) {
  const row = await getEnrichmentByRootDomain(pool, parsed.rdap_domain);
  const extra = targetFields(parsed);
  if (!row) {
    return rowToApiPayload(null, {
      enriched: false,
      observableValue: parsed.observable_value,
      rootDomain: parsed.rdap_domain,
      iocType: parsed.ioc_type,
      ...extra
    });
  }
  return rowToApiPayload(row, {
    enriched: row.rdap_status === 'success',
    cached: false,
    observableValue: parsed.observable_value,
    rootDomain: parsed.rdap_domain,
    iocType: parsed.ioc_type,
    ...extra
  });
}

async function handleRdapRefresh(pool, audit, req, parsed, force) {
  await audit.auditSuccess({
    req,
    action: AUDIT_ACTION.RDAP_ENRICHMENT_REQUESTED,
    entityType: AUDIT_ENTITY.ENRICHMENT,
    entityId: parsed.rdap_domain,
    entityDisplay: parsed.rdap_domain,
    severity: AUDIT_SEVERITY.INFO,
    metadata: {
      root_domain: parsed.rdap_domain,
      normalized_host: parsed.normalized_host,
      original_value: parsed.original_value,
      observable_value: parsed.observable_value,
      observable_type: parsed.ioc_type,
      provider: 'rdap',
      force,
      source_page: 'ioc_detail_intelligence'
    }
  }).catch(() => {});

  const result = await refreshRdapEnrichment(pool, parsed, { force });
  const row = result.row;
  const extra = targetFields(parsed);
  const payload = rowToApiPayload(row, {
    enriched: row.rdap_status === 'success',
    cached: result.cached,
    observableValue: parsed.observable_value,
    rootDomain: parsed.rdap_domain,
    iocType: parsed.ioc_type,
    ...extra
  });

  if (row.rdap_status === 'success') {
    await audit.auditSuccess({
      req,
      action: AUDIT_ACTION.RDAP_ENRICHMENT_COMPLETED,
      entityType: AUDIT_ENTITY.ENRICHMENT,
      entityId: parsed.rdap_domain,
      entityDisplay: parsed.rdap_domain,
      severity: AUDIT_SEVERITY.INFO,
      metadata: {
        root_domain: parsed.rdap_domain,
        normalized_host: parsed.normalized_host,
        original_value: parsed.original_value,
        observable_value: parsed.observable_value,
        observable_type: parsed.ioc_type,
        provider: 'rdap',
        cached: result.cached,
        force,
        from_lookup: result.fromLookup
      }
    }).catch(() => {});
    return { status: 200, body: payload };
  }

  await audit.auditFailure({
    req,
    action: AUDIT_ACTION.RDAP_ENRICHMENT_FAILED,
    entityType: AUDIT_ENTITY.ENRICHMENT,
    entityId: parsed.rdap_domain,
    entityDisplay: parsed.rdap_domain,
    severity: AUDIT_SEVERITY.WARNING,
      metadata: {
        root_domain: parsed.rdap_domain,
        original_value: parsed.original_value,
        observable_value: parsed.observable_value,
        observable_type: parsed.ioc_type,
        provider: 'rdap',
        cached: result.cached,
        error_message: row.error_message
      }
  }).catch(() => {});

  return {
    status: 502,
    body: {
      ...payload,
      error: row.error_message || 'RDAP lookup failed',
      message: row.error_message || 'RDAP lookup failed'
    }
  };
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {ReturnType<import('../lib/auditLogService.js').createAuditLogService>} audit
 */
export function registerRdapEnrichmentRoutes(app, pool, audit) {
  /** Safe: query param — no path encoding issues for full URLs */
  app.get('/api/enrichment/rdap', async (req, res) => {
    try {
      const value = resolveRequestValue(req);
      if (!value) {
        return res.status(400).json({ error: 'value query parameter is required', message: 'value query parameter is required' });
      }
      const hintType = String(req.query?.ioc_type || req.query?.type || '').trim() || null;
      const parsed = normalizeRdapTarget(value, hintType);
      if (!parsed.ok) return sendValidationError(res, parsed);
      if (hintType && !isRdapSupportedIocType(hintType)) {
        return res.status(422).json({
          error: 'RDAP enrichment supports domain and URL observables only',
          message: 'RDAP enrichment supports domain and URL observables only',
          code: 'unsupported'
        });
      }
      return res.json(await handleRdapGet(pool, parsed));
    } catch (err) {
      console.error('[rdap-enrichment] GET failed', err?.message || err);
      return res.status(500).json({ error: 'Failed to load RDAP enrichment', message: 'Failed to load RDAP enrichment' });
    }
  });

  /** Safe: JSON body */
  app.post('/api/enrichment/rdap/refresh', async (req, res) => {
    const value = resolveRequestValue(req);
    if (!value) {
      return res.status(400).json({ error: 'value is required in request body', message: 'value is required in request body' });
    }
    const hintType = String(req.query?.ioc_type || req.query?.type || req.body?.ioc_type || '').trim() || null;
    const force = req.body?.force === true
      || String(req.query?.force || '').toLowerCase() === 'true';

    const role = normalizeAppRole(req.user?.role) || ROLES.ADMIN;
    if (force && role !== ROLES.ADMIN) {
      return res.status(403).json({ error: 'Force refresh requires admin role', message: 'Force refresh requires admin role' });
    }

    const parsed = normalizeRdapTarget(value, hintType);
    if (!parsed.ok) return sendValidationError(res, parsed);
    if (hintType && !isRdapSupportedIocType(hintType)) {
      return res.status(422).json({
        error: 'RDAP enrichment supports domain and URL observables only',
        message: 'RDAP enrichment supports domain and URL observables only',
        code: 'unsupported'
      });
    }

    try {
      const out = await handleRdapRefresh(pool, audit, req, parsed, force);
      return res.status(out.status).json(out.body);
    } catch (err) {
      console.error('[rdap-enrichment] POST refresh failed', err?.message || err);
      if (err?.code === 'rate_limit') {
        return res.status(429).json({
          error: err.message || 'RDAP rate limit reached',
          message: err.message || 'RDAP rate limit reached',
          retry_after: err.retryAfter || null
        });
      }
      await audit.auditFailure({
        req,
        action: AUDIT_ACTION.RDAP_ENRICHMENT_FAILED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: parsed.rdap_domain,
        entityDisplay: parsed.rdap_domain,
        severity: AUDIT_SEVERITY.WARNING,
        metadata: { error_message: String(err?.message || err) }
      }).catch(() => {});
      return res.status(500).json({ error: 'RDAP enrichment failed', message: 'RDAP enrichment failed' });
    }
  });

  /** Legacy path param */
  app.get('/api/enrichment/rdap/:value', async (req, res) => {
    try {
      const value = decodeRouteValue(req.params.value);
      const hintType = String(req.query?.ioc_type || req.query?.type || '').trim() || null;
      const parsed = normalizeRdapTarget(value, hintType);
      if (!parsed.ok) return sendValidationError(res, parsed);
      if (hintType && !isRdapSupportedIocType(hintType)) {
        return res.status(422).json({
          error: 'RDAP enrichment supports domain and URL observables only',
          message: 'RDAP enrichment supports domain and URL observables only',
          code: 'unsupported'
        });
      }
      return res.json(await handleRdapGet(pool, parsed));
    } catch (err) {
      console.error('[rdap-enrichment] GET legacy failed', err?.message || err);
      return res.status(500).json({ error: 'Failed to load RDAP enrichment', message: 'Failed to load RDAP enrichment' });
    }
  });

  /** Legacy path param */
  app.post('/api/enrichment/rdap/:value/refresh', async (req, res) => {
    const value = decodeRouteValue(req.params.value);
    const hintType = String(req.query?.ioc_type || req.query?.type || '').trim() || null;
    const force = String(req.query?.force || '').toLowerCase() === 'true';

    const role = normalizeAppRole(req.user?.role) || ROLES.ADMIN;
    if (force && role !== ROLES.ADMIN) {
      return res.status(403).json({ error: 'Force refresh requires admin role', message: 'Force refresh requires admin role' });
    }

    const parsed = normalizeRdapTarget(value, hintType);
    if (!parsed.ok) return sendValidationError(res, parsed);

    if (hintType && !isRdapSupportedIocType(hintType)) {
      return res.status(422).json({
        error: 'RDAP enrichment supports domain and URL observables only',
        message: 'RDAP enrichment supports domain and URL observables only',
        code: 'unsupported'
      });
    }

    try {
      const out = await handleRdapRefresh(pool, audit, req, parsed, force);
      return res.status(out.status).json(out.body);
    } catch (err) {
      console.error('[rdap-enrichment] POST legacy failed', err?.message || err);
      if (err?.code === 'rate_limit') {
        return res.status(429).json({
          error: err.message || 'RDAP rate limit reached',
          message: err.message || 'RDAP rate limit reached',
          retry_after: err.retryAfter || null
        });
      }
      await audit.auditFailure({
        req,
        action: AUDIT_ACTION.RDAP_ENRICHMENT_FAILED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: parsed.rdap_domain,
        entityDisplay: parsed.rdap_domain,
        severity: AUDIT_SEVERITY.WARNING,
        metadata: { error_message: String(err?.message || err) }
      }).catch(() => {});
      return res.status(500).json({ error: 'RDAP enrichment failed', message: 'RDAP enrichment failed' });
    }
  });
}
