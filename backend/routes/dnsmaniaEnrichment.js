import { isDnsmaniaSupportedIocType, normalizeDnsmaniaLookup } from '../lib/dnsmaniaTarget.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import {
  DNSMANIA_PROVIDER,
  enrichIocWithDnsmania,
  getDnsmaniaConfig,
  getEnrichmentByLookupKey,
  rowToApiPayload
} from '../services/dnsmaniaEnrichmentService.js';

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

function resolveIocType(req) {
  const fromBody = req.body?.ioc_type ?? req.body?.iocType;
  const fromQuery = req.query?.ioc_type ?? req.query?.iocType;
  return String(fromBody || fromQuery || '').trim().toLowerCase() || null;
}

function validationStatus(code) {
  if (code === 'unsupported') return 422;
  return 400;
}

function sendValidationError(res, parsed) {
  return res.status(validationStatus(parsed.code)).json({
    error: parsed.message,
    message: parsed.message,
    code: parsed.code,
    provider: DNSMANIA_PROVIDER
  });
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {{ auditSuccess: Function, auditFailure: Function }} audit
 */
export function registerDnsmaniaEnrichmentRoutes(app, pool, audit) {
  app.get('/api/enrichment/dnsmania', async (req, res) => {
    try {
      const value = resolveRequestValue(req);
      const iocType = resolveIocType(req);
      if (!value) {
        return res.status(400).json({
          error: 'value is required',
          message: 'value is required',
          provider: DNSMANIA_PROVIDER
        });
      }
      if (iocType && !isDnsmaniaSupportedIocType(iocType)) {
        return res.status(422).json({
          error: 'DNSMania enrichment supports domain, URL, and IP observables only',
          message: 'DNSMania enrichment supports domain, URL, and IP observables only',
          code: 'unsupported',
          provider: DNSMANIA_PROVIDER
        });
      }

      const parsed = normalizeDnsmaniaLookup(iocType, value);
      if (!parsed.ok) return sendValidationError(res, parsed);

      const cfg = getDnsmaniaConfig();
      if (!cfg.configured) {
        return res.json(rowToApiPayload(null, {
          status: 'not_configured',
          lookup_type: parsed.lookup_type,
          lookup_value: parsed.lookup_value,
          message: 'DNSMania base URL is not configured'
        }));
      }
      if (!cfg.enabled) {
        return res.json(rowToApiPayload(null, {
          status: 'disabled',
          lookup_type: parsed.lookup_type,
          lookup_value: parsed.lookup_value,
          message: 'DNSMania enrichment is currently disabled'
        }));
      }

      const row = await getEnrichmentByLookupKey(pool, parsed.lookup_key);
      if (!row) {
        return res.json(rowToApiPayload(null, {
          status: 'not_run',
          lookup_type: parsed.lookup_type,
          lookup_value: parsed.lookup_value,
          data_source: 'none'
        }));
      }

      return res.json(rowToApiPayload(row, {
        cached: true,
        data_source: 'db',
        message: row.provider_status === 'failed'
          ? (row.error_message || 'DNSMania enrichment failed')
          : undefined
      }));
    } catch (err) {
      console.error('[dnsmania-enrichment] GET failed', err?.message || err);
      return res.status(500).json({
        error: 'Failed to load DNSMania enrichment',
        message: 'Failed to load DNSMania enrichment',
        provider: DNSMANIA_PROVIDER
      });
    }
  });

  app.post('/api/enrichment/dnsmania/refresh', async (req, res) => {
    try {
      const value = resolveRequestValue(req);
      const iocType = resolveIocType(req);
      if (!value) {
        return res.status(400).json({
          error: 'value is required',
          message: 'value is required',
          provider: DNSMANIA_PROVIDER
        });
      }
      if (iocType && !isDnsmaniaSupportedIocType(iocType)) {
        return res.status(422).json({
          error: 'DNSMania enrichment supports domain, URL, and IP observables only',
          message: 'DNSMania enrichment supports domain, URL, and IP observables only',
          code: 'unsupported',
          provider: DNSMANIA_PROVIDER
        });
      }

      const parsed = normalizeDnsmaniaLookup(iocType, value);
      if (!parsed.ok) return sendValidationError(res, parsed);

      const cfg = getDnsmaniaConfig();
      if (!cfg.configured) {
        return res.status(503).json({
          error: 'DNSMania base URL is not configured',
          message: 'DNSMania base URL is not configured',
          code: 'not_configured',
          provider: DNSMANIA_PROVIDER,
          status: 'not_configured'
        });
      }
      if (!cfg.enabled) {
        return res.status(503).json({
          error: 'DNSMania enrichment is currently disabled',
          message: 'DNSMania enrichment is currently disabled',
          code: 'disabled',
          provider: DNSMANIA_PROVIDER,
          status: 'disabled'
        });
      }

      await audit?.auditSuccess?.({
        req,
        action: AUDIT_ACTION.DNSMANIA_ENRICHMENT_REQUESTED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: parsed.lookup_key,
        entityDisplay: parsed.lookup_value,
        severity: AUDIT_SEVERITY.INFO,
        metadata: {
          ioc_type: parsed.ioc_type,
          lookup_type: parsed.lookup_type,
          lookup_value: parsed.lookup_value,
          provider: DNSMANIA_PROVIDER,
          source_page: 'ioc_detail_intelligence'
        }
      })?.catch?.(() => {});

      const result = await enrichIocWithDnsmania(pool, parsed, { config: cfg });
      const row = result.row;
      const payload = rowToApiPayload(row, {
        cached: false,
        data_source: result.dataSource
      });

      if (row.provider_status === 'completed' || row.provider_status === 'no_data') {
        await audit?.auditSuccess?.({
          req,
          action: AUDIT_ACTION.DNSMANIA_ENRICHMENT_COMPLETED,
          entityType: AUDIT_ENTITY.ENRICHMENT,
          entityId: parsed.lookup_key,
          entityDisplay: parsed.lookup_value,
          severity: AUDIT_SEVERITY.INFO,
          metadata: {
            ioc_type: parsed.ioc_type,
            lookup_type: parsed.lookup_type,
            lookup_value: parsed.lookup_value,
            provider: DNSMANIA_PROVIDER,
            result_status: row.provider_status,
            known: row.known
          }
        })?.catch?.(() => {});
        return res.json(payload);
      }

      await audit?.auditFailure?.({
        req,
        action: AUDIT_ACTION.DNSMANIA_ENRICHMENT_FAILED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: parsed.lookup_key,
        entityDisplay: parsed.lookup_value,
        severity: AUDIT_SEVERITY.WARNING,
        metadata: {
          ioc_type: parsed.ioc_type,
          lookup_type: parsed.lookup_type,
          lookup_value: parsed.lookup_value,
          provider: DNSMANIA_PROVIDER,
          result_status: row.provider_status,
          error_code: row.error_code
        }
      })?.catch?.(() => {});

      const statusCode = row.error_code === 'timeout' ? 504 : 502;
      return res.status(statusCode).json({
        ...payload,
        error: row.error_message || 'DNSMania enrichment failed',
        message: row.error_message || 'DNSMania enrichment failed'
      });
    } catch (err) {
      console.error('[dnsmania-enrichment] POST refresh failed', err?.message || err);
      return res.status(500).json({
        error: 'DNSMania enrichment failed',
        message: 'DNSMania enrichment failed',
        provider: DNSMANIA_PROVIDER
      });
    }
  });
}
