import { authenticateApiKey, requireApiScope } from '../lib/apiKeyAuth.js';
import { API_SCOPE } from '../lib/apiKeyProfiles.js';
import { createApiIoc, updateApiIoc } from '../lib/apiIocService.js';
import { getApiIoc, listApiIocs, searchApiIocs, exportApiIocs } from '../lib/apiIocReadService.js';
import { ensureRequestId } from '../lib/apiRequestId.js';
import { sendApiError, API_ERROR_CODE } from '../lib/apiV1Errors.js';

function sendOutcome(res, req, outcome) {
  if (outcome.error) {
    return sendApiError(res, outcome.status, outcome.error.code, outcome.error.message, req, {
      details: outcome.error.details
    });
  }
  res.set('Cache-Control', 'no-store');
  if (outcome.bodyText != null) {
    if (outcome.contentType) res.set('Content-Type', outcome.contentType);
    if (outcome.truncated) res.set('X-Truncated', 'true');
    return res.status(outcome.status).send(outcome.bodyText);
  }
  return res.status(outcome.status).json(outcome.body);
}

/**
 * Versioned REST management API for IOCs.
 * Auth: Bearer API key + scope checks (no session/admin inheritance).
 *
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {{ auditSuccess?: Function }} [audit]
 */
export function registerApiV1IocRoutes(app, pool, audit) {
  const auth = authenticateApiKey(pool);

  app.get(
    '/api/v1/iocs',
    auth,
    requireApiScope(API_SCOPE.IOC_READ),
    async (req, res) => {
      ensureRequestId(req, res);
      try {
        const outcome = await listApiIocs(pool, {
          cursor: req.query?.cursor,
          limit: req.query?.limit ?? req.query?.page_size,
          type: req.query?.type,
          status: req.query?.status
        });
        return sendOutcome(res, req, outcome);
      } catch {
        return sendApiError(res, 500, API_ERROR_CODE.INTERNAL_ERROR, 'Internal error', req);
      }
    }
  );

  app.post(
    '/api/v1/iocs/search',
    auth,
    requireApiScope(API_SCOPE.IOC_READ),
    async (req, res) => {
      ensureRequestId(req, res);
      try {
        const outcome = await searchApiIocs(pool, {
          query: req.body?.query,
          cursor: req.body?.cursor ?? req.query?.cursor,
          limit: req.body?.limit ?? req.body?.page_size
        });
        return sendOutcome(res, req, outcome);
      } catch {
        return sendApiError(res, 500, API_ERROR_CODE.INTERNAL_ERROR, 'Internal error', req);
      }
    }
  );

  app.post(
    '/api/v1/iocs/export',
    auth,
    requireApiScope(API_SCOPE.IOC_EXPORT),
    async (req, res) => {
      ensureRequestId(req, res);
      try {
        const outcome = await exportApiIocs(pool, {
          query: req.body?.query,
          format: req.body?.format
        });
        return sendOutcome(res, req, outcome);
      } catch {
        return sendApiError(res, 500, API_ERROR_CODE.INTERNAL_ERROR, 'Internal error', req);
      }
    }
  );

  app.get(
    '/api/v1/iocs/:id',
    auth,
    requireApiScope(API_SCOPE.IOC_READ),
    async (req, res) => {
      ensureRequestId(req, res);
      try {
        const outcome = await getApiIoc(pool, req.params.id);
        return sendOutcome(res, req, outcome);
      } catch {
        return sendApiError(res, 500, API_ERROR_CODE.INTERNAL_ERROR, 'Internal error', req);
      }
    }
  );

  app.post(
    '/api/v1/iocs',
    auth,
    requireApiScope(API_SCOPE.IOC_CREATE),
    async (req, res) => {
      ensureRequestId(req, res);
      try {
        // Drop spoofable provenance keys before they reach the service.
        const raw = req.body && typeof req.body === 'object' ? { ...req.body } : {};
        delete raw.source;
        delete raw.source_name;
        delete raw.source_id;
        delete raw.ioc_source_id;
        delete raw.created_origin;
        delete raw.created_by_user_id;

        const result = await createApiIoc(pool, raw, {
          req,
          apiKey: req.apiKey,
          audit
        });
        if (result.error) {
          return sendApiError(res, result.status, result.error.code, result.error.message, req, {
            details: result.error.details
          });
        }
        res.set('Cache-Control', 'no-store');
        return res.status(result.status).json(result.body);
      } catch {
        return sendApiError(res, 500, API_ERROR_CODE.INTERNAL_ERROR, 'Internal error', req);
      }
    }
  );

  app.patch(
    '/api/v1/iocs/:id',
    auth,
    requireApiScope(API_SCOPE.IOC_UPDATE),
    async (req, res) => {
      ensureRequestId(req, res);
      try {
        const raw = req.body && typeof req.body === 'object' ? { ...req.body } : {};
        delete raw.source;
        delete raw.source_name;
        delete raw.source_id;
        delete raw.ioc_source_id;

        const result = await updateApiIoc(pool, req.params.id, raw, {
          req,
          apiKey: req.apiKey,
          audit
        });
        if (result.error) {
          return sendApiError(res, result.status, result.error.code, result.error.message, req, {
            details: result.error.details
          });
        }
        res.set('Cache-Control', 'no-store');
        return res.status(result.status).json(result.body);
      } catch {
        return sendApiError(res, 500, API_ERROR_CODE.INTERNAL_ERROR, 'Internal error', req);
      }
    }
  );
}
