/**
 * Streamable HTTP MCP endpoint at /mcp.
 * Auth: Bearer MCP API key bound to an owner user (authenticateMcp).
 */

import { randomUUID } from 'node:crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { authenticateMcp } from '../lib/mcpAuth.js';
import { createTalonHoundMcpServer } from '../lib/mcpServer.js';
import { createSlidingWindowRateLimit } from '../lib/slidingWindowRateLimit.js';
import { getMcpConfig, isMcpEnabled } from '../lib/mcpConfig.js';
import { ensureRequestId } from '../lib/apiRequestId.js';
import { sendApiError, API_ERROR_CODE } from '../lib/apiV1Errors.js';
import { registerRouteModule } from '../lib/routeRegistry.js';

function clientKey(req) {
  const keyId = req.apiKey?.id != null ? `key:${req.apiKey.id}` : null;
  if (keyId) return keyId;
  const fwd = String(req?.headers?.['x-forwarded-for'] || '')
    .split(',')[0]
    .trim();
  return `ip:${fwd || req?.ip || 'unknown'}`;
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {{ auditSuccess?: Function, auditFailure?: Function }} [audit]
 */
export function registerMcpRoutes(app, pool, audit) {
  registerRouteModule('mcp');
  const auth = authenticateMcp(pool);
  const limiter = createSlidingWindowRateLimit({ windowMs: 60_000 });
  const config = getMcpConfig();

  // AsyncLocal-ish per-request context via closure set just before handleRequest.
  let requestContext = { req: null };

  function rateLimitMiddleware(req, res, next) {
    ensureRequestId(req, res);
    const cfg = getMcpConfig();
    const key = clientKey(req);
    if (!limiter.check(`mcp:all:${key}`, cfg.rateLimitPerMin)) {
      return sendApiError(res, 429, API_ERROR_CODE.RATE_LIMIT_EXCEEDED, 'MCP rate limit exceeded', req);
    }

    // Heuristic tool-specific limits from JSON-RPC body when present.
    const method = req.body?.method;
    const toolName = req.body?.params?.name;
    if (method === 'tools/call' && toolName === 'import_iocs') {
      if (!limiter.check(`mcp:import:${key}`, cfg.rateLimitImportPerMin)) {
        return sendApiError(res, 429, API_ERROR_CODE.RATE_LIMIT_EXCEEDED, 'MCP import rate limit exceeded', req);
      }
    }
    if (method === 'tools/call' && toolName === 'search_iocs') {
      if (!limiter.check(`mcp:search:${key}`, cfg.rateLimitSearchPerMin)) {
        return sendApiError(res, 429, API_ERROR_CODE.RATE_LIMIT_EXCEEDED, 'MCP search rate limit exceeded', req);
      }
    }
    if (method === 'tools/call' && toolName === 'bulk_lookup_iocs') {
      if (!limiter.check(`mcp:bulk:${key}`, cfg.rateLimitBulkPerMin)) {
        return sendApiError(res, 429, API_ERROR_CODE.RATE_LIMIT_EXCEEDED, 'MCP bulk lookup rate limit exceeded', req);
      }
    }
    return next();
  }

  async function handleMcp(req, res) {
    ensureRequestId(req, res);
    if (!isMcpEnabled()) {
      return sendApiError(res, 503, API_ERROR_CODE.INTERNAL_ERROR, 'MCP is disabled', req);
    }

    requestContext = { req };
    res.set('Cache-Control', 'no-store');

    const server = createTalonHoundMcpServer({
      pool,
      audit,
      getRequestContext: () => requestContext
    });

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // stateless
      enableJsonResponse: true
    });

    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      if (!res.headersSent) {
        return sendApiError(res, 500, API_ERROR_CODE.INTERNAL_ERROR, 'MCP request failed', req);
      }
    } finally {
      try { await transport.close(); } catch { /* ignore */ }
      try { await server.close(); } catch { /* ignore */ }
      requestContext = { req: null };
    }
  }

  // Lightweight reachability probe (auth still required).
  app.get('/mcp/health', auth, rateLimitMiddleware, (req, res) => {
    ensureRequestId(req, res);
    res.set('Cache-Control', 'no-store');
    return res.json({
      ok: true,
      mcp: true,
      enabled: isMcpEnabled(),
      transport: 'streamable-http',
      limits: {
        bulk_lookup_max: config.bulkLookupMax,
        import_max: config.importMax,
        search_page_max: config.searchPageMax,
        rate_limit_per_min: config.rateLimitPerMin
      },
      request_id: req.requestId || randomUUID()
    });
  });

  app.all('/mcp', auth, rateLimitMiddleware, (req, res) => {
    void handleMcp(req, res);
  });
}
