/**
 * MCP enrichment tools — thin adapters over lib/enrichmentOrchestrator.js.
 *
 * Read side (list_enrichment_providers, get_enrichment_job) never contacts a
 * provider. Action side (enrich_ioc, bulk_enrich_iocs) is the only MCP path that
 * can cause an external provider call, and only through the canonical provider
 * refresh functions registered in the enrichment provider registry.
 */

import {
  describeEnrichmentProviders,
  requestEnrichment,
  getEnrichmentJobView,
  waitForEnrichmentJob
} from './enrichmentOrchestrator.js';
import { mcpActorAuditFields } from './mcpIocService.js';
import { getMcpConfig } from './mcpConfig.js';

function clientIp(req) {
  const fwd = String(req?.headers?.['x-forwarded-for'] || '').split(',')[0].trim();
  return fwd || req?.ip || req?.socket?.remoteAddress || null;
}

/**
 * Request snapshot that outlives the HTTP request (the job runs in the
 * background): principal, channel, correlation id and client address only.
 */
function requestSnapshot(req) {
  return {
    user: req?.user ? { ...req.user } : null,
    authVia: 'mcp',
    requestId: req?.requestId || null,
    ip: clientIp(req),
    headers: {
      'user-agent': req?.headers?.['user-agent'] ? String(req.headers['user-agent']).slice(0, 512) : 'mcp-client',
      ...(req?.requestId ? { 'x-request-id': String(req.requestId) } : {})
    }
  };
}

/**
 * Audit adapter stamping MCP provenance (channel, API key id/name, owner, job
 * id, force flag) onto every event — the parent job events and the provider
 * events written by the shared refresh functions alike. Never includes tokens.
 */
function buildMcpAuditAdapter(audit, snapshot, mcpAuth, extras = {}) {
  if (!audit?.auditSuccess) return null;
  const actor = mcpActorAuditFields(mcpAuth, snapshot.user);
  const wrap = (fn) => (event) => fn({
    ...event,
    req: snapshot,
    actorUsername: actor.actorUsername,
    actorEmail: actor.actorEmail,
    actorRole: actor.actorRole,
    actorPublicId: actor.actorPublicId,
    source: 'mcp',
    metadata: {
      ...(event.metadata || {}),
      ...actor.metadataExtras,
      ...extras
    }
  });
  return {
    auditSuccess: wrap(audit.auditSuccess),
    auditFailure: wrap(audit.auditFailure || audit.auditSuccess)
  };
}

export async function mcpListEnrichmentProviders(pool) {
  const providers = await describeEnrichmentProviders(pool);
  return {
    body: {
      providers,
      notes: {
        available: 'enabled AND configured AND triggerable through enrich_ioc',
        external: 'true = outbound third-party request that may consume provider API quota',
        supported_observable_types: 'url coverage for IP/domain providers applies to the URL host (Derived Infrastructure)'
      }
    }
  };
}

function normalizeProvidersArg(raw) {
  if (raw == null || raw === 'all') return 'all';
  if (Array.isArray(raw)) return raw.map((p) => String(p || '').trim().toLowerCase()).filter(Boolean);
  return null;
}

/**
 * @param {import('pg').Pool} pool
 * @param {{ ioc_id?: string|number, ioc_ids?: Array<string|number>, providers?: 'all'|string[], force_refresh?: boolean, wait_seconds?: number }} args
 * @param {{ req?: object, mcpAuth?: object, audit?: object, config?: object }} ctx
 * @param {{ bulk?: boolean }} mode
 */
export async function mcpEnrichIocs(pool, args = {}, ctx = {}, { bulk = false } = {}) {
  const config = ctx.config || getMcpConfig();
  const providers = normalizeProvidersArg(args.providers);
  if (!providers || (providers !== 'all' && !providers.length)) {
    return { error: { code: 'VALIDATION_ERROR', message: 'providers must be "all" or a non-empty array of provider ids (see list_enrichment_providers)' } };
  }
  const refs = bulk ? (Array.isArray(args.ioc_ids) ? args.ioc_ids : []) : [args.ioc_id];
  const force = args.force_refresh === true;

  const snapshot = requestSnapshot(ctx.req);
  const mcpAuth = ctx.mcpAuth || ctx.req?.mcpAuth || null;
  const tool = bulk ? 'bulk_enrich_iocs' : 'enrich_ioc';
  // source_page overrides the UI-origin label the shared refresh functions stamp.
  const audit = buildMcpAuditAdapter(ctx.audit, snapshot, mcpAuth, { tool, force_refresh: force, source_page: 'mcp' });

  const outcome = await requestEnrichment(pool, {
    iocRefs: refs,
    providers,
    force,
    actor: { userId: snapshot.user?.id ?? null, apiKeyId: mcpAuth?.apiKeyId ?? null },
    principal: snapshot.user,
    mcpAuth,
    audit,
    providerAudit: audit,
    requestId: snapshot.requestId,
    clientIp: snapshot.ip,
    origin: 'mcp',
    maxIocs: bulk ? config.enrichBulkMax : 1,
    maxOperations: config.enrichMaxOperations,
    maxActiveJobs: config.enrichMaxActiveJobs,
    auditFields: { tool }
  });
  if (outcome.error) {
    return {
      error: outcome.error,
      ...(outcome.notFound?.length ? { not_found: outcome.notFound } : {})
    };
  }

  let view = outcome.view;
  const waitSeconds = Math.min(Math.max(Number(args.wait_seconds) || 0, 0), config.enrichWaitMaxSeconds);
  if (waitSeconds > 0 && (view.status === 'queued' || view.status === 'running')) {
    await waitForEnrichmentJob(pool, view.job_id, waitSeconds * 1000);
    view = await getEnrichmentJobView(pool, view.job_id) || view;
  }

  const body = {
    ...view,
    terminal: !['queued', 'running'].includes(view.status),
    next: ['queued', 'running'].includes(view.status)
      ? 'Poll get_enrichment_job with job_id, then read results with get_ioc_context.'
      : 'Read stored results with get_ioc_context.',
    ...(outcome.notApplicable?.length ? { not_applicable: outcome.notApplicable } : {}),
    ...(outcome.notFound?.length ? { not_found: outcome.notFound } : {})
  };
  if (!bulk && body.iocs?.length === 1) {
    // Single-IOC convenience: flatten to the requested IOC.
    const [one] = body.iocs;
    body.ioc_id = one.ioc_id;
    body.observable = one.observable;
    body.observable_type = one.observable_type;
    body.providers = one.providers;
    delete body.iocs;
  }
  return { body };
}

export async function mcpGetEnrichmentJob(pool, args = {}, ctx = {}) {
  const ownerUserId = ctx.req?.user?.id ?? null;
  const view = await getEnrichmentJobView(pool, String(args.job_id || '').trim(), { ownerUserId });
  if (!view) {
    return { error: { code: 'JOB_NOT_FOUND', message: 'Enrichment job not found' } };
  }
  return {
    body: {
      ...view,
      terminal: !['queued', 'running'].includes(view.status)
    }
  };
}
