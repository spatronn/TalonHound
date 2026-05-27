import { normalizeRdapTarget } from './domainRoot.js';
import { resolveIpEnrichmentTarget } from './ipEnrichmentEligibility.js';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function addLower(set, value) {
  const v = String(value || '').trim();
  if (!v) return;
  set.add(v.toLowerCase());
}

/**
 * Build lookup keys for IOC-scoped audit log queries.
 * @param {{ id?: number, public_id?: string, observable?: string, observable_type?: string }} item
 */
export function buildIocAuditMatchContext(item) {
  const observable = String(item?.observable || '').trim();
  const observableType = String(item?.observable_type || '').trim().toLowerCase();
  const publicId = item?.public_id ? String(item.public_id) : null;
  const internalId = item?.id != null ? String(item.id) : null;

  const entityIds = new Set();
  const entityDisplays = new Set();

  if (publicId) entityIds.add(publicId);
  if (internalId) entityIds.add(internalId);
  addLower(entityDisplays, observable);

  let rootDomain = null;
  let normalizedHost = null;
  let parsedIp = null;

  if (observable && (observableType === 'domain' || observableType === 'url')) {
    const rdap = normalizeRdapTarget(observable, observableType);
    if (rdap.ok) {
      rootDomain = rdap.rdap_domain;
      normalizedHost = rdap.normalized_host;
      if (rootDomain) entityIds.add(rootDomain);
      if (normalizedHost) entityIds.add(normalizedHost);
      addLower(entityDisplays, normalizedHost);
    }
    if (observableType === 'domain') {
      entityIds.add(observable.toLowerCase());
    }
  }

  if (observable && (observableType === 'ip' || observableType === 'ip6' || observableType === 'url')) {
    const ipTarget = resolveIpEnrichmentTarget(observable, observableType);
    if (ipTarget.eligible && ipTarget.ip) {
      parsedIp = ipTarget.ip;
      entityIds.add(parsedIp);
    }
  }

  return {
    observable,
    observableType,
    publicId,
    internalId,
    rootDomain,
    normalizedHost,
    parsedIp,
    entityIds: [...entityIds].filter(Boolean),
    entityDisplays: [...entityDisplays].filter(Boolean)
  };
}

export function isUuid(value) {
  return UUID_RE.test(String(value || '').trim());
}

/**
 * @param {ReturnType<typeof buildIocAuditMatchContext>} ctx
 * @returns {{ whereSql: string, params: unknown[] }}
 */
export function buildIocAuditLogsWhere(ctx) {
  const entityIds = ctx.entityIds.length ? ctx.entityIds : ['__none__'];
  const entityDisplays = ctx.entityDisplays.length ? ctx.entityDisplays : ['__none__'];
  const internalId = ctx.internalId || '__none__';

  const params = [entityIds, entityDisplays, internalId];
  const whereSql = `(
    (entity_type = 'ioc' AND (
      entity_id = ANY($1::text[])
      OR lower(COALESCE(entity_display, '')) = ANY($2::text[])
    ))
    OR (entity_type = 'ioc_suppression' AND (
      lower(COALESCE(entity_display, '')) = ANY($2::text[])
      OR lower(COALESCE(metadata->>'ioc_value', '')) = ANY($2::text[])
    ))
    OR (entity_type = 'enrichment' AND (
      entity_id = ANY($1::text[])
      OR lower(COALESCE(entity_display, '')) = ANY($2::text[])
      OR lower(COALESCE(metadata->>'root_domain', '')) = ANY($1::text[])
      OR lower(COALESCE(metadata->>'ip', '')) = ANY($1::text[])
      OR lower(COALESCE(metadata->>'observable_value', '')) = ANY($2::text[])
      OR lower(COALESCE(metadata->>'original_value', '')) = ANY($2::text[])
      OR metadata->>'ioc_id' = $3
    ))
  )`;

  return { whereSql, params };
}
