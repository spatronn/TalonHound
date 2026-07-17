/**
 * Build lookup keys for IOC-scoped audit log queries.
 *
 * Enrichment history is scoped by subject IOC id (column or metadata).
 * Shared hostname / root domain / IP must NOT be primary match keys —
 * that leaks audits across URL IOCs that share infrastructure.
 *
 * @param {{ id?: number, public_id?: string, observable?: string, observable_type?: string }} item
 */
export function buildIocAuditMatchContext(item) {
  const observable = String(item?.observable || '').trim();
  const observableType = String(item?.observable_type || '').trim().toLowerCase();
  const publicId = item?.public_id ? String(item.public_id) : null;
  const internalId = item?.id != null ? String(item.id) : null;

  const entityIds = new Set();
  const entityDisplays = new Set();
  const exactObservables = new Set();

  if (publicId) entityIds.add(publicId);
  if (internalId) entityIds.add(internalId);
  if (observable) {
    entityDisplays.add(observable.toLowerCase());
    exactObservables.add(observable.toLowerCase());
    // Domain/IP IOC values are themselves the technical identity.
    if (observableType === 'domain' || observableType === 'ip' || observableType === 'ip6') {
      entityIds.add(observable.toLowerCase());
    }
  }

  return {
    observable,
    observableType,
    publicId,
    internalId,
    rootDomain: null,
    normalizedHost: null,
    parsedIp: null,
    entityIds: [...entityIds].filter(Boolean),
    entityDisplays: [...entityDisplays].filter(Boolean),
    exactObservables: [...exactObservables].filter(Boolean)
  };
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

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
  const exactObservables = ctx.exactObservables?.length
    ? ctx.exactObservables
    : (ctx.entityDisplays.length ? ctx.entityDisplays : ['__none__']);
  const internalId = ctx.internalId || '__none__';

  // $1 entity ids (ioc public/internal + domain/ip self)
  // $2 entity displays for ioc / suppression rows
  // $3 internal ioc id (text) for enrichment subject match
  // $4 exact full observable values for safe legacy enrichment fallback
  const params = [entityIds, entityDisplays, internalId, exactObservables];
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
      subject_ioc_id::text = $3
      OR metadata->>'subject_ioc_id' = $3
      OR metadata->>'ioc_id' = $3
      OR lower(COALESCE(subject_ioc_value, '')) = ANY($4::text[])
      OR lower(COALESCE(entity_display, '')) = ANY($4::text[])
      OR lower(COALESCE(metadata->>'subject_ioc_value', '')) = ANY($4::text[])
      OR lower(COALESCE(metadata->>'observable_value', '')) = ANY($4::text[])
      OR lower(COALESCE(metadata->>'original_value', '')) = ANY($4::text[])
      OR lower(COALESCE(entity_id, '')) = ANY($4::text[])
    ))
  )`;

  return { whereSql, params };
}
