const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Resolve subject IOC id from request body/query (numeric id or public UUID).
 * Does not invent an IOC by looking up shared host/domain values.
 * @param {import('pg').Pool} pool
 * @param {import('express').Request} req
 * @returns {Promise<{ id: number, public_id: string, observable: string, observable_type: string }|null>}
 */
export async function resolveSubjectIocFromRequest(pool, req) {
  const raw = req?.body?.ioc_id ?? req?.body?.iocId ?? req?.query?.ioc_id ?? req?.query?.iocId;
  if (raw == null || String(raw).trim() === '') return null;
  const value = String(raw).trim();

  try {
    if (UUID_RE.test(value)) {
      const { rows } = await pool.query(
        `SELECT id, public_id, observable, observable_type
         FROM ioc_items WHERE public_id = $1::uuid LIMIT 1`,
        [value]
      );
      return rows[0] || null;
    }

    const n = Number(value);
    if (!Number.isFinite(n) || n <= 0) return null;
    const { rows } = await pool.query(
      `SELECT id, public_id, observable, observable_type
       FROM ioc_items WHERE id = $1 LIMIT 1`,
      [n]
    );
    return rows[0] || null;
  } catch {
    return null;
  }
}

/**
 * Build entity + column + metadata fields for IOC-scoped enrichment audits.
 * Subject = which IOC the user acted on. Target = technical lookup key.
 *
 * @param {{
 *   subject?: { id?: number, public_id?: string, observable?: string, observable_type?: string }|null,
 *   subjectIocId?: number|string|null,
 *   subjectIocType?: string|null,
 *   subjectIocValue?: string|null,
 *   targetType?: string|null,
 *   targetValue?: string|null,
 *   provider?: string|null,
 *   extraMetadata?: Record<string, unknown>
 * }} opts
 */
export function buildEnrichmentAuditScope(opts = {}) {
  const subject = opts.subject || null;
  const subjectIocIdRaw = subject?.id ?? opts.subjectIocId;
  const subjectIocId = subjectIocIdRaw != null && Number.isFinite(Number(subjectIocIdRaw))
    ? Number(subjectIocIdRaw)
    : null;
  const subjectIocPublicId = subject?.public_id ? String(subject.public_id) : null;
  const subjectIocType = String(
    subject?.observable_type || opts.subjectIocType || ''
  ).trim().toLowerCase() || null;
  const subjectIocValue = String(
    subject?.observable || opts.subjectIocValue || ''
  ).trim() || null;
  const targetType = opts.targetType ? String(opts.targetType).trim().toLowerCase() : null;
  const targetValue = opts.targetValue != null ? String(opts.targetValue).trim() : null;
  const provider = opts.provider ? String(opts.provider) : null;

  const entityId = subjectIocPublicId
    || (subjectIocId != null ? String(subjectIocId) : null)
    || targetValue
    || null;
  const entityDisplay = subjectIocValue || targetValue || null;

  const metadata = {
    ...(opts.extraMetadata && typeof opts.extraMetadata === 'object' ? opts.extraMetadata : {}),
    provider: provider || opts.extraMetadata?.provider || null,
    ioc_id: subjectIocId != null ? String(subjectIocId) : (opts.extraMetadata?.ioc_id ?? null),
    subject_ioc_id: subjectIocId != null ? String(subjectIocId) : null,
    subject_ioc_type: subjectIocType,
    subject_ioc_value: subjectIocValue,
    target_type: targetType,
    target_value: targetValue
  };

  // Drop nullish metadata keys that would clutter JSON
  for (const key of Object.keys(metadata)) {
    if (metadata[key] == null || metadata[key] === '') delete metadata[key];
  }

  return {
    entityId,
    entityDisplay,
    subjectIocId,
    subjectIocType,
    subjectIocValue,
    targetType,
    targetValue,
    metadata
  };
}
