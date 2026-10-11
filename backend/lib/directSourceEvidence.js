/**
 * Direct source evidence: a publisher explicitly ties one IOC to one catalog
 * entity (e.g. a report's IOC table row "PhantomPolia Domain").
 *
 * Stored as ordinary source assertions in ioc_source_attributions, never as
 * analyst attribution (ioc_malware_families / ioc_threat_actors):
 *   feed_key = 'publisher-report', evidence_ref_type = 'publisher_report',
 *   evidence_ref_id = the report URL, association_kind = directly_attributed_to
 *   | malware_sample_of, observed_at = the report's publication time,
 *   provider_metadata = { publisher, published_at, section, row_label, value_as_published, ... }.
 * Its own feed_key keeps it out of feed re-ingestion / withdrawal (those are
 * scoped to their feed + evidence reference) and out of the OTX label backfill,
 * and the Pulse-context assertions for the same IOC stay untouched.
 *
 * Every item is checked before anything is written: the IOC must exist with the
 * exact canonical value, the label must resolve to exactly the named active
 * catalog entity, and the publisher's row label must name that entity.
 * Re-running is idempotent (unique assertion key; ON CONFLICT DO NOTHING).
 */

import { AUDIT_ACTION, AUDIT_ENTITY } from './auditConstants.js';
import { ASSOCIATION_KIND, ENTITY_KIND, normalizeAttributionLabelKey, resolveCatalogEntity } from './iocSourceAttributions.js';

export const DIRECT_EVIDENCE_FEED_KEY = 'publisher-report';
export const DIRECT_EVIDENCE_REF_TYPE = 'publisher_report';
export const DIRECT_EVIDENCE_PROVIDER = 'publisher_report';
export const DIRECT_EVIDENCE_MAX_ITEMS = 500;

const HASH_LENGTHS = { md5: 32, sha1: 40, sha256: 64 };
const OBSERVABLE_TYPES = ['domain', 'url', 'ip', 'md5', 'sha1', 'sha256'];
const ASSOCIATION_KINDS = [ASSOCIATION_KIND.DIRECTLY_ATTRIBUTED_TO, ASSOCIATION_KIND.MALWARE_SAMPLE_OF];
const ENTITY_KINDS = [ENTITY_KIND.MALWARE_FAMILY, ENTITY_KIND.THREAT_ACTOR];

export const DIRECT_EVIDENCE_STATUS = Object.freeze({
  CREATE: 'create',
  ALREADY_RECORDED: 'already_recorded',
  SKIP: 'skip'
});

/** Undo common report defanging ("example[.]com", "hxxps://"). */
export function refang(raw) {
  return String(raw ?? '')
    .trim()
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]/gi, '.')
    .replace(/\[:\]/g, ':')
    .replace(/^hxxp(s?):\/\//i, 'http$1://');
}

/**
 * Exact canonical IOC value for a published indicator, or an error. No fuzzy
 * normalization: only refanging plus the case rules TalonHound stores.
 */
export function canonicalObservable(observableType, rawValue) {
  const type = String(observableType || '').trim().toLowerCase();
  const value = refang(rawValue);
  if (!OBSERVABLE_TYPES.includes(type)) return { ok: false, error: 'unsupported_observable_type' };
  if (!value) return { ok: false, error: 'empty_value' };
  if (type in HASH_LENGTHS) {
    const v = value.toLowerCase();
    if (!/^[0-9a-f]+$/.test(v) || v.length !== HASH_LENGTHS[type]) return { ok: false, error: 'hash_type_mismatch' };
    return { ok: true, value: v };
  }
  if (type === 'domain') {
    const v = value.toLowerCase().replace(/\.$/, '');
    if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/.test(v)) return { ok: false, error: 'invalid_domain' };
    return { ok: true, value: v };
  }
  if (type === 'ip') {
    const parts = value.split('.');
    if (parts.length !== 4 || parts.some((p) => !/^\d{1,3}$/.test(p) || Number(p) > 255)) return { ok: false, error: 'invalid_ip' };
    return { ok: true, value };
  }
  // url: kept verbatim (case-sensitive path); a scheme-less published URL is
  // not guessed into one.
  if (!/^https?:\/\/\S+$/i.test(value)) return { ok: false, error: 'url_requires_scheme' };
  return { ok: true, value };
}

function isoTimestamp(raw) {
  const text = String(raw ?? '').trim();
  if (!text) return null;
  const date = /^\d{4}-\d{2}-\d{2}$/.test(text) ? new Date(`${text}T00:00:00Z`) : new Date(text);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

/**
 * Validate a manifest. Returns { source, items, errors } where each item keeps
 * its own validation errors (an invalid item is skipped, never "fixed").
 */
export function validateDirectEvidenceManifest(manifest) {
  const errors = [];
  const src = manifest?.source || {};
  const source = {
    publisher: String(src.publisher || '').trim(),
    title: String(src.title || '').trim(),
    url: String(src.url || '').trim(),
    published_at: isoTimestamp(src.published_at),
    section: String(src.section || '').trim() || null
  };
  if (!source.publisher) errors.push('source.publisher is required');
  if (!source.title) errors.push('source.title is required');
  if (!/^https:\/\/\S+$/i.test(source.url)) errors.push('source.url must be an https URL');
  if (!source.published_at) errors.push('source.published_at must be a date (YYYY-MM-DD) or ISO timestamp');

  const rawItems = Array.isArray(manifest?.items) ? manifest.items : [];
  if (!rawItems.length) errors.push('items must be a non-empty array');
  if (rawItems.length > DIRECT_EVIDENCE_MAX_ITEMS) errors.push(`at most ${DIRECT_EVIDENCE_MAX_ITEMS} items per manifest`);

  const items = rawItems.slice(0, DIRECT_EVIDENCE_MAX_ITEMS).map((raw, index) => {
    const itemErrors = [];
    const entityKind = String(raw?.entity_kind || '').trim();
    const entityName = String(raw?.entity_name || '').trim();
    const sourceLabel = String(raw?.source_label || entityName).trim();
    const rowLabel = String(raw?.row_label || '').trim();
    const observableType = String(raw?.observable_type || '').trim().toLowerCase();
    const associationKind = String(raw?.association_kind || ASSOCIATION_KIND.DIRECTLY_ATTRIBUTED_TO).trim();
    if (!ENTITY_KINDS.includes(entityKind)) itemErrors.push('invalid_entity_kind');
    if (!entityName) itemErrors.push('entity_name_required');
    if (!rowLabel) itemErrors.push('row_label_required');
    if (!ASSOCIATION_KINDS.includes(associationKind)) itemErrors.push('invalid_association_kind');
    if (associationKind === ASSOCIATION_KIND.MALWARE_SAMPLE_OF
      && (entityKind !== ENTITY_KIND.MALWARE_FAMILY || !(observableType in HASH_LENGTHS))) {
      itemErrors.push('malware_sample_of_requires_family_hash');
    }
    // Evidence mismatch: the publisher's row must itself name the entity.
    if (rowLabel && sourceLabel && !rowLabel.toLowerCase().includes(sourceLabel.toLowerCase())) {
      itemErrors.push('row_label_does_not_name_entity');
    }
    const canonical = canonicalObservable(observableType, raw?.value);
    if (!canonical.ok) itemErrors.push(canonical.error);
    return {
      index,
      entity_kind: entityKind,
      entity_name: entityName,
      source_label: sourceLabel,
      source_label_normalized: normalizeAttributionLabelKey(sourceLabel),
      row_label: rowLabel,
      observable_type: observableType,
      value_as_published: String(raw?.value ?? '').trim(),
      value: canonical.ok ? canonical.value : null,
      association_kind: associationKind,
      evidence_role: String(raw?.evidence_role || '').trim() || null,
      errors: itemErrors
    };
  });

  return { source, items, errors };
}

async function resolveEntity(client, item, cache) {
  const key = `${item.entity_kind}|${item.source_label_normalized}`;
  if (!cache.has(key)) cache.set(key, resolveCatalogEntity(client, item.entity_kind, item.source_label));
  const r = await cache.get(key);
  if (r.status !== 'resolved') {
    return { ok: false, reason: r.status === 'ambiguous' ? 'entity_ambiguous' : 'entity_not_found' };
  }
  const table = item.entity_kind === ENTITY_KIND.THREAT_ACTOR ? 'threat_actors' : 'malware_families';
  const { rows } = await client.query(`SELECT id, name, active FROM ${table} WHERE id = $1::uuid`, [r.entityId]);
  const entity = rows[0];
  if (!entity) return { ok: false, reason: 'entity_not_found' };
  if (entity.active === false) return { ok: false, reason: 'entity_inactive' };
  // The label must resolve to the entity the manifest names - never another one.
  if (String(entity.name).toLowerCase() !== item.entity_name.toLowerCase()) {
    return { ok: false, reason: 'label_resolves_to_other_entity', resolved_to: entity.name };
  }
  const method = r.method
    || (String(entity.name).toLowerCase() === item.source_label_normalized ? 'name' : 'alias');
  return { ok: true, entity: { id: String(entity.id), name: entity.name }, method };
}

/**
 * Read-only plan: what would be written, already exists or is skipped (and why).
 */
export async function planDirectEvidence(client, manifest) {
  const { source, items, errors } = validateDirectEvidenceManifest(manifest);
  if (errors.length) return { ok: false, errors, source, items: [] };
  const cache = new Map();
  const planned = [];
  for (const item of items) {
    const base = {
      index: item.index,
      entity_kind: item.entity_kind,
      entity_name: item.entity_name,
      row_label: item.row_label,
      observable_type: item.observable_type,
      value_as_published: item.value_as_published,
      value: item.value,
      association_kind: item.association_kind
    };
    if (item.errors.length) {
      planned.push({ ...base, status: DIRECT_EVIDENCE_STATUS.SKIP, reason: item.errors.join(',') });
      continue;
    }
    const resolved = await resolveEntity(client, item, cache);
    if (!resolved.ok) {
      planned.push({ ...base, status: DIRECT_EVIDENCE_STATUS.SKIP, reason: resolved.reason, resolved_to: resolved.resolved_to || null });
      continue;
    }
    // Exact IOC identity (type + canonical value). Several rows of one identity
    // follow the feed-import convention: the oldest row carries the assertion.
    const { rows: iocRows } = await client.query(
      `SELECT id, public_id, observable, observable_type
       FROM ioc_items
       WHERE observable_type = $1 AND observable = $2
       ORDER BY created_at ASC, id ASC
       LIMIT 5`,
      [item.observable_type, item.value]
    );
    if (!iocRows.length) {
      planned.push({ ...base, status: DIRECT_EVIDENCE_STATUS.SKIP, reason: 'ioc_not_found', entity_id: resolved.entity.id });
      continue;
    }
    const ioc = iocRows[0];
    const { rows: existing } = await client.query(
      `SELECT id, entity_id, association_kind, assertion_status
       FROM ioc_source_attributions
       WHERE ioc_id = $1 AND ioc_observable_type = $2 AND entity_kind = $3
         AND feed_key = $4 AND evidence_ref_type = $5 AND evidence_ref_id = $6
         AND source_label_normalized = $7`,
      [ioc.id, ioc.observable_type, item.entity_kind, DIRECT_EVIDENCE_FEED_KEY, DIRECT_EVIDENCE_REF_TYPE, source.url, item.source_label_normalized]
    );
    const row = {
      ...base,
      ioc_id: Number(ioc.id),
      ioc_public_id: ioc.public_id,
      ioc_rows: iocRows.length,
      entity_id: resolved.entity.id,
      resolution_method: resolved.method,
      source_label: item.source_label,
      source_label_normalized: item.source_label_normalized,
      evidence_role: item.evidence_role
    };
    if (existing[0]) {
      const same = String(existing[0].entity_id || '') === resolved.entity.id
        && existing[0].association_kind === item.association_kind;
      planned.push({
        ...row,
        status: same ? DIRECT_EVIDENCE_STATUS.ALREADY_RECORDED : DIRECT_EVIDENCE_STATUS.SKIP,
        reason: same ? null : 'conflicting_existing_evidence',
        existing_assertion_id: existing[0].id
      });
      continue;
    }
    planned.push({ ...row, status: DIRECT_EVIDENCE_STATUS.CREATE });
  }
  const count = (status) => planned.filter((p) => p.status === status).length;
  return {
    ok: true,
    source,
    items: planned,
    totals: {
      items: planned.length,
      create: count(DIRECT_EVIDENCE_STATUS.CREATE),
      already_recorded: count(DIRECT_EVIDENCE_STATUS.ALREADY_RECORDED),
      skipped: count(DIRECT_EVIDENCE_STATUS.SKIP)
    }
  };
}

/**
 * Write the planned `create` items in one transaction (re-planned under a
 * per-report lock, so a concurrent or repeated run cannot duplicate). Only new
 * rows are returned; existing assertions (incl. Pulse context) are untouched.
 */
export async function applyDirectEvidence(client, manifest, { recordedBy = 'direct-source-evidence' } = {}) {
  await client.query('BEGIN');
  try {
    const { source } = validateDirectEvidenceManifest(manifest);
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`talonhound:direct-evidence:${source.url}`]);
    const plan = await planDirectEvidence(client, manifest);
    if (!plan.ok) {
      await client.query('ROLLBACK');
      return { ...plan, created: [] };
    }
    const created = [];
    for (const item of plan.items.filter((i) => i.status === DIRECT_EVIDENCE_STATUS.CREATE)) {
      const metadata = {
        provider: DIRECT_EVIDENCE_PROVIDER,
        publisher: plan.source.publisher,
        published_at: plan.source.published_at,
        section: plan.source.section,
        row_label: item.row_label,
        value_as_published: item.value_as_published,
        evidence_role: item.evidence_role,
        recorded_via: 'record-direct-source-evidence'
      };
      const { rows } = await client.query(
        `INSERT INTO ioc_source_attributions (
           ioc_id, ioc_observable_type, entity_kind, source_label, source_label_normalized,
           entity_id, resolution_status, resolution_method, resolved_at, resolved_by,
           feed_key, source_name, evidence_ref_type, evidence_ref_id, evidence_url, evidence_title,
           association_kind, assertion_status, observed_at, is_backfill, provider_metadata
         ) VALUES (
           $1, $2, $3, $4, $5,
           $6::uuid, 'resolved', $7, NOW(), $8,
           $9, $10, $11, $12, $12, $13,
           $14, 'current', $15::timestamptz, false, $16::jsonb
         )
         ON CONFLICT (ioc_id, ioc_observable_type, entity_kind, feed_key,
                      evidence_ref_type, evidence_ref_id, source_label_normalized) DO NOTHING
         RETURNING id, first_ingested_at`,
        [
          item.ioc_id, item.observable_type, item.entity_kind, item.source_label, item.source_label_normalized,
          item.entity_id, item.resolution_method, recordedBy,
          DIRECT_EVIDENCE_FEED_KEY, plan.source.publisher, DIRECT_EVIDENCE_REF_TYPE, plan.source.url, plan.source.title,
          item.association_kind, plan.source.published_at, JSON.stringify(metadata)
        ]
      );
      if (rows[0]) created.push({ ...item, assertion_id: rows[0].id, recorded_at: rows[0].first_ingested_at });
    }
    await client.query('COMMIT');
    return { ...plan, created };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  }
}

/** One IOC-scoped audit event per newly recorded assertion (none on retries). */
export function directEvidenceAuditEvents(result, { actorUsername = 'direct-source-evidence' } = {}) {
  return (result?.created || []).map((item) => ({
    action: item.entity_kind === ENTITY_KIND.THREAT_ACTOR
      ? AUDIT_ACTION.IOC_THREAT_ACTOR_DIRECT_SOURCE_EVIDENCE_RECORDED
      : AUDIT_ACTION.IOC_MALWARE_FAMILY_DIRECT_SOURCE_EVIDENCE_RECORDED,
    entityType: AUDIT_ENTITY.IOC,
    entityId: String(item.ioc_id),
    entityDisplay: `${item.observable_type} · ${item.value}`,
    source: 'system',
    actorUsername,
    actorRole: 'admin',
    metadata: {
      ioc_id: item.ioc_id,
      observable_type: item.observable_type,
      ioc_value: item.value,
      ioc_public_id: item.ioc_public_id,
      operation: 'direct_source_evidence',
      // Publisher evidence: a source claim, not analyst attribution.
      attribution: 'source_reported',
      relationship_scope: 'direct',
      association_kind: item.association_kind,
      entity_kind: item.entity_kind,
      entity_id: item.entity_id,
      entity_name: item.entity_name,
      source_label: item.source_label,
      resolution_method: item.resolution_method,
      assertion_id: item.assertion_id,
      source: {
        publisher: result.source.publisher,
        title: result.source.title,
        url: result.source.url,
        published_at: result.source.published_at,
        section: result.source.section,
        row_label: item.row_label,
        value_as_published: item.value_as_published
      }
    }
  }));
}

export function formatDirectEvidencePlan(plan) {
  if (!plan.ok) return ['[direct-evidence] manifest rejected:', ...plan.errors.map((e) => `  - ${e}`)];
  const lines = [
    `[direct-evidence] source: ${plan.source.publisher} — ${plan.source.title} (${plan.source.published_at})`,
    `[direct-evidence] ${plan.source.url}`,
    `[direct-evidence] items=${plan.totals.items} create=${plan.totals.create} already_recorded=${plan.totals.already_recorded} skipped=${plan.totals.skipped}`
  ];
  for (const i of plan.items) {
    const ioc = i.ioc_id ? ` ioc=${i.ioc_id}${i.ioc_rows > 1 ? ` (${i.ioc_rows} rows)` : ''}` : '';
    const why = i.reason ? ` reason=${i.reason}${i.resolved_to ? `(${i.resolved_to})` : ''}` : '';
    lines.push(`  ${i.status.padEnd(16)} ${i.entity_name} · ${i.association_kind} · ${i.observable_type} ${i.value || i.value_as_published} · "${i.row_label}"${ioc}${why}`);
  }
  return lines;
}
