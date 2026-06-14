/** Threat classification slug normalization + DB-backed dictionary registry. */

export const UNKNOWN_THREAT_CLASSIFICATION = 'unknown';

/** Legacy free-text / tag values → canonical slug before dictionary lookup. */
const LEGACY_NORMALIZE_MAP = Object.freeze({
  c2: 'command_and_control',
  command_and_control: 'command_and_control',
  'command and control': 'command_and_control',
  scanner: 'scanner_recon',
  scanner_recon: 'scanner_recon',
  suspicious_infra: 'suspicious_infrastructure',
  suspicious_infrastructure: 'suspicious_infrastructure',
  test: 'benign_test',
  benign_test: 'benign_test',
  exploit_explitation: 'exploit',
  'exploit / explitation': 'exploit',
  'exploit / exploitation': 'exploit'
});

/** @type {Map<string, { slug: string, name: string, active: boolean, system_default: boolean, sort_order: number }> | null} */
let registryCache = null;

export function normalizeClassificationSlug(raw, { defaultValue = UNKNOWN_THREAT_CLASSIFICATION } = {}) {
  if (raw == null || raw === '') return defaultValue;
  let s = String(raw).trim().toLowerCase();
  if (s === 'not selected' || s === '— not selected —') return UNKNOWN_THREAT_CLASSIFICATION;
  s = s.replace(/[\s-]+/g, '_');
  if (LEGACY_NORMALIZE_MAP[s]) return LEGACY_NORMALIZE_MAP[s];
  if (/^[a-z0-9_]+$/.test(s)) return s;
  return defaultValue;
}

/** @deprecated use normalizeClassificationSlug */
export function normalizeThreatClassification(raw, opts) {
  return normalizeClassificationSlug(raw, opts);
}

export function normalizeThreatClassificationSlugInput(raw) {
  return String(raw || '')
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, '_')
    .replace(/[^a-z0-9_]+/g, '_')
    .replace(/^_+|_+$/g, '');
}

export function invalidateThreatClassificationRegistry() {
  registryCache = null;
}

export async function loadThreatClassificationRegistry(pool) {
  const { rows } = await pool.query(
    `SELECT slug, name, active, system_default, sort_order
     FROM threat_classifications
     ORDER BY sort_order ASC, name ASC`
  );
  const map = new Map();
  for (const row of rows) {
    map.set(row.slug, {
      slug: row.slug,
      name: row.name,
      active: Boolean(row.active),
      system_default: Boolean(row.system_default),
      sort_order: Number(row.sort_order) || 0
    });
  }
  registryCache = map;
  return map;
}

export async function ensureThreatClassificationRegistry(pool) {
  if (registryCache) return registryCache;
  return loadThreatClassificationRegistry(pool);
}

function fallbackLabel(slug) {
  if (slug === UNKNOWN_THREAT_CLASSIFICATION) return 'Unknown';
  return String(slug).replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

export function lookupThreatClassificationEntry(slug) {
  return registryCache?.get(slug) || null;
}

export async function listActiveThreatClassifications(pool) {
  const reg = await ensureThreatClassificationRegistry(pool);
  return [...reg.values()]
    .filter((x) => x.active)
    .sort((a, b) => a.sort_order - b.sort_order || a.name.localeCompare(b.name))
    .map((x) => ({
      value: x.slug,
      label: x.name,
      system_default: x.system_default
    }));
}

export async function validateThreatClassificationSlug(pool, raw, { requireActive = true } = {}) {
  const slug = normalizeClassificationSlug(raw);
  if (slug === UNKNOWN_THREAT_CLASSIFICATION) {
    return { ok: true, value: slug };
  }
  const reg = await ensureThreatClassificationRegistry(pool);
  const entry = reg.get(slug);
  if (!entry) {
    return { ok: false, error: `threat_classification must be a valid active classification slug (unknown allowed)` };
  }
  if (requireActive && !entry.active) {
    return { ok: false, error: `threat classification "${slug}" is inactive and cannot be assigned to new IOCs` };
  }
  return { ok: true, value: slug };
}

/** @deprecated use validateThreatClassificationSlug */
export async function validateThreatClassification(pool, raw, opts) {
  return validateThreatClassificationSlug(pool, raw, opts);
}

export function threatClassificationLabelFromRow(row) {
  if (row?.threat_classification_label) return row.threat_classification_label;
  const slug = normalizeClassificationSlug(row?.threat_classification);
  const cached = lookupThreatClassificationEntry(slug);
  return cached?.name || fallbackLabel(slug);
}

export function threatClassificationLabel(value) {
  const slug = normalizeClassificationSlug(value);
  const cached = lookupThreatClassificationEntry(slug);
  return cached?.name || fallbackLabel(slug);
}

export function buildThreatClassificationResponseFields(rowOrSlug) {
  const slug = typeof rowOrSlug === 'string'
    ? normalizeClassificationSlug(rowOrSlug)
    : normalizeClassificationSlug(rowOrSlug?.threat_classification);
  const cached = lookupThreatClassificationEntry(slug);
  const label = (typeof rowOrSlug === 'object' && rowOrSlug?.threat_classification_label)
    ? rowOrSlug.threat_classification_label
    : (cached?.name || fallbackLabel(slug));
  let active = cached?.active;
  if (typeof rowOrSlug === 'object' && rowOrSlug?.threat_classification_active != null) {
    active = Boolean(rowOrSlug.threat_classification_active);
  }
  return {
    threat_classification: slug,
    threat_classification_label: label,
    threat_classification_active: active ?? true,
    primary_threat_classification: slug
  };
}

/** @deprecated alias */
export function threatClassificationResponseFields(rowOrSlug) {
  return buildThreatClassificationResponseFields(rowOrSlug);
}

/** @deprecated */
export function listThreatClassifications() {
  if (!registryCache) return [{ value: UNKNOWN_THREAT_CLASSIFICATION, label: 'Unknown', system_default: true }];
  return listActiveThreatClassificationsSync();
}

function listActiveThreatClassificationsSync() {
  return [...registryCache.values()]
    .filter((x) => x.active)
    .sort((a, b) => a.sort_order - b.sort_order || a.name.localeCompare(b.name))
    .map((x) => ({ value: x.slug, label: x.name, system_default: x.system_default }));
}
