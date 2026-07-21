import {
  categoryToLegacyType,
  formatTagSourceLabels,
  isValidCategory,
  normalizeTagName,
  normalizeTagSlug,
  parseNormalizedTagName,
  toPublicTag
} from './tagHelpers.js';

const TAG_ROW_COLS = `id, name, slug, description, color, category, type, enabled, created_origin, created_at, updated_at`;

/**
 * Parse raw tags= CSV from a feed evidence note (pipe-delimited key=value segments).
 * @returns {string[]}
 */
export function parseRawTagsFromNote(note) {
  if (!note || typeof note !== 'string') return [];
  for (const part of note.split(' | ')) {
    const eqIdx = part.indexOf('=');
    if (eqIdx <= 0) continue;
    const key = part.slice(0, eqIdx).trim().toLowerCase();
    if (key !== 'tags') continue;
    const val = part.slice(eqIdx + 1).trim();
    if (!val) return [];
    return val.split(',').map((t) => t.trim()).filter(Boolean);
  }
  return [];
}

/**
 * Build a unique slug when the base slug is already taken by a different name.
 */
export async function resolveUniqueSlug(client, baseSlug, { excludeTagId = null } = {}) {
  let slug = baseSlug || 'tag';
  if (!slug) slug = 'tag';
  for (let i = 0; i < 20; i += 1) {
    const candidate = i === 0 ? slug : `${slug}-${i + 1}`;
    const { rows } = await client.query(
      `SELECT id FROM tags WHERE slug = $1 ${excludeTagId ? 'AND id <> $2' : ''} LIMIT 1`,
      excludeTagId ? [candidate, excludeTagId] : [candidate]
    );
    if (!rows.length) return candidate;
  }
  return `${slug}-${Date.now()}`;
}

/**
 * Find or create a catalog tag. Never re-enables an inactive tag.
 * @returns {Promise<{ tag: object, created: boolean, existing: boolean }>}
 */
export async function ensureCatalogTag(client, {
  name,
  createdOrigin = 'manual',
  category = 'custom',
  description = null,
  color = null,
  enabled = true
} = {}) {
  const parsed = parseNormalizedTagName(name);
  if (!parsed.ok) {
    const err = new Error(parsed.error === 'too_long' ? 'Tag name is too long' : 'Tag name is required');
    err.code = parsed.error === 'too_long' ? 'TAG_TOO_LONG' : 'TAG_EMPTY';
    throw err;
  }
  const normalized = parsed.name;
  const origin = createdOrigin === 'integration' ? 'integration' : 'manual';
  const cat = isValidCategory(category) ? String(category).trim().toLowerCase() : 'custom';
  const legacyType = categoryToLegacyType(cat);

  const existingQ = await client.query(
    `SELECT ${TAG_ROW_COLS} FROM tags WHERE name = $1 LIMIT 1`,
    [normalized]
  );
  if (existingQ.rows[0]) {
    return { tag: existingQ.rows[0], created: false, existing: true };
  }

  const baseSlug = normalizeTagSlug(normalized) || 'tag';
  const slug = await resolveUniqueSlug(client, baseSlug);

  try {
    const insertQ = await client.query(
      `INSERT INTO tags (name, slug, type, category, description, color, enabled, created_origin, updated_at)
       VALUES ($1, $2, $3::tag_type, $4, $5, $6, $7, $8, NOW())
       RETURNING ${TAG_ROW_COLS}`,
      [
        normalized,
        slug,
        legacyType,
        cat,
        description,
        color,
        origin === 'integration' ? true : enabled !== false,
        origin
      ]
    );
    return { tag: insertQ.rows[0], created: true, existing: false };
  } catch (err) {
    if (err.code === '23505') {
      const raceQ = await client.query(
        `SELECT ${TAG_ROW_COLS} FROM tags WHERE name = $1 LIMIT 1`,
        [normalized]
      );
      if (raceQ.rows[0]) return { tag: raceQ.rows[0], created: false, existing: true };
    }
    throw err;
  }
}

/**
 * Upsert an IOC↔tag assignment with origin/source uniqueness.
 * @returns {Promise<{ inserted: boolean }>}
 */
export async function ensureIocTagAssignment(client, {
  iocId,
  observableType,
  tagId,
  origin,
  sourceName = null,
  createdBy = null
} = {}) {
  const ioc = Number(iocId);
  const tag = Number(tagId);
  const obs = String(observableType || '').trim();
  const orig = origin === 'integration' ? 'integration' : 'manual';
  if (!ioc || !tag || !obs) {
    const err = new Error('Invalid tag assignment');
    err.code = 'TAG_ASSIGN_INVALID';
    throw err;
  }

  if (orig === 'manual') {
    const q = await client.query(
      `INSERT INTO ioc_tags (ioc_id, ioc_observable_type, tag_id, origin, source_name, source_key, created_by)
       VALUES ($1, $2, $3, 'manual', NULL, '', $4)
       ON CONFLICT (ioc_id, tag_id, origin, source_key)
       DO NOTHING
       RETURNING tag_id`,
      [ioc, obs, tag, createdBy]
    );
    return { inserted: Boolean(q.rowCount) };
  }

  const source = String(sourceName || '').trim();
  if (!source) {
    const err = new Error('source_name is required for integration tag assignments');
    err.code = 'TAG_SOURCE_REQUIRED';
    throw err;
  }

  const sourceKey = source.toLowerCase();
  const q = await client.query(
    `INSERT INTO ioc_tags (ioc_id, ioc_observable_type, tag_id, origin, source_name, source_key, created_by)
     VALUES ($1, $2, $3, 'integration', $4, $5, NULL)
     ON CONFLICT (ioc_id, tag_id, origin, source_key)
     DO NOTHING
     RETURNING tag_id`,
    [ioc, obs, tag, source, sourceKey]
  );
  return { inserted: Boolean(q.rowCount) };
}

/**
 * Sync catalog + integration assignments from a feed evidence note's tags= field.
 * Does not re-enable inactive catalog tags.
 */
export async function syncIntegrationTagsFromNote(client, {
  iocId,
  observableType,
  sourceName,
  note
} = {}) {
  const source = String(sourceName || '').trim();
  if (!iocId || !observableType || !source) return { synced: 0, tags: [] };

  const rawTags = parseRawTagsFromNote(note);
  if (!rawTags.length) return { synced: 0, tags: [] };

  const synced = [];
  for (const raw of rawTags) {
    const parsed = parseNormalizedTagName(raw);
    if (!parsed.ok) continue;
    const { tag } = await ensureCatalogTag(client, {
      name: parsed.name,
      createdOrigin: 'integration',
      category: 'custom'
    });
    await ensureIocTagAssignment(client, {
      iocId,
      observableType,
      tagId: tag.id,
      origin: 'integration',
      sourceName: source
    });
    synced.push(tag);
  }
  return { synced: synced.length, tags: synced };
}

/**
 * Aggregate Tag Manager source labels from created_origin + assignment rows.
 * @param {{ created_origin?: string, assignment_origins?: string[], assignment_sources?: string[] }} row
 */
export function aggregateTagSources(row = {}) {
  const labels = [];
  const createdOrigin = row.created_origin === 'integration' ? 'integration' : 'manual';
  const origins = Array.isArray(row.assignment_origins) ? row.assignment_origins : [];
  const sources = Array.isArray(row.assignment_sources) ? row.assignment_sources : [];

  const hasManualAssignment = origins.some((o) => o === 'manual');
  if (createdOrigin === 'manual' || hasManualAssignment) labels.push('Manual');

  for (const s of sources) {
    const name = String(s || '').trim();
    if (name) labels.push(name);
  }

  // Feed-created tag with no assignments yet still shows as integration provenance.
  if (createdOrigin === 'integration' && !sources.length && !hasManualAssignment && !labels.includes('Manual')) {
    // Keep empty feeds out of "Manual"; UI can show Integration if needed — prefer no fake Manual.
  }

  return formatTagSourceLabels(labels);
}

/**
 * Map admin list query rows (with array_agg fields) to public tags + sources.
 */
export function mapAdminTagRow(row) {
  const sources = aggregateTagSources({
    created_origin: row.created_origin,
    assignment_origins: row.assignment_origins || [],
    assignment_sources: (row.assignment_sources || []).filter(Boolean)
  });
  return toPublicTag(row, { sources });
}

/**
 * Disabled catalog tag names (normalized) for filtering feed badges.
 * @returns {Promise<Set<string>>}
 */
export async function loadDisabledTagNameSet(client, names = []) {
  const normalized = [...new Set(
    (names || []).map((n) => normalizeTagName(n)).filter(Boolean)
  )];
  if (!normalized.length) return new Set();
  const { rows } = await client.query(
    `SELECT name FROM tags WHERE enabled = FALSE AND name = ANY($1::text[])`,
    [normalized]
  );
  return new Set(rows.map((r) => r.name));
}

/**
 * Remove feed_intelligence tags that match disabled catalog names.
 */
export function filterFeedIntelligenceByDisabledTags(feedIntelligence, disabledNames) {
  const disabled = disabledNames instanceof Set
    ? disabledNames
    : new Set([...(disabledNames || [])].map((n) => normalizeTagName(n)).filter(Boolean));
  if (!feedIntelligence || !disabled.size) return feedIntelligence;
  const tags = Array.isArray(feedIntelligence.tags) ? feedIntelligence.tags : [];
  return {
    ...feedIntelligence,
    tags: tags.filter((t) => !disabled.has(normalizeTagName(t?.normalized || t?.tag)))
  };
}

export { normalizeTagName, parseNormalizedTagName, formatTagSourceLabels, toPublicTag };
