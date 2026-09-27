/**
 * Explicit-table completeness diagnostics.
 *
 * Diagnostic only: this module never inserts, promotes, or re-validates
 * candidates. It records the IOC identities a valid explicit table asserted
 * *before* candidate `add()` can reject them, then compares that set to the
 * identities that actually materialized.
 */

export const DROPPED_ASSERTED_LIMIT = 40;
export const MISSING_IDENTITIES_LIMIT = 40;

export function explicitTableIdentityKey(type, value) {
  return `${String(type || '')}\0${String(value || '')}`;
}

export function formatExplicitTableIdentityKey(key) {
  return String(key || '').replace('\0', ':');
}

/**
 * @returns {{
 *   rememberAsserted: (type: string, value: string) => string,
 *   rememberDropped: (type: string, value: string, reason?: string) => void,
 *   finalize: (createdCandidates: object[]) => {
 *     candidates_created: number,
 *     explicit_identities: number,
 *     missing_identities: string[],
 *     dropped_asserted_identities: { type: string, value: string, reason: string }[],
 *     inconsistent: boolean
 *   }
 * }}
 */
export function createExplicitTableAssertionTracker() {
  /** @type {Map<string, { type: string, value: string }>} */
  const asserted = new Map();
  /** @type {Map<string, { type: string, value: string, reason: string }>} */
  const dropped = new Map();

  const rememberDropped = (type, value, reason) => {
    const key = explicitTableIdentityKey(type, value);
    if (dropped.has(key) || dropped.size >= DROPPED_ASSERTED_LIMIT) return;
    dropped.set(key, { type, value, reason: reason || 'rejected' });
  };

  return {
    rememberAsserted(type, value) {
      const key = explicitTableIdentityKey(type, value);
      if (!asserted.has(key)) asserted.set(key, { type, value });
      return key;
    },
    rememberDropped,
    finalize(createdCandidates) {
      const created = (createdCandidates || []).filter(
        (c) => Array.isArray(c.table_rows) && c.table_rows.some((r) => r.explicit)
      );
      const createdKeys = new Set(created.map((c) => explicitTableIdentityKey(c.candidate_type, c.normalized_value)));
      const missing = [];
      for (const [key, ident] of asserted) {
        if (createdKeys.has(key)) continue;
        missing.push(formatExplicitTableIdentityKey(key));
        if (!dropped.has(key)) rememberDropped(ident.type, ident.value, 'not_materialized');
      }
      return {
        candidates_created: created.length,
        explicit_identities: asserted.size,
        missing_identities: missing.slice(0, MISSING_IDENTITIES_LIMIT),
        dropped_asserted_identities: [...dropped.values()].slice(0, DROPPED_ASSERTED_LIMIT),
        inconsistent: missing.length > 0
      };
    }
  };
}

/** Zones where the publisher curated indicators (mirrors documentZones STRONG_IOC_ZONES). */
const CURATED_ZONES = new Set(['explicit_ioc_section', 'c2_section', 'sample_table', 'operational_infrastructure']);
export const DEGRADED_BLOCKS_LIMIT = 40;
/** A prose block inside a curated section warns only when it carries at least this many degraded values. */
export const DEGRADED_BLOCK_MIN_VALUES = 2;

const IOC_SHAPE_RE =
  /\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b|\b(?:hxxps?|https?):\/\/|\b(?:\d{1,3}\.){3}\d{1,3}\b|\[\.\]/gi;

function iocShapeCount(text) {
  return (String(text || '').match(IOC_SHAPE_RE) || []).length;
}

/**
 * Structural completeness diagnostics (never alters candidates): a curated
 * IOC section / table whose values did NOT become deterministic assertions
 * and were left to the model (or to nothing).
 *
 *  - `tables_not_interpreted`: a table inside a curated section, or holding
 *    IOC-shaped values under an indicator-looking header, that table
 *    semantics did not read as an explicit IOC table (with the reason).
 *  - `degraded_blocks`: a non-table block inside a curated section whose IOC
 *    candidates were not asserted and went to AI classification (>= 2 values,
 *    so a single narrative sentence in an appendix does not warn).
 *
 * Ordinary narrative outside curated sections never warns.
 * @param {object[]} blocks zone-annotated canonical blocks
 * @param {object[]} candidates finalized candidates (evidence policy applied)
 */
export function structuralCompleteness(blocks, candidates) {
  const tablesNotInterpreted = [];
  for (const b of blocks || []) {
    if (b.type !== 'table' || !b.table) continue;
    const interp = b.ioc_table || null;
    if (interp && interp.kind === 'ioc_table' && interp.explicit) continue;
    if (interp && (interp.kind === 'identifier_table' || interp.kind === 'artifact_table')) continue;
    const shapes = iocShapeCount(b.text);
    const curated = CURATED_ZONES.has(String(b.zone || ''));
    const indicatorHeader = Array.isArray(interp?.columns) && interp.columns.some((c) => c.method === 'header_unverified');
    if (!shapes || (!curated && !indicatorHeader)) continue;
    tablesNotInterpreted.push({
      block_id: b.id,
      zone: b.zone || null,
      section_heading: b.section_heading ? String(b.section_heading).slice(0, 120) : null,
      kind: interp?.kind || 'not_ioc_table',
      reason: interp?.reason || 'not_interpreted',
      ioc_shaped_values: shapes
    });
  }

  /** block id → degraded candidate keys */
  const perBlock = new Map();
  const blockById = new Map((blocks || []).map((b) => [b.id, b]));
  let degradedCandidates = 0;
  for (const c of candidates || []) {
    if (c.is_ioc === false || c.assessment === 'context_only') continue;
    if (!c.ai_needed) continue;
    const occ = Array.isArray(c.occurrences) ? c.occurrences : [];
    let counted = false;
    for (const o of occ) {
      if (o.asserted === true || !CURATED_ZONES.has(String(o.zone || ''))) continue;
      const block = blockById.get(o.block_id);
      if (!block) continue;
      if (!perBlock.has(block.id)) perBlock.set(block.id, new Set());
      perBlock.get(block.id).add(`${c.candidate_type}:${c.normalized_value}`);
      counted = true;
    }
    if (counted) degradedCandidates += 1;
  }
  const degradedBlocks = [];
  for (const [id, keys] of perBlock) {
    const b = blockById.get(id);
    const isTable = b.type === 'table';
    if (!isTable && keys.size < DEGRADED_BLOCK_MIN_VALUES) continue;
    degradedBlocks.push({
      block_id: id,
      block_type: b.type || null,
      zone: b.zone || null,
      section_heading: b.section_heading ? String(b.section_heading).slice(0, 120) : null,
      ai_needed_values: keys.size,
      examples: [...keys].slice(0, 5)
    });
  }
  const warning = tablesNotInterpreted.length > 0 || degradedBlocks.length > 0;
  return {
    warning,
    tables_not_interpreted: tablesNotInterpreted.slice(0, DEGRADED_BLOCKS_LIMIT),
    degraded_blocks: degradedBlocks.slice(0, DEGRADED_BLOCKS_LIMIT),
    degraded_candidates: degradedCandidates
  };
}
