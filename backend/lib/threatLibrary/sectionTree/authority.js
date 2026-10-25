/**
 * Authoritative section-tree scope application.
 *
 * Remaps occurrence zones from heading ancestry, then re-runs evidence policy
 * so MODE A/B membership uses a single authority system (not an additive patch
 * on top of linear zones).
 */

import { applyEvidencePolicy, buildCandidateEvidenceRecord } from '../evidencePolicy.js';
import { DELEGATED_IOC_ZONE, NEGATIVE_ZONES, STRONG_IOC_ZONES } from '../documentZones.js';
import {
  isIndicatorValueLine,
  isAnnotatedIndicatorRowLine,
  isObservableListLine,
  lineContainingObservable,
  textDescribesValueAsBenign
} from '../indicatorScope.js';
import { refangTextForExtraction } from '../defang.js';
import { annotateSectionTree } from './annotate.js';
import {
  SECTION_TREE_SCOPE_ENGINE_VERSION,
  SECTION_TREE_VERSION,
  SCOPE_ENGINE_SECTION_TREE
} from './version.js';

const HASH_TYPES = new Set(['md5', 'sha1', 'sha256', 'sha512']);

function rowShaped(text) {
  const t = String(text || '').trim();
  if (!t) return false;
  if (isIndicatorValueLine(t) || isAnnotatedIndicatorRowLine(t) || isObservableListLine(t)) return true;
  return t.length <= 96 && !/[.!?。]/.test(t);
}

function blockIsFocusedOnValue(blockText, value) {
  const raw = refangTextForExtraction(String(blockText || ''))
    .replace(/\[\.\]/g, '.')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
  const v = String(value || '').trim().toLowerCase();
  if (!raw || !v) return false;
  if (raw === v) return true;
  if (raw.startsWith(v) && raw.length <= v.length + 80) return true;
  if (raw.endsWith(v) && raw.length <= v.length + 80) return true;
  if (isIndicatorValueLine(blockText) && raw.includes(v) && raw.length <= v.length + 16) return true;
  return false;
}

/**
 * Publisher inventory placement (table / typed list row / endpoint).
 * Do not treat generic HTML `list` blocks as inventory — reports often wrap
 * narrative bullets in <ul>/<li>.
 */
function isInventoryPlacement(occ, block) {
  const form = String(occ?.form || '');
  if (form === 'table_row' || form === 'list_row' || form === 'ip_port') return true;
  if (String(occ?.block_type || '') === 'list_item' || occ?.layout === 'observable_row') return true;
  if (String(block?.type || '') === 'table') return true;
  return false;
}

function textContainsValue(text, value) {
  const raw = refangTextForExtraction(String(text || ''))
    .replace(/\[\.\]/g, '.')
    .toLowerCase();
  const v = String(value || '').trim().toLowerCase();
  return Boolean(raw && v && raw.includes(v));
}

/**
 * Publisher IOC annotation led by the observable itself:
 * "8.218.50[.]207 - Staging server (Alibaba Cloud, Hong Kong)"
 * (isAnnotatedIndicatorRowLine rejects these when the note has many tokens.)
 */
function isHttpExampleLine(text) {
  const line = String(text || '').trim();
  if (!line) return false;
  if (/^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|curl)\b/i.test(line)) return true;
  if (/^(?:\d+\s+){1,10}\|\s*(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|curl|\{)/i.test(line)) return true;
  return false;
}

function isObservableLedAnnotation(text, value) {
  const line = String(lineContainingObservable(text, value) || text || '').trim();
  const v = String(value || '').trim();
  if (!line || !v || line.length > 200) return false;
  if (isHttpExampleLine(line)) return false;
  const refanged = refangTextForExtraction(line).replace(/\[\.\]/g, '.').trim();
  const vl = v.toLowerCase();
  const lower = refanged.toLowerCase();
  if (!lower.startsWith(vl)) return false;
  const after = refanged.slice(v.length).trim();
  if (!after) return true;
  return /^[-–—|:·]\s+\S/.test(after);
}

function shouldForceStructuralRow(candidateType, text, value, occ, block) {
  if (isInventoryPlacement(occ, block)) return true;
  const type = String(candidateType || '').toLowerCase();
  const line = lineContainingObservable(text, value) || text;
  // Publisher annotation rows: "8.218.50[.]207 - Staging server …"
  if (
    isIndicatorValueLine(line) ||
    isAnnotatedIndicatorRowLine(line) ||
    isObservableListLine(line) ||
    isObservableLedAnnotation(line, value)
  ) {
    return true;
  }
  // Appendix metadata rows: "SHA256 hash: <digest> File size: …"
  if (HASH_TYPES.has(type) && textContainsValue(text, value)) {
    if (
      String(text || '').length <= 280 ||
      /(?:md5|sha-?1|sha-?256|sha-?512|hash)\s*:/i.test(text)
    ) {
      return true;
    }
  }
  const focused = rowShaped(line) && blockIsFocusedOnValue(line, value);
  if (!focused) return false;
  if (HASH_TYPES.has(type)) return true;
  return false;
}

const NETWORK_OR_HASH_DECLARED = new Set(['ip', 'ipv6', 'cidr', 'domain', 'url', 'md5', 'sha1', 'sha256', 'hash']);
/** Column headers that declare indicator / infrastructure values. */
const INDICATOR_COLUMN_HEADER_RE =
  /\b(?:domains?|hosts?|hostnames?|ips?|ip\s+address(?:es)?|addresses|urls?|uris?|c2s?|c&c|servers?|infrastructure|endpoints?|indicators?|iocs?|observables?|sha-?(?:1|256)|md5|hash(?:es)?)\b/i;

/**
 * Row label of a key-value ("Property | Value") table that names this
 * value's own type: "SHA256 | <hex>", "MD5: <hex>", "C2 | <host>". The label
 * cell is the type declaration of that row, the same way a typed column
 * header is for a column. Hash labels must match the hash length.
 */
const KEY_VALUE_TYPE_LABELS = [
  [/^(?:sha-?256(?:\s+hash)?|sha2-256)$/i, new Set(['sha256'])],
  [/^(?:sha-?1(?:\s+hash)?)$/i, new Set(['sha1'])],
  [/^(?:md-?5(?:\s+hash)?)$/i, new Set(['md5'])],
  [/^(?:ip(?:v4)?(?:\s+address)?|c2\s+ip)$/i, new Set(['ip'])],
  [/^(?:domain|domain\s+name|c2(?:\s+(?:domain|server|host))?|hostname)$/i, new Set(['domain', 'ip'])],
  [/^(?:url|c2\s+url|download\s+url|payload\s+url)$/i, new Set(['url'])]
];

/**
 * True when the table row's label cell (another column of the same row) is a
 * pure type label matching this candidate's type, and the table does not call
 * the described file / host legitimate ("Description | Legitimate Microsoft
 * binary", "Signed by Microsoft Corporation").
 * @param {object} candidate
 * @param {object} r table_rows entry for this value
 * @param {string} text the table block text
 * @param {string} value
 */
function keyValueRowDeclaresType(candidate, r, text, value) {
  const type = String(candidate.candidate_type || '').toLowerCase();
  const labels = (Array.isArray(r.cells) ? r.cells : [])
    .filter((cell) => cell && cell.column_index !== r.column_index)
    .map((cell) => String(cell.text || '').trim().replace(/[:：]\s*$/, ''));
  const declares = labels.some((label) =>
    KEY_VALUE_TYPE_LABELS.some(([re, types]) => re.test(label) && types.has(type))
  );
  if (!declares) return false;
  return !textDescribesValueAsBenign(text, [value, r.raw_value].filter(Boolean));
}

/**
 * Row placement that is a publisher assertion inside the delegated scope:
 * an ip:port endpoint, an observable-only list line, or a table cell of a
 * column the publisher typed as network / hash / indicator values ("Domain /
 * IP", "Key infrastructure", "URL", "SHA256"). Free-form value / config
 * columns ("Value", "Variable-name", "Name") assert nothing.
 * @param {object} candidate
 * @param {object} occ
 * @param {string} text block text
 * @param {string} value
 */
function delegatedStructuralRow(candidate, occ, text, value) {
  const form = String(occ?.form || '');
  if (form === 'ip_port') return true;
  if (form === 'table_row') {
    const rows = (Array.isArray(candidate.table_rows) ? candidate.table_rows : [])
      .concat(Array.isArray(candidate.evidence?.table_rows) ? candidate.evidence.table_rows : [])
      .filter((r) => r && r.table_id === occ.block_id);
    return rows.some((r) =>
      NETWORK_OR_HASH_DECLARED.has(String(r.declared_type || '').toLowerCase()) ||
      INDICATOR_COLUMN_HEADER_RE.test(String(r.column_header || '')) ||
      INDICATOR_COLUMN_HEADER_RE.test(String(r.type_cell || '')) ||
      keyValueRowDeclaresType(candidate, r, text, value)
    );
  }
  const line = lineContainingObservable(text, value) || text;
  return isIndicatorValueLine(line) || isObservableListLine(line);
}

/**
 * Apply section-tree ancestry as the sole authoritative occurrence-zone source.
 *
 * @param {object} document canonical document
 * @param {object[]} candidates linear-extraction candidates
 * @param {{ tree?: object }} [opts]
 * @returns {{
 *   candidates: object[],
 *   tree: object,
 *   has_authoritative_scope: boolean,
 *   scope_engine: string,
 *   scope_engine_version: string,
 *   section_tree_version: string,
 *   remapped_occurrences: number,
 *   demoted_occurrences: number
 * }}
 */
export function applySectionTreeAuthority(document, candidates, opts = {}) {
  const tree = opts.tree || annotateSectionTree(document);
  const byId = new Map(tree.blocks.map((b) => [b.id, b]));
  const hasAuth = tree.meta.has_authoritative_scope === true;
  let remappedOccurrences = 0;
  let demotedOccurrences = 0;
  let delegatedOccurrences = 0;

  const out = (candidates || []).map((c) => {
    const value = c.normalized_value || c.original_value;
    const occurrences = Array.isArray(c.occurrences)
      ? c.occurrences.map((o) => {
          const next = { ...o };
          const block = byId.get(o.block_id);
          const authZone = block?.authoritative_zone;
          const text = String(
            block?.text || o.evidence_text || o.text || c.original_value || c.normalized_value || ''
          );

          if (block?.negative_scope === true || (block?.tree_zone && NEGATIVE_ZONES.has(block.tree_zone))) {
            next.zone = block.tree_zone && NEGATIVE_ZONES.has(block.tree_zone) ? block.tree_zone : 'reference_section';
            next.zone_reason = 'section_tree_negative_ancestry';
            next.structural_row = false;
            next.row_shape = false;
            next.section_path = Array.isArray(block.section_path) ? block.section_path.slice(0, 8) : next.section_path;
            next.section_path_ids = Array.isArray(block.section_path_ids)
              ? block.section_path_ids.slice(0, 8)
              : next.section_path_ids;
            delete next.asserted;
            demotedOccurrences += 1;
            return next;
          }

          if (authZone && STRONG_IOC_ZONES.has(authZone)) {
            // Under tree-authoritative ancestry: zone follows ancestry.
            next.zone = authZone;
            next.zone_reason = 'section_tree_authoritative_ancestry';
            next.scope_opening_id = block.authoritative_ancestor_id || next.scope_opening_id || null;
            next.section_path = Array.isArray(block.section_path) ? block.section_path.slice(0, 8) : next.section_path;
            next.section_path_ids = Array.isArray(block.section_path_ids)
              ? block.section_path_ids.slice(0, 8)
              : next.section_path_ids;
            // Only inventory placements / focused hash|value lines may assert by
            // row shape. Short API/code URLs keep ancestry but lose stale row_shape
            // so evidence policy treats them as narrative under MODE A.
            if (authZone === DELEGATED_IOC_ZONE) {
              // Delegated scope: only publisher-typed inventory placements are
              // rows; everything else is read for its relation (operational
              // clause / sample statement) and never asserts by shape alone.
              // A section whose lead-in declares it lists indicators (tl-section-
              // tree-v7): its observables are the publisher's assertions —
              // download commands and config dumps included — unless the text
              // calls the value benign / legitimate.
              const declared = block?.declared_indicator_section === true;
              const row = declared
                ? !textDescribesValueAsBenign(text, [value].filter(Boolean))
                : !isHttpExampleLine(text) && delegatedStructuralRow(c, next, text, value);
              next.structural_row = row;
              next.row_shape = row;
              next.zone_reason = declared ? 'section_tree_declared_indicator_section' : 'section_tree_delegated_scope';
              delete next.asserted;
              delegatedOccurrences += 1;
              remappedOccurrences += 1;
              return next;
            }
            if (
              !isHttpExampleLine(text) &&
              shouldForceStructuralRow(c.candidate_type, text, value, next, block)
            ) {
              if (next.structural_row !== true) next.structural_row = true;
              if (next.row_shape !== true) next.row_shape = true;
            } else {
              next.structural_row = false;
              next.row_shape = false;
            }
            delete next.asserted;
            remappedOccurrences += 1;
            return next;
          }

          if (STRONG_IOC_ZONES.has(String(next.zone || ''))) {
            // Linear authority without tree ancestry → narrative body under MODE A.
            next.zone = 'report_body';
            next.zone_reason = 'section_tree_outside_authoritative_ancestry';
            delete next.asserted;
            demotedOccurrences += 1;
            return next;
          }

          // Non-strong zones: keep typing/layout signals; clear asserted for recompute.
          delete next.asserted;
          return next;
        })
      : [];

    const draft = {
      ...c,
      occurrences,
      document_has_authoritative_scope: hasAuth,
      // Force evidence policy to recompute publisher assertion from remapped zones.
      // Clear deterministic classification fields too: a linear-pass explicit /
      // malicious assessment from structural discovery must not survive when
      // section-tree demotes the occurrence out of authoritative scope
      // (AI classification has not run yet at this stage).
      source_assertion: undefined,
      evidence_strength: undefined,
      evidence_tier: undefined,
      policy_decision: undefined,
      assessment: undefined,
      decision_source: undefined,
      match_state: undefined,
      ai_needed: undefined,
      role: undefined,
      confidence: undefined,
      scope_engine: SCOPE_ENGINE_SECTION_TREE,
      scope_engine_version: SECTION_TREE_SCOPE_ENGINE_VERSION,
      section_tree_version: tree.version || SECTION_TREE_VERSION
    };
    const policed = applyEvidencePolicy(draft);
    policed.document_has_authoritative_scope = hasAuth;
    policed.scope_engine = SCOPE_ENGINE_SECTION_TREE;
    policed.scope_engine_version = SECTION_TREE_SCOPE_ENGINE_VERSION;
    policed.section_tree_version = tree.version || SECTION_TREE_VERSION;
    if (policed.evidence && typeof policed.evidence === 'object') {
      policed.evidence = {
        ...policed.evidence,
        document_has_authoritative_scope: hasAuth,
        scope_engine: SCOPE_ENGINE_SECTION_TREE,
        scope_engine_version: SECTION_TREE_SCOPE_ENGINE_VERSION,
        section_tree_version: tree.version || SECTION_TREE_VERSION
      };
    } else {
      policed.evidence = buildCandidateEvidenceRecord(policed);
      policed.evidence.scope_engine = SCOPE_ENGINE_SECTION_TREE;
      policed.evidence.scope_engine_version = SECTION_TREE_SCOPE_ENGINE_VERSION;
      policed.evidence.section_tree_version = tree.version || SECTION_TREE_VERSION;
    }
    return policed;
  });

  return {
    candidates: out,
    tree,
    has_authoritative_scope: hasAuth,
    scope_engine: SCOPE_ENGINE_SECTION_TREE,
    scope_engine_version: SECTION_TREE_SCOPE_ENGINE_VERSION,
    section_tree_version: tree.version || SECTION_TREE_VERSION,
    remapped_occurrences: remappedOccurrences,
    demoted_occurrences: demotedOccurrences,
    delegated_scope: tree.meta.delegated_scope === true,
    external_ioc_pointer: tree.meta.external_ioc_pointer === true,
    delegated_occurrences: delegatedOccurrences
  };
}
