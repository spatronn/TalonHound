/**
 * Section-tree annotation over canonical document blocks.
 *
 * Each content block receives:
 *   - section_path: heading texts from root → nearest ancestor
 *   - authoritative_ancestor_id / authoritative_zone: nearest strong IOC ancestor
 *   - tree_zone: structural zone for this block (authoritative or report_body / negative)
 *
 * Does not mutate the caller's blocks. Does not decide Indicator membership.
 */

import {
  classifyHeadingText,
  STRONG_IOC_ZONES,
  NEGATIVE_ZONES,
  detectRepeatedHeaderFooterBlockIds
} from '../documentZones.js';
import {
  classifySectionRole,
  zoneForSectionRole,
  isIndicatorValueLine,
  isObservableListLine,
  isAnnotatedIndicatorRowLine
} from '../indicatorScope.js';
import { collapseLetterSpacing } from '../pdfLayout.js';
import { refangTextForExtraction } from '../defang.js';
import { SECTION_TREE_VERSION } from './version.js';

const AUTHORITATIVE = STRONG_IOC_ZONES;

/** Intent vocabulary for synthetic subgroup labels (not publisher names). */
const GROUP_LABEL_RE =
  /\b(?:domains?|ips?|ip\s+addresses?|addresses?|urls?|hash(?:es)?|hosts?|hostnames?|servers?|c2|indicators?|iocs?|samples?|files?|infrastructure|payloads?|droppers?|loaders?|malware|phishing|md5|sha-?\d*)\b/i;

const OBSERVABLE_RE =
  /https?:\/\/|(?:\d{1,3}\.){3}\d{1,3}|\b[a-f0-9]{32,64}\b|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/i;

const MAX_TRACE = 80;

function textOf(b) {
  return collapseLetterSpacing(String(b?.text || '').trim());
}

function isChrome(b, chromeIds) {
  return !b || b.layout === 'page_edge' || (b.id && chromeIds.has(b.id));
}

function documentUsesInferredLevels(doc) {
  return String(doc?.meta?.adapter || doc?.meta?.extractor || '').includes('pdf');
}

function looksHeadingLike(b) {
  if (!b) return false;
  if (b.type === 'heading') return true;
  if (b.type !== 'paragraph' && b.type !== 'caption') return false;
  const t = textOf(b);
  if (!t || t.length > 90 || /[.!?。]$/.test(t)) return false;
  // Short observable-only lines are content, not headings.
  if (isIndicatorValueLine(t) || isObservableListLine(t)) return false;
  if (OBSERVABLE_RE.test(refangTextForExtraction(t)) && t.length < 48) return false;
  return true;
}

function isInventoryish(b) {
  if (!b || b.type === 'heading') return false;
  const t = textOf(b);
  if (!t) return false;
  if (b.layout === 'observable_row') return true;
  if (isIndicatorValueLine(t) || isObservableListLine(t) || isAnnotatedIndicatorRowLine(t)) return true;
  if (
    (b.type === 'list' || b.type === 'list_item' || b.type === 'paragraph') &&
    OBSERVABLE_RE.test(refangTextForExtraction(t)) &&
    t.length <= 200
  ) {
    return true;
  }
  // Filename / archive inventory lead-in (hash often on the next line).
  if (/\.(?:exe|dll|zip|rar|7z|js|vbs|ps1|csproj|conf|apk|msi|scr|bat|cmd)\b/i.test(t) && t.length <= 160) {
    return true;
  }
  if (b.type === 'table') return true;
  return false;
}

function lookAheadInventory(blocks, i, chromeIds, depth = 4) {
  let seen = 0;
  for (let j = i + 1; j < blocks.length && seen < depth; j += 1) {
    const b = blocks[j];
    if (isChrome(b, chromeIds)) continue;
    if (b.type === 'heading') return false;
    seen += 1;
    if (isInventoryish(b)) return true;
  }
  return false;
}

function headingLevel(b, stack) {
  if (Number.isInteger(b.level)) return b.level;
  if (stack.length) return stack[stack.length - 1].level + 1;
  return 2;
}

function zoneForHeading(text, isRealHeading) {
  const role = classifySectionRole(text);
  const fromRole = zoneForSectionRole(role);
  if (fromRole) return { zone: fromRole, role };
  const z = classifyHeadingText(text, { isHeading: isRealHeading });
  return { zone: z, role: role || null };
}

function nearestAuthoritative(stack) {
  for (let i = stack.length - 1; i >= 0; i -= 1) {
    if (stack[i].authoritative && AUTHORITATIVE.has(stack[i].zone)) return stack[i];
  }
  return null;
}

function annotateContentFields(b, stack) {
  const auth = nearestAuthoritative(stack);
  b.section_path = stack.map((s) => s.text);
  b.authoritative_ancestor_id = auth?.id || null;
  b.authoritative_zone = auth?.zone || null;
  b.tree_zone = auth?.zone || 'report_body';
}

/**
 * @param {{ blocks?: object[], meta?: object }} doc
 * @param {{ inferredLevels?: boolean }} [opts]
 */
export function annotateSectionTree(doc, opts = {}) {
  const sourceBlocks = Array.isArray(doc?.blocks) ? doc.blocks : [];
  const chromeIds = detectRepeatedHeaderFooterBlockIds(sourceBlocks);
  const inferredLevels = opts.inferredLevels === true || documentUsesInferredLevels(doc);
  const blocks = sourceBlocks.map((b) => ({ ...b }));
  /** @type {{ id: string, text: string, level: number, zone: string|null, role: string|null, authoritative: boolean, synthetic: boolean }[]} */
  const stack = [];
  let authoritativeOpenings = 0;
  const trace = [];

  const pushTrace = (entry) => {
    if (trace.length < MAX_TRACE) trace.push(entry);
  };

  for (let i = 0; i < blocks.length; i += 1) {
    const b = blocks[i];
    if (isChrome(b, chromeIds)) {
      b.tree_zone = 'header_footer';
      b.section_path = [];
      b.authoritative_ancestor_id = null;
      b.authoritative_zone = null;
      continue;
    }

    const t = textOf(b);
    const isRealHeading = b.type === 'heading';
    if (!(looksHeadingLike(b) && t)) {
      annotateContentFields(b, stack);
      continue;
    }

    const { zone, role } = zoneForHeading(t, isRealHeading);
    const level = headingLevel(b, stack);
    const parentAuth = nearestAuthoritative(stack);
    const groupLabel = GROUP_LABEL_RE.test(t);
    const inventoryNext = lookAheadInventory(blocks, i, chromeIds);

    // Subgroup continuation under an open appendix: group-label vocabulary
    // and/or inventory look-ahead. Real same-level HTML siblings that name a
    // new topic (no group label, no inventory) close scope below.
    let treatAsSubgroup = false;
    if (parentAuth) {
      const deeper =
        Number.isInteger(b.level) &&
        Number.isInteger(parentAuth.level) &&
        b.level > parentAuth.level;
      const levelUnknown =
        !Number.isInteger(b.level) ||
        !Number.isInteger(parentAuth.level) ||
        (inferredLevels && Number.isInteger(b.level) && b.level === parentAuth.level);
      if (deeper || levelUnknown || !isRealHeading) {
        treatAsSubgroup = groupLabel || inventoryNext || (zone && AUTHORITATIVE.has(zone));
      }
    }

    if (isRealHeading && Number.isInteger(b.level) && !inferredLevels) {
      // DOM hierarchy: pop to parent of this heading.
      while (stack.length && stack[stack.length - 1].level >= level) {
        // Keep appendix parent when this heading is a nested subgroup.
        if (treatAsSubgroup && stack[stack.length - 1].authoritative) break;
        stack.pop();
      }
    } else if (isRealHeading && (inferredLevels || !Number.isInteger(b.level))) {
      if (zone && NEGATIVE_ZONES.has(zone)) {
        while (stack.length) stack.pop();
      } else if (zone && AUTHORITATIVE.has(zone) && !treatAsSubgroup) {
        while (stack.length && !AUTHORITATIVE.has(stack[stack.length - 1].zone)) stack.pop();
        while (stack.length && stack[stack.length - 1].level >= level && !stack[stack.length - 1].authoritative) {
          stack.pop();
        }
      } else if (!treatAsSubgroup && zone && !AUTHORITATIVE.has(zone) && !NEGATIVE_ZONES.has(zone)) {
        // Non-IOC real heading with unknown hierarchy under appendix: leave
        // appendix open but do not push a competing authoritative node.
        annotateContentFields(b, stack);
        b.tree_is_heading = true;
        b.tree_heading_zone = zone;
        pushTrace({
          block_id: b.id,
          decision: 'skip_non_ioc_heading',
          zone,
          level,
          reason: 'unknown_hierarchy_non_authoritative'
        });
        continue;
      }
    } else if (!isRealHeading) {
      // Synthetic / bold label.
      if (zone && NEGATIVE_ZONES.has(zone)) {
        while (stack.length) stack.pop();
      } else if (parentAuth && treatAsSubgroup) {
        // nest under appendix — do not clear
      } else if (parentAuth && zone && !AUTHORITATIVE.has(zone) && !treatAsSubgroup) {
        annotateContentFields(b, stack);
        b.tree_is_heading = true;
        b.tree_heading_zone = zone;
        pushTrace({
          block_id: b.id,
          decision: 'synthetic_narrative_under_appendix',
          zone,
          opened_by: parentAuth.id
        });
        continue;
      }
    }

    const inheritAuth = Boolean(parentAuth && treatAsSubgroup);
    const authoritative = Boolean(zone && AUTHORITATIVE.has(zone)) || inheritAuth;
    const effectiveZone = authoritative
      ? zone && AUTHORITATIVE.has(zone)
        ? zone
        : parentAuth?.zone || zone
      : zone && NEGATIVE_ZONES.has(zone)
        ? zone
        : null;

    const node = {
      id: b.id,
      text: t.slice(0, 160),
      level,
      zone: effectiveZone || null,
      role: role || null,
      authoritative: Boolean(effectiveZone && AUTHORITATIVE.has(effectiveZone)),
      synthetic: !isRealHeading
    };
    stack.push(node);
    if (node.authoritative) authoritativeOpenings += 1;
    pushTrace({
      block_id: b.id,
      decision: 'push',
      zone: node.zone,
      level: node.level,
      synthetic: node.synthetic,
      subgroup: treatAsSubgroup,
      inventory_next: inventoryNext
    });

    b.tree_is_heading = true;
    b.tree_heading_zone = node.zone;
    annotateContentFields(b, stack);
    if (node.authoritative) {
      b.authoritative_ancestor_id = node.id;
      b.authoritative_zone = node.zone;
      b.tree_zone = node.zone;
    }
  }

  return {
    version: SECTION_TREE_VERSION,
    blocks,
    meta: {
      authoritative_openings: authoritativeOpenings,
      has_authoritative_scope: authoritativeOpenings > 0,
      inferred_levels: inferredLevels,
      trace
    }
  };
}
