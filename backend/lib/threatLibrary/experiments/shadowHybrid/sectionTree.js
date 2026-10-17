/**
 * Shadow section-tree annotator (EXPERIMENTAL — not used by production).
 *
 * Replaces fragile linear zone open/reset with heading ancestry:
 * each content block inherits the nearest authoritative ancestor in the
 * heading stack. Synthetic / bold subgroup labels under an open IOC appendix
 * become children instead of closing the appendix.
 *
 * This module must never be imported from pipeline.js / extractionRefresh.js.
 */

import {
  classifyHeadingText,
  STRONG_IOC_ZONES,
  NEGATIVE_ZONES,
  detectRepeatedHeaderFooterBlockIds
} from '../../documentZones.js';
import {
  classifySectionRole,
  zoneForSectionRole,
  isIndicatorValueLine,
  isObservableListLine,
  isAnnotatedIndicatorRowLine
} from '../../indicatorScope.js';
import { collapseLetterSpacing } from '../../pdfLayout.js';
import { refangTextForExtraction } from '../../defang.js';

export const SHADOW_SECTION_TREE_VERSION = 'tl-shadow-section-tree-v1';

const AUTHORITATIVE = STRONG_IOC_ZONES;
const GROUP_LABEL_RE =
  /\b(?:domains?|ips?|ip\s+addresses?|addresses?|urls?|hash(?:es)?|hosts?|hostnames?|servers?|c2|indicators?|iocs?|samples?|files?|infrastructure|payloads?|droppers?|loaders?|malware|phishing)\b/i;

const OBSERVABLE_RE =
  /https?:\/\/|(?:\d{1,3}\.){3}\d{1,3}|\b[a-f0-9]{32,64}\b|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/i;

function textOf(b) {
  return collapseLetterSpacing(String(b?.text || '').trim());
}

function isChrome(b, chromeIds) {
  return !b || b.layout === 'page_edge' || (b.id && chromeIds.has(b.id));
}

function looksHeadingLike(b) {
  if (!b) return false;
  if (b.type === 'heading') return true;
  if (b.type !== 'paragraph' && b.type !== 'caption') return false;
  const t = textOf(b);
  if (!t || t.length > 90 || /[.!?。]$/.test(t)) return false;
  if (OBSERVABLE_RE.test(refangTextForExtraction(t)) && t.length < 40) return false;
  return true;
}

function isInventoryish(b) {
  if (!b || b.type === 'heading') return false;
  const t = textOf(b);
  if (!t) return false;
  if (b.layout === 'observable_row') return true;
  if (isIndicatorValueLine(t) || isObservableListLine(t) || isAnnotatedIndicatorRowLine(t)) return true;
  if ((b.type === 'list' || b.type === 'list_item' || b.type === 'paragraph') && OBSERVABLE_RE.test(refangTextForExtraction(t))) {
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
    if (looksHeadingLike(b) && b.type === 'heading') return false;
    seen += 1;
    if (isInventoryish(b)) return true;
  }
  return false;
}

function headingLevel(b, stack) {
  if (Number.isInteger(b.level)) return b.level;
  // Synthetic / level-less: nest under current parent.
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

/**
 * Annotate a canonical document with section-tree fields (shadow only).
 * Does not mutate production zone fields on the original blocks; returns copies.
 *
 * @param {{ blocks?: object[] }} doc
 * @returns {{ version: string, blocks: object[], meta: object }}
 */
export function annotateSectionTree(doc) {
  const sourceBlocks = Array.isArray(doc?.blocks) ? doc.blocks : [];
  const chromeIds = detectRepeatedHeaderFooterBlockIds(sourceBlocks);
  const blocks = sourceBlocks.map((b) => ({ ...b }));
  /** @type {{ id: string, text: string, level: number, zone: string|null, role: string|null, authoritative: boolean }[]} */
  const stack = [];
  let authoritativeOpenings = 0;
  const trace = [];

  const nearestAuthoritative = () => {
    for (let i = stack.length - 1; i >= 0; i -= 1) {
      if (stack[i].authoritative && AUTHORITATIVE.has(stack[i].zone)) return stack[i];
    }
    return null;
  };

  for (let i = 0; i < blocks.length; i += 1) {
    const b = blocks[i];
    if (isChrome(b, chromeIds)) {
      b.shadow_zone = 'header_footer';
      b.section_path = [];
      b.authoritative_ancestor_id = null;
      b.authoritative_zone = null;
      continue;
    }

    const t = textOf(b);
    const isRealHeading = b.type === 'heading';
    const headingLike = looksHeadingLike(b);

    if (headingLike && t) {
      const { zone, role } = zoneForHeading(t, isRealHeading);
      const level = headingLevel(b, stack);
      const parentAuth = nearestAuthoritative();
      const groupLabel = GROUP_LABEL_RE.test(t);
      const inventoryNext = lookAheadInventory(blocks, i, chromeIds);

      // Pop deeper-or-equal real headings (document structure).
      if (isRealHeading && Number.isInteger(b.level)) {
        while (stack.length && stack[stack.length - 1].level >= level) stack.pop();
      } else if (isRealHeading) {
        // Level-less real heading: pop equal synthetic children only when it
        // opens a new topic zone that is not a strong continuation.
        if (zone && NEGATIVE_ZONES.has(zone)) {
          while (stack.length) stack.pop();
        } else if (zone && AUTHORITATIVE.has(zone)) {
          while (stack.length && !AUTHORITATIVE.has(stack[stack.length - 1].zone)) stack.pop();
          while (stack.length && stack[stack.length - 1].level >= level) stack.pop();
        }
      } else {
        // Synthetic heading under an open appendix: nest as child whenever it
        // is a group label or inventory follows — do NOT clear the appendix.
        if (parentAuth && (groupLabel || inventoryNext || (zone && AUTHORITATIVE.has(zone)))) {
          // keep stack; nest
        } else if (zone && NEGATIVE_ZONES.has(zone)) {
          while (stack.length) stack.pop();
        } else if (!parentAuth && zone && AUTHORITATIVE.has(zone)) {
          // open new
        } else if (parentAuth && zone && !AUTHORITATIVE.has(zone) && !groupLabel && !inventoryNext) {
          // Prose topic under appendix without inventory → leave appendix, do
          // not push (treat as narrative content under parent).
          b.shadow_is_heading = true;
          b.shadow_heading_zone = zone;
          // fall through to content annotation under parent
          const auth = nearestAuthoritative();
          b.section_path = stack.map((s) => s.text);
          b.authoritative_ancestor_id = auth?.id || null;
          b.authoritative_zone = auth?.zone || null;
          b.shadow_zone = auth?.zone || 'report_body';
          continue;
        }
      }

      const authoritative = Boolean(zone && AUTHORITATIVE.has(zone)) || Boolean(parentAuth && (groupLabel || inventoryNext));
      const effectiveZone = authoritative
        ? (zone && AUTHORITATIVE.has(zone) ? zone : parentAuth?.zone || zone)
        : zone;

      const node = {
        id: b.id,
        text: t.slice(0, 160),
        level,
        zone: effectiveZone || null,
        role: role || null,
        authoritative: Boolean(effectiveZone && AUTHORITATIVE.has(effectiveZone))
      };
      stack.push(node);
      if (node.authoritative) authoritativeOpenings += 1;
      trace.push({
        block_id: b.id,
        decision: 'push',
        zone: node.zone,
        level: node.level,
        synthetic: !isRealHeading,
        group_label: groupLabel,
        inventory_next: inventoryNext
      });

      b.shadow_is_heading = true;
      b.shadow_heading_zone = node.zone;
      b.section_path = stack.map((s) => s.text);
      b.authoritative_ancestor_id = node.authoritative ? node.id : nearestAuthoritative()?.id || null;
      b.authoritative_zone = node.authoritative ? node.zone : nearestAuthoritative()?.zone || null;
      b.shadow_zone = node.zone || 'report_body';
      continue;
    }

    const auth = nearestAuthoritative();
    b.section_path = stack.map((s) => s.text);
    b.authoritative_ancestor_id = auth?.id || null;
    b.authoritative_zone = auth?.zone || null;
    b.shadow_zone = auth?.zone || 'report_body';
  }

  return {
    version: SHADOW_SECTION_TREE_VERSION,
    blocks,
    meta: {
      authoritative_openings: authoritativeOpenings,
      has_authoritative_scope: authoritativeOpenings > 0,
      trace
    }
  };
}
