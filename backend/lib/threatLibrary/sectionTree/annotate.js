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
  confirmedQualifiedIocHeading,
  DELEGATED_IOC_ZONE,
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
import { interpretIocTable } from '../tableSemantics.js';
import {
  EXTERNAL_IOC_POINTER_RE,
  blockIsExternalIocReference
} from '../iocSources/externalIocReference.js';
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
  // Observable inventory / annotated IOC rows are content, never synthetic headings
  // (e.g. "8.218.50[.]207 - Staging server …" must not open a C2 scope from "C2").
  if (isIndicatorValueLine(t) || isObservableListLine(t) || isAnnotatedIndicatorRowLine(t)) return false;
  const refanged = refangTextForExtraction(t);
  if (OBSERVABLE_RE.test(refanged) && t.length < 48) return false;
  // Observable-led annotation lines ("host - role", "ip | note") stay content.
  if (
    OBSERVABLE_RE.test(refanged) &&
    /^(?:https?:\/\/|\d{1,3}(?:\.\d{1,3}){3}|[a-f0-9]{32,64}\b|[a-z0-9][a-z0-9.-]+\.[a-z]{2,})/i.test(
      refanged.replace(/\[\.\]/g, '.')
    )
  ) {
    return false;
  }
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

/** A sentence that points at an externally published indicator file. */
export const EXTERNAL_POINTER_RE = EXTERNAL_IOC_POINTER_RE;

const OBSERVABLE_GLOBAL_RE = new RegExp(OBSERVABLE_RE.source, 'gi');

/**
 * A sentence that names observables only to say they are legitimate or cannot
 * be blocked ("Blocking docs.google.com or googleapis.com is not viable",
 * "… are legitimate Google services"). Those names describe the environment,
 * not an inventory the publisher curated.
 */
const NON_INVENTORY_STANCE_RE =
  /\b(?:block(?:ing|ed)?|deny(?:ing)?|blacklist(?:ing)?|blocklist(?:ing)?|filter(?:ing)?)\b[^.;]{0,160}?\b(?:is|are|would\s+be|isn['’]t|aren['’]t)\s+(?:not\s+)?(?:viable|feasible|practical|possible|realistic|recommended|an\s+option)\b|\b(?:legitimate|benign|trusted|well-known)\s+(?:[\w-]+\s+){0,3}?(?:services?|platforms?|providers?|domains?|infrastructure|apis?|endpoints?|cdns?)\b/i;

/**
 * Content that lists at least one observable (an inventory), as opposed to a
 * pointer sentence such as "These indicators are also available for download
 * here." or "IOCs are listed in our GitHub repository: <url>", or a prose
 * sentence that names services only to call them legitimate / unblockable.
 * @param {object} b annotated content block
 */
function hasObservableInventory(b) {
  if (!b || b.type === 'heading') return false;
  const t = textOf(b);
  if (!t) return false;
  const refanged = refangTextForExtraction(t);
  // A URL is one observable (not its scheme + host + path pieces).
  const urls = refanged.match(/\bhttps?:\/\/\S+/gi) || [];
  const rest = refanged.replace(/\bhttps?:\/\/\S+/gi, ' ');
  const hits = urls.length + (rest.match(OBSERVABLE_GLOBAL_RE) || []).length;
  if (!hits) return false;
  if (b.type !== 'table' && hits <= 1 && EXTERNAL_POINTER_RE.test(t)) return false;
  if (
    b.type !== 'table' &&
    !isIndicatorValueLine(t) &&
    !isObservableListLine(t) &&
    !isAnnotatedIndicatorRowLine(t) &&
    NON_INVENTORY_STANCE_RE.test(refanged)
  ) {
    return false;
  }
  return true;
}

/**
 * A table that is a publisher indicator inventory: it has an indicator column
 * whose cells parse as observables. A descriptive table under a C2 heading
 * ("Endpoint | Method | Description", "Channel | Authentication | Poll") is
 * technical content and never opens C2 authority. A table block without a
 * parsed grid falls back to "carries an observable".
 * @param {object} b
 */
function isInventoryTable(b) {
  if (b.table && Array.isArray(b.table.rows) && b.table.rows.length) {
    return interpretIocTable(b, { inAuthoritativeScope: true }).kind === 'ioc_table';
  }
  return OBSERVABLE_RE.test(refangTextForExtraction(textOf(b)));
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

/**
 * Strong inventory look-ahead for C2 / operational openings: IOC tables, list
 * rows, and annotated value lines — not prose that merely mentions an
 * observable, and not a descriptive technical table.
 */
function lookAheadStrongInventory(blocks, i, chromeIds, depth = 6) {
  let seen = 0;
  for (let j = i + 1; j < blocks.length && seen < depth; j += 1) {
    const b = blocks[j];
    if (isChrome(b, chromeIds)) continue;
    if (b.type === 'heading') return false;
    seen += 1;
    if (b.layout === 'observable_row') return true;
    if (b.type === 'table') {
      if (isInventoryTable(b)) return true;
      continue;
    }
    const t = textOf(b);
    if (!t) continue;
    // HTTP/API examples are technical prose, not publisher IOC inventory.
    if (/^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|curl)\b/i.test(t.trim())) continue;
    if (/^(?:\d+\s+){2,}\|\s*(?:GET|POST|\{)/i.test(t.trim())) continue;
    if (isIndicatorValueLine(t) || isAnnotatedIndicatorRowLine(t) || isObservableListLine(t)) return true;
    if (
      (b.type === 'list' || b.type === 'list_item') &&
      OBSERVABLE_RE.test(refangTextForExtraction(t)) &&
      t.length <= 140 &&
      !/[.!?。]/.test(t) &&
      !/\b(?:microsoft\.com|microsoftonline\.com|googleapis\.com)\b/i.test(t)
    ) {
      return true;
    }
  }
  return false;
}

function headingLevel(b, stack) {
  if (Number.isInteger(b.level)) return b.level;
  if (stack.length) return stack[stack.length - 1].level + 1;
  return 2;
}

function zoneForHeading(text, isRealHeading, blocks, i, chromeIds) {
  const role = classifySectionRole(text);
  const fromRole = zoneForSectionRole(role);
  if (fromRole) return { zone: fromRole, role };
  const z = classifyHeadingText(text, { isHeading: isRealHeading });
  if (!z) {
    // "Observations" opens an IOC scope only when a declared-type IOC table follows.
    const qualified = confirmedQualifiedIocHeading(text, blocks, i, chromeIds);
    if (qualified) return qualified;
  }
  return { zone: z, role: role || null };
}

function nearestAuthoritative(stack) {
  for (let i = stack.length - 1; i >= 0; i -= 1) {
    if (stack[i].authoritative && AUTHORITATIVE.has(stack[i].zone)) return stack[i];
  }
  return null;
}

function nearestNegative(stack) {
  for (let i = stack.length - 1; i >= 0; i -= 1) {
    if (stack[i].zone && NEGATIVE_ZONES.has(stack[i].zone) && !stack[i].authoritative) {
      return stack[i];
    }
  }
  return null;
}

function annotateContentFields(b, stack) {
  const auth = nearestAuthoritative(stack);
  const neg = auth ? null : nearestNegative(stack);
  // Stable structural provenance: path texts for display + heading block ids
  // for identity (heading wording changes must not orphan ancestry joins).
  b.section_path = stack.map((s) => s.text);
  b.section_path_ids = stack.map((s) => s.id);
  b.authoritative_ancestor_id = auth?.id || null;
  b.authoritative_zone = auth?.zone || null;
  if (auth?.zone) {
    b.tree_zone = auth.zone;
    b.negative_scope = false;
  } else if (neg?.zone) {
    b.tree_zone = neg.zone;
    b.negative_scope = true;
  } else {
    b.tree_zone = 'report_body';
    b.negative_scope = false;
  }
}

function popAuthoritativeAppendix(stack) {
  while (stack.length && stack[stack.length - 1].authoritative) {
    stack.pop();
  }
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
  let realAuthoritativeOpenings = 0;
  /** @type {string[]} */
  const realOpeningIds = [];
  const trace = [];

  const pushTrace = (entry) => {
    if (trace.length < MAX_TRACE) trace.push(entry);
  };

  for (let i = 0; i < blocks.length; i += 1) {
    const b = blocks[i];
    if (isChrome(b, chromeIds)) {
      b.tree_zone = 'header_footer';
      b.section_path = [];
      b.section_path_ids = [];
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

    const { zone, role } = zoneForHeading(t, isRealHeading, blocks, i, chromeIds);
    const level = headingLevel(b, stack);
    const parentAuth = nearestAuthoritative(stack);
    const groupLabel = GROUP_LABEL_RE.test(t);
    const inventoryNext = lookAheadInventory(blocks, i, chromeIds);

    // Subgroup continuation under an open appendix: group-label vocabulary
    // and/or inventory look-ahead. Real same-level HTML siblings that name a
    // new topic (no group label, no inventory) close scope below.
    // Reference / negative headings never inherit appendix authority — even when
    // the following blocks look like URL "inventory" (citation lists).
    let treatAsSubgroup = false;
    const isNegativeHeading = Boolean(zone && NEGATIVE_ZONES.has(zone));
    if (parentAuth && !isNegativeHeading) {
      const deeper =
        Number.isInteger(b.level) &&
        Number.isInteger(parentAuth.level) &&
        b.level > parentAuth.level;
      const sameLevelInferred =
        inferredLevels &&
        Number.isInteger(b.level) &&
        Number.isInteger(parentAuth.level) &&
        b.level === parentAuth.level;
      // PDF same-level real headings are sibling topics, not nested subgroups —
      // even when inventory-ish content follows (that content belongs to the
      // new topic, not the prior appendix).
      if (
        sameLevelInferred &&
        isRealHeading &&
        !groupLabel &&
        !(zone && AUTHORITATIVE.has(zone))
      ) {
        treatAsSubgroup = false;
      } else {
        const levelUnknown =
          !Number.isInteger(b.level) ||
          !Number.isInteger(parentAuth.level) ||
          sameLevelInferred;
        if (deeper || levelUnknown || !isRealHeading) {
          treatAsSubgroup = groupLabel || inventoryNext || (zone && AUTHORITATIVE.has(zone));
        }
      }
    }

    if (isNegativeHeading) {
      // Bibliography / references terminate authoritative IOC scope.
      popAuthoritativeAppendix(stack);
      pushTrace({
        block_id: b.id,
        decision: 'close_appendix_on_negative_heading',
        zone,
        level,
        reason: 'reference_or_negative_terminates_authority'
      });
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
      } else if (
        !treatAsSubgroup &&
        parentAuth &&
        !(zone && AUTHORITATIVE.has(zone)) &&
        !(zone && NEGATIVE_ZONES.has(zone))
      ) {
        // Non-IOC real heading (including unzoned topic titles) under an open
        // appendix. Under PDF inferred levels — or when the zone is unknown —
        // leaving the appendix open leaks authority across topic siblings
        // (Conclusion, Analysis, …). Close authoritative scope.
        if (inferredLevels || !zone) {
          popAuthoritativeAppendix(stack);
          pushTrace({
            block_id: b.id,
            decision: 'close_appendix_on_topic_heading',
            zone,
            level,
            reason: inferredLevels ? 'pdf_inferred_non_ioc_sibling' : 'unzoned_topic_sibling'
          });
        }
        annotateContentFields(b, stack);
        b.tree_is_heading = true;
        b.tree_heading_zone = zone;
        if (!(inferredLevels || !zone)) {
          pushTrace({
            block_id: b.id,
            decision: 'skip_non_ioc_heading',
            zone,
            level,
            reason: 'unknown_hierarchy_non_authoritative'
          });
        }
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

    // C2 / operational topic headings open MODE A authority only when the
    // following blocks look like a publisher inventory (not narrative prose
    // that happens to discuss C2 technique). Long descriptive titles
    // ("Outlook calendar events as a C2 channel") never open authority.
    const isC2orOps = zone === 'c2_section' || zone === 'operational_infrastructure';
    const narrativeC2Topic =
      isC2orOps &&
      (t.length > 64 ||
        /\bas a\b|\bchannel\b|\bmodule\b|\babuses?\b|\busing\b|\bvia\b|\bdetails?\b|\bfigure\b/i.test(t));
    const strongInventory = isC2orOps && !narrativeC2Topic ? lookAheadStrongInventory(blocks, i, chromeIds) : false;
    // groupLabel is for nested appendix subgroups only — a heading that merely
    // contains the word "C2" must not open MODE A without inventory evidence.
    const opensAuthoritativeZone =
      Boolean(zone && AUTHORITATIVE.has(zone)) && (!isC2orOps || strongInventory);

    const inheritAuth = Boolean(parentAuth && treatAsSubgroup);
    const authoritative = opensAuthoritativeZone || inheritAuth;
    const effectiveZone = authoritative
      ? opensAuthoritativeZone && zone && AUTHORITATIVE.has(zone)
        ? zone
        : parentAuth?.zone || (opensAuthoritativeZone ? zone : null)
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
    if (node.authoritative) {
      authoritativeOpenings += 1;
      // Count independently of the bounded trace buffer — late appendix headings
      // must still establish MODE A on long documents.
      if (!node.synthetic && node.zone && AUTHORITATIVE.has(node.zone)) {
        realAuthoritativeOpenings += 1;
        realOpeningIds.push(node.id);
      }
    }
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

  // Empty formal IOC sections: when every real authoritative opening holds no
  // observable inventory (only "available for download here"), the publisher
  // released its indicators elsewhere. MODE A stays (assertion required), but
  // authority is delegated to the publisher's own body assertions instead of
  // silently suppressing all of them — unless the empty section explicitly
  // points at an external IOC dataset. In that case body technical narrative
  // must not inherit Indicator authority; linked IOC Source discovery owns
  // the publisher pack. Reference / chrome / code blocks and headings never
  // join the delegated scope.
  let inventoryInScope = 0;
  let externalPointerInScope = false;
  /** @type {{ id: string, text: string }|null} */
  let externalPointerAnchor = null;
  for (const b of blocks) {
    if (b.tree_is_heading || !b.authoritative_ancestor_id || b.tree_zone === 'header_footer') continue;
    if (hasObservableInventory(b)) inventoryInScope += 1;
    // Shared scorer with discovery: visible URL and/or structured block.links
    // (destination-only "can be found here" anchors). Vague "download here"
    // without a concrete destination still allows delegated body authority.
    const headingText =
      (Array.isArray(b.section_path) && b.section_path.length
        ? b.section_path[b.section_path.length - 1]
        : null) || null;
    if (
      blockIsExternalIocReference(b, {
        headingText,
        reportUrl: doc?.meta?.source_url || null
      })
    ) {
      externalPointerInScope = true;
      if (!externalPointerAnchor) {
        externalPointerAnchor = { id: b.id, text: String(b.text || '').slice(0, 160) };
      }
    }
  }
  const delegatedScope =
    realAuthoritativeOpenings > 0 && inventoryInScope === 0 && !externalPointerInScope;
  let delegatedBlocks = 0;
  if (delegatedScope) {
    const anchor = realOpeningIds[0];
    for (const b of blocks) {
      if (b.tree_is_heading || b.tree_zone === 'header_footer' || b.negative_scope === true) continue;
      if (b.authoritative_ancestor_id) continue;
      if (b.type === 'code' || b.layout === 'page_edge') continue;
      b.authoritative_ancestor_id = anchor;
      b.authoritative_zone = DELEGATED_IOC_ZONE;
      b.tree_zone = DELEGATED_IOC_ZONE;
      b.delegated_scope = true;
      delegatedBlocks += 1;
    }
    pushTrace({ block_id: anchor, decision: 'delegate_empty_authoritative_scope', zone: DELEGATED_IOC_ZONE, blocks: delegatedBlocks });
  }

  // MODE A requires a real (non-synthetic) publisher IOC/C2/sample heading.
  // Synthetic subgroup nesting under that heading is allowed, but synthetic-only
  // openings must not invent MODE A on a narrative (MODE B) document.
  // realAuthoritativeOpenings is counted during the walk (not from the bounded
  // trace) so late appendix headings on long reports still establish MODE A.

  return {
    version: SECTION_TREE_VERSION,
    blocks,
    meta: {
      authoritative_openings: authoritativeOpenings,
      real_authoritative_openings: realAuthoritativeOpenings,
      // Publisher-authoritative IOC inventory governs the document (MODE A).
      has_authoritative_scope: realAuthoritativeOpenings > 0,
      // Every formal IOC section empty → body assertions carry authority,
      // unless an explicit external IOC pointer owns the pack instead.
      delegated_scope: delegatedScope,
      external_ioc_pointer: externalPointerInScope,
      external_ioc_pointer_block_id: externalPointerAnchor?.id || null,
      empty_authoritative_openings: delegatedScope ? realOpeningIds.slice(0, 8) : [],
      delegated_blocks: delegatedBlocks,
      inferred_levels: inferredLevels,
      trace
    }
  };
}
