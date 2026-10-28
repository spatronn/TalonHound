/**
 * Source indicator-scope and occurrence-relation model.
 *
 * Threat Library must not treat every syntactic observable in a report as a
 * review IOC. When the publisher curates operational indicator sections
 * (IOC appendix, C2 list, VPN/admin infrastructure, sample table), those
 * sections are authoritative. Narrative mentions — including that an actor
 * bought or used a legitimate service — stay context unless the source
 * independently asserts the exact observable as malicious / operational
 * infrastructure.
 *
 * No vendor or domain allowlists. Heading hints are multilingual optimizations;
 * unknown-language sections still work via list/table structure.
 */

import { collapseLetterSpacing, isObservableOnlyLine } from './pdfLayout.js';
import { looksDefanged, refangTextForExtraction } from './defang.js';
import { FILE_EXT_HINT, hasDelegatedDnsSuffix, suffixStrength, trimUrlBoundary, validateUrlCandidate } from './observableTypeResolver.js';

/**
 * True when a dotted token is a filename-shaped annotation (loader.exe,
 * wg-ca.crt), not a network observable suitable for a pure IOC list line.
 * Publisher defanging (`[.]`) is refanged first so `example[.]com` and
 * `198[.]51[.]100[.]20` are never misread as weak filename shapes.
 * @param {string} token
 */
export function isFilenameShapedToken(token) {
  const t = refangTextForExtraction(String(token || ''))
    .replace(/[.,;)\]。，；]+$/g, '')
    .toLowerCase();
  if (!t) return false;
  // CIDR / IP:port are network tokens, never filesystem paths.
  if (/^(?:\d{1,3}\.){3}\d{1,3}(?:\/(?:3[0-2]|[12]?\d)|:\d{1,5})?$/.test(t)) return false;
  if (/^[0-9a-f:]+\/\d{1,3}$/i.test(t)) return false;
  // Absolute and scheme-less network URLs contain "/" but are not filenames.
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(t)) return false;
  if (t.includes('/') || t.includes('\\')) {
    if (isSchemeLessUrlToken(t)) return false;
    return true;
  }
  const labels = t.split('.').filter(Boolean);
  if (labels.length < 2) return false;
  const last = labels[labels.length - 1];
  if (FILE_EXT_HINT.has(last) && !hasDelegatedDnsSuffix(t)) return true;
  // Compound archives: name.tar.gz
  if (labels.length >= 3 && FILE_EXT_HINT.has(labels[labels.length - 2]) && FILE_EXT_HINT.has(last)) return true;
  return suffixStrength(labels) === 'weak' && !hasDelegatedDnsSuffix(t);
}

export const INDICATOR_SCOPES = Object.freeze({
  AUTHORITATIVE: 'authoritative',
  CONTEXTUAL: 'contextual',
  EXCLUDED: 'excluded'
});

export const SOURCE_RELATIONS = Object.freeze({
  OPERATIONAL_MALICIOUS: 'operational_malicious',
  PROVIDER_SERVICE: 'provider_service',
  CONTEXTUAL: 'contextual',
  REFERENCE: 'reference'
});

/**
 * Structural kind of one occurrence. Row kinds are source assertions when they
 * sit inside an authoritative section; narrative kinds need relation semantics
 * whatever the zone says. Zone membership alone never asserts maliciousness.
 */
export const OCCURRENCE_KINDS = Object.freeze({
  TYPED_TABLE_ROW: 'typed_table_row',
  STANDALONE_INDICATOR_ROW: 'standalone_indicator_row',
  LIST_ITEM: 'list_item',
  ENDPOINT: 'endpoint',
  NARRATIVE_ASSERTION: 'narrative_assertion',
  NARRATIVE_CONTEXT: 'narrative_context',
  NARRATIVE_MENTION: 'narrative_mention',
  REFERENCE: 'reference'
});

const ROW_KINDS = new Set([
  OCCURRENCE_KINDS.TYPED_TABLE_ROW,
  OCCURRENCE_KINDS.STANDALONE_INDICATOR_ROW,
  OCCURRENCE_KINDS.LIST_ITEM,
  OCCURRENCE_KINDS.ENDPOINT
]);

/**
 * @param {string|null|undefined} kind
 */
export function isRowOccurrenceKind(kind) {
  return ROW_KINDS.has(String(kind || ''));
}

/** How a heading declared an indicator section. */
export const INDICATOR_HEADING_FORMS = Object.freeze({
  /** A recognised label ("IOCs", "Appendix B: C2 Servers", "Göstergeler"). */
  LABEL: 'label',
  /** Indicator concept first, then descriptive text ("Indicators: Campaign A"). */
  DESCRIPTIVE_SUFFIX: 'descriptive_suffix'
});

export const SECTION_ROLES = Object.freeze({
  IOC_APPENDIX: 'ioc_appendix',
  C2_INFRASTRUCTURE: 'c2_infrastructure',
  OPERATIONAL_INFRASTRUCTURE: 'operational_infrastructure',
  SAMPLE_TABLE: 'sample_table',
  NARRATIVE: 'narrative',
  REFERENCES: 'references',
  SOURCE_METADATA: 'source_metadata',
  LAYOUT: 'layout'
});

/** Appendix / annex / 附录 / ek / anhang — not a specific letter or number. */
const APPENDIX_RE =
  /\b(?:appendix|appendices|annex|annexe|anexo|anhang|anlage|ekler|ek\b|附录|附件|annexes?)\b/i;

// Appendix/annex must LEAD the heading. Mid-title mentions
// ("without an appendix heading") are narrative, not appendix labels.
const APPENDIX_LEAD_RE =
  /^(?:(?:appendix|appendices|annex|annexe|anexo|anhang|anlage|ekler|ek|annexes?)\b|附录|附件)/i;

const C2_INTENT_RE =
  /\b(?:c\s*&\s*c|c2|c&c|command\s*(?:and|&)\s*control|komuta\s*kontrol)\b|控制端|回连地址|通信地址|远控地址|c2地址|c2服务器/i;

const IOC_INTENT_RE =
  /\b(?:iocs?|indicators?\s+of\s+compromise|compromise\s+indicators?|network\s+indicators?|host\s+indicators?|file\s+indicators?|technical\s+indicators?|atomic\s+indicators?|detection\s+data|observables?)\b|威胁指标|妥协指标|göstergeler|indicadores/i;

/**
 * Headings that title an indicator inventory only when the section proves it:
 * "Observations" heads an `Observable | Type | …` IOC table in some vendor
 * templates and a narrative findings section in others. Callers confirm it
 * structurally (a declared-type IOC table directly under the heading) before
 * granting authority; the heading alone never opens an IOC scope.
 */
const QUALIFIED_IOC_INVENTORY_HEADING_RE =
  /^(?:(?:key|technical|network|host|file|related|additional)\s+)?observations?\s*(?:[:：\-–—|(]|$)/i;

/**
 * @param {string} text heading text
 */
export function isQualifiedIocInventoryHeading(text) {
  const t = collapseLetterSpacing(String(text || '').trim());
  if (!t || t.length > 80) return false;
  return QUALIFIED_IOC_INVENTORY_HEADING_RE.test(t);
}

const OPERATIONAL_INFRA_RE =
  /\b(?:vpn\s+nodes?|admin(?:istrative)?\s+(?:nodes?|infrastructure)|(?:ip|ipv4|ipv6)\s+(?:address\s+)?ranges?|address\s+ranges?|malicious\s+infrastructure|threat\s+infrastructure|operator\s+infrastructure|admin(?:istering|istration)\b.{0,48}(?:infrastructure|nodes?|ranges?)|(?:infrastructure|nodes?|ranges?).{0,48}admin(?:istering|istration)?)\b|基础设施|运营节点/i;

const SAMPLE_INTENT_RE = /\b(?:malicious\s+samples?|sample\s+hash|file\s+hash)\b|恶意样本|样本哈希|örnek\s+hash/i;

const REFERENCE_INTENT_RE =
  /^(?:references?|bibliography|reporting|how\s+to\s+report|further\s+(?:reading|information)|quellen|kaynaklar|referanslar|références|referencias)\b|^contact(?:s|ing)?(?:\s+(?:us|information|info|details|the\s+(?:authors?|team|researchers?)|our\s+team))?\s*[:.!]?\s*$|参考链接|参考文献|相关链接|联系方式/i;

/**
 * Surrounding prose that names a reporting / law-enforcement contact channel
 * rather than attacker infrastructure (agency complaint portals, "report to").
 */
const REPORTING_CONTACT_RE =
  /\b(?:please\s+report|report\s+(?:significant\s+)?(?:cyber\s+)?(?:security\s+)?incidents?\s+to|file\s+a\s+complaint|report(?:ing)?\s+(?:this|the)\s+(?:incident|compromise|activity)|contact\s+(?:the\s+)?(?:general\s+intelligence|local\s+law|your\s+it|national\s+cyber)|monitored\s+24(?:\s*\/\s*|\s*)?7|internet\s+crime\s+complaint\s+center)\b/i;

/**
 * A community / open-source resource the publisher recommends to defenders
 * ("Community-driven resources like OBSERVABLE help support this approach"):
 * a reference, never an Indicator (MODE A or B) (tl-candidates-v41).
 */
const DEFENDER_RESOURCE_RE =
  /\b(?:community[\s-]*(?:driven|maintained|curated|led|sourced)|open[\s-]*source|publicly[\s-]+available)\s+(?:[\w-]+\s+){0,3}?(?:resources?|projects?|databases?|catalogu?es?|knowledge[\s-]*bases?|repositor(?:y|ies)|references?|lists?)\s*,?\s*(?:such\s+as|like|including|e\.g\.,?)\s+OBSERVABLE\b/i;

/**
 * Indicator concept at the head of a heading, then a separator or the end:
 * "Indicators: Three Casinos…", "Indicators – Network Infrastructure",
 * "IOCs (Type 3)", "Göstergeler: Ek Altyapı", "威胁指标：活动A". A heading that
 * merely contains the word later in a sentence ("Why these indicators matter",
 * "Indicators suggest a Chinese origin") does not match: the concept must lead
 * and be closed by punctuation, "of", or the end of the heading.
 */
// Inventory-grade qualifiers ("Primary IOCs", "Full Indicators of Compromise",
// "Supplementary IOCs") are part of the closed list (tl-section-tree-v9).
const INDICATOR_HEAD_RE =
  /^(?:(?:host|network|file|atomic|additional|other|related|technical|known|key|observed|associated|new|example|selected|listed|sample|primary|secondary|main|core|full|complete|confirmed|extended|supplementary|supplemental|notable|ağ|dosya|ek)\s+)?(?:indicators?|iocs?|göstergeler|indicadores|威胁指标|妥协指标)\s*(?:[:：\-–—|(\[（]|of\b|$)/i;

/**
 * Classify a heading as an indicator-section declaration, with its form.
 * @param {string} text
 * @returns {{ role: string, form: string }|null}
 */
export function classifyIndicatorHeading(text) {
  const t = collapseLetterSpacing(String(text || '').trim());
  if (!t || t.length > 200) return null;
  const role = classifySectionRole(t, { allowDescriptiveSuffix: false });
  if (role) return { role, form: INDICATOR_HEADING_FORMS.LABEL };
  const m = t.match(INDICATOR_HEAD_RE);
  if (!m) return null;
  const rest = t.slice(m[0].length).trim();
  return {
    role: SECTION_ROLES.IOC_APPENDIX,
    form: rest ? INDICATOR_HEADING_FORMS.DESCRIPTIVE_SUFFIX : INDICATOR_HEADING_FORMS.LABEL
  };
}

/**
 * Classify a heading's section role. Returns null when the heading does not
 * declare an indicator, reference or sample section (narrative / unknown).
 * A bare indicator concept followed by descriptive text ("Indicators: …")
 * counts as an IOC appendix; callers that need to know it was the descriptive
 * form (and confirm it structurally) use classifyIndicatorHeading.
 * @param {string} text
 * @param {{ allowDescriptiveSuffix?: boolean }} [opts]
 * @returns {string|null}
 */
export function classifySectionRole(text, opts = {}) {
  const t = collapseLetterSpacing(String(text || '').trim());
  if (!t || t.length > 200) return null;
  if (REFERENCE_INTENT_RE.test(t) && t.length <= 80) return SECTION_ROLES.REFERENCES;
  if (SAMPLE_INTENT_RE.test(t) && t.length <= 80) return SECTION_ROLES.SAMPLE_TABLE;
  if (C2_INTENT_RE.test(t)) return SECTION_ROLES.C2_INFRASTRUCTURE;
  if (OPERATIONAL_INFRA_RE.test(t)) return SECTION_ROLES.OPERATIONAL_INFRASTRUCTURE;
  // IOC appendix via synonym inventory labels (IOC_INTENT_RE). Bare English
  // "IOC"/"IOCs" must be head-anchored (INDICATOR_HEAD_RE) or appendix-led —
  // mid-title / hyphenated mentions ("IOC-shaped", "near IOC inventory",
  // "IOC inventory methodology discussion", "without an appendix heading")
  // are narrative chrome, not MODE A openers.
  if (IOC_INTENT_RE.test(t)) {
    if (/\biocs?-/i.test(t)) {
      // Hyphenated compound (IOC-shaped): only accept if a non-bare synonym
      // also matched. IOC_INTENT's bare iocs? alternative is what fired; reject.
    } else {
      const bareIoc = /\biocs?\b/i.test(t);
      if (!bareIoc) return SECTION_ROLES.IOC_APPENDIX;
      if (INDICATOR_HEAD_RE.test(t) || APPENDIX_LEAD_RE.test(t)) return SECTION_ROLES.IOC_APPENDIX;
      // mid-title bare IOC — not an appendix declaration
    }
  }
  if (APPENDIX_LEAD_RE.test(t) && /(?:server|node|range|indicator|ioc|infrastructure|vpn|c2|hash|sample)/i.test(t)) {
    if (C2_INTENT_RE.test(t)) return SECTION_ROLES.C2_INFRASTRUCTURE;
    if (OPERATIONAL_INFRA_RE.test(t) || /\b(?:vpn|range|node|infrastructure)\b/i.test(t)) {
      return SECTION_ROLES.OPERATIONAL_INFRASTRUCTURE;
    }
    return SECTION_ROLES.IOC_APPENDIX;
  }
  // Descriptive "Indicators: …" / "IOCs (Type 3)" when callers allow the suffix form.
  if (opts.allowDescriptiveSuffix !== false && INDICATOR_HEAD_RE.test(t)) return SECTION_ROLES.IOC_APPENDIX;
  return null;
}

export function zoneForSectionRole(role) {
  switch (role) {
    case SECTION_ROLES.C2_INFRASTRUCTURE:
      return 'c2_section';
    case SECTION_ROLES.SAMPLE_TABLE:
      return 'sample_table';
    case SECTION_ROLES.IOC_APPENDIX:
      return 'explicit_ioc_section';
    case SECTION_ROLES.OPERATIONAL_INFRASTRUCTURE:
      return 'operational_infrastructure';
    case SECTION_ROLES.REFERENCES:
      return 'reference_section';
    default:
      return null;
  }
}

const AUTHORITATIVE_ZONES = new Set([
  'explicit_ioc_section',
  'c2_section',
  'sample_table',
  'operational_infrastructure',
  'delegated_ioc_scope'
]);

const EXCLUDED_ZONES = new Set([
  'reference_section',
  'source_metadata',
  'header_footer',
  'navigation',
  'vendor_about'
]);

/**
 * @param {string|null|undefined} zone
 */
export function indicatorScopeForZone(zone) {
  const z = String(zone || '');
  if (AUTHORITATIVE_ZONES.has(z)) return INDICATOR_SCOPES.AUTHORITATIVE;
  if (EXCLUDED_ZONES.has(z)) return INDICATOR_SCOPES.EXCLUDED;
  return INDICATOR_SCOPES.CONTEXTUAL;
}

/**
 * Document-level: does the publisher curate at least one operational indicator set?
 * @param {object[]} blocks
 */
export function discoverDocumentIndicatorScope(blocks) {
  const zones = new Set();
  const roles = new Set();
  let authoritativeBlocks = 0;
  for (const b of blocks || []) {
    const zone = b.zone || 'report_body';
    zones.add(zone);
    if (b.section_role) roles.add(b.section_role);
    if (AUTHORITATIVE_ZONES.has(zone)) authoritativeBlocks += 1;
    const headingRole = b.type === 'heading' ? classifySectionRole(b.text) : null;
    if (headingRole) roles.add(headingRole);
  }
  return {
    has_authoritative_indicator_scope: authoritativeBlocks > 0,
    authoritative_block_count: authoritativeBlocks,
    zones: [...zones],
    section_roles: [...roles]
  };
}

/**
 * Strong operational-malicious relation: the source asserts this exact
 * observable is C2 / payload / attacker infrastructure, not merely mentioned.
 * Hints are multilingual optimizations — unknown languages still use
 * structural forms (ip:port, indicator-list row).
 */
const OPERATIONAL_RELATION_RE =
  /\b(?:c2|c&c|c\s*&\s*c|command\s*(?:and|&)\s*control|beacon(?:s|ing)?|connect(?:s|ed|ing)?\s+to|communicat(?:es|ed|ing)\s+with|callback|payload|downloads?\s+(?:hxxps?:\/\/|https?:\/\/|from|OBSERVABLE)|downloaded?\s+from|fetch(?:es|ed)?\s+from|drops?\s+from|phish(?:ing)?|malware\s+(?:connects?|beacons?|talks?)|attacker[- ]controlled|malicious\s+(?:server|host|domain|url|ip|infrastructure)|hard-?coded|(?:fetch|download|retriev|pull|load|deliver|drop|serv(?!ic|er)|stag|exfiltrat|upload)\w*\b(?:[^.;]|\.(?!\s|$)){0,60}?\b(?:from|to)\s+(?:the\s+)?(?:(?:url|uri|domain|server|host|address|site|endpoint|link)\s+)?["'“”‘’`]?\s*OBSERVABLE|(?:hosted|served|staged|stored)\s+(?:at|on)\s+OBSERVABLE|(?:get|post|put|head|http|https)\s+requests?\s+(?:is\s+|was\s+)?(?:sent\s+)?(?:to|from)\s+(?:the\s+)?(?:(?:url|uri|domain|server|host|address|endpoint)\s+)?["'“”‘’`]?\s*OBSERVABLE|OBSERVABLE\s*["'“”‘’`]?\s+(?:was|were|is|are|has|have|had)\s+(?:\w+ly\s+)?(?:been\s+)?(?:\w+ly\s+)?(?:used|abused|leveraged|set\s+up)\s+to\s+(?:host|serve|stage|deliver|distribute)|OBSERVABLE\s*["'“”‘’`]?\s+(?:was|were|is|are|has|have|had)\s+(?:\w+ly\s+)?(?:been\s+)?(?:\w+ly\s+)?(?:hosted|served|staged)\s+(?:on|at|from|by)|(?:used|operated|controlled|owned|run|registered)\s+by\s+(?:the\s+|a\s+|an\s+)?(?:[\w-]+\s+){0,4}?(?:threat\s+actors?|apt[\w-]*|attackers?|adversar(?:y|ies)|operators?|threat\s+group|intrusion\s+set)|attributed\s+to\s+(?:the\s+)?(?:[\w-]+\s+){0,3}?(?:apt[\w-]*|group|actors?|threat\s+actors?|operators?|intrusion\s+set))\b|回连|远控|木马连接|命令控制|komuta|bağlan(?:ır|ıyor|dı|maktadır)/i;

/**
 * The observable is the thing being hosted ("… was used to host the domain
 * OBSERVABLE", "servers hosting OBSERVABLE"): infrastructure served it. The
 * hosted object is never the hosting provider, whatever acquisition verb the
 * sentence uses for the host itself.
 */
const HOSTED_OBJECT_RE =
  /\bhost(?:s|ed|ing)?\s+(?:the\s+|a\s+|an\s+)?(?:(?:malicious|phishing|attacker|fake|rogue|c2|c&c)\s+)?(?:(?:domains?|sites?|websites?|pages?|payloads?|servers?|urls?|files?)\s+)?[-–—:]?\s*["'“”‘’`]?\s*OBSERVABLE/i;

const PROVIDER_RELATION_RE =
  /\b(?:purchased?|bought|rented?|leased?|registered?\s+(?:via|through|with|at)|subscri(?:bed|be)|procur(?:ed|e)|to\s+purchase|(?:rent|purchas|bought|buy|leas|subscrib|procur|acquir)\w*\b[^.;]{0,60}?\bto\s+host|services?\s+such\s+as|infrastructure\s+provider|cloud\s+provider|hosting\s+provider|vps\s+provider|vpn\s+provider|used\s+(?:the\s+)?(?:commercial\s+)?(?:services?|providers?|vendors?|platforms?|vpn|vps|proxy|cloud(?:\s+provider)?)|from\s+(?:a\s+)?(?:vps|vpn|proxy|hosting|cloud)\s+(?:provider|vendor|service)|commercial\s+vpn)\b|satın\s+al|satın\s+ald|购买|租用|注册于/i;

/**
 * The observable names the platform itself ("abuse of the public Archive.org
 * service", "the legitimate Telegram API"): a hosting / service provider the
 * operation used, not infrastructure the operators own.
 */
const PLATFORM_SERVICE_RE =
  /\b(?:public|legitimate|free|popular|commercial|third[\s-]party|cloud)\s+OBSERVABLE\s+(?:service|platform|hosting|storage|cdn|api|website|site)s?\b/i;

const PROVIDER_CATALOGUE_RE =
  /\b(?:likely\s+to\s+purchase|to\s+obtain\s+(?:infrastructure|services?|prox(?:y|ies)|vps|vpn)|used\s+\w[\w.-]*\s+(?:to\s+purchase|for\s+(?:infrastructure|hosting|prox(?:y|ies)|vps)))\b/i;

/**
 * Contextual relation: the observable names who researched / reported /
 * documented something, or an organisation, vendor or tool — not attacker
 * infrastructure. "Org Name (OBSERVABLE)" is the parenthetical-organisation
 * shape ("Interisle Consulting (interisle[.]net) flagged …").
 */
const CONTEXT_RELATION_RE =
  /\b(?:research(?:er|ers|ed)?|consult(?:ing|ancy|ants?)|according\s+to|reported\s+by|report(?:ed)?\s+(?:by|from)|documented\s+(?:by|in)|analys(?:ts?|is)\s+(?:at|from|by)|team\s+at|colleagues?\s+at|published\s+(?:by|on)|blog\s+post|advisory\s+(?:by|from)|whitepaper|write-?up|security\s+(?:firm|vendor|company|researchers?)|flagged\s+by|credit(?:s|ed)?\s+to|thanks\s+to|courtesy\s+of|our\s+(?:website|blog|site|portal))\b|araştırma|firması|şirketi|göre|研究(?:人员|团队)?|安全公司|据|\b[A-Z][\w&.'-]*(?:\s+[A-Z][\w&.'-]*){0,4}\s*[(（]\s*OBSERVABLE\s*[)）]/;

/**
 * Benign-component evidence: the source says the observable is a legitimate /
 * signed / genuine component ("a legitimate component of <product> (host.exe,
 * MD5 …)"). Negated by any maliciousness / abuse cue in the same
 * window ("a trojanized version of the legitimate …", "legitimate-looking").
 */
const BENIGN_COMPONENT_RE =
  /\b(?:legitimate|legit|benign|genuine|clean|non-malicious|not\s+malicious|official(?:ly)?\s+signed|digitally\s+signed|signed\s+by|trusted\s+(?:binary|component|executable|application|program|file))\b/i;
const BENIGN_NEGATION_RE =
  /\b(?:malicious|malware|trojan\w*|backdoor\w*|implant|fake|fraudulent|masquerad\w*|impersonat\w*|spoof\w*|disguis\w*|mimic\w*|look-?alike|typo-?squat\w*|legitimate[- ]looking|appears?\s+(?:to\s+be\s+)?legitimate|looks?\s+legitimate|abus\w*|hijack\w*|weaponi[sz]\w*|tamper\w*|modified|patched|compromised|infected|side-?load\w*|payload|loader|dropper)\b/i;

/**
 * A structural IOC row that names its own value a lure / phishing / decoy
 * resource ("<url> | Lure link on legitimate dropbox service") asserts that
 * resource, whatever the row says about the service hosting it
 * (tl-candidates-v40). Rows only — in prose a lure is often the attacker's
 * page while "the legitimate <site>" is where the victim signs in.
 */
const ROW_MALICIOUS_RESOURCE_RE = /\b(?:lures?|phish\w*|decoys?)\b/i;

/**
 * Publisher stance that the value is not itself malicious: hedged negation
 * ("not inherently / necessarily / confirmed malicious") or a dual-use /
 * shared-service class ("dual-use tools", "free tunnel brokers"). The hedge
 * contains the word "malicious" itself, so it is matched — and removed —
 * before the maliciousness-cue check runs on the rest of the window.
 */
const REMEDIATED_STANCE_RE =
  /\bno\s+longer\s+(?:infected|compromised|malicious|backdoored|trojani[sz]ed|weaponi[sz]ed|(?:hosting|serving|distributing)\s+(?:the\s+)?(?:malware|payloads?|backdoors?|malicious\s+\w+))\b/i;
const HEDGED_NOT_MALICIOUS_RE =
  /\b(?:not|never|isn['’]?t|aren['’]?t|wasn['’]?t)\s+(?:(?:inherently|necessarily|itself|by\s+itself|in\s+itself|per\s+se|confirmed|known|considered|deemed|proven|believed|thought|assessed)\s+)?(?:(?:as|to\s+be)\s+)?(?:malicious|harmful|attacker[- ]controlled)\b|\bdoes\s+not\s+(?:confirm|indicate|prove|imply)\s+(?:abuse|malicious\w*|compromise)\b/gi;
const DUAL_USE_RE =
  /\b(?:dual[\s-]?use|free\s+(?:ssh\s+)?tunnel(?:ing)?\s+(?:providers?|brokers?|services?)|tunnel\s+brokers?|known\s+free\s+\w+\s+(?:providers?|brokers?|services?)|(?:legitimate|public|commercial)\s+(?:third[\s-]party\s+)?(?:services?|platforms?|providers?|apis?|endpoints?|infrastructure|rpc(?:\s+(?:providers?|endpoints?))?|resolvers?|cdns?)|third[\s-]party\s+services?)\b/i;
/** Maliciousness that a hedge or a dual-use class does not cancel. */
const STANCE_OVERRIDE_RE =
  /\b(?:attacker[- ]controlled|actor[- ]controlled|operated\s+by\s+(?:the\s+)?(?:threat\s+)?(?:actors?|attackers?|operators?|group)|registered\s+by\s+(?:the\s+)?(?:threat\s+)?(?:actors?|attackers?)|malicious\s+(?:domain|server|host|infrastructure|url|ip|site|c2)|fake|typo-?squat\w*|look-?alike|impersonat\w*|spoof\w*|phishing)\b/i;

/** Contrast with other values: the stance words are about those, not this one. */
/**
 * A trailing clause that locates the malicious logic in another named
 * component ("all malicious logic is contained within the JAR", "the malicious
 * code resides in the side-loaded DLL"). Never matches when it names the
 * observable itself.
 */
const MALICE_ELSEWHERE_RE =
  /[,;]?\s*(?:while\s+|whereas\s+|and\s+|but\s+)?(?:all|the|any)\s+(?:of\s+the\s+)?malicious\s+(?:logic|code|functionality|behaviou?r|content)\s+(?:is|are|was|were|resides?|lives?|sits?)\s+(?:entirely\s+|only\s+|solely\s+)?(?:contained\s+|located\s+|embedded\s+|implemented\s+)?(?:with)?in(?:side)?\s+(?:the\s+|a\s+|an\s+)?(?!\s*OBSERVABLE)[^.;!?]*?(?=$|[.;!?])/gi;

/** An outright (unhedged) row statement that the row's subject is not malicious. */
const ROW_NOT_MALICIOUS_RE = /(?<![\w-])(?:not|non)[\s-]malicious(?![\w-])/i;
const CONTRASTIVE_STANCE_RE =
  /\b(?:alongside|unlike|besides|other\s+than|apart\s+from|in\s+addition\s+to|in\s+contrast|whereas|rather\s+than|instead\s+of|beyond\s+the)\b|\bwhile\s+the\s+(?:[\w-]+\s+){0,10}?(?:are|were|is|was)\b/i;

/** "(This domain is …)" / "It is …": the next sentence still describes the value. */
const ANAPHORIC_STANCE_START_RE =
  /^\s*[(\[]?\s*(?:this|that|the|such)\s+(?:domain|host(?:name)?|ip(?:\s+address)?|address|url|uri|endpoint|service|value|indicator|site|server|platform|api|provider)\b|^\s*[(\[]?\s*(?:it|they)\s+(?:is|are|was|were)\b/i;

/**
 * True when the window states the publisher's stance that this value is
 * legitimate / dual-use / not inherently malicious, with no cue that the
 * value itself is attacker infrastructure.
 * @param {string} window text around the masked OBSERVABLE
 */
function statesNonMaliciousStance(window) {
  // "X … alongside the five legitimate providers" / "unlike the public
  // endpoints, X …": the benign words describe the OTHER values.
  if (CONTRASTIVE_STANCE_RE.test(window)) return false;
  // The publisher states the value was remediated ("GitHub repo (no longer
  // infected with backdoor)"): historical context, not a live indicator.
  if (REMEDIATED_STANCE_RE.test(window)) return true;
  const hedge = HEDGED_NOT_MALICIOUS_RE.test(window);
  HEDGED_NOT_MALICIOUS_RE.lastIndex = 0;
  const rest = window.replace(HEDGED_NOT_MALICIOUS_RE, ' ');
  HEDGED_NOT_MALICIOUS_RE.lastIndex = 0;
  if (STANCE_OVERRIDE_RE.test(rest)) return false;
  if (hedge) return true;
  return DUAL_USE_RE.test(rest) && !BENIGN_NEGATION_RE.test(rest);
}

/**
 * A row / list lead-in that names its value as a third-party provider or
 * service the operation relies on ("Blockchain provider", "public resolver",
 * "through three Blockscout providers:") rather than as attacker
 * infrastructure. A malicious role for the value itself ("C2 server",
 * "staging server", "phishing domain", "attacker-controlled") keeps the
 * assertion; so does any spoof / abuse cue of the value.
 *
 * Row descriptor: a category-qualified provider ("Blockchain provider", "DNS
 * resolver", "block explorer") or an explicitly third-party / public service.
 * A bare "service" / "platform" ("a port 8001 service", "shared service",
 * "exposed AI-related services") says nothing about who operates the value.
 */
const PROVIDER_ROLE_NOUN_RE =
  /(?<![\w.-])(?:(?:blockchain|rpc|dns|doh|cdn|ip[\s-]?lookup|ip[\s-]?geolocation|geolocation|block|wallet)\s+(?:providers?|explorers?|resolvers?|apis?)|(?:public|legitimate|third[\s-]party|commercial)\s+(?:[\w-]+\s+)?(?:providers?|services?|platforms?|explorers?|resolvers?|apis?))(?![\w.-])/i;
// List lead-in object phrase ("through three Blockscout providers:", "on three
// Blockscout instances:"): the grammar already scopes the noun to the listed
// values (instances: tl-candidates-v43).
const PROVIDER_LEAD_NOUN_RE = /(?<![\w.-])(?:providers?|explorers?|resolvers?|instances?)(?![\w.-])/i;
const MALICIOUS_VALUE_ROLE_RE =
  /\b(?:c2|c&c|command\s*(?:and|&)\s*control)\s+(?:servers?|panels?|domains?|hosts?|ips?|nodes?|addresses|infrastructure|endpoints?|urls?|instances?)\b(?!\s+(?:resolution|resolv\w*|lookups?|retrieval|discovery))|\b(?:staging|phishing|malware|payloads?|droppers?|loaders?|exfil\w*|beacons?|implants?|backdoors?|stealers?|trojans?|ransomware|botnets?|malicious|attacker[- ]controlled|actor[- ]controlled|operator[- ]controlled|fake|spoof\w*|impersonat\w*|typo-?squat\w*|look-?alike|compromised|bulletproof|weaponi[sz]\w*|trojani[sz]\w*|backdoored|abus\w*|hijack\w*|rogue|lure|operational|operators?|tasking|lookalikes?)\b/i;

/**
 * @param {string} window row / lead-in text with this value masked as OBSERVABLE
 * @param {{ lead?: boolean }} [opts] lead: the text is a list lead-in object phrase
 */
export function namesProviderService(window, opts = {}) {
  const t = String(window || '');
  if (!(opts.lead ? PROVIDER_LEAD_NOUN_RE : PROVIDER_ROLE_NOUN_RE).test(t)) return false;
  if (MALICIOUS_VALUE_ROLE_RE.test(t)) return false;
  if (STANCE_OVERRIDE_RE.test(t)) return false;
  return true;
}

/** Another hash / URL / IP token: the boundary of the window that describes this observable. */
const FOREIGN_OBSERVABLE_TOKEN_RE =
  /\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b|\b(?:hxxps?|https?):\/\/\S+|\b(?:\d{1,3}\.){3}\d{1,3}\b|\bURL\b|\bIP\b/gi;

/**
 * True when the text describing this exact observable (same sentence, not
 * crossing another hash / URL / IP) calls it a legitimate component and says
 * nothing malicious about it.
 * @param {string} masked surrounding text with this observable masked as OBSERVABLE
 */
export function describesBenignComponent(masked) {
  const t = String(masked || '');
  const at = t.indexOf('OBSERVABLE');
  if (at < 0) return false;
  const tail = at + 'OBSERVABLE'.length;
  // A wildcard / subdomain dot glued to the value ("*.lhr.life" masked as
  // "*. OBSERVABLE") is not a sentence boundary.
  const before = t.slice(0, at).replace(/\*?\.\s*$/, '');
  let start = Math.max(before.lastIndexOf('. '), before.lastIndexOf('; '), before.lastIndexOf('! '), before.lastIndexOf('? '));
  const base = start >= 0 ? start + 2 : 0;
  start = base;
  for (const m of before.slice(base).matchAll(FOREIGN_OBSERVABLE_TOKEN_RE)) {
    start = Math.max(start, base + m.index + m[0].length);
  }
  const after = t.slice(tail);
  let end = after.length;
  const sentenceEnd = after.search(/[.;!?](?:\s|$)/);
  if (sentenceEnd >= 0) end = Math.min(end, sentenceEnd);
  const foreign = after.slice(0, end).search(FOREIGN_OBSERVABLE_TOKEN_RE);
  if (foreign >= 0) end = foreign;
  // "…, all malicious logic is contained within the JAR": a clause that places
  // the malice in ANOTHER component confirms this one's legitimate stance; it
  // is not a malicious cue about this value.
  const window = `${before.slice(start)} OBSERVABLE ${after.slice(0, end)}`.replace(MALICE_ELSEWHERE_RE, ' ');
  if (BENIGN_COMPONENT_RE.test(window) && !BENIGN_NEGATION_RE.test(window) && !CONTRASTIVE_STANCE_RE.test(window)) return true;
  if (statesNonMaliciousStance(window)) return true;
  // The next sentence may still describe this value ("… (This domain is not
  // inherently malicious, but …)"): read its stance when it starts anaphorically.
  if (sentenceEnd >= 0 && foreign < 0) {
    const next = after.slice(sentenceEnd + 1);
    const nextEnd = next.search(/[.;!?](?:\s|$)/);
    const sentence = nextEnd >= 0 ? next.slice(0, nextEnd) : next;
    if (ANAPHORIC_STANCE_START_RE.test(sentence) && !/OBSERVABLE/.test(sentence) &&
        sentence.search(FOREIGN_OBSERVABLE_TOKEN_RE) < 0 && statesNonMaliciousStance(sentence)) {
      return true;
    }
  }
  return false;
}

/** Verbs / prepositions that introduce the object phrase of a list lead-in. */
const LEAD_OBJECT_SPLIT_RE =
  /\b(?:through|via|using|uses|use|from|on|with|quer(?:y|ies|ied)|contacts?|relies\s+on|rel(?:y|ies)\s+on|leverag\w*|abus\w*)\b/i;

/** A lead-in whose last noun phrase names the listed items as providers / services. */
const PROVIDER_LIST_LEAD_RE =
  /\b(?:providers?|services?|explorers?|resolvers?|platforms?|instances?)\s*(?:[(（][^)）]*[)）])?\s*[:：]?\s*$/i;

/** "These endpoints are …" / "The above domains are …": a sentence about the preceding list. */
const LIST_ANAPHORA_RE =
  /^\s*(?:these|those|the\s+(?:above|listed|preceding|following)|all\s+(?:of\s+)?(?:these|the\s+above))\s+(?:\w+\s+){0,3}?(?:endpoints?|domains?|urls?|uris?|services?|hosts?|hostnames?|addresses|ips?|servers?|providers?|resolvers?|sites?|platforms?|nodes?)\b/i;

function firstSentence(text) {
  const t = String(text || '').trim();
  const end = t.search(/[.;!?](?:\s|$)/);
  return end >= 0 ? t.slice(0, end) : t;
}

/**
 * Publisher stance about a whole observable list, from its lead-in or the
 * sentence right after it ("These endpoints are legitimate public Ethereum
 * RPC services … rather than blocking these endpoints outright"). Marks each
 * list block with `list_stance: 'non_malicious'`; occurrences carry it and
 * read as a benign relation (same as a row that calls its value legitimate).
 * Pure over a block array (mutates the given copies only).
 * @param {object[]} blocks canonical / zone-annotated blocks (mutated)
 */
export function annotateListStances(blocks) {
  const list = Array.isArray(blocks) ? blocks : [];
  // Only lists whose rows are bare observables (an inventory the sentence can
  // describe as a whole); prose bullets argue, they are not a value list.
  const isListBlock = (b) => b && (b.type === 'list_item' || b.type === 'list' || b.layout === 'observable_row') &&
    (b.layout === 'observable_row' || isIndicatorValueLine(String(b.text || '')) || isObservableListLine(String(b.text || '')) ||
      isAnnotatedIndicatorRowLine(String(b.text || '')));
  // Value-only paragraph lines (one observable per <br>-split line) are the
  // same inventory shape as list items when a stance heading introduces them.
  const isValueLine = (b) => b && b.type === 'paragraph' &&
    (isIndicatorValueLine(String(b.text || '')) || isObservableListLine(String(b.text || '')));
  const isCaption = (b) => b && (b.type === 'caption' || /^\s*(?:figure|fig\.|table|image)\s*\d+/i.test(String(b.text || '')));
  const stanceOf = (text) => {
    const s = firstSentence(text);
    if (!s || CONTRASTIVE_STANCE_RE.test(s)) return false;
    if (BENIGN_COMPONENT_RE.test(s) && !BENIGN_NEGATION_RE.test(s)) return true;
    if (statesNonMaliciousStance(s)) return true;
    // "… C2 lookup through three Blockscout providers:" names the listed values
    // as the providers relied on. Only the object phrase is read; the sentence
    // subject is the malware itself.
    if (!/[:：]\s*$/.test(String(text || '').trim()) || !PROVIDER_LIST_LEAD_RE.test(s)) return false;
    const objectPhrase = s.split(LEAD_OBJECT_SPLIT_RE).pop();
    return namesProviderService(objectPhrase, { lead: true });
  };
  for (let i = 0; i < list.length; i += 1) {
    // Paragraph value lines directly under a sub-heading: heading stance only.
    if (isValueLine(list[i]) && list[i - 1]?.type === 'heading' && !isListBlock(list[i])) {
      const h = String(list[i - 1].text || '');
      let j = i;
      while (j + 1 < list.length && isValueLine(list[j + 1])) j += 1;
      if (BENIGN_COMPONENT_RE.test(h) && !BENIGN_NEGATION_RE.test(h) && !CONTRASTIVE_STANCE_RE.test(h)) {
        for (let k = i; k <= j; k += 1) list[k].list_stance = 'non_malicious';
      }
      i = j;
      continue;
    }
    if (!isListBlock(list[i]) || isListBlock(list[i - 1])) continue;
    let j = i;
    while (j + 1 < list.length && isListBlock(list[j + 1])) j += 1;
    let lead = i - 1;
    while (lead >= 0 && isCaption(list[lead])) lead -= 1;
    let next = j + 1;
    while (next < list.length && isCaption(list[next])) next += 1;
    const leadText = lead >= 0 && list[lead]?.type !== 'heading' ? list[lead].text : '';
    // A sub-heading right above the list that names its values legitimate
    // ("Hashes of TWCore (the legitimate software used to distribute X)"),
    // tl-candidates-v33: the heading is the list's stance.
    const headingText = lead >= 0 && list[lead]?.type === 'heading' ? String(list[lead].text || '') : '';
    const heading_stance = Boolean(headingText) && BENIGN_COMPONENT_RE.test(headingText) &&
      !BENIGN_NEGATION_RE.test(headingText) && !CONTRASTIVE_STANCE_RE.test(headingText);
    const nextText = next < list.length && list[next]?.type !== 'heading' ? list[next].text : '';
    // A lead-in that names the class ("legitimate services such as:") or an
    // anaphoric follow-up sentence about "these endpoints".
    const lead_stance = /[:：]\s*$/.test(String(leadText || '').trim()) && stanceOf(leadText);
    const next_stance = LIST_ANAPHORA_RE.test(String(nextText || '')) && stanceOf(nextText);
    if (lead_stance || next_stance || heading_stance) {
      for (let k = i; k <= j; k += 1) list[k].list_stance = 'non_malicious';
    }
    i = j;
  }
  return list;
}

/**
 * True when `text` describes this exact value as a legitimate / benign
 * component (same window and negation rules as relation classification).
 * Read-only helper for diagnostics.
 * @param {string} text surrounding / row text
 * @param {string[]} values the value's spellings
 */
export function textDescribesValueAsBenign(text, values) {
  const focus = (Array.isArray(values) ? values : [values]).filter(Boolean);
  if (!focus.length) return false;
  const surrounding = refangTextForExtraction(String(text || ''));
  return describesBenignComponent(maskForeignNetworkTokens(maskObservable(surrounding, focus), focus));
}

/**
 * Anaphor that refers back to the observable of the previous sentence, per
 * observable kind ("… 198.51.100[.]7. This IP address was previously used by
 * …"). Only the immediately following sentence is read, and only when it
 * starts with the anaphor for the same kind of observable.
 */
const ANAPHOR_BY_KIND = Object.freeze({
  ip: /^\s*(?:this|that|the\s+same)\s+(?:ip(?:v4|v6)?(?:\s+address)?|address|server|host|node)\b/i,
  domain: /^\s*(?:this|that|the\s+same)\s+(?:domain(?:\s+name)?|hostname|host|server|site|website)\b/i,
  url: /^\s*(?:this|that|the\s+same)\s+(?:url|uri|link|address|resource|page)\b/i,
  hash: /^\s*(?:this|that|the\s+same)\s+(?:sample|file|hash|binary|executable|payload|document|dll|implant)\b/i
});

function observableKind(value) {
  const v = String(Array.isArray(value) ? value[0] : value || '').trim();
  if (/^https?:\/\//i.test(v) || /^[^\s/]+\.[^\s/]+\/\S/.test(v)) return 'url';
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(v) || /^[0-9a-f:]+:[0-9a-f:]*$/i.test(v)) return 'ip';
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(v)) return 'hash';
  return 'domain';
}

/**
 * The sentence right after the one naming OBSERVABLE, when it opens with an
 * anaphor for the same kind of observable ("This IP address …").
 * @param {string} masked
 * @param {string} kind
 */
function followingAnaphoricSentence(masked, kind) {
  const t = String(masked || '');
  const at = t.indexOf('OBSERVABLE');
  if (at < 0) return null;
  const rest = t.slice(at + 'OBSERVABLE'.length);
  const end = rest.search(/[.!?](?:\s|$)/);
  if (end < 0) return null;
  const next = rest.slice(end + 1).trimStart();
  const re = ANAPHOR_BY_KIND[kind];
  if (!re || !re.test(next)) return null;
  const stop = next.search(/[.!?](?:\s|$)/);
  return stop >= 0 ? next.slice(0, stop) : next;
}

/** Value-only lines and "value – note" / "label: value" rows are structural indicator rows. */
/** "1. ", "[2] ", "• " — a list marker must be followed by whitespace so "36.35.56.0/24" keeps its first octet. */
const BULLET_PREFIX_RE = /^(?:[\[(]?\d{1,3}[\])]?[.、)]?\s+|[-•*·]\s*)/;

/**
 * Attribute labels of a key/value indicator record ("SHA256 hash: … / File
 * name: … / File size: … / Description: …", Unit 42 IOC appendices).
 */
const RECORD_FIELD_LABEL =
  '(?:file\\s*(?:name|type|size|description|location|path)|filename|description|notes?|comments?|purpose|size|location|path|(?:sha-?(?:1|256|512)|md5|imphash|ssdeep)(?:\\s+hash)?|hash|url|domain|host(?:name)?|ip(?:\\s+address)?|e-?mail|first\\s+seen|last\\s+seen|compil(?:ed|ation)(?:\\s+time(?:stamp)?)?|signer|thumbprint|serial(?:\\s+number)?|mutex|user[\\s-]?agent|command\\s+line)';

/** "<record attribute>: <value>" line — one field of an indicator record, never a heading. */
export const RECORD_FIELD_LINE_RE = new RegExp(`^${RECORD_FIELD_LABEL}\\s*[:：]\\s*\\S`, 'i');
const RECORD_FIELD_PREFIX_RE = new RegExp(`^${RECORD_FIELD_LABEL}\\s*[:：]`, 'i');
const OTHER_OBSERVABLE_RE =
  /https?:\/\/|(?:\d{1,3}\.){3}\d{1,3}|\b[a-f0-9]{32,64}\b|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/i;

/** Separator-only tokens between values on one publisher row. */
const ROW_SEPARATOR_TOKEN_RE = /^(?:[-–—=]+>?|→|⇒|:)$/;

/**
 * Trailing row punctuation off one token; URL-shaped tokens keep balanced
 * path parentheses ("…/admin/(login)") through the shared URL boundary.
 * @param {string} tok
 */
function cleanRowToken(tok) {
  const t = String(tok || '');
  return t.includes('/') ? trimUrlBoundary(t) : t.replace(/[.,;:)\]。，；]+$/g, '');
}

/** Network schemes that are not an Indicator URL type; the host they carry is. */
const NON_HTTP_NETWORK_SCHEME_RE = /^(?:ftps?|sftp|scp|smb|ssh|telnet|tcp|udp|irc|ldaps?):\/\//i;
/** One transport endpoint and nothing else (host = name or IPv4, optional port). */
const TRANSPORT_ENDPOINT_LINE_RE =
  /^(?:tcp|udp|tls|ssl|socks[45]h?):\/\/(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}|(?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?\/?$/i;

const OBSERVABLE_TOKEN_RE =
  /^(?:https?:\/\/\S+|(?:\d{1,3}\.){3}\d{1,3}(?:\/(?:3[0-2]|[12]?\d)|:\d{1,5})?|[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::\d{1,5})?)$/i;

/**
 * One scheme-less host/path URL value ("host.example/path/file.bin"), exactly
 * as candidate extraction accepts it: DNS-shaped host with a strong suffix (or
 * an IPv4 host with a non-digit path) and a non-empty path. Relative paths / filesystem paths never qualify.
 * @param {string} token refanged or source spelling, no surrounding prose
 */
export function isSchemeLessUrlToken(token) {
  const t = refangTextForExtraction(String(token || '').trim()).replace(/[.,;)\]。，；]+$/, '');
  if (!t || /\s/.test(t) || t.length > 2048) return false;
  const slash = t.indexOf('/');
  if (slash <= 0 || slash === t.length - 1) return false;
  const v = validateUrlCandidate(t);
  if (v.ok !== true || v.reason !== 'scheme_less_url_with_dns_host') return false;
  // IPv4 host: only with a non-digit path, never a CIDR prefix (tl-candidates-v43).
  return v.host_kind === 'domain' || (v.host_kind === 'ip' && /^(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\/(?=\S*[a-z_~%])/i.test(t));
}

/**
 * A line that is one indicator value (optionally bulleted): the observable-only
 * line shapes, plus a scheme-less host/path URL value.
 * Filename-shaped dotted tokens (`Node.js`, `loader.exe`) are never indicator
 * value lines — they must not inherit a preceding "Domains" type label.
 * @param {string} text
 */
export function isIndicatorValueLine(text) {
  const t = String(text || '').trim().replace(BULLET_PREFIX_RE, '').trim();
  if (!t) return false;
  // A lone transport endpoint ("tcp://c2.example:443"): its host is the value.
  if (TRANSPORT_ENDPOINT_LINE_RE.test(refangTextForExtraction(t))) return true;
  // Scheme-less host/path URLs contain "/" and would otherwise look like paths.
  if (isSchemeLessUrlToken(t)) return true;
  if (isFilenameShapedToken(t)) return false;
  return isObservableOnlyLine(t);
}

/**
 * A short publisher IOC row that pairs one observable with a filename or short
 * annotation on either side ("loader.exe &lt;md5&gt;", "&lt;md5&gt; oleasapi.dll").
 * Shared by zone scope continuation and PDF line assembly so filename-first
 * rows are never treated as narrative while hash-first rows remain rows.
 * @param {string} text
 */
export function isAnnotatedIndicatorRowLine(text) {
  const raw = String(text || '').trim().replace(BULLET_PREFIX_RE, '').trim();
  if (!raw || raw.length > 160) return false;
  // HTTP request / API examples are technical prose, not publisher IOC rows.
  if (/^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|curl)\b/i.test(raw)) return false;
  if (isObservableListLine(raw) || isIndicatorValueLine(raw)) return true;
  const t = refangTextForExtraction(raw);
  const tokens = t.split(/\s+/).filter(Boolean);
  if (tokens.length < 1 || tokens.length > 6) return false;
  for (const tok of tokens) {
    // "FTP Server: ftp://host": a non-HTTP network scheme only carries its
    // host (FTP URLs are not an Indicator type); the host is the row value.
    const clean = cleanRowToken(tok).replace(NON_HTTP_NETWORK_SCHEME_RE, '');
    if (!clean) continue;
    const looksObservable =
      /^[a-f0-9]{32}$/i.test(clean) ||
      /^[a-f0-9]{40}$/i.test(clean) ||
      /^[a-f0-9]{64}$/i.test(clean) ||
      /^(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?:\/(?:3[0-2]|[12]?\d))?$/.test(clean) ||
      /\[\.]/.test(tok) ||
      isSchemeLessUrlToken(clean) ||
      isIndicatorValueLine(clean) ||
      isObservableOnlyLine(clean);
    if (looksObservable && isIndicatorRowShape(t, clean)) return true;
  }
  return false;
}

/**
 * A line made only of observables ("36.35.56.0/24 36.49.207.0/24", a <pre>
 * block of hashes, "a.example, b.example"): a publisher list whose layout
 * did not split one value per row. Structural, like a list.
 * @param {string} text
 */
export function isObservableListLine(text) {
  const t = refangTextForExtraction(String(text || '').trim()).replace(BULLET_PREFIX_RE, '').trim();
  if (!t || t.length > 2000) return false;
  // Pure separators between values ("<hash> – <url>", "a → b") are layout.
  const tokens = t.split(/[\s,;|，；]+/).filter((tok) => tok && !ROW_SEPARATOR_TOKEN_RE.test(tok));
  if (!tokens.length) return false;
  // "filename HASH" rows are one hash indicator with a file annotation, not a
  // two-token observable list (otherwise loader.exe / wg-ca.crt become domains).
  return tokens.every((tok) => {
    const clean = cleanRowToken(tok);
    if (isSchemeLessUrlToken(clean)) return true;
    if (isFilenameShapedToken(clean)) return false;
    return OBSERVABLE_TOKEN_RE.test(clean);
  });
}

/**
 * The visual line that carries `value` inside a multi-line block. Publisher
 * IOC appendices often keep several "filename HASH" / endpoint rows in one
 * `<pre>` (or one retained block); row-shape must read the line the value sits
 * on, not the whole block (which would look like prose because other hashes
 * sit on both sides).
 * @param {string} text
 * @param {string} value
 */
export function lineContainingObservable(text, value) {
  const hay = String(text || '');
  const v = refangTextForExtraction(String(value || '').trim());
  if (!hay || !v) return hay;
  if (!hay.includes('\n') && !hay.includes('\r')) return hay;
  const low = v.toLowerCase();
  for (const line of hay.split(/\r?\n/)) {
    if (line.toLowerCase().includes(low)) return line.trim();
  }
  return hay;
}

/**
 * True when a short line is one indicator value plus at most a short label or
 * annotation on one side ("vip311[.]cc – Decoy domain", "C2 203.0.113.44",
 * "Domain: evil.example", "_grab.py &lt;sha256&gt;"). A value embedded in prose
 * on both sides is not a row.
 * @param {string} text
 * @param {string} value normalized or original observable spelling
 */
export function isIndicatorRowShape(text, value) {
  const focused = lineContainingObservable(text, value);
  const t = refangTextForExtraction(String(focused || '').trim()).replace(BULLET_PREFIX_RE, '').trim();
  if (!t) return false;
  if (isObservableListLine(t)) return true;
  if (t.length > 160) return false;
  if (isIndicatorValueLine(t)) return true;
  const v = refangTextForExtraction(String(value || '').trim());
  if (!v) return false;
  const idx = t.toLowerCase().indexOf(v.toLowerCase());
  if (idx < 0) return false;
  const before = t.slice(0, idx).trim();
  let after = t.slice(idx + v.length).trim();
  // "SHA256 hash: <hash> File size: 92,657 bytes": a labelled value followed by
  // the next attribute of the same record is still one row (tl-zones-v13).
  if (before && RECORD_FIELD_PREFIX_RE.test(before) && RECORD_FIELD_PREFIX_RE.test(after)) after = '';
  if (before && after) return false;
  const annotation = before || after;
  if (!annotation) return true;
  if (annotation.length > 80) return false;
  if (/[.!?。]$/.test(annotation) && annotation.split(/\s+/).length > 6) return false;
  if (annotationHasOtherObservable(annotation)) return false;
  return true;
}

/**
 * Hex runs labelled as credentials / tokens / passwords are not file hashes.
 * Shape alone (`[0-9a-f]{32|40|64}`) never overrides an explicit credential
 * label. A concurrent hash keyword (md5 / sha / hash / sample / checksum) keeps
 * the hash reading — including mislabeled lengths ("SHA-256: <32 hex>"), which
 * are typed by value elsewhere.
 *
 * @param {string} text line or surrounding window
 * @param {string} value hex hash spelling
 * @returns {boolean} true when the occurrence must NOT become md5/sha1/sha256
 */
export function isCredentialLabeledHex(text, value) {
  const focused = lineContainingObservable(text, value) || text;
  const t = refangTextForExtraction(String(focused || '').trim()).replace(BULLET_PREFIX_RE, '').trim();
  const v = String(value || '').trim();
  if (!t || !v) return false;
  const idx = t.toLowerCase().indexOf(v.toLowerCase());
  if (idx < 0) return false;
  const before = t.slice(0, idx);
  if (!before.trim()) return false;
  // Hash / sample vocabulary on the label wins over credential wording.
  if (/\b(?:md5|sha-?1|sha-?256|sha-?384|sha-?512|hash(?:es)?|checksum|digest|sample)\b/i.test(before)) {
    return false;
  }
  return /\b(?:auth(?:entication)?\s+token|access\s+token|refresh\s+token|api[\s_-]?key|bearer(?:\s+token)?|password|passwd|passphrase|username|user\s*name|credential(?:s)?|secret|token)\b/i.test(before);
}

/**
 * A second network observable in a row annotation ("H1 – also 1.2.3.4") makes
 * the line prose, not a row. A file name ("H1 (loader.exe)", "H2 – map.aspx")
 * is the usual annotation of a sample hash and does not count: a dotted token
 * only counts when its suffix could be a DNS suffix.
 * @param {string} annotation
 */
function annotationHasOtherObservable(annotation) {
  const a = String(annotation || '');
  if (/https?:\/\/|(?:\d{1,3}\.){3}\d{1,3}|\b[a-f0-9]{32,64}\b/i.test(a)) return true;
  for (const m of a.matchAll(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi)) {
    const labels = m[0].toLowerCase().split('.');
    const last = labels[labels.length - 1];
    if (FILE_EXT_HINT.has(last) || suffixStrength(labels) === 'weak') continue;
    return true;
  }
  return false;
}

/**
 * The clause that actually mentions the observable, so a mixed sentence does
 * not transfer "beacons to Y" onto an unrelated "traffic to X".
 * @param {string} text
 * @param {string|null} value
 */
export function clauseContaining(text, value) {
  const hay = String(text || '');
  const variants = spellingVariants(value);
  if (!variants.length) return hay;
  const parts = hay.split(/(?<=[.;，；])\s+|,\s+|\s+(?:and|und|et|ve|和)\s+/);
  const index = parts.findIndex((p) => {
    const low = p.toLowerCase();
    return variants.some((v) => v && low.includes(String(v).toLowerCase()));
  });
  if (index < 0) return hay;
  const hit = parts[index];
  // A coordinated list member ("… sent to the following two C2 endpoints: X
  // and Y") carries no words of its own: it shares the clause it continues.
  const bare = variants.reduce((s, v) => s.split(String(v)).join(' '), hit).replace(/[\s.,;:()[\]"'“”‘’`]+/g, '');
  if (!bare && index > 0 && !/[.;!?]\s*$/.test(parts[index - 1])) return `${parts[index - 1]} ${hit}`;
  return hit;
}

function escapeRegExp(s) {
  return String(s || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Every spelling under which the observable may appear in the source: the
 * normalized value AND the original spelling, defanged / refanged, with and
 * without the trailing "/" URL normalization adds to a bare host ("https://host"
 * in the text vs "https://host/" as the identity). Longest first, so a longer
 * spelling is masked before its prefix.
 * @param {string|string[]|null} value
 */
function spellingVariants(value) {
  const bases = (Array.isArray(value) ? value : [value]).map((v) => String(v || '').trim()).filter(Boolean);
  const out = new Set();
  for (const b of bases) {
    for (const v of [b, b.replace(/\/$/, '')]) {
      if (!v) continue;
      out.add(v);
      out.add(v.replace(/\[\.\]/g, '.'));
      out.add(v.replace(/\./g, '[.]'));
    }
  }
  return [...out].filter(Boolean).sort((a, b) => b.length - a.length);
}

function maskObservable(text, value) {
  const hay = String(text || '');
  const variants = spellingVariants(value);
  if (!variants.length) return hay;
  let out = hay;
  for (const v of variants) {
    if (!v) continue;
    out = out.replace(new RegExp(escapeRegExp(v), 'ig'), ' OBSERVABLE ');
  }
  return out;
}

/** Other URLs/IPs in the same sentence must not transfer "downloads https://X" onto Y. */
function maskForeignNetworkTokens(text, keepValue) {
  const keeps = spellingVariants(keepValue).map((k) => k.toLowerCase());
  return String(text || '')
    .replace(/\b(?:hxxps?|https?):\/\/[^\s<>"'）)\]]+/gi, (m) => {
      const low = m.toLowerCase().replace(/hxxp/g, 'http');
      if (keeps.some((k) => low.includes(k) || k.includes(low))) return m;
      return ' URL ';
    })
    .replace(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\/(?:3[0-2]|[12]?\d))?\b/g, (m) => {
      if (keeps.some((k) => k.includes(m))) return m;
      return ' IP ';
    });
}
/**
 * Structural reading of one occurrence: is it an indicator row (assertion by
 * placement) or a mention inside prose?
 * @param {{ form?: string, block_type?: string|null, layout?: string|null, zone_reason?: string|null, structural_row?: boolean, row_shape?: boolean }} occ
 */
function structuralRowOf(occ) {
  const form = String(occ.form || '');
  // Domain part of an email address: never a row (see candidateExtraction).
  if (form === 'email_domain') return false;
  if (occ.structural_row === true || occ.row_shape === true) return true;
  // Delegated scope decided the row reading already (publisher-typed columns,
  // endpoints, value lines only): a free-form table cell is not a row there.
  if (String(occ.zone_reason || '') === 'section_tree_delegated_scope') return false;
  if (form === 'table_row' || form === 'list_row' || form === 'ip_port') return true;
  const bt = String(occ.block_type || '');
  if (bt === 'list_item' || occ.layout === 'observable_row') return true;
  const zr = String(occ.zone_reason || '');
  return zr === 'observable_list' || zr === 'cidr_list' || zr === 'ioc_table';
}

/**
 * Malware-artifact nouns that make a prose hash the publisher's sample. The
 * delivery containers of a payload ("a ZIP archive named X.zip (SHA-256: H)",
 * "the JAR file (SHA-256: H)") name the analysed artifact the same way; a
 * legitimate / signed stance is read first and still wins. The container must
 * be named as a file ("ZIP archive", "archive named …", "JAR file"): a bare
 * "archive" is also a service name ("an Internet Archive file").
 */
const SAMPLE_SUBJECT_RE =
  /\b(?:samples?|scripts?|loaders?|installers?|droppers?|payloads?|implants?|backdoors?|stealers?|rats?|trojans?|malware|binar(?:y|ies)|executables?|dlls?|variants?|stagers?|reimplementation|(?:zip|rar|7z|7-zip|tar|gz|iso|cab|password[- ]protected)\s+(?:archives?|files?)|archives?\s+(?:named|called|titled)|jar\s+(?:files?|archives?|payloads?)|wave\s+[a-z0-9])\b/i;

/**
 * A publisher list labelled by the operator's role, inside a curated IOC
 * section ("Specific operator-side IPs observed: X (…) and Y (…)", "Attacker
 * domains: X, Y"). The role word is required: "Legitimate IPs observed:" or
 * "Victim hosts:" assert nothing. Read on the whole sentence (the coordinated
 * second value has no words of its own).
 */
const ROLE_ENUMERATION_RE =
  /\b(?:operators?|attackers?|actors?|adversar(?:y|ies)|threat[- ]actors?|malicious|c2|c&c|campaign|intrusion|kit)(?:[- ](?:side|controlled|owned|operated|used))?\s+(?:[\w-]+\s+){0,2}?(?:ips?|ip\s+addresses|addresses|domains?|hosts?|hostnames?|urls?|servers?|nodes?|infrastructure|hashes|samples|files)\s+(?:(?:were|was|are|is)\s+)?(?:observed|seen|used|identified|included|noted|recorded|attributed)?\s*[:：](?:[^.;!?]|\.(?=\S)){0,240}?OBSERVABLE/i;

/**
 * The operator hands the value to the victim ("the threat actor pasted a URL
 * into the Teams chat: X", "the attacker sent a link to X"): delivery
 * infrastructure. Actor subject + delivery verb + link / file object, and the
 * value inside the same sentence.
 */
const ACTOR_DELIVERY_RE =
  /\b(?:threat\s+actors?|attackers?|operators?|adversar(?:y|ies)|intruders?|the\s+actors?)(?:\(s\))?\s+(?:\w+\s+){0,2}?(?:pasted|sent|shared|posted|delivered|messaged|dropped)\s+(?:a|an|the)\s+(?:[\w-]+\s+){0,2}?(?:url|link|lure|file|payload|archive|attachment)s?\b(?:[^.;!?]|\.(?=\S)){0,100}?OBSERVABLE/i;

/**
 * The value is named a lookalike / typosquat / impersonation host. Direction
 * matters: the role noun must govern this value ("the lookalike domain, X",
 * "X, a typosquatted domain", "X … and several other lookalike domains"),
 * never the organisation it imitates ("a lookalike of X", "impersonating X").
 */
const LOOKALIKE_ROLE_RE =
  /\b(?:look-?alike|typo-?squat(?:ted|ting)?|impersonation|spoofed)\s+(?:domains?|sites?|websites?|hosts?|hostnames?|urls?)\s*[,:(–—-]?\s*["'“”‘’`]?\s*OBSERVABLE|OBSERVABLE\s*["'“”‘’`]?\s*[,(]?\s*(?:is\s+|was\s+)?(?:a|an|the)\s+(?:look-?alike|typo-?squat(?:ted|ting)?|spoofed)\s+(?:domains?|sites?|websites?|hosts?)\b|OBSERVABLE\s*["'“”‘’`]?(?:[^.;!?]|\.(?=\S)){0,160}?\b(?:other|similar|additional|more)\s+(?:look-?alike|typo-?squat(?:ted|ting)?|impersonation|spoofed)\s+(?:domains?|sites?|websites?)\b/i;

/**
 * The sentence holding OBSERVABLE, plus a short record label right before it
 * ("Wave A. OBSERVABLE First observed …" → "Wave A. OBSERVABLE First observed …").
 * @param {string} masked
 */
function sentenceWithLeadLabel(masked) {
  const t = String(masked || '');
  const at = t.indexOf('OBSERVABLE');
  if (at < 0) return '';
  const boundaries = [...t.slice(0, at).matchAll(/[.;!?]\s+/g)];
  let start = boundaries.length ? boundaries[boundaries.length - 1].index + boundaries[boundaries.length - 1][0].length : 0;
  if (boundaries.length) {
    const prevStart = boundaries.length >= 2 ? boundaries[boundaries.length - 2].index + boundaries[boundaries.length - 2][0].length : 0;
    const label = t.slice(prevStart, start).trim();
    if (label && label.split(/\s+/).length <= 4) start = prevStart;
  }
  const rest = t.slice(at);
  const end = rest.search(/[.;!?](?:\s|$)/);
  return t.slice(start, end >= 0 ? at + end : t.length);
}

function isHexDigestValue(values) {
  return (Array.isArray(values) ? values : [values]).some((v) => /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(String(v || '').trim()));
}

const ALERT_ADJECTIVE_RE =
  /\b(?:unusual|suspicious|potential|possible|anomalous|uncommon|rare|abnormal|detected|detection|alert)\b/i;

/**
 * A detection-rule / alert caption: a Title-Case rule name containing an
 * alert adjective, then ":" and the matched telemetry naming the observable.
 * @param {string} masked clause with the observable masked as OBSERVABLE
 */
export function isDetectionAlertCaption(masked) {
  const t = String(masked || '').trim();
  const colon = t.indexOf(':');
  if (colon < 8 || colon > 120) return false;
  const name = t.slice(0, colon);
  if (/OBSERVABLE/.test(name) || !/OBSERVABLE/.test(t.slice(colon))) return false;
  if (!ALERT_ADJECTIVE_RE.test(name)) return false;
  const words = name.split(/\s+/).filter((w) => /^[A-Za-z]/.test(w) && w.length > 3);
  if (words.length < 3) return false;
  const titled = words.filter((w) => /^[A-Z]/.test(w)).length;
  return titled / words.length >= 0.75;
}

/**
 * The value is the legitimate service whose traffic the malware intercepts
 * ("a handler intercepts /x.js from OBSERVABLE and substitutes …"): a victim /
 * target service, not infrastructure the operator owns.
 */
const INTERCEPTED_SERVICE_RE =
  /\b(?:intercept\w*|hooks?|hooked|hooking)\b(?:[^.;]|\.(?!\s|$)){0,80}?\b(?:from|responses?\s+(?:of|from)|traffic\s+(?:to|from|for)|requests?\s+(?:to|for))\s+(?:the\s+)?(?:legitimate\s+|genuine\s+|official\s+)?OBSERVABLE/i;

/**
 * A bibliography entry written in the body: "[3] View8 (original): <url>".
 * The entry is a numbered citation whose title precedes the live link.
 */
const CITATION_ENTRY_RE = /^\s*[\[(]\d{1,3}[\])]\s*[^\s:][^:\n]{0,160}:\s*OBSERVABLE\s*[.;]?\s*$/i;
/** "1 <url>" / "[2] <url>": a footnote line holding only the link. */
const FOOTNOTE_URL_LINE_RE = /^\s*(?:\d{1,2}|\[\d{1,2}\]|\^\d{1,2})\s+OBSERVABLE\s*$/;
/** "<url> [7]": a link carrying the publisher's own citation marker. */
const TRAILING_CITATION_MARKER_RE = /OBSERVABLE\s*\[\d{1,3}\]/;
/** The publisher's own published tooling / material ("Our toolkit is publicly available at <url>"). */
const OWN_RESOURCE_RE =
  /\b(?:our|my)\s+(?:[\w-]+\s+){0,3}?(?:toolkit|tools?|repositor(?:y|ies)|repo|scripts?|code|datasets?|plugins?|project|materials?|decompiler|deobfuscator)\b[^.]{0,80}?\b(?:(?:publicly\s+)?available|published|hosted|released|shared)\b/i;

/**
 * True when a fanged URL occurrence outside any IOC scope is a citation: a
 * numbered reference entry, a link followed by the publisher's citation
 * marker, or a pointer to the publisher's own released tooling.
 * @param {string} masked surrounding text with the value masked as OBSERVABLE
 * @param {string} original original spelling
 */
function isCitationReference(masked, original) {
  if (!/^https?:\/\//i.test(String(original || '').trim())) return false;
  const t = String(masked || '').trim();
  if (CITATION_ENTRY_RE.test(t)) return true;
  if (TRAILING_CITATION_MARKER_RE.test(t)) return true;
  return OWN_RESOURCE_RE.test(t) && /OBSERVABLE/.test(t);
}

/**
 * Semantic relation of one occurrence to the observable it contains, with the
 * marker that produced it.
 *
 * Rows (table / list / value-only / annotated indicator lines / ip:port) inside
 * an authoritative section are source assertions. Prose is read for its
 * relation in every zone: an authoritative zone is evidence, never proof — a
 * research firm named in a C2 section stays contextual, a "connects to" clause
 * in the same section is operational.
 *
 * @param {string} surroundingText
 * @param {{ form?: string, zone?: string, value?: string, original?: string, structuralRow?: boolean, blockType?: string|null, layout?: string|null, zoneReason?: string|null }} [opts]
 * @returns {{ relation: string, marker: 'excluded_zone'|'structural_row'|'operational'|'provider'|'contextual'|'none'|'empty', authoritative: boolean, structural_row: boolean }}
 */
export function classifySourceRelationDetail(surroundingText, opts = {}) {
  const zone = String(opts.zone || '');
  const authoritative = AUTHORITATIVE_ZONES.has(zone);
  const structuralRow = structuralRowOf({
    form: opts.form,
    block_type: opts.blockType,
    layout: opts.layout,
    zone_reason: opts.zoneReason,
    structural_row: opts.structuralRow
  });
  if (EXCLUDED_ZONES.has(zone)) {
    return { relation: SOURCE_RELATIONS.REFERENCE, marker: 'excluded_zone', authoritative: false, structural_row: structuralRow };
  }
  // The publisher said what the whole list is ("These endpoints are legitimate
  // public … services"): every row of it is context, never an assertion.
  if (opts.listStance === 'non_malicious') {
    return { relation: SOURCE_RELATIONS.REFERENCE, marker: 'benign', authoritative, structural_row: structuralRow };
  }

  const form = String(opts.form || '');
  // A numbered citation / the publisher's own tooling link in the body is a
  // reference, never an Indicator (MODE A or B). IOC scopes are left alone:
  // a numbered IOC list there is an inventory, and defanged values never qualify.
  if (!authoritative && !looksDefanged(String(opts.original || '')) && form === 'url') {
    const refangedBlock = refangTextForExtraction(String(surroundingText || ''));
    if (isCitationReference(maskObservable(refangedBlock, [opts.value, opts.original].filter(Boolean)), opts.original || opts.value)) {
      return { relation: SOURCE_RELATIONS.REFERENCE, marker: 'citation', authoritative: false, structural_row: false };
    }
  }
  // A numbered footnote line that is only a live (fanged) link — "1 https://…"
  // under an IOC table whose values the publisher defanged — is the
  // reference list of the article, in any zone (tl-candidates-v33). A
  // numbered IOC row ("1. hxxp://evil[.]com") is defanged and never matches.
  if (form === 'url' && !looksDefanged(String(opts.original || ''))) {
    const line = maskObservable(refangTextForExtraction(String(surroundingText || '')), [opts.value, opts.original].filter(Boolean));
    if (FOOTNOTE_URL_LINE_RE.test(line)) {
      return { relation: SOURCE_RELATIONS.REFERENCE, marker: 'citation', authoritative: false, structural_row: false };
    }
  }
  // Endpoint forms (ip:port) assert by shape. Table rows assert only inside a
  // publisher-curated section (or after an explicit typed/header-labelled
  // table upgraded the block zone). A narrative dense IP grid must not become
  // operational-malicious merely because cells were extracted as table_row.
  const focusValue = [opts.value, opts.original].filter(Boolean);
  const surrounding = refangTextForExtraction(String(surroundingText || ''));
  const full = maskForeignNetworkTokens(maskObservable(surrounding, focusValue), focusValue);

  if (form === 'ip_port' || (authoritative && structuralRow)) {
    // The row itself can say what the value is: a publisher row that calls
    // this exact value a legitimate / benign component ("<hash> | Legitimate
    // <Vendor> executable") lists it for context — the side-loading
    // host beside the malicious DLL — not as an Indicator. Any maliciousness
    // or abuse cue in the same row window keeps the row assertion.
    if (structuralRow && form !== 'ip_port' && !ROW_MALICIOUS_RESOURCE_RE.test(full) && describesBenignComponent(full)) {
      return { relation: SOURCE_RELATIONS.REFERENCE, marker: 'benign', authoritative, structural_row: true };
    }
    // A table row that states outright that its subject is not malicious
    // ("Legitimate Windows binary used to sideload the loader. Not malicious.")
    // covers EVERY value of the row — the MD5 / SHA1 / SHA256 of one file —
    // not only the cell next to the statement (tl-candidates-v33).
    if (structuralRow && form === 'table_row' && ROW_NOT_MALICIOUS_RE.test(full)) {
      return { relation: SOURCE_RELATIONS.REFERENCE, marker: 'benign', authoritative, structural_row: true };
    }
    // A typed table row whose own descriptor cells call the value a provider /
    // service ("<host> | domain | Blockchain provider | C2 URL resolution")
    // lists infrastructure the malware relies on, not infrastructure it owns.
    if (structuralRow && form === 'table_row' && namesProviderService(full.replace(/\bOBSERVABLE\b/g, ' '))) {
      return { relation: SOURCE_RELATIONS.PROVIDER_SERVICE, marker: 'provider', authoritative, structural_row: true };
    }
    return { relation: SOURCE_RELATIONS.OPERATIONAL_MALICIOUS, marker: 'structural_row', authoritative, structural_row: true };
  }
  const text = maskForeignNetworkTokens(
    maskObservable(clauseContaining(surrounding, focusValue), focusValue),
    focusValue
  );
  if (!text.trim()) return { relation: SOURCE_RELATIONS.CONTEXTUAL, marker: 'empty', authoritative, structural_row: false };

  // "Unusual Network Connection to Suspicious Web Service: cloudflared to X":
  // a detection-rule / alert name with its telemetry detail describes what a
  // rule matched, not a publisher assertion that X is malicious.
  if (isDetectionAlertCaption(text)) {
    return { relation: SOURCE_RELATIONS.CONTEXTUAL, marker: 'detection_alert', authoritative, structural_row: false };
  }

  // Direction: the hosted object ("… used to host the domain OBSERVABLE") was
  // served by infrastructure — an operational reading, never "provider".
  if (HOSTED_OBJECT_RE.test(text) || HOSTED_OBJECT_RE.test(full)) {
    return { relation: SOURCE_RELATIONS.OPERATIONAL_MALICIOUS, marker: 'operational', authoritative, structural_row: false };
  }

  if (INTERCEPTED_SERVICE_RE.test(text) && !STANCE_OVERRIDE_RE.test(text)) {
    return { relation: SOURCE_RELATIONS.PROVIDER_SERVICE, marker: 'provider', authoritative, structural_row: false };
  }

  // A lookalike / impersonation host is attacker infrastructure by role, in
  // any zone (the role noun has to govern this exact value).
  if ((LOOKALIKE_ROLE_RE.test(text) || LOOKALIKE_ROLE_RE.test(full) || ACTOR_DELIVERY_RE.test(full)) && !describesBenignComponent(full)) {
    return { relation: SOURCE_RELATIONS.OPERATIONAL_MALICIOUS, marker: 'operational', authoritative, structural_row: false };
  }
  // Inside a curated / delegated IOC scope, a list the publisher labels by the
  // operator's role enumerates Indicators.
  if (authoritative && ROLE_ENUMERATION_RE.test(full) && !describesBenignComponent(full)) {
    return { relation: SOURCE_RELATIONS.OPERATIONAL_MALICIOUS, marker: 'operational', authoritative, structural_row: false };
  }

  const operational = OPERATIONAL_RELATION_RE.test(text);
  const providerLocal = PROVIDER_RELATION_RE.test(text) || PROVIDER_CATALOGUE_RE.test(text) || PLATFORM_SERVICE_RE.test(text);
  const providerCatalogue = PROVIDER_RELATION_RE.test(full) || PROVIDER_CATALOGUE_RE.test(full);
  const provider = providerLocal || (providerCatalogue && !operational);

  if (operational && !provider) {
    return { relation: SOURCE_RELATIONS.OPERATIONAL_MALICIOUS, marker: 'operational', authoritative, structural_row: false };
  }
  if (provider && !operational) {
    return { relation: SOURCE_RELATIONS.PROVIDER_SERVICE, marker: 'provider', authoritative, structural_row: false };
  }
  if (operational && provider) {
    if (/\b(?:as|is|were|was)\s+(?:a\s+)?(?:c2|c&c|command)/i.test(text)) {
      return { relation: SOURCE_RELATIONS.OPERATIONAL_MALICIOUS, marker: 'operational', authoritative, structural_row: false };
    }
    return { relation: SOURCE_RELATIONS.PROVIDER_SERVICE, marker: 'provider', authoritative, structural_row: false };
  }
  // A legitimate / signed component named as such is reference context,
  // decided before the model ever sees it.
  if (describesBenignComponent(full)) {
    return { relation: SOURCE_RELATIONS.REFERENCE, marker: 'benign', authoritative, structural_row: false };
  }
  // Delegated scope (every formal IOC section empty): a hash the clause names
  // as the analysed malware artifact ("we examine the following script:
  // <hash>", "Wave A. <hash> … downloads", "the installer <hash>") is the
  // publisher's sample assertion. Curated IOC sections never need this.
  if (zone === 'delegated_ioc_scope' && isHexDigestValue(focusValue) &&
      (SAMPLE_SUBJECT_RE.test(text) || SAMPLE_SUBJECT_RE.test(sentenceWithLeadLabel(full)))) {
    return { relation: SOURCE_RELATIONS.OPERATIONAL_MALICIOUS, marker: 'operational', authoritative, structural_row: false };
  }
  // "Report incidents to …" / "file a complaint at …" — agency contact chrome,
  // never an Indicator (MODE A and MODE B).
  if (REPORTING_CONTACT_RE.test(text) || REPORTING_CONTACT_RE.test(full)) {
    return { relation: SOURCE_RELATIONS.REFERENCE, marker: 'reporting_contact', authoritative: false, structural_row: false };
  }
  if (DEFENDER_RESOURCE_RE.test(text) || DEFENDER_RESOURCE_RE.test(full)) {
    return { relation: SOURCE_RELATIONS.REFERENCE, marker: 'defender_resource', authoritative: false, structural_row: false };
  }
  if (CONTEXT_RELATION_RE.test(text)) {
    return { relation: SOURCE_RELATIONS.CONTEXTUAL, marker: 'contextual', authoritative, structural_row: false };
  }
  // The next sentence continues about this exact observable ("This IP address
  // was used by the threat actor …"): its operational relation applies.
  const anaphoric = followingAnaphoricSentence(full, observableKind(focusValue));
  if (anaphoric && OPERATIONAL_RELATION_RE.test(anaphoric) && !PROVIDER_RELATION_RE.test(anaphoric)) {
    return { relation: SOURCE_RELATIONS.OPERATIONAL_MALICIOUS, marker: 'operational', authoritative, structural_row: false };
  }
  return { relation: SOURCE_RELATIONS.CONTEXTUAL, marker: 'none', authoritative, structural_row: false };
}

/**
 * Semantic relation of one occurrence to the observable it contains.
 * @param {string} surroundingText
 * @param {{ form?: string, zone?: string, value?: string, original?: string }} [opts]
 */
export function classifySourceRelation(surroundingText, opts = {}) {
  return classifySourceRelationDetail(surroundingText, opts).relation;
}

/**
 * Occurrence kind from its structural reading and relation.
 * @param {{ form?: string, block_type?: string|null }} occ
 * @param {{ relation: string, marker: string, structural_row: boolean }} detail
 */
export function occurrenceKindFor(occ, detail) {
  if (detail.marker === 'excluded_zone') return OCCURRENCE_KINDS.REFERENCE;
  const form = String(occ.form || '');
  if (form === 'table_row') return OCCURRENCE_KINDS.TYPED_TABLE_ROW;
  if (form === 'ip_port') return OCCURRENCE_KINDS.ENDPOINT;
  if (detail.structural_row) {
    return String(occ.block_type || '') === 'list_item' || form === 'list_row'
      ? OCCURRENCE_KINDS.LIST_ITEM
      : OCCURRENCE_KINDS.STANDALONE_INDICATOR_ROW;
  }
  if (detail.relation === SOURCE_RELATIONS.OPERATIONAL_MALICIOUS) return OCCURRENCE_KINDS.NARRATIVE_ASSERTION;
  if (detail.marker === 'provider' || detail.marker === 'contextual') return OCCURRENCE_KINDS.NARRATIVE_CONTEXT;
  return OCCURRENCE_KINDS.NARRATIVE_MENTION;
}

/**
 * Strongest relation across occurrences of one candidate.
 * @param {object} candidate
 */
export function strongestSourceRelation(candidate) {
  const rank = {
    [SOURCE_RELATIONS.OPERATIONAL_MALICIOUS]: 4,
    [SOURCE_RELATIONS.PROVIDER_SERVICE]: 2,
    [SOURCE_RELATIONS.CONTEXTUAL]: 1,
    [SOURCE_RELATIONS.REFERENCE]: 0
  };
  const occ = Array.isArray(candidate.occurrences) ? candidate.occurrences : [];
  if (!occ.length) {
    return classifySourceRelation(candidate.evidence_text || '', {
      form: candidate.form,
      zone: candidate.zone,
      value: candidate.normalized_value,
      original: candidate.original_value
    });
  }
  // Seed below REFERENCE (0) so a reporting-contact / bibliography-only
  // occurrence is not masked by a CONTEXTUAL default (NCSC agency chrome).
  let best = null;
  let bestRank = -1;
  for (const o of occ) {
    const rel = o.source_relation || relationDetailForOccurrence(candidate, o).relation;
    const rk = rank[rel] ?? 0;
    if (rk > bestRank) {
      best = rel;
      bestRank = rk;
    }
  }
  return best || SOURCE_RELATIONS.CONTEXTUAL;
}

/**
 * @param {object} candidate
 * @param {object} o occurrence
 */
/**
 * True when the occurrence carries the structural inputs the row reading is
 * computed from. Fresh extraction always does; evidence records persisted
 * before those inputs were stored (buildCandidateEvidenceRecord) do not.
 * @param {object} o occurrence
 */
export function hasStructuralInputs(o) {
  return typeof o?.row_shape === 'boolean'
    || typeof o?.structural_row === 'boolean'
    || Boolean(o?.block_type)
    || Boolean(o?.layout);
}

/**
 * A reloaded legacy record cannot recompute its row reading (the inputs were
 * never persisted), so it keeps the reading the extractor recorded: an
 * asserted row-kind occurrence. Narrative kinds never qualify, so a body
 * mention is never promoted by this fallback.
 * @param {object} o occurrence
 */
function legacyRecordedRow(o) {
  return !hasStructuralInputs(o) && o?.asserted === true && ROW_KINDS.has(String(o?.occurrence_kind || ''));
}

function relationDetailForOccurrence(candidate, o) {
  return classifySourceRelationDetail(o.surrounding_text || '', {
    form: o.form,
    zone: o.zone || o.section_kind,
    value: candidate.normalized_value,
    original: o.original_value || candidate.original_value,
    structuralRow: o.structural_row === true || o.row_shape === true || legacyRecordedRow(o),
    blockType: o.block_type || null,
    layout: o.layout || null,
    zoneReason: o.zone_reason || null,
    listStance: o.list_stance || null
  });
}

/**
 * Annotate each occurrence with source_relation, relation_marker and
 * occurrence_kind (mutates candidate).
 * @param {object} candidate
 */
export function attachOccurrenceRelations(candidate) {
  const occ = Array.isArray(candidate.occurrences) ? candidate.occurrences : [];
  for (const o of occ) {
    // A table reference / prose cell that did not assert the value is row
    // context: no relation, no assertion (tl-candidates-v37).
    if (o.reference_cell === true || o.description_cell === true || o.hosts_file_entry === true || o.truncated_duplicate === true) {
      o.source_relation = SOURCE_RELATIONS.CONTEXTUAL;
      o.relation_marker = o.hosts_file_entry === true
        ? 'hosts_file_entry'
        : o.truncated_duplicate === true ? 'truncated_duplicate' : 'context_cell';
      o.occurrence_kind = 'context_cell';
      o.asserted = false;
      continue;
    }
    const detail = relationDetailForOccurrence(candidate, o);
    o.source_relation = detail.relation;
    o.relation_marker = detail.marker;
    o.occurrence_kind = occurrenceKindFor(o, detail);
    // Source assertion = publisher-curated section AND (row placement OR an
    // operational clause). Zone alone is never an assertion.
    // A row that names the value as a benign component asserts nothing malicious.
    o.asserted = detail.marker !== 'benign' && detail.marker !== 'provider' && detail.authoritative && (detail.structural_row || detail.relation === SOURCE_RELATIONS.OPERATIONAL_MALICIOUS);
  }
  candidate.source_relation = strongestSourceRelation(candidate);
  return candidate;
}
