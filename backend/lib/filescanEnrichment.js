export const FILESCAN_PROVIDER = 'filescan';
export const FILESCAN_API_BASE = 'https://www.filescan.io/api';
export const FILESCAN_SEARCH_PATH = '/reports/search';

export function maskApiKey(key) {
  const s = String(key || '').trim();
  if (!s) return null;
  if (s.length <= 4) return '****';
  return `${s.slice(0, 4)}${'*'.repeat(Math.max(8, s.length - 4))}`;
}

/**
 * Normalize a raw Filescan verdict string to a canonical value.
 * Handles Filescan-specific labels like "confirmed_threat" / "Confirmed Threat".
 */
export function normalizeVerdict(raw) {
  const s = String(raw || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
  if (['malicious', 'confirmed_threat', 'threat', 'infected', 'malware'].includes(s)) return 'malicious';
  // likely_malicious is Filescan's second-highest severity — treat as malicious for threat triage
  if (s === 'likely_malicious') return 'malicious';
  if (s === 'suspicious') return 'suspicious';
  if (['benign', 'clean', 'safe'].includes(s)) return 'benign';
  if (s === 'no_threat') return 'no_threat';
  return 'unknown';
}

/**
 * Human-readable display label preserving original casing with underscores replaced.
 * @returns {string|null}
 */
export function verdictDisplayLabel(raw) {
  const s = String(raw || '').trim();
  if (!s) return null;
  return s.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()) || null;
}

/**
 * Aggregate a list of raw verdict strings into a single canonical verdict.
 * Precedence: malicious > suspicious > benign > no_threat > unknown
 */
export function aggregateVerdict(verdicts) {
  const all = (verdicts || []).map((v) => normalizeVerdict(String(v || '')));
  if (all.includes('malicious')) return 'malicious';
  if (all.includes('suspicious')) return 'suspicious';
  if (all.includes('benign')) return 'benign';
  if (all.includes('no_threat')) return 'no_threat';
  return 'unknown';
}

/**
 * Confidence hint from canonical verdict. Never written to IOC global confidence.
 */
export function verdictToConfidenceHint(verdict, summaryCounts) {
  if (verdict === 'malicious') return 'high';
  if (verdict === 'suspicious') return 'medium';
  if (verdict === 'benign' || verdict === 'no_threat') return 'low';
  return null;
}

// Cluster types that identify OSINT_LOOKUP tags as malware families
const MALWARE_CLUSTER_TYPES = new Set(['malpedia', 'ransomware', 'tool', 'exploit_kit', 'rat']);

/**
 * Determine if a tag entry from Filescan is a malware family reference.
 * `isMalwareFamilyTag` is unreliable — many known families (phorpiex, bashlite)
 * have it set to false. Use cluster type from descriptions as the primary signal.
 */
export function isTagMalwareFamily(tagEntry) {
  if (tagEntry?.isMalwareFamilyTag) return true;
  const src = tagEntry?.source;
  if (src === 'OSINT_LOOKUP' || src === 'THREAT_ATTRIBUTION') {
    const descs = tagEntry?.tag?.descriptions;
    if (Array.isArray(descs)) {
      return descs.some((d) => MALWARE_CLUSTER_TYPES.has(d?.cluster?.type));
    }
  }
  return false;
}

// Tag classification — small focused sets, not exhaustive
const MALWARE_FAMILY_TAGS = new Set([
  'phorpiex', 'emotet', 'trickbot', 'wannacry', 'locky', 'mirai',
  'dridex', 'qakbot', 'ryuk', 'conti', 'njrat', 'remcos', 'asyncrat',
  'nanocore', 'agent_tesla', 'formbook', 'redline', 'vidar', 'raccoon',
  'azorult', 'darkcomet', 'netwire', 'ursnif', 'zeus', 'blackcat',
  'lockbit', 'revil', 'sodinokibi', 'icedid', 'bazarloader', 'darkside',
  'cobaltstrike', 'metasploit', 'sliver', 'brute_ratel'
]);

const THREAT_TYPE_TAGS = new Set([
  'dropper', 'downloader', 'trojan', 'stealer', 'ransomware', 'botnet',
  'phishing', 'c2', 'loader', 'backdoor', 'rat', 'keylogger', 'rootkit',
  'worm', 'adware', 'spyware', 'infostealer', 'miner', 'cryptominer',
  'exploit', 'shellcode', 'injector', 'packer', 'banker', 'credential_stealer'
]);

const FILE_TYPE_TAGS = new Set([
  'peexe', 'pe32', 'pe64', 'elf', 'elf64', 'macho', 'apk', 'jar', 'dex',
  'document', 'pdf', 'office', 'docx', 'xlsx', 'script', 'dll', 'lnk',
  'vbs', 'js', 'ps1', 'bat', 'hta', 'msi', 'iso'
]);

const COMPILER_HINT_TAGS = new Set([
  'microsoft_visual_cc', 'visual_cpp', 'dotnet', 'net', 'csharp',
  'go', 'golang', 'rust', 'python', 'autoit', 'nsis', 'inno',
  'upx', 'aspack', 'themida', 'vmprotect', 'msil', 'delphi', 'vb6', 'visualbasic'
]);

/**
 * Classify a tag into semantic buckets.
 * A single tag may appear in multiple buckets.
 */
export function classifyTag(name) {
  const n = String(name || '').trim().toLowerCase();
  return {
    is_malware_family: MALWARE_FAMILY_TAGS.has(n),
    is_threat_type: THREAT_TYPE_TAGS.has(n),
    is_file_type: FILE_TYPE_TAGS.has(n),
    is_compiler_hint: COMPILER_HINT_TAGS.has(n)
  };
}

/**
 * Normalize a raw Filescan.io search response into the canonical enrichment model.
 */
export function normalizeFilescanResponse(rawBody, ctx) {
  const items = Array.isArray(rawBody?.items) ? rawBody.items : [];
  const fetchedAt = ctx.fetchedAt || new Date().toISOString();

  // --- Verdict aggregation ---
  const rawVerdicts = items.map((item) => String(item?.verdict || 'unknown'));
  const verdict = aggregateVerdict(rawVerdicts);
  const bestRawVerdict = rawVerdicts.find((v) => normalizeVerdict(v) === verdict) || null;
  const verdict_label = verdictDisplayLabel(bestRawVerdict);

  // Primary item: first with the highest-severity verdict
  const primaryItem = items.find((item) => normalizeVerdict(String(item?.verdict || '')) === verdict) || items[0] || null;

  // --- File metadata ---
  const fileObj = primaryItem?.file && typeof primaryItem.file === 'object' ? primaryItem.file : null;
  const file = fileObj ? {
    name: fileObj.name || null,
    sha256: fileObj.sha256 || null,
    sha1: fileObj.sha1 || null,
    md5: fileObj.md5 || null,
    // API field is mime_type (not media_type); short_type for PE/ELF/etc label
    media_type: fileObj.mime_type || fileObj.media_type || fileObj.mediaType || null,
    type: fileObj.short_type || fileObj.type || null,
    size: fileObj.size != null ? fileObj.size : null,
    entropy: fileObj.entropy != null ? Number(fileObj.entropy) : null,
    strings_count: fileObj.strings != null ? Number(fileObj.strings)
      : (fileObj.strings_count != null ? Number(fileObj.strings_count) : null)
  } : null;

  // --- Primary report metadata ---
  const primaryFlowId = primaryItem?.scan_init?.id || primaryItem?.id || null;
  const primaryReportId = primaryItem?.id ? String(primaryItem.id) : null;
  const primaryLink = primaryFlowId
    ? `https://www.filescan.io/reports/${encodeURIComponent(String(primaryFlowId))}`
    : null;
  const report = primaryItem ? {
    report_id: primaryReportId,
    flow_id: primaryFlowId ? String(primaryFlowId) : null,
    report_date: primaryItem.date || null,
    scan_engine: primaryItem.scan_engine || primaryItem.scanEngine || null,
    link: primaryLink
  } : null;

  // --- Reports list ---
  const reports = items.slice(0, 20).map((item) => {
    const flowId = item?.scan_init?.id || item?.id || null;
    const reportLink = flowId
      ? `https://www.filescan.io/reports/${encodeURIComponent(String(flowId))}`
      : null;
    return {
      report_id: item?.id ? String(item.id) : null,
      flow_id: flowId ? String(flowId) : null,
      verdict: normalizeVerdict(String(item?.verdict || 'unknown')),
      report_date: item?.date || null,
      file_name: item?.file?.name || null,
      file_hash: item?.file?.sha256 || null,
      sha256: item?.file?.sha256 || null,
      file_link: item?.file?.link || null,
      link: reportLink
    };
  });

  // --- Tags + semantic classification ---
  const tagSet = new Set();
  const malwareFamilySet = new Set();
  const threatTypeSet = new Set();
  const fileTypeSet = new Set();
  const compilerHintSet = new Set();

  for (const item of items) {
    if (!Array.isArray(item?.tags)) continue;
    for (const t of item.tags) {
      const name = t?.tag?.name;
      if (!name || typeof name !== 'string') continue;
      const n = name.trim();
      if (!n) continue;
      tagSet.add(n);
      // isTagMalwareFamily checks isMalwareFamilyTag + cluster type (more reliable)
      if (isTagMalwareFamily(t)) malwareFamilySet.add(n);
      const cls = classifyTag(n);
      if (cls.is_malware_family) malwareFamilySet.add(n);
      if (cls.is_threat_type) threatTypeSet.add(n);
      if (cls.is_file_type) fileTypeSet.add(n);
      if (cls.is_compiler_hint) compilerHintSet.add(n);
    }
  }

  // --- Threat indicators ---
  // Deduplicated by title+provider key
  const indicatorMap = new Map();
  for (const item of items) {
    // Option A: dedicated threat_indicators array on item
    if (Array.isArray(item?.threat_indicators)) {
      for (const ti of item.threat_indicators) {
        const key = `${ti?.title || ''}|${ti?.origin || ti?.provider || ''}`;
        if (!indicatorMap.has(key)) {
          indicatorMap.set(key, {
            title: ti?.title || null,
            verdict: ti?.verdict ? String(ti.verdict).toLowerCase() : null,
            origin: ti?.origin || ti?.provider || null,
            provider: ti?.origin || ti?.provider || null,
            resource_type: ti?.resource_type || ti?.resourceType || null,
            resource_value: ti?.resource_value || ti?.resourceValue || null
          });
        }
      }
    }
    // Option B: root-tagged items as indicators
    if (Array.isArray(item?.tags)) {
      for (const t of item.tags) {
        if (t?.isRootTag && t?.source && t?.tag?.name) {
          const key = `tag|${t.tag.name}|${t.source}`;
          if (!indicatorMap.has(key)) {
            indicatorMap.set(key, {
              title: t.tag.name,
              verdict: normalizeVerdict(String(item?.verdict || 'unknown')),
              origin: t.source || null,
              provider: t.source || null,
              resource_type: null,
              resource_value: null
            });
          }
        }
      }
    }
  }
  const threat_indicators = Array.from(indicatorMap.values()).slice(0, 20);

  // --- Summary counts ---
  const primarySummary = primaryItem?.summary && typeof primaryItem.summary === 'object'
    ? primaryItem.summary : {};
  const summary_counts = {
    threat_reputation_iocs: primarySummary.threat_reputation_iocs ?? primarySummary.reputationIocs ?? null,
    confirmed_threat_indicators: primarySummary.confirmed_threat_indicators
      ?? primarySummary.confirmedThreatIndicators
      ?? (indicatorMap.size > 0 ? indicatorMap.size : null),
    similar_samples: primarySummary.similar_samples ?? primarySummary.similarSamples ?? null,
    extracted_iocs: primarySummary.extracted_iocs ?? primarySummary.extractedIocs ?? null
  };

  // --- Emulation data ---
  const emuObj = primaryItem?.emulation && typeof primaryItem.emulation === 'object'
    ? primaryItem.emulation : null;
  const emulation = emuObj ? {
    applicable: emuObj.applicable ?? null,
    processes_count: emuObj.processes ?? emuObj.processesCount ?? null,
    network_count: emuObj.network ?? emuObj.networkCount ?? null,
    other_count: emuObj.other ?? emuObj.otherCount ?? null
  } : null;

  return {
    provider: FILESCAN_PROVIDER,
    found: items.length > 0,
    verdict,
    verdict_label,
    confidence_hint: verdictToConfidenceHint(verdict, summary_counts),
    report_count: items.length,

    tags: Array.from(tagSet).slice(0, 30),
    malware_families: Array.from(malwareFamilySet).slice(0, 10),
    threat_types: Array.from(threatTypeSet).slice(0, 10),
    file_type_hints: Array.from(fileTypeSet).slice(0, 5),
    compiler_hints: Array.from(compilerHintSet).slice(0, 5),

    file,
    report,
    reports,
    threat_indicators,
    summary_counts,
    emulation,

    source_references: [],
    ioc_type: ctx.iocType,
    ioc_value: ctx.iocValue,
    fetched_at: fetchedAt,
    provider_status: 'success',
    raw_summary: {
      count: rawBody?.count ?? items.length,
      method: rawBody?.method || null
    }
  };
}

/**
 * Map HTTP status to normalized provider_status + user message.
 */
export function filescanHttpError(status) {
  const code = Number(status);
  if (code === 401 || code === 403) {
    return { provider_status: 'auth_error', code: 'auth', message: 'Invalid or unauthorized Filescan.io API key' };
  }
  if (code === 429) {
    return { provider_status: 'rate_limited', code: 'rate_limit', message: 'Filescan.io rate limit reached. Try again later.' };
  }
  if (code >= 500) {
    return { provider_status: 'provider_error', code: 'provider_error', message: 'Filescan.io service error. Try again later.' };
  }
  return { provider_status: 'failed', code: 'http_error', message: `Filescan.io lookup failed (${code})` };
}

/**
 * Normalize an IOC value for cache key purposes.
 */
export function normalizeFilescanCacheKey(iocType, iocValue) {
  const t = String(iocType || '').trim().toLowerCase();
  const v = String(iocValue || '').trim().toLowerCase();
  return `${t}:${v}`;
}
