/**
 * urlscan.io Result API detail extraction (passive, read-only).
 *
 * Turns one already-retrieved Result API JSON document into a bounded,
 * analyst-oriented summary. Pure: never performs network I/O and never
 * follows URLs found in the scan. Request/response headers, cookies, DOM,
 * response bodies, console text beyond counts, and storage are never kept.
 *
 * Field paths are the ones observed in live Result API responses
 * (verdicts.overall/urlscan/engines/community, page.*, lists.*,
 * data.requests[].request/response, data.redirects[{from,to,status}],
 * meta.processors.wappa/download/rdns, stats.ipStats/domainStats/resourceStats).
 * Every path is optional — older or partial scans simply omit groups.
 */

import { redactUrlSecrets } from './auditRedaction.js';

export const URLSCAN_DETAIL_VERSION = 2;

const SHA256_RE = /^[0-9a-f]{64}$/i;
const MAX_REQUEST_SCAN = 2000;
const MAX_IPS = 10;
const MAX_DOMAINS = 10;
const MAX_LINK_DOMAINS = 10;
const MAX_TECHNOLOGIES = 15;
const MAX_HASHES = 5;
const MAX_DOWNLOADS = 5;
const MAX_REDIRECTS = 10;
const MAX_RELATED = 25;
const MAX_FAILED_ERRORS = 3;
const MAX_STATUS_BUCKETS = 8;
/** Browsers reject publicly trusted leaf certificates valid for longer than this. */
const PUBLIC_CA_MAX_VALIDITY_DAYS = 398;
/** At or below this many requests, an HTTP error page is treated as the whole observed session. */
const LIMITED_VISIBILITY_MAX_REQUESTS = 5;

const RESERVED_TLD_RE = /\.(invalid|test|example|localhost|local)$/i;
// Titles commonly served by anti-bot / access-challenge interstitials.
const CHALLENGE_TITLE_RE =
  /(just a moment|attention required|checking your browser|access denied|are you a robot|captcha|ddos-guard|security check|verify you are human|one more step)/i;

function obj(v) {
  return v && typeof v === 'object' && !Array.isArray(v) ? v : {};
}

function arr(v) {
  return Array.isArray(v) ? v : [];
}

function str(v, max = 300) {
  if (v === null || v === undefined) return null;
  const s = String(v).trim();
  if (!s) return null;
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

function num(v) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function bool(v) {
  return typeof v === 'boolean' ? v : null;
}

function host(v) {
  let h = String(v || '').trim().toLowerCase();
  if (!h) return null;
  if (h.endsWith('.')) h = h.slice(0, -1);
  return h || null;
}

function hostOfUrl(u) {
  try {
    return host(new URL(String(u)).hostname.replace(/^\[|\]$/g, ''));
  } catch {
    return null;
  }
}

/** Discovered URLs may carry signed tokens (e.g. SAS `sig=`): mask before persisting. */
function safeUrl(u, max = 500) {
  const r = redactUrlSecrets(u);
  return r ? str(r, max) : null;
}

function epochToIso(v) {
  const n = num(v);
  if (n === null || n <= 0) return null;
  const d = new Date(n > 1e12 ? n : n * 1000);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function isoOrNull(v) {
  if (!v) return null;
  const t = Date.parse(String(v));
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
}

function sameSite(domain, apex) {
  const d = host(domain);
  const a = host(apex);
  if (!d || !a) return false;
  return d === a || d.endsWith(`.${a}`);
}

function countMapToSortedList(map, keyName, limit) {
  return [...map.entries()]
    .sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])))
    .slice(0, limit)
    .map(([k, count]) => ({ [keyName]: k, count }));
}

/**
 * Normalize the four verdict sources. Supports the nested Result API shape
 * (verdicts.overall/urlscan/engines/community) and the flat shape some search
 * plans return (verdicts.malicious/score) by synthesizing `overall`.
 */
export function normalizeUrlscanVerdicts(rawVerdicts) {
  const v = obj(rawVerdicts);
  const hasAny = Object.keys(v).length > 0;
  if (!hasAny) return null;

  const brandNames = (list) => arr(list)
    .map((b) => str(typeof b === 'string' ? b : (b?.name || b?.key), 80))
    .filter(Boolean)
    .slice(0, 10);
  const strings = (list, max = 10) => arr(list).map((x) => str(x, 80)).filter(Boolean).slice(0, max);

  const source = (s) => {
    const o = obj(s);
    if (!Object.keys(o).length) return null;
    return {
      malicious: bool(o.malicious),
      score: num(o.score),
      has_verdicts: bool(o.hasVerdicts),
      categories: strings(o.categories),
      brands: brandNames(o.brands),
      tags: strings(o.tags)
    };
  };

  let overall = source(v.overall);
  if (!overall && (typeof v.malicious === 'boolean' || num(v.score) !== null)) {
    overall = {
      malicious: bool(v.malicious),
      score: num(v.score),
      has_verdicts: true,
      categories: strings(v.categories),
      brands: brandNames(v.brands),
      tags: strings(v.tags)
    };
  }

  const urlscan = source(v.urlscan);
  const enginesRaw = obj(v.engines);
  const engineName = (e) => str(typeof e === 'string' ? e : (e?.engine || e?.name), 80);
  const engines = Object.keys(enginesRaw).length ? {
    malicious: bool(enginesRaw.malicious),
    score: num(enginesRaw.score),
    has_verdicts: bool(enginesRaw.hasVerdicts),
    engines_total: num(enginesRaw.enginesTotal),
    malicious_total: num(enginesRaw.maliciousTotal),
    benign_total: num(enginesRaw.benignTotal),
    malicious_engines: arr(enginesRaw.maliciousVerdicts).map(engineName).filter(Boolean).slice(0, 10),
    categories: strings(enginesRaw.categories),
    tags: strings(enginesRaw.tags)
  } : null;
  const communityRaw = obj(v.community);
  const community = Object.keys(communityRaw).length ? {
    malicious: bool(communityRaw.malicious),
    score: num(communityRaw.score),
    has_verdicts: bool(communityRaw.hasVerdicts),
    votes_total: num(communityRaw.votesTotal),
    votes_malicious: num(communityRaw.votesMalicious),
    votes_benign: num(communityRaw.votesBenign)
  } : null;

  // Legacy flat shape without an overall object but with urlscan/community flags.
  if (!overall && (urlscan || community)) {
    const mal = urlscan?.malicious === true || community?.malicious === true;
    overall = {
      malicious: mal ? true : (urlscan?.malicious === false ? false : null),
      score: urlscan?.score ?? null,
      has_verdicts: urlscan?.has_verdicts ?? null,
      categories: urlscan?.categories || [],
      brands: urlscan?.brands || [],
      tags: []
    };
  }

  return { overall, urlscan, engines, community };
}

/**
 * Provider classification of one scan. Only urlscan's overall verdict
 * decides malicious/benign; a 0 score or missing verdict is "unclassified",
 * never "clean". Engine (ML) signals are surfaced separately as observations.
 */
export function deriveScanClassification(verdicts) {
  const overall = verdicts?.overall || null;
  if (!overall) {
    return { state: 'unknown', label: 'No verdict data', score: null, categories: [], brands: [] };
  }
  const categories = overall.categories || [];
  const brands = overall.brands || [];
  if (overall.malicious === true) {
    return { state: 'malicious', label: 'Malicious', score: overall.score, categories, brands };
  }
  if (overall.score !== null && overall.score < 0) {
    return { state: 'benign', label: 'Benign verdict', score: overall.score, categories, brands };
  }
  return { state: 'unclassified', label: 'Unclassified', score: overall.score, categories, brands };
}

function findPrimaryRequest(requests) {
  let firstDocument = null;
  for (const item of requests) {
    const req = obj(item?.request);
    if (req.primaryRequest === true) return item;
    if (!firstDocument && req.type === 'Document') firstDocument = item;
  }
  return firstDocument || requests[0] || null;
}

function extractNetwork(raw, requests, primaryItem) {
  const data = obj(raw.data);
  const stats = obj(raw.stats);
  const lists = obj(raw.lists);

  const methods = new Map();
  const statuses = new Map();
  const failedErrors = new Map();
  let failed = 0;
  let httpErrors = 0;
  for (const item of requests.slice(0, MAX_REQUEST_SCAN)) {
    const method = str(obj(obj(item?.request).request).method, 16);
    if (method) methods.set(method.toUpperCase(), (methods.get(method.toUpperCase()) || 0) + 1);
    const resp = obj(item?.response);
    const status = num(obj(resp.response).status);
    if (status !== null) {
      statuses.set(String(status), (statuses.get(String(status)) || 0) + 1);
      if (status >= 400) httpErrors += 1;
    }
    if (resp.failed && typeof resp.failed === 'object') {
      failed += 1;
      const text = str(resp.failed.errorText, 80) || 'unknown';
      failedErrors.set(text, (failedErrors.get(text) || 0) + 1);
    }
  }

  const resourceTypes = arr(stats.resourceStats)
    .map((r) => ({ type: str(r?.type, 40), count: num(r?.count) }))
    .filter((r) => r.type && r.count !== null)
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  const consoleErrors = arr(data.console)
    .filter((c) => String(obj(c?.message).level || '').toLowerCase() === 'error').length;
  const downloads = arr(obj(obj(raw.meta).processors).download?.data);
  const primaryStatus = num(obj(obj(primaryItem?.response).response).status);

  return {
    requests: requests.length,
    unique_ips: arr(lists.ips).length,
    unique_domains: arr(lists.domains).length,
    unique_countries: arr(lists.countries).length,
    redirects: arr(data.redirects).length,
    http_error_responses: httpErrors,
    failed_requests: failed,
    failed_request_errors: countMapToSortedList(failedErrors, 'error', MAX_FAILED_ERRORS),
    status_codes: countMapToSortedList(statuses, 'status', MAX_STATUS_BUCKETS),
    methods: countMapToSortedList(methods, 'method', 6),
    resource_types: resourceTypes,
    console_errors: consoleErrors,
    outgoing_links: num(stats.totalLinks) ?? arr(data.links).length,
    link_domains: arr(lists.linkDomains).length,
    websockets: arr(data.websockets).length,
    downloads: downloads.length,
    secure_percentage: num(stats.securePercentage),
    ipv6_percentage: num(stats.IPv6Percentage),
    primary_status: primaryStatus
  };
}

function extractRedirects(raw) {
  return arr(obj(raw.data).redirects)
    .slice(0, MAX_REDIRECTS)
    .map((r) => ({
      from: safeUrl(r?.from),
      to: safeUrl(r?.to),
      status: num(r?.status)
    }))
    .filter((r) => r.from || r.to);
}

function extractTls(raw, primaryItem) {
  const page = obj(raw.page);
  const sec = obj(obj(obj(primaryItem?.response).response).securityDetails);
  const issuer = str(page.tlsIssuer, 200) || str(sec.issuer, 200);
  const subject = str(sec.subjectName, 200);
  const validFrom = isoOrNull(page.tlsValidFrom) || epochToIso(sec.validFrom);
  const validTo = epochToIso(sec.validTo);
  const validDays = num(page.tlsValidDays);
  const ageDays = num(page.tlsAgeDays);
  if (!issuer && !subject && !validFrom && validDays === null) return null;
  return {
    issuer,
    subject,
    valid_from: validFrom,
    valid_to: validTo,
    valid_days: validDays,
    age_days: ageDays,
    protocol: str(sec.protocol, 20),
    san_count: Array.isArray(sec.sanList) ? sec.sanList.length : null,
    certificates_observed: arr(obj(raw.lists).certificates).length
  };
}

function extractTechnologies(raw) {
  const data = arr(obj(obj(obj(raw.meta).processors).wappa).data);
  return data
    .map((t) => ({
      name: str(t?.app, 80),
      categories: arr(t?.categories).map((c) => str(c?.name || c, 60)).filter(Boolean).slice(0, 3),
      confidence: num(t?.confidenceTotal)
    }))
    .filter((t) => t.name)
    .slice(0, MAX_TECHNOLOGIES);
}

function rdnsByIp(raw) {
  const out = new Map();
  for (const r of arr(obj(obj(obj(raw.meta).processors).rdns).data)) {
    const ip = str(r?.ip, 64);
    const ptr = str(r?.ptr, 255);
    if (ip && ptr && !out.has(ip)) out.set(ip, ptr);
  }
  return out;
}

function roleForDomain(domain, { pageDomain, pageApex, redirectHosts }) {
  if (domain && domain === pageDomain) return 'primary';
  if (domain && redirectHosts.has(domain)) return 'redirect_hop';
  if (sameSite(domain, pageApex)) return 'same_site';
  return 'third_party';
}

function extractInfrastructure(raw, redirects) {
  const page = obj(raw.page);
  const stats = obj(raw.stats);
  const pageIp = str(page.ip, 64);
  const pageDomain = host(page.domain);
  const pageApex = host(page.apexDomain) || pageDomain;
  const redirectHosts = new Set(
    redirects.flatMap((r) => [hostOfUrl(r.from)]).filter((h) => h && h !== pageDomain)
  );
  const ctx = { pageDomain, pageApex, redirectHosts };
  const ptrs = rdnsByIp(raw);
  const roleRank = { primary: 0, redirect_hop: 1, same_site: 2, third_party: 3 };

  const ips = arr(stats.ipStats)
    .map((s) => {
      const ip = str(s?.ip, 64);
      if (!ip) return null;
      const domains = arr(s?.domains).map(host).filter(Boolean);
      let role;
      if (ip === pageIp) role = 'primary';
      else if (domains.some((d) => redirectHosts.has(d))) role = 'redirect_hop';
      else if (domains.length && domains.every((d) => sameSite(d, pageApex))) role = 'same_site';
      else role = 'third_party';
      const asn = obj(s?.asn);
      const geo = obj(s?.geoip);
      return {
        ip,
        role,
        asn: str(asn.asn, 20),
        asn_name: str(asn.name || asn.description, 120),
        country: str(geo.country || asn.country, 4),
        requests: num(s?.requests) ?? num(s?.count),
        domains: domains.slice(0, 5),
        ptr: ptrs.get(ip) || null
      };
    })
    .filter(Boolean)
    .sort((a, b) => roleRank[a.role] - roleRank[b.role] || (b.requests || 0) - (a.requests || 0))
    .slice(0, MAX_IPS);

  const domains = arr(stats.domainStats)
    .map((s) => {
      const domain = host(s?.domain);
      if (!domain) return null;
      return {
        domain,
        role: roleForDomain(domain, ctx),
        requests: num(s?.count),
        ips: arr(s?.ips).map((x) => str(x, 64)).filter(Boolean).slice(0, 3)
      };
    })
    .filter(Boolean)
    .sort((a, b) => roleRank[a.role] - roleRank[b.role] || (b.requests || 0) - (a.requests || 0))
    .slice(0, MAX_DOMAINS);

  const contacted = new Set(arr(obj(raw.lists).domains).map(host).filter(Boolean));
  const linkedNotContacted = arr(obj(raw.lists).linkDomains)
    .map(host)
    .filter((d) => d && !contacted.has(d))
    .slice(0, MAX_LINK_DOMAINS);

  return { ips, domains, linked_not_contacted_domains: linkedNotContacted };
}

function extractHashes(requests, primaryItem) {
  const seen = new Map();
  for (const item of requests.slice(0, MAX_REQUEST_SCAN)) {
    const resp = obj(item?.response);
    const hash = String(resp.hash || '').toLowerCase();
    if (!SHA256_RE.test(hash) || seen.has(hash)) continue;
    const inner = obj(resp.response);
    seen.set(hash, {
      sha256: hash,
      context: item === primaryItem ? 'primary_response_body' : 'resource_response_body',
      resource_type: str(obj(item?.request).type || resp.type, 40),
      http_status: num(inner.status),
      mime_type: str(inner.mimeType, 80),
      size: num(resp.size) ?? num(resp.dataLength),
      url: safeUrl(obj(obj(item?.request).request).url, 300)
    });
  }
  const list = [...seen.values()];
  // Primary document body first, then larger resources (more distinctive than tiny shared assets).
  list.sort((a, b) => (a.context === 'primary_response_body' ? -1 : 0) - (b.context === 'primary_response_body' ? -1 : 0)
    || (b.size || 0) - (a.size || 0));
  return { total: list.length, sample: list.slice(0, MAX_HASHES) };
}

function extractDownloads(raw) {
  return arr(obj(obj(obj(raw.meta).processors).download).data)
    .slice(0, MAX_DOWNLOADS)
    .map((d) => {
      const sha = String(d?.sha256 || '').toLowerCase();
      return {
        filename: str(d?.filename, 200),
        file_size: num(d?.filesize),
        state: str(d?.state, 40),
        url: safeUrl(d?.url, 300),
        sha256: SHA256_RE.test(sha) ? sha : null
      };
    })
    .filter((d) => d.filename || d.url);
}

function buildRelatedObservables({ page, infrastructure, hashes, downloads, redirects }) {
  const out = [];
  const seen = new Set();
  const push = (type, value, relationship, origin, extra = {}) => {
    if (!value) return;
    // One row per observable: the first (most specific) relationship wins.
    const key = `${type}|${value}`;
    if (seen.has(key) || out.length >= MAX_RELATED) return;
    seen.add(key);
    out.push({ type, value, relationship, origin, ...extra });
  };

  if (page.url_changed && page.effective_url) {
    push('url', page.effective_url, 'final_url', 'page.url');
  }
  if (page.ip) push('ip', page.ip, 'primary_page_ip', 'page.ip');
  if (page.domain && page.submitted_domain && page.domain !== page.submitted_domain) {
    push('domain', page.domain, 'redirect_destination', 'page.domain');
  }
  for (const r of redirects) {
    const h = hostOfUrl(r.from);
    if (h && h !== page.domain) push('domain', h, 'redirect_hop', 'data.redirects');
  }
  for (const h of hashes.sample) {
    push('sha256', h.sha256, h.context, 'data.requests[].response.hash', {
      note: [h.resource_type, h.http_status !== null ? `HTTP ${h.http_status}` : null, h.mime_type]
        .filter(Boolean).join(' · ') || null
    });
  }
  for (const d of downloads) {
    if (d.sha256) push('sha256', d.sha256, 'download_sha256', 'meta.processors.download');
    push('filename', d.filename, 'download_attempt', 'meta.processors.download', {
      note: [d.state, d.file_size !== null ? `${d.file_size} bytes` : null].filter(Boolean).join(' · ') || null
    });
  }
  for (const ip of infrastructure.ips) {
    if (ip.role === 'primary') continue;
    push('ip', ip.ip, 'contacted_ip', 'stats.ipStats', { role: ip.role });
  }
  for (const d of infrastructure.domains) {
    if (d.role === 'primary') continue;
    push('domain', d.domain, 'contacted_domain', 'stats.domainStats', { role: d.role });
  }
  for (const d of infrastructure.linked_not_contacted_domains) {
    push('domain', d, 'linked_not_contacted', 'lists.linkDomains');
  }
  return out;
}

/**
 * Coverage/visibility observations. Contextual only — they never change the
 * provider classification or TalonHound's IOC verdict.
 */
export function buildScanObservations({ page, network, tls, classification, verdicts, downloads }) {
  const out = [];
  const status = page.status;
  const requests = network?.requests ?? null;

  if (status !== null && status >= 400) {
    const label = `HTTP ${status}${page.status_text ? ` ${page.status_text}` : ''}`;
    if (requests !== null && requests <= LIMITED_VISIBILITY_MAX_REQUESTS) {
      out.push({
        code: 'limited_visibility_http_error',
        level: 'caution',
        label: `Limited page visibility — ${label}`,
        detail: `The scanner received an error response (${requests} request${requests === 1 ? '' : 's'} total). The site's intended content was not observed; the provider assessment reflects only this response.`
      });
    } else {
      out.push({
        code: 'primary_http_error',
        level: 'info',
        label: `Primary response ${label}`,
        detail: requests !== null ? `The page still loaded ${requests} requests; review the scan before relying on its content.` : null
      });
    }
  } else if (status === null && page.navigation_error) {
    out.push({
      code: 'navigation_failed',
      level: 'caution',
      label: 'Limited page visibility — navigation failed',
      detail: `Primary request failed (${page.navigation_error}); no page content was observed.`
    });
  }

  if (page.title && CHALLENGE_TITLE_RE.test(page.title)) {
    out.push({
      code: 'possible_challenge_page',
      level: 'caution',
      label: 'Possible access-challenge or block page',
      detail: `Page title "${page.title}" resembles an anti-bot or access-control interstitial; the real content may be hidden from the scanner.`
    });
  }

  if (page.redirected === 'off-domain' || (page.url_changed && page.domain && page.submitted_domain && page.domain !== page.submitted_domain)) {
    out.push({
      code: 'off_domain_redirect',
      level: 'info',
      label: 'Redirected to a different domain',
      detail: `Scanned content came from ${page.domain || 'another domain'}; page facts and the verdict describe the destination, not only the submitted URL.`
    });
  }

  if (classification.state === 'unclassified') {
    out.push({
      code: 'unclassified',
      level: 'info',
      label: 'No urlscan classification',
      detail: 'Neither urlscan nor the community classified this scan. A score of 0 means no verdict signal — it is not a benign or safe verdict.'
    });
  }

  const engines = verdicts?.engines;
  if (engines?.malicious === true && classification.state !== 'malicious') {
    out.push({
      code: 'engine_signal_conflict',
      level: 'caution',
      label: 'Engine signal not reflected in overall verdict',
      detail: `urlscan's ML engine marked this scan malicious${engines.score !== null ? ` (engine score ${engines.score})` : ''}, but the overall urlscan verdict is not malicious. Treat as a lead, not a classification.`
    });
  }

  if (downloads.length) {
    out.push({
      code: 'download_attempt',
      level: 'caution',
      label: `Page triggered ${downloads.length} file download${downloads.length === 1 ? '' : 's'}`,
      detail: 'Download metadata only — files were not retrieved by TalonHound.'
    });
  }

  if (tls) {
    const issuer = String(tls.issuer || '');
    if (tls.subject && issuer && tls.subject === issuer) {
      out.push({
        code: 'self_issued_certificate',
        level: 'info',
        label: 'Self-issued TLS certificate',
        detail: `Issuer equals subject (${issuer})${RESERVED_TLD_RE.test(issuer) ? '; the name uses a reserved non-public domain' : ''} — not issued by a public CA.`
      });
    } else if (RESERVED_TLD_RE.test(issuer)) {
      out.push({
        code: 'reserved_tls_issuer',
        level: 'info',
        label: 'TLS issuer uses a reserved non-public name',
        detail: `Issuer "${issuer}" is not a public certificate authority.`
      });
    }
    if (tls.valid_days !== null && tls.valid_days > PUBLIC_CA_MAX_VALIDITY_DAYS) {
      out.push({
        code: 'long_tls_validity',
        level: 'info',
        label: `TLS validity ${tls.valid_days} days`,
        detail: `Exceeds the ${PUBLIC_CA_MAX_VALIDITY_DAYS}-day maximum browsers accept for publicly trusted certificates.`
      });
    }
  }

  return out;
}

/**
 * Normalize a Result API document into the bounded v2 detail summary.
 * Legacy flat keys (page_*, urlscan_score, …) are kept for older consumers.
 */
export function extractUrlscanResultDetail(raw, { scanId, resultUrl } = {}) {
  if (!raw || typeof raw !== 'object') return null;
  const task = obj(raw.task);
  const page = obj(raw.page);
  const data = obj(raw.data);
  const requests = arr(data.requests);
  const primaryItem = findPrimaryRequest(requests);
  const primaryResp = obj(obj(primaryItem?.response).response);
  const primaryFailed = obj(obj(primaryItem?.response).failed);

  const submittedUrl = str(task.url, 2048);
  const effectiveUrl = str(page.url, 2048);
  const submittedDomain = host(task.domain) || hostOfUrl(submittedUrl);
  const pageStatus = num(page.status) ?? num(primaryResp.status);

  const pageSummary = {
    submitted_url: submittedUrl,
    effective_url: effectiveUrl,
    url_changed: Boolean(submittedUrl && effectiveUrl && submittedUrl !== effectiveUrl),
    submitted_domain: submittedDomain,
    domain: host(page.domain),
    apex_domain: host(page.apexDomain),
    title: str(page.title, 300),
    status: pageStatus,
    status_text: str(primaryResp.statusText, 60),
    navigation_error: Object.keys(primaryFailed).length ? str(primaryFailed.errorText, 80) : null,
    mime_type: str(page.mimeType || primaryResp.mimeType, 80),
    redirected: str(page.redirected, 40),
    server: str(page.server, 200),
    ip: str(page.ip, 64),
    ptr: str(page.ptr, 255),
    asn: str(page.asn, 20),
    asn_name: str(page.asnname, 200),
    country: page.country ? String(page.country).toUpperCase().slice(0, 4) : null,
    city: str(page.city, 120),
    language: str(page.language, 20),
    umbrella_rank: num(page.umbrellaRank)
  };

  const verdicts = normalizeUrlscanVerdicts(raw.verdicts);
  const classification = deriveScanClassification(verdicts);
  const network = extractNetwork(raw, requests, primaryItem);
  const redirects = extractRedirects(raw);
  const tls = extractTls(raw, primaryItem);
  const technologies = extractTechnologies(raw);
  const infrastructure = extractInfrastructure(raw, redirects);
  const hashes = extractHashes(requests, primaryItem);
  const downloads = extractDownloads(raw);
  const related = buildRelatedObservables({ page: pageSummary, infrastructure, hashes, downloads, redirects });
  const observations = buildScanObservations({
    page: pageSummary, network, tls, classification, verdicts, downloads
  });

  return {
    detail_version: URLSCAN_DETAIL_VERSION,
    scan_id: scanId,
    result_url: resultUrl,
    scanned_at: task.time ? String(task.time) : null,
    visibility: str(task.visibility, 20),
    // Legacy flat fields (v1 consumers).
    task_url: submittedUrl,
    page_url: effectiveUrl,
    page_domain: pageSummary.domain,
    page_ip: pageSummary.ip,
    page_asn: pageSummary.asn,
    page_asnname: pageSummary.asn_name,
    page_country: pageSummary.country,
    page_city: pageSummary.city,
    page_server: pageSummary.server,
    page_title: pageSummary.title,
    page_status: pageStatus !== null ? String(pageStatus) : null,
    page_redirected: pageSummary.redirected,
    urlscan_malicious: verdicts?.urlscan?.malicious === true,
    engines_malicious: verdicts?.engines?.malicious === true,
    community_malicious: verdicts?.community?.malicious === true,
    overall_malicious: verdicts?.overall ? verdicts.overall.malicious === true : null,
    urlscan_score: verdicts?.overall?.score ?? null,
    score_is_not_confidence: true,
    categories: classification.categories,
    contacted_ips_sample: arr(obj(raw.lists).ips).map((x) => str(x, 64)).filter(Boolean).slice(0, 15),
    contacted_domains_sample: arr(obj(raw.lists).domains).map((x) => str(x, 255)).filter(Boolean).slice(0, 15),
    // v2 groups.
    classification,
    verdicts,
    page: pageSummary,
    network,
    redirects,
    tls,
    technologies,
    infrastructure,
    response_hashes: hashes,
    downloads,
    related_observables: related,
    observations
  };
}

function tally(values) {
  const map = new Map();
  for (const { value, at } of values) {
    if (value === null || value === undefined || value === '') continue;
    const key = String(value);
    const cur = map.get(key) || { value: key, count: 0, first_seen: null, last_seen: null };
    cur.count += 1;
    if (at && (!cur.first_seen || at < cur.first_seen)) cur.first_seen = at;
    if (at && (!cur.last_seen || at > cur.last_seen)) cur.last_seen = at;
    map.set(key, cur);
  }
  return [...map.values()].sort((a, b) => b.count - a.count || String(b.last_seen).localeCompare(String(a.last_seen)));
}

/**
 * Bounded comparison across the retrieved search sample (no extra API calls).
 * Only direct matches (exact URL / page hostname / primary page IP) are compared —
 * contacted-resource scans describe other infrastructure.
 */
export function buildUrlscanScanHistory(hits, { totalReported = null } = {}) {
  const direct = (hits || []).filter((h) => h && h.exact_match);
  const at = (h) => isoOrNull(h.scanned_at);
  const dimension = (pick) => tally(direct.map((h) => ({ value: pick(h), at: at(h) }))).slice(0, 5);
  const history = {
    compared_scans: direct.length,
    sample_size: (hits || []).length,
    total_reported: totalReported,
    primary_ips: dimension((h) => h.page_ip),
    asns: dimension((h) => h.page_asn),
    titles: dimension((h) => h.page_title),
    statuses: dimension((h) => h.page_status),
    effective_domains: dimension((h) => h.page_domain),
    tls_issuers: dimension((h) => h.tls_issuer)
  };
  history.changed = {
    primary_ip: history.primary_ips.length > 1,
    asn: history.asns.length > 1,
    title: history.titles.length > 1,
    status: history.statuses.length > 1,
    effective_domain: history.effective_domains.length > 1,
    tls_issuer: history.tls_issuers.length > 1
  };
  return history;
}
