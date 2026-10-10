/**
 * View model for the urlscan.io Intelligence card.
 *
 * Pure: turns a stored urlscan normalized_summary (v2, or a legacy v1 row)
 * into display groups ordered "conclusion → explanation → evidence". Never
 * invents fields — absent data yields absent rows. Provider classification is
 * shown as provider evidence only; it never maps to a TalonHound IOC verdict.
 *
 * Presentation priority (findingPriority) is a fixed display mapping over the
 * backend observation codes. It orders and emphasizes findings; it never
 * changes the observation, the classification, or the stored evidence.
 */

export const RELATION_LABELS = {
  exact_url: 'Exact URL',
  canonical_url: 'Canonical URL',
  page_hostname: 'Page hostname',
  task_hostname: 'Task hostname',
  page_apex: 'Page apex domain',
  subdomain_of_ioc: 'Subdomain of IOC',
  ioc_subdomain_of_page: 'IOC is subdomain of page',
  contacted_domain: 'Contacted domain',
  primary_page_ip: 'Primary page IP',
  contacted_ip: 'Contacted IP (related)',
  related: 'Related'
};

export const OBSERVABLE_RELATIONSHIP_LABELS = {
  primary_page_ip: 'Primary hosting IP',
  final_url: 'Final URL after redirects',
  redirect_destination: 'Redirect destination',
  redirect_hop: 'Redirect hop',
  primary_response_body: 'Primary HTTP response body — not a malware sample',
  resource_response_body: 'Loaded resource body — not a malware sample',
  download_attempt: 'File download triggered by the page',
  download_sha256: 'Downloaded file (urlscan metadata)',
  contacted_ip: 'Contacted IP',
  contacted_domain: 'Contacted domain',
  linked_not_contacted: 'Linked on page, not contacted'
};

export const INFRA_ROLE_LABELS = {
  primary: 'primary hosting',
  redirect_hop: 'redirect hop',
  same_site: 'same site',
  third_party: 'third-party resource'
};

/** Related-observable groups, in display order. */
export const RELATED_GROUPS = [
  { key: 'primary', label: 'Primary infrastructure' },
  { key: 'redirect', label: 'Redirect infrastructure' },
  { key: 'same_site', label: 'Same-site resources' },
  { key: 'third_party', label: 'Third-party resources' },
  { key: 'linked', label: 'Linked only (not contacted)' },
  { key: 'hash', label: 'Response-body hashes' },
  { key: 'download', label: 'Downloads' }
];

/**
 * Display priority for backend observation codes.
 *  signal    — investigation lead (amber, always visible)
 *  coverage  — scan visibility limitation (amber, always visible)
 *  context   — changes how to read the evidence (neutral, always visible)
 *  technical — unusual technical detail (neutral, behind "technical observations")
 *  covered   — already conveyed by the assessment tiles; not repeated
 * Unknown codes fall back by backend level: caution → coverage, else technical.
 */
export const FINDING_PRIORITY = {
  engine_signal_conflict: { group: 'signal', title: 'Conflicting ML signal' },
  download_attempt: { group: 'signal', title: 'File download triggered' },
  limited_visibility_http_error: { group: 'coverage', title: 'Limited page visibility' },
  navigation_failed: { group: 'coverage', title: 'Navigation failed' },
  possible_challenge_page: { group: 'coverage', title: 'Possible challenge or block page' },
  off_domain_redirect: { group: 'context', title: 'Redirected to another domain' },
  primary_http_error: { group: 'context', title: 'Primary response was an HTTP error' },
  self_issued_certificate: { group: 'technical', title: 'Self-issued TLS certificate' },
  reserved_tls_issuer: { group: 'technical', title: 'Non-public TLS issuer' },
  long_tls_validity: { group: 'technical', title: 'Long TLS validity period' },
  unclassified: { group: 'covered', title: 'No urlscan classification' }
};

const GROUP_ORDER = ['coverage', 'signal', 'context', 'technical'];
const CLASSIFICATION_STATES = new Set(['malicious', 'benign', 'unclassified', 'unknown']);

function arr(v) {
  return Array.isArray(v) ? v : [];
}

function present(v) {
  return v !== null && v !== undefined && v !== '';
}

function toInt(v) {
  if (!present(v)) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function plural(n, one, many = `${one}s`) {
  return `${n} ${n === 1 ? one : many}`;
}

export function countryLabel(code) {
  const c = String(code || '').trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(c)) return c || null;
  try {
    const name = new Intl.DisplayNames(['en'], { type: 'region' }).of(c);
    return name && name !== c ? `${name} (${c})` : c;
  } catch {
    return c;
  }
}

export function isOfficialResultUrl(href) {
  try {
    const u = new URL(String(href || ''));
    return u.protocol === 'https:'
      && u.hostname === 'urlscan.io'
      && /^\/result\/[0-9a-f-]{36}\/?$/i.test(u.pathname);
  } catch {
    return false;
  }
}

function formatAsn(asn) {
  const s = String(asn || '').trim();
  if (!s) return null;
  return /^AS/i.test(s) ? s.toUpperCase() : `AS${s}`;
}

function statusLabel(status, text) {
  const n = toInt(status);
  if (n === null) return null;
  return text ? `${n} ${text}` : String(n);
}

/** Classification of one search hit for the history list. */
export function scanVerdictLabel(hit) {
  const state = hit?.classification_state;
  if (state === 'malicious' || hit?.malicious === true) return 'Malicious';
  if (state === 'benign') return 'Benign verdict';
  if (state === 'unclassified') return 'Unclassified';
  if (hit?.malicious === false) return 'Not malicious';
  return 'Verdict not retrieved';
}

/** Limited-visibility fallback for legacy rows stored before observations existed. */
function legacyObservations(detail, hit) {
  const status = toInt(detail?.page_status ?? hit?.page_status);
  const requests = toInt(hit?.stats_requests);
  if (status !== null && status >= 400 && requests !== null && requests <= 5) {
    return [{
      code: 'limited_visibility_http_error',
      level: 'caution',
      label: `Limited page visibility — HTTP ${status}`,
      detail: `The scanner received an error response (${plural(requests, 'request')} total). The site's intended content was not observed.`
    }];
  }
  return [];
}

/**
 * Card state from a GET/refresh payload (previously inline in the card).
 * @returns {{ status: string, message: string }}
 */
export function urlscanPayloadState(data) {
  const status = String(data?.provider_status || data?.status || 'not_run').toLowerCase();
  const assessment = data?.evidence_assessment || data?.summary?.evidence_assessment || null;
  if (status === 'not_configured' || status === 'api_key_missing') {
    return { status: 'not_configured', message: data?.message || 'urlscan.io API key is not configured' };
  }
  if (status === 'disabled') return { status: 'disabled', message: 'urlscan.io provider is disabled' };
  if ((status === 'not_run' || status === 'not_found') && !data?.summary) {
    return { status: 'not_run', message: data?.message || 'No urlscan data yet' };
  }
  if (status === 'rate_limited') return { status: 'rate_limited', message: data?.message || 'urlscan.io rate limit reached' };
  if (status === 'error' || status === 'failed' || status === 'auth_error') {
    return { status: 'error', message: data?.error_message || data?.message || 'urlscan.io enrichment failed' };
  }
  if (status === 'skipped' || assessment === 'privacy_restricted') {
    return { status: 'privacy_restricted', message: data?.error_message || data?.message || 'Lookup skipped for privacy' };
  }
  if (status === 'unsupported' || status === 'unsupported_private_ip') {
    return { status: 'unsupported', message: data?.message || 'Unsupported for urlscan enrichment' };
  }
  return { status: assessment === 'no_results' || status === 'not_found' ? 'no_results' : 'success', message: '' };
}

/** Card state after a failed refresh request. */
export function urlscanRefreshErrorState(httpStatus, body = {}) {
  if (httpStatus === 429) return { status: 'rate_limited', message: body.message || 'urlscan.io rate limit reached' };
  if (httpStatus === 409 && body.provider_status === 'not_configured') {
    return { status: 'not_configured', message: body.message || 'urlscan.io API key is not configured' };
  }
  if (httpStatus === 409) return { status: 'disabled', message: body.message || 'urlscan.io provider is disabled' };
  return { status: 'error', message: body.message || body.error || 'urlscan.io enrichment failed' };
}

function pageRows(page, { showScannedUrl }) {
  const rows = [];
  const add = (label, value, opts = {}) => {
    if (present(value)) rows.push({ label, value: String(value), ...opts });
  };
  add('Page title', page.title);
  add('HTTP status', statusLabel(page.status, page.status_text));
  if (page.navigation_error) add('Navigation', `Failed (${page.navigation_error})`);
  if (page.url_changed) {
    add('Submitted URL', page.submitted_url, { mono: true, copy: true });
    add('Effective URL', page.effective_url, { mono: true, copy: true });
  } else if (showScannedUrl) {
    add('Scanned URL', page.effective_url || page.submitted_url, { mono: true, copy: true });
  }
  add('Redirect', page.redirected);
  add('MIME type', page.mime_type);
  add('Web server', page.server);
  return rows;
}

function hostingRows(page) {
  const rows = [];
  const add = (label, value, opts = {}) => {
    if (present(value)) rows.push({ label, value: String(value), ...opts });
  };
  add('Primary IP', page.ip, { mono: true, copy: true });
  add('Reverse DNS', page.ptr, { mono: true, copy: true });
  const asn = formatAsn(page.asn);
  add('ASN / Organization', [asn, page.asn_name].filter(Boolean).join(' · ') || null);
  add('Country', countryLabel(page.country));
  add('City', page.city);
  return rows;
}

/** Compact counters (kept for consumers of the flat list). */
function networkStats(network) {
  if (!network) return [];
  const stats = [];
  const add = (label, value, { always = false, tone = null } = {}) => {
    const n = toInt(value);
    if (n === null) return;
    if (!always && n === 0) return;
    stats.push({ label, value: n, tone });
  };
  add('HTTP requests', network.requests, { always: true });
  add('Domains', network.unique_domains, { always: true });
  add('IPs', network.unique_ips, { always: true });
  add('Redirects', network.redirects, { always: true });
  // Backend counts responses with status >= 400 — i.e. 4xx and 5xx.
  add('HTTP errors (4xx/5xx)', network.http_error_responses, { always: true, tone: toInt(network.http_error_responses) > 0 ? 'caution' : null });
  add('Failed loads', network.failed_requests, { always: true, tone: toInt(network.failed_requests) > 0 ? 'caution' : null });
  add('Outgoing links', network.outgoing_links, { always: true });
  add('Console errors', network.console_errors);
  add('Downloads', network.downloads, { tone: 'caution' });
  add('WebSockets', network.websockets);
  return stats;
}

function networkGroups(network) {
  if (!network) return [];
  const row = (label, value, { cautionWhenPositive = false, hideZero = false } = {}) => {
    const n = toInt(value);
    if (n === null || (hideZero && n === 0)) return null;
    return { label, value: n, tone: cautionWhenPositive && n > 0 ? 'caution' : (n === 0 ? 'muted' : null) };
  };
  const activity = [
    row('HTTP requests', network.requests),
    row('Contacted domains', network.unique_domains),
    row('Contacted IPs', network.unique_ips),
    row('Countries', network.unique_countries, { hideZero: true }),
    row('Redirects', network.redirects),
    row('Outgoing links', network.outgoing_links),
    row('WebSockets', network.websockets, { hideZero: true }),
    row('Downloads', network.downloads, { hideZero: true, cautionWhenPositive: true })
  ].filter(Boolean);
  const errors = [
    row('HTTP errors (4xx/5xx)', network.http_error_responses, { cautionWhenPositive: true }),
    row('Failed loads', network.failed_requests, { cautionWhenPositive: true }),
    row('Console errors', network.console_errors)
  ].filter(Boolean);
  return [
    { key: 'activity', label: 'Activity', rows: activity },
    { key: 'errors', label: 'Errors', rows: errors }
  ].filter((g) => g.rows.length);
}

function tlsRows(tls, network, codes) {
  if (!tls) return [];
  const rows = [];
  const add = (label, value, opts = {}) => {
    if (present(value)) rows.push({ label, value: String(value), ...opts });
  };
  const selfIssued = codes.has('self_issued_certificate');
  const nonPublic = codes.has('reserved_tls_issuer');
  add('Issuer', tls.issuer, { flag: selfIssued ? 'Self-issued' : (nonPublic ? 'Non-public issuer' : null) });
  add('Subject', tls.subject && tls.subject !== tls.issuer ? tls.subject : (tls.subject ? `${tls.subject} (same as issuer)` : null));
  add('Valid from', tls.valid_from, { date: true });
  add('Valid until', tls.valid_to, { date: true });
  if (toInt(tls.valid_days) !== null) {
    add('Validity period', plural(tls.valid_days, 'day'), {
      flag: codes.has('long_tls_validity') ? 'Exceeds 398-day public CA limit' : null
    });
  }
  if (toInt(tls.age_days) !== null) add('Certificate age at scan', plural(tls.age_days, 'day'));
  add('Protocol', tls.protocol);
  if (toInt(network?.secure_percentage) !== null) add('Secure requests', `${network.secure_percentage}%`);
  return rows;
}

const TYPE_LABELS = { ip: ['IP', 'IPs'], domain: ['domain', 'domains'], url: ['URL', 'URLs'], sha256: ['SHA256', 'SHA256'], filename: ['file', 'files'] };

function observableTypeCount(type, n) {
  const [one, many] = TYPE_LABELS[type] || [type, type];
  return `${n} ${n === 1 ? one : many}`;
}

function relatedGroupKey(r) {
  if (r.type === 'sha256') return 'hash';
  if (r.type === 'filename' || r.relationship === 'download_attempt') return 'download';
  if (r.relationship === 'primary_page_ip') return 'primary';
  if (['final_url', 'redirect_destination', 'redirect_hop'].includes(r.relationship) || r.role === 'redirect_hop') return 'redirect';
  if (r.relationship === 'linked_not_contacted') return 'linked';
  if (r.role === 'same_site') return 'same_site';
  if (r.role === 'primary') return 'primary';
  return 'third_party';
}

function historyView(summary, scans, { legacy = false } = {}) {
  const rows = scans.slice(0, 20).map((s) => ({
    scan_id: s.scan_id,
    scanned_at: s.scanned_at || null,
    relation: RELATION_LABELS[s.match_relation] || s.match_relation || null,
    exact: s.exact_match === true,
    status: s.page_status || null,
    title: s.page_title || null,
    ip: s.page_ip || null,
    asn: formatAsn(s.page_asn),
    // v1 rows parsed Result API verdicts from a non-existent path; never present those flags.
    verdict: legacy ? 'Verdict needs refresh' : scanVerdictLabel(s),
    malicious: !legacy && s.malicious === true,
    href: isOfficialResultUrl(s.result_url) ? s.result_url : null
  }));
  const h = summary.history || null;
  const changes = [];
  if (h?.changed) {
    const dims = [
      ['primary_ip', 'Primary IP', h.primary_ips],
      ['asn', 'ASN', h.asns],
      ['title', 'Page title', h.titles],
      ['status', 'HTTP status', h.statuses],
      ['effective_domain', 'Effective domain', h.effective_domains],
      ['tls_issuer', 'TLS issuer', h.tls_issuers]
    ];
    for (const [key, label, values] of dims) {
      if (h.changed[key]) changes.push({ label, values: arr(values).map((v) => `${v.value} ×${v.count}`) });
    }
  }
  const latestAt = rows
    .map((r) => r.scanned_at)
    .filter((t) => t && Number.isFinite(Date.parse(t)))
    .sort((a, b) => Date.parse(b) - Date.parse(a))[0] || null;
  return {
    rows,
    changes,
    latestAt,
    compared: toInt(h?.compared_scans),
    retrieved: scans.length,
    total: toInt(summary.total_reported_by_api),
    bounded: summary.results_are_exhaustive === false
  };
}

function prioritizeFindings(observations) {
  const groups = { signal: [], coverage: [], context: [], technical: [] };
  for (const o of observations) {
    if (!o?.code && !o?.label) continue;
    const known = FINDING_PRIORITY[o.code];
    const group = known?.group || (o.level === 'caution' ? 'coverage' : 'technical');
    if (group === 'covered') continue;
    groups[group].push({
      code: o.code || o.label,
      group,
      title: known?.title || o.label,
      label: o.label || known?.title || '',
      detail: o.detail || null,
      tone: group === 'signal' || group === 'coverage' ? 'caution' : 'neutral'
    });
  }
  // Visibility first: it decides how much weight every other signal deserves.
  const primary = [...groups.coverage, ...groups.signal, ...groups.context];
  return { primary, technical: groups.technical, order: GROUP_ORDER };
}

function visibilityOf(page, codes) {
  const status = toInt(page.status);
  if (codes.has('navigation_failed')) {
    return { state: 'limited', value: 'Limited · navigation failed', tone: 'caution' };
  }
  if (codes.has('limited_visibility_http_error')) {
    return { state: 'limited', value: `Limited · HTTP ${status ?? 'error'}`, tone: 'caution' };
  }
  if (codes.has('possible_challenge_page')) {
    return { state: 'limited', value: 'Possibly limited · challenge page', tone: 'caution' };
  }
  if (status !== null && status >= 400) {
    return { state: 'partial', value: `Page loaded · HTTP ${status}`, tone: 'neutral' };
  }
  if (status !== null) return { state: 'observed', value: `Page loaded · HTTP ${status}`, tone: 'neutral' };
  return null;
}

function mlSignalOf(engines) {
  if (!engines) return null;
  const score = toInt(engines.score);
  if (engines.malicious === true) {
    return { value: `Malicious signal${score !== null ? ` · ${score}` : ''}`, tone: 'caution', malicious: true };
  }
  if (engines.has_verdicts === false) return { value: 'No signal', tone: 'muted', malicious: false };
  return { value: `No malicious signal${score !== null ? ` · ${score}` : ''}`, tone: 'neutral', malicious: false };
}

function classificationTone(state) {
  if (state === 'malicious') return 'malicious';
  if (state === 'unknown') return 'muted';
  return 'neutral';
}

/** One-sentence conclusion; only clauses that add something beyond the tiles. */
function buildSummarySentence({ classification, visibility, mlSignal, codes, isV2 }) {
  if (!isV2) return null;
  const clauses = [];
  if (visibility?.state === 'limited') {
    clauses.push(`the scan had limited visibility (${visibility.value.replace(/^.*· /, '')})`);
  }
  if (mlSignal?.malicious && classification.state !== 'malicious') {
    clauses.push('the ML engine reported a malicious signal that is not reflected in the overall verdict');
  }
  if (codes.has('off_domain_redirect')) clauses.push('the scanned content came from a redirect destination on another domain');
  if (codes.has('download_attempt')) clauses.push('the page triggered a file download');
  const lead = classification.state === 'malicious'
    ? `Classified malicious by urlscan${classification.categories.length ? ` (${classification.categories.join(', ')})` : ''}.`
    : `${classification.label} by urlscan.`;
  if (!clauses.length) return classification.state === 'unclassified'
    ? `${lead} No malicious or limiting signals were recorded for this scan.`
    : lead;
  const body = clauses.length === 1
    ? clauses[0]
    : `${clauses.slice(0, -1).join(', ')}, and ${clauses[clauses.length - 1]}`;
  return `${lead} ${body.charAt(0).toUpperCase()}${body.slice(1)}.`;
}

function assessmentTiles({ classification, mlSignal, visibility, primaryScan, isV2 }) {
  const tiles = [{
    key: 'verdict',
    label: 'Overall verdict',
    value: classification.label,
    tone: classificationTone(classification.state),
    hint: classification.brands.length ? `Brands: ${classification.brands.join(', ')}` : null
  }];
  if (classification.score !== null) {
    tiles.push({
      key: 'score',
      label: 'urlscan score',
      value: String(classification.score),
      tone: classification.state === 'malicious' ? 'malicious' : 'neutral',
      hint: classification.state === 'unclassified' && classification.score === 0
        ? 'No verdict signal — not benign'
        : 'Scale −100 benign … 100 malicious',
      title: 'urlscan scale from −100 (legitimate) to 100 (malicious). Not a probability and not TalonHound confidence.'
    });
  }
  if (mlSignal) tiles.push({ key: 'ml', label: 'ML engine', value: mlSignal.value, tone: mlSignal.tone });
  if (visibility) tiles.push({ key: 'visibility', label: 'Visibility', value: visibility.value, tone: visibility.tone });
  if (primaryScan.scanned_at) {
    tiles.push({ key: 'last_scan', label: 'Last scan', value: primaryScan.scanned_at, date: true, tone: 'neutral' });
  }
  if (!isV2) tiles[0].hint = 'Refresh to load the scan verdict';
  return tiles;
}

export function buildUrlscanView(summary) {
  if (!summary || typeof summary !== 'object') return null;
  const scans = arr(summary.scans);
  const details = arr(summary.detail_scans);
  const primaryDetail = details.find((d) => d?.scan_id && d.scan_id === summary.primary_scan_id)
    || details[0]
    || null;
  const isV2 = Number(primaryDetail?.detail_version) >= 2;
  const latest = summary.most_recent_scan || scans[0] || null;
  const primaryHit = (primaryDetail && scans.find((s) => s.scan_id === primaryDetail.scan_id)) || latest;

  let classification;
  if (isV2) {
    const c = summary.classification || primaryDetail.classification || {};
    const state = CLASSIFICATION_STATES.has(c.state) ? c.state : 'unknown';
    classification = {
      state,
      label: c.label || 'No verdict data',
      score: toInt(c.score),
      categories: arr(c.categories),
      brands: arr(c.brands)
    };
  } else {
    classification = {
      state: 'unknown',
      label: primaryDetail ? 'Verdict detail not parsed' : 'No detailed scan retrieved',
      score: null,
      categories: [],
      brands: []
    };
  }

  const verdicts = isV2 ? primaryDetail.verdicts || null : null;
  const verdictSources = [];
  if (verdicts) {
    const describe = (s, { votes = false } = {}) => {
      if (!s) return null;
      if (s.malicious === true) return `malicious${toInt(s.score) !== null ? `, score ${s.score}` : ''}`;
      if (votes && toInt(s.votes_total) === 0) return 'no votes';
      if (s.has_verdicts === false) return 'no verdict';
      return `not malicious${toInt(s.score) !== null ? `, score ${s.score}` : ''}`;
    };
    const u = describe(verdicts.urlscan);
    const e = describe(verdicts.engines);
    const c = describe(verdicts.community, { votes: true });
    if (u) verdictSources.push({ source: 'urlscan', value: u, caution: verdicts.urlscan?.malicious === true });
    if (e) verdictSources.push({ source: 'Engines (ML)', value: e, caution: verdicts.engines?.malicious === true });
    if (c) verdictSources.push({ source: 'Community', value: c, caution: verdicts.community?.malicious === true });
  }

  // Page facts: v2 group, else legacy flat detail/hit fields.
  const page = isV2 ? (primaryDetail.page || {}) : {
    effective_url: primaryDetail?.page_url || primaryHit?.page_url || null,
    submitted_url: primaryDetail?.task_url || primaryHit?.task_url || null,
    url_changed: false,
    title: primaryDetail?.page_title || primaryHit?.page_title || null,
    status: primaryDetail?.page_status || primaryHit?.page_status || null,
    redirected: primaryDetail?.page_redirected || primaryHit?.page_redirected || null,
    server: primaryDetail?.page_server || primaryHit?.page_server || null,
    ip: primaryDetail?.page_ip || primaryHit?.page_ip || null,
    asn: primaryDetail?.page_asn || primaryHit?.page_asn || null,
    asn_name: primaryDetail?.page_asnname || null,
    country: primaryDetail?.page_country || primaryHit?.page_country || null,
    city: primaryDetail?.page_city || null
  };

  const network = isV2 ? primaryDetail.network || null : null;
  const observations = isV2
    ? arr(summary.observations).length ? arr(summary.observations) : arr(primaryDetail.observations)
    : legacyObservations(primaryDetail, primaryHit);
  const codes = new Set(observations.map((o) => o?.code).filter(Boolean));

  const related = isV2 ? arr(primaryDetail.related_observables).map((r) => ({
    type: r.type,
    value: r.value,
    group: relatedGroupKey(r),
    relationship: OBSERVABLE_RELATIONSHIP_LABELS[r.relationship] || r.relationship,
    role: r.role ? INFRA_ROLE_LABELS[r.role] || r.role : null,
    origin: r.origin || null,
    note: r.note || null
  })) : [];
  const relatedGroups = RELATED_GROUPS
    .map((g) => ({ ...g, items: related.filter((r) => r.group === g.key) }))
    .filter((g) => g.items.length);

  const resultHref = [primaryDetail?.result_url, primaryHit?.result_url, latest?.result_url]
    .find((u) => isOfficialResultUrl(u)) || null;

  const primaryScan = {
    scan_id: primaryDetail?.scan_id || primaryHit?.scan_id || null,
    scanned_at: primaryDetail?.scanned_at || primaryHit?.scanned_at || null,
    href: resultHref,
    relation: primaryHit?.match_relation ? RELATION_LABELS[primaryHit.match_relation] || primaryHit.match_relation : null,
    exact: primaryHit?.exact_match === true
  };

  const visibility = visibilityOf(page, codes);
  const mlSignal = isV2 ? mlSignalOf(verdicts?.engines) : null;
  const findings = prioritizeFindings(observations);
  const tlsDetail = isV2 ? primaryDetail.tls || null : null;
  const technologies = isV2 ? arr(primaryDetail.technologies) : [];
  const redirects = isV2 ? arr(primaryDetail.redirects) : [];
  const history = historyView(summary, scans, { legacy: !isV2 });

  const counts = {
    retrieved: toInt(summary.matches_retrieved) ?? scans.length,
    exact: toInt(summary.exact_match_count) ?? 0,
    related: toInt(summary.related_match_count) ?? 0,
    malicious: toInt(summary.malicious_scan_count) ?? 0,
    bounded: summary.results_are_exhaustive === false
  };

  const typeCounts = new Map();
  for (const r of related) typeCounts.set(r.type, (typeCounts.get(r.type) || 0) + 1);

  return {
    version: isV2 ? 2 : 1,
    needsRefreshForDetail: !isV2,
    primaryScan,
    classification,
    verdictSources,
    mlSignal,
    visibility,
    tiles: assessmentTiles({ classification, mlSignal, visibility, primaryScan, isV2 }),
    summarySentence: buildSummarySentence({ classification, visibility, mlSignal, codes, isV2 }),
    sampleLine: [
      summary.evidence_assessment_label ? `Sample assessment: ${summary.evidence_assessment_label}` : null,
      `${plural(counts.retrieved, 'scan')} retrieved${counts.bounded ? ' (bounded sample)' : ''}`,
      `${counts.exact} exact / ${counts.related} related`,
      `${counts.malicious} malicious`
    ].filter(Boolean).join(' · '),
    assessmentLabel: summary.evidence_assessment_label || null,
    assessment: summary.evidence_assessment || null,
    counts,
    observations,
    findings,
    pageRows: pageRows(page, { showScannedUrl: summary.ioc_category !== 'url' }),
    hostingRows: hostingRows(page),
    networkStats: networkStats(network),
    networkGroups: networkGroups(network),
    networkSummary: network ? [
      plural(toInt(network.requests) ?? 0, 'request'),
      plural(toInt(network.unique_ips) ?? 0, 'IP'),
      plural(toInt(network.unique_domains) ?? 0, 'domain'),
      toInt(network.redirects) > 0 ? plural(network.redirects, 'redirect') : null,
      toInt(network.http_error_responses) > 0 ? plural(network.http_error_responses, 'HTTP error') : null
    ].filter(Boolean).join(' · ') : null,
    statusCodes: arr(network?.status_codes).map((s) => `${s.status} ×${s.count}`),
    resourceTypes: arr(network?.resource_types).map((r) => `${r.type} ${r.count}`),
    failedErrors: arr(network?.failed_request_errors).map((f) => `${f.error} ×${f.count}`),
    redirects,
    tlsRows: isV2 ? tlsRows(tlsDetail, network, codes) : [],
    tlsSummary: tlsDetail ? [
      tlsDetail.protocol,
      codes.has('self_issued_certificate') ? 'Self-issued' : (tlsDetail.issuer || null),
      codes.has('long_tls_validity') && toInt(tlsDetail.valid_days) !== null ? `${tlsDetail.valid_days}-day validity` : null
    ].filter(Boolean).join(' · ') : null,
    technologies,
    technologiesSummary: technologies.length
      ? `${technologies.length} detected · ${technologies.slice(0, 3).map((t) => t.name).join(', ')}${technologies.length > 3 ? '…' : ''}`
      : null,
    related,
    relatedGroups,
    relatedSummary: related.length
      ? [...typeCounts.entries()].map(([type, n]) => observableTypeCount(type, n)).join(' · ')
      : null,
    hashTotal: isV2 ? toInt(primaryDetail.response_hashes?.total) : null,
    history,
    fetchedAt: summary.fetched_at || null
  };
}
