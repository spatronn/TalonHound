/**
 * View model for the urlscan.io Intelligence card.
 *
 * Pure: turns a stored urlscan normalized_summary (v2, or a legacy v1 row)
 * into compact display groups. Never invents fields — absent data yields
 * absent rows. Provider classification is shown as provider evidence only;
 * it never maps to a TalonHound IOC verdict.
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

/** Classification of one search hit for the history table. */
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
      detail: `The scanner received an error response (${requests} request${requests === 1 ? '' : 's'} total). The site's intended content was not observed.`
    }];
  }
  return [];
}

function pageRows(page, { showScannedUrl }) {
  const rows = [];
  const add = (label, value, opts = {}) => {
    if (present(value)) rows.push({ label, value: String(value), ...opts });
  };
  if (page.url_changed) {
    add('Submitted URL', page.submitted_url, { mono: true, copy: true });
    add('Effective URL', page.effective_url, { mono: true, copy: true });
  } else if (showScannedUrl) {
    add('Scanned URL', page.effective_url || page.submitted_url, { mono: true, copy: true });
  }
  add('Page title', page.title);
  add('HTTP status', statusLabel(page.status, page.status_text), { tone: toInt(page.status) >= 400 ? 'caution' : null });
  if (page.navigation_error) add('Navigation', `Failed (${page.navigation_error})`, { tone: 'caution' });
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
  add('Reverse DNS', page.ptr, { mono: true });
  add('ASN', formatAsn(page.asn));
  add('Organization', page.asn_name);
  add('Country', countryLabel(page.country));
  add('City', page.city);
  return rows;
}

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
  add('HTTP ≥400', network.http_error_responses, { always: true, tone: toInt(network.http_error_responses) > 0 ? 'caution' : null });
  add('Failed loads', network.failed_requests, { always: true, tone: toInt(network.failed_requests) > 0 ? 'caution' : null });
  add('Outgoing links', network.outgoing_links, { always: true });
  add('Console errors', network.console_errors);
  add('Downloads', network.downloads, { tone: 'caution' });
  add('WebSockets', network.websockets);
  return stats;
}

function tlsRows(tls, network) {
  if (!tls) return [];
  const rows = [];
  const add = (label, value, opts = {}) => {
    if (present(value)) rows.push({ label, value: String(value), ...opts });
  };
  add('Issuer', tls.issuer);
  add('Subject', tls.subject && tls.subject !== tls.issuer ? tls.subject : (tls.subject ? `${tls.subject} (same as issuer)` : null));
  add('Valid from', tls.valid_from, { date: true });
  add('Valid until', tls.valid_to, { date: true });
  if (toInt(tls.valid_days) !== null) add('Validity period', `${tls.valid_days} days`);
  if (toInt(tls.age_days) !== null) add('Certificate age at scan', `${tls.age_days} days`);
  add('Protocol', tls.protocol);
  if (toInt(network?.secure_percentage) !== null) add('Secure requests', `${network.secure_percentage}%`);
  return rows;
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
  return {
    rows,
    changes,
    compared: toInt(h?.compared_scans),
    retrieved: scans.length,
    total: toInt(summary.total_reported_by_api),
    bounded: summary.results_are_exhaustive === false
  };
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

  const related = isV2 ? arr(primaryDetail.related_observables).map((r) => ({
    type: r.type,
    value: r.value,
    relationship: OBSERVABLE_RELATIONSHIP_LABELS[r.relationship] || r.relationship,
    role: r.role ? INFRA_ROLE_LABELS[r.role] || r.role : null,
    origin: r.origin || null,
    note: r.note || null
  })) : [];

  const resultHref = [primaryDetail?.result_url, primaryHit?.result_url, latest?.result_url]
    .find((u) => isOfficialResultUrl(u)) || null;

  return {
    version: isV2 ? 2 : 1,
    needsRefreshForDetail: !isV2,
    primaryScan: {
      scan_id: primaryDetail?.scan_id || primaryHit?.scan_id || null,
      scanned_at: primaryDetail?.scanned_at || primaryHit?.scanned_at || null,
      href: resultHref,
      relation: primaryHit?.match_relation ? RELATION_LABELS[primaryHit.match_relation] || primaryHit.match_relation : null,
      exact: primaryHit?.exact_match === true
    },
    classification,
    verdictSources,
    assessmentLabel: summary.evidence_assessment_label || null,
    assessment: summary.evidence_assessment || null,
    counts: {
      retrieved: toInt(summary.matches_retrieved) ?? scans.length,
      exact: toInt(summary.exact_match_count) ?? 0,
      related: toInt(summary.related_match_count) ?? 0,
      malicious: toInt(summary.malicious_scan_count) ?? 0,
      bounded: summary.results_are_exhaustive === false
    },
    observations,
    pageRows: pageRows(page, { showScannedUrl: summary.ioc_category !== 'url' }),
    hostingRows: hostingRows(page),
    networkStats: networkStats(network),
    statusCodes: arr(network?.status_codes).map((s) => `${s.status} ×${s.count}`),
    resourceTypes: arr(network?.resource_types).map((r) => `${r.type} ${r.count}`),
    failedErrors: arr(network?.failed_request_errors).map((f) => `${f.error} ×${f.count}`),
    redirects: isV2 ? arr(primaryDetail.redirects) : [],
    tlsRows: isV2 ? tlsRows(primaryDetail.tls, network) : [],
    technologies: isV2 ? arr(primaryDetail.technologies) : [],
    related,
    hashTotal: isV2 ? toInt(primaryDetail.response_hashes?.total) : null,
    history: historyView(summary, scans, { legacy: !isV2 }),
    fetchedAt: summary.fetched_at || null
  };
}
