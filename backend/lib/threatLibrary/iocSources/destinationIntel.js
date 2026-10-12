/**
 * IOC-intelligence guard for Additional IOC Source fetches.
 *
 * An IOC Source is an external dataset an analyst asks TalonHound to read.
 * A destination TalonHound already knows as malicious infrastructure (a C2
 * URL, a payload host) is never contacted, even when an analyst submits it:
 * submission is intent to read a dataset, not permission to touch known
 * attacker infrastructure.
 *
 * A destination is known malicious when its exact URL, its exact host name or
 * its IP-literal host is
 *   - an IOC in the TalonHound inventory (ioc_items, any lifecycle status), or
 *   - an IOC candidate of the same report that is not Context Only / benign.
 *
 * Deliberately NOT checked: the addresses a host name resolves to, and parent
 * domains. Shared hosting / CDN addresses (e.g. GitHub's raw CDN) and platform
 * apex domains appear in feeds; matching them would block legitimate public
 * datasets. Only what the URL itself names is compared.
 *
 * Pure decision + one bounded query per table; never fetches anything.
 */

import { isIP } from 'node:net';
import { normalizeFeedHostname } from '../../customThreatFeedSsrf.js';
import { normalizeUrlForMatch } from '../../observable-normalization.js';

export const KNOWN_MALICIOUS_DESTINATION = 'known_malicious_destination';

/** Candidate assessments that never mark infrastructure as malicious. */
const NON_THREAT_ASSESSMENTS = ['context_only', 'benign', 'invalid'];

/**
 * Observable identities a destination URL names: the URL (both schemes,
 * matching how feeds record C2 URLs), its host as a domain, or its IP literal.
 * @param {string} url
 * @returns {Array<{ type: string, value: string }>}
 */
export function destinationObservableKeys(url) {
  let u;
  try {
    u = new URL(String(url || '').trim());
  } catch {
    return [];
  }
  const keys = [];
  const add = (type, value) => {
    if (value && !keys.some((k) => k.type === type && k.value === value)) keys.push({ type, value });
  };
  const href = normalizeUrlForMatch(u.href);
  add('url', href);
  const flipped = new URL(u.href);
  flipped.protocol = u.protocol === 'https:' ? 'http:' : 'https:';
  if (!u.port) add('url', normalizeUrlForMatch(flipped.href));

  const host = normalizeFeedHostname(u.hostname);
  const ipVersion = isIP(host);
  if (ipVersion === 4) add('ip', host);
  else if (ipVersion === 6) {
    add('ip', host);
    add('ipv6', host);
  } else if (host) {
    add('domain', host);
    if (host.startsWith('www.')) add('domain', host.slice(4));
  }
  return keys;
}

function describe(match) {
  const where = match.kind === 'inventory'
    ? `IOC inventory${match.status ? ` (${match.status})` : ''}`
    : 'an indicator of this report';
  return `${match.type} ${match.value} is ${where}`;
}

/**
 * @param {import('pg').Pool} pool
 * @param {{ url: string, reportId?: number|null }} input
 * @returns {Promise<{ ok: true } | { ok: false, code: string, reason: string, matches: object[] }>}
 */
export async function assessIocSourceDestination(pool, { url, reportId = null }) {
  const keys = destinationObservableKeys(url);
  if (!keys.length) return { ok: true };
  const types = keys.map((k) => k.type);
  const values = keys.map((k) => k.value);
  const matches = [];

  const inventory = await pool.query(
    `SELECT DISTINCT ON (observable_type, observable) observable_type, observable, status
     FROM ioc_items
     WHERE (observable_type, observable) IN (
       SELECT * FROM unnest($1::text[], $2::text[]) AS t(observable_type, observable)
     )
     ORDER BY observable_type, observable, created_at ASC, id ASC`,
    [types, values]
  );
  for (const r of inventory.rows) {
    matches.push({ kind: 'inventory', type: r.observable_type, value: r.observable, status: r.status || null });
  }

  if (reportId != null) {
    const report = await pool.query(
      `SELECT candidate_type, normalized_value, assessment
       FROM threat_report_candidates
       WHERE report_id = $1
         AND is_ioc = true
         AND assessment <> ALL($4::text[])
         AND (candidate_type, normalized_value) IN (
           SELECT * FROM unnest($2::text[], $3::text[]) AS t(candidate_type, normalized_value)
         )`,
      [reportId, types, values, NON_THREAT_ASSESSMENTS]
    );
    for (const r of report.rows) {
      matches.push({ kind: 'report_indicator', type: r.candidate_type, value: r.normalized_value, assessment: r.assessment });
    }
  }

  if (!matches.length) return { ok: true };
  return {
    ok: false,
    code: KNOWN_MALICIOUS_DESTINATION,
    reason: `Not fetched: known malicious destination; ${matches.slice(0, 2).map(describe).join('; ')}`.slice(0, 240),
    matches: matches.slice(0, 10)
  };
}

/**
 * Per-hop guard for fetchIocSourceUrl (the source URL, GitHub API calls,
 * raw downloads and every redirect target).
 * @param {import('pg').Pool} pool
 * @param {number|null} reportId
 */
export function createIocSourceDestinationGuard(pool, reportId) {
  return (url) => assessIocSourceDestination(pool, { url, reportId });
}
