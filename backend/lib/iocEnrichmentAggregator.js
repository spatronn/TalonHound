// Canonical multi-provider enrichment aggregator.
//
// TalonHound stores enrichment results across several tables, one generic and
// several provider-specific:
//
//   provider         supported IOC types   storage table                   read fn
//   ---------------  --------------------  ------------------------------  -------------------------------
//   virustotal       ip/domain/url/hash    ioc_enrichments (generic)       (direct query here)
//   rdap             domain/url            ioc_domain_enrichment           rdapEnrichmentService
//   abuseipdb        ip (+ URL derived)    ioc_abuseipdb_enrichment        abuseipdbService
//   ipinfo_lite      ip (+ URL derived)    ioc_ip_enrichment               ipinfoLiteService
//   spamhaus_drop    ip (+ URL derived)    ioc_spamhaus_drop_enrichment    spamhausDropEnrichmentService
//
// The IOC Details UI splits these into:
//   - Direct IOC enrichment (Automated Intelligence)
//   - Derived Infrastructure (URL host → IP providers)
//
// MCP mirrors that split:
//   - collectIocEnrichments → direct `enrichment` array (type-gated)
//   - collectDerivedInfrastructure → additive `derived_infrastructure` for URL IP hosts
//
// All reads are stored/cached rows only — never trigger external provider APIs.

import { getEnrichmentByRootDomain } from '../services/rdapEnrichmentService.js';
import { normalizeRdapTarget, isRdapSupportedIocType } from './domainRoot.js';
import {
  getEnrichmentByIp as getAbuseIpdbEnrichmentByIp,
  ABUSEIPDB_PROVIDER
} from '../services/abuseipdbService.js';
import { getEnrichmentByIp as getIpinfoEnrichmentByIp } from '../services/ipinfoLiteService.js';
import {
  getSpamhausDropEnrichmentByIp,
  rowToSpamhausApiPayload
} from '../services/spamhausDropEnrichmentService.js';
import { SPAMHAUS_DROP_PROVIDER } from './spamhausDropSync.js';
import { VT_PROVIDER, buildVirusTotalNotFoundMessage } from './virustotalEnrichment.js';
import { extractIpLiteralFromIoc } from './iocIpExtraction.js';
import { resolveIpEnrichmentTarget } from './ipEnrichmentEligibility.js';

const RDAP_PROVIDER = 'rdap';
const IPINFO_LITE_PROVIDER = 'ipinfo_lite';

/** IP-typed observables the IP-only providers apply to as *direct* IOC enrichment. */
function isIpIocType(type) {
  const t = String(type || '').toLowerCase();
  return t === 'ip' || t === 'ipv4' || t === 'ipv6' || t === 'ip6';
}

/**
 * A provider-specific store may be absent on older schemas. Swallow only the
 * "relation does not exist" case (undefined_table 42P01) so a genuine query bug
 * still surfaces — mirrors the ioc_feed_source_evidence tolerance in the caller.
 */
function isMissingRelationError(err, table) {
  if (!err) return false;
  if (err.code === '42P01') return true;
  const msg = String(err.message || '');
  return msg.includes(table);
}

async function safeOptionalRead(table, read) {
  try {
    return await read();
  } catch (err) {
    if (!isMissingRelationError(err, table)) throw err;
    return null;
  }
}

/**
 * VirusTotal (and any future generic-table provider) — keyed by ioc_id.
 * For VT `not_found`, rebuild the user message from `ioc_type` so MCP /
 * get_ioc_context matches the UI GET path even when DB still has a legacy
 * hardcoded URL-only `error_message` (no backfill required).
 */
// Prefer a usable result when the same provider has rows under several linked
// (exact-hash alias) ioc_ids: success beats "no report" beats error/other, then
// the freshest. Keeps one entry per provider so a VT result enriched via a SHA1
// alias surfaces on the canonical SHA256 without a second provider call.
const GENERIC_STATUS_RANK = { success: 3, not_found: 1 };
function genericStatusRank(status) {
  return GENERIC_STATUS_RANK[String(status || '').toLowerCase()] ?? 0;
}

async function readGenericEnrichments(pool, iocIds) {
  const ids = (Array.isArray(iocIds) ? iocIds : [iocIds])
    .map((n) => Number(n))
    .filter((n) => Number.isFinite(n));
  if (!ids.length) return [];
  const { rows } = await pool.query(
    `SELECT provider, status, ioc_type, normalized_summary, fetched_at, expires_at, error_message
     FROM ioc_enrichments
     WHERE ioc_id = ANY($1::bigint[])
     ORDER BY provider ASC`,
    [ids]
  );
  // One entry per provider (best status, then freshest).
  const bestByProvider = new Map();
  for (const e of rows) {
    const prev = bestByProvider.get(e.provider);
    if (!prev) { bestByProvider.set(e.provider, e); continue; }
    const better = genericStatusRank(e.status) - genericStatusRank(prev.status)
      || (new Date(e.fetched_at || 0) - new Date(prev.fetched_at || 0));
    if (better > 0) bestByProvider.set(e.provider, e);
  }
  return [...bestByProvider.values()].map((e) => {
    const isVtNotIndexed = e.provider === VT_PROVIDER && e.status === 'not_found';
    return {
      provider: e.provider,
      status: e.status,
      summary: e.normalized_summary || null,
      fetched_at: e.fetched_at || null,
      expires_at: e.expires_at || null,
      error_message: isVtNotIndexed
        ? buildVirusTotalNotFoundMessage(e.ioc_type)
        : (e.error_message || null)
    };
  });
}

/** RDAP / WHOIS — domain & url only, keyed by root domain. */
async function readRdapEnrichment(pool, type, value) {
  if (!isRdapSupportedIocType(type)) return null;
  const parsed = normalizeRdapTarget(value, type);
  if (!parsed.ok || !parsed.rdap_domain) return null;
  const row = await getEnrichmentByRootDomain(pool, parsed.rdap_domain);
  if (!row) return null;
  return {
    provider: RDAP_PROVIDER,
    status: row.rdap_status || 'unknown',
    summary: {
      root_domain: row.root_domain,
      registrar: row.registrar ?? null,
      registration_date: row.registration_date ?? null,
      expiration_date: row.expiration_date ?? null,
      last_changed_date: row.last_changed_date ?? null,
      domain_age_days: row.domain_age_days ?? null,
      nameservers: Array.isArray(row.nameservers) ? row.nameservers : [],
      statuses: Array.isArray(row.statuses) ? row.statuses : [],
      derived_signals:
        row.derived_signals && typeof row.derived_signals === 'object' ? row.derived_signals : {}
    },
    // RDAP has no TTL/expiry column; freshness is derived from last fetch time.
    fetched_at: row.last_success_at || row.last_enriched_at || null,
    expires_at: null,
    error_message: row.last_error || row.error_message || null
  };
}

/** AbuseIPDB — keyed by IP string (caller gates applicability). */
async function readAbuseIpdbByIp(pool, ip) {
  if (!ip) return null;
  const row = await getAbuseIpdbEnrichmentByIp(pool, ip);
  if (!row) return null;
  const summary =
    row.normalized_summary && typeof row.normalized_summary === 'object' ? row.normalized_summary : {};
  return {
    provider: ABUSEIPDB_PROVIDER,
    status: row.provider_status || summary.provider_status || 'unknown',
    summary,
    fetched_at: row.last_enriched_at || null,
    expires_at: null,
    error_message: row.error_message || null
  };
}

/** IPinfo Lite — keyed by IP string (caller gates applicability). */
async function readIpinfoByIp(pool, ip) {
  if (!ip) return null;
  const row = await getIpinfoEnrichmentByIp(pool, ip);
  if (!row) return null;
  return {
    provider: IPINFO_LITE_PROVIDER,
    status: row.provider_status || 'unknown',
    summary: {
      ip: row.ip ?? ip,
      normalized_ip: row.normalized_ip || row.ip || ip,
      asn: row.asn ?? null,
      as_name: row.as_name ?? null,
      as_domain: row.as_domain ?? null,
      country_code: row.country_code ?? null,
      country: row.country ?? null,
      continent_code: row.continent_code ?? null,
      continent: row.continent ?? null,
      provider: row.provider || IPINFO_LITE_PROVIDER,
      derived_signals:
        row.derived_signals && typeof row.derived_signals === 'object' ? row.derived_signals : {}
    },
    fetched_at: row.last_enriched_at || null,
    expires_at: null,
    error_message: row.error_message || null
  };
}

/** Spamhaus DROP — stored lookup only (local dataset; no live re-query). */
async function readSpamhausByIp(pool, ip) {
  if (!ip) return null;
  const row = await getSpamhausDropEnrichmentByIp(pool, ip);
  // Match UI GET /enrichment/spamhaus-drop/ioc: absent row → not_run payload.
  // For MCP direct/derived arrays we only emit when a stored result exists
  // (including listed / not_listed / failed), never fabricate availability.
  if (!row) return null;
  const payload = rowToSpamhausApiPayload(row);
  return {
    provider: SPAMHAUS_DROP_PROVIDER,
    status: payload.status || row.provider_status || 'unknown',
    summary: payload,
    fetched_at: payload.last_enriched_at || row.enriched_at || row.last_attempt_at || null,
    expires_at: null,
    error_message: payload.error_message || row.error_message || null
  };
}

async function readAbuseIpdbEnrichment(pool, type, value) {
  if (!isIpIocType(type)) return null;
  return readAbuseIpdbByIp(pool, value);
}

async function readIpinfoEnrichment(pool, type, value) {
  if (!isIpIocType(type)) return null;
  return readIpinfoByIp(pool, value);
}

async function readSpamhausEnrichment(pool, type, value) {
  if (!isIpIocType(type)) return null;
  return readSpamhausByIp(pool, value);
}

/**
 * Collect every stored enrichment result applicable to one IOC across all
 * provider stores (direct IOC enrichment). Returns a provider-sorted array.
 *
 * Does not include URL Derived Infrastructure — use collectDerivedInfrastructure.
 *
 * @param {import('pg').Pool} pool
 * @param {{ iocId: number|string, type: string, value: string }} ioc
 * @returns {Promise<Array<{provider:string,status:string,summary:any,fetched_at:any,expires_at:any,error_message:any}>>}
 */
export async function collectIocEnrichments(pool, { iocId, type, value, linkedIocIds } = {}) {
  const entries = [];

  // Generic table (VirusTotal today) — keyed by ioc_id, plus any exact-hash alias
  // ioc_ids of the same file artifact so one VT file result covers every hash.
  const genericIds = [...new Set([
    ...(iocId != null ? [iocId] : []),
    ...(Array.isArray(linkedIocIds) ? linkedIocIds : [])
  ])];
  entries.push(...(await readGenericEnrichments(pool, genericIds)));

  // Provider-specific stores. Each is type-gated + data-aware; a missing table
  // on an older schema is non-fatal, but any other error propagates.
  const optionalReads = [
    ['ioc_domain_enrichment', () => readRdapEnrichment(pool, type, value)],
    ['ioc_abuseipdb_enrichment', () => readAbuseIpdbEnrichment(pool, type, value)],
    ['ioc_ip_enrichment', () => readIpinfoEnrichment(pool, type, value)],
    ['ioc_spamhaus_drop_enrichment', () => readSpamhausEnrichment(pool, type, value)]
  ];
  for (const [table, read] of optionalReads) {
    const entry = await safeOptionalRead(table, read);
    if (entry) entries.push(entry);
  }

  entries.sort((a, b) => String(a.provider).localeCompare(String(b.provider)));
  return entries;
}

/**
 * Collect Derived Infrastructure for a URL IOC whose host is an IP literal.
 *
 * Mirrors the UI "Derived Infrastructure" panel:
 * - extracted host from the URL (same extractIpLiteralFromIoc path as Spamhaus routes)
 * - stored IPinfo / AbuseIPDB / Spamhaus DROP for that host
 * - does NOT create or require an ioc_items row for the host IP
 * - does NOT call external enrichment APIs
 *
 * @returns {Promise<null|{
 *   extracted_host: string,
 *   host_type: 'ip',
 *   enrichments: Array<{provider:string,status:string,summary:any,fetched_at:any,expires_at:any,error_message:any}>
 * }>}
 */
export async function collectDerivedInfrastructure(pool, { type, value } = {}) {
  const iocType = String(type || '').toLowerCase();
  if (iocType !== 'url') return null;

  const extractedHost = extractIpLiteralFromIoc(value, 'url');
  if (!extractedHost) return null;

  // IPinfo only for public IPs (same gate as UI IPinfo eligibility / resolveIpEnrichmentTarget).
  const publicTarget = resolveIpEnrichmentTarget(value, 'url');
  const ipinfoIp = publicTarget.eligible ? publicTarget.ip : null;

  const [ipinfo, abuseipdb, spamhaus] = await Promise.all([
    safeOptionalRead('ioc_ip_enrichment', () => readIpinfoByIp(pool, ipinfoIp)),
    safeOptionalRead('ioc_abuseipdb_enrichment', () => readAbuseIpdbByIp(pool, extractedHost)),
    safeOptionalRead('ioc_spamhaus_drop_enrichment', () => readSpamhausByIp(pool, extractedHost))
  ]);

  const enrichments = [ipinfo, abuseipdb, spamhaus]
    .filter(Boolean)
    .sort((a, b) => String(a.provider).localeCompare(String(b.provider)));

  return {
    extracted_host: extractedHost,
    host_type: 'ip',
    enrichments
  };
}
