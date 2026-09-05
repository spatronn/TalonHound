// Canonical multi-provider enrichment aggregator.
//
// TalonHound stores enrichment results across several tables, one generic and
// several provider-specific:
//
//   provider      supported IOC types   storage table                read fn
//   ------------  --------------------  ---------------------------  -------------------------------
//   virustotal    ip/domain/url/hash    ioc_enrichments (generic)    (direct query here)
//   rdap          domain/url            ioc_domain_enrichment        rdapEnrichmentService
//   abuseipdb     ip                    ioc_abuseipdb_enrichment     abuseipdbService
//   ipinfo_lite   ip                    ioc_ip_enrichment            ipinfoLiteService
//
// The IOC Details "Automated Intelligence" UI composes these by calling each
// provider's own endpoint. Any backend consumer that wants the SAME complete
// view (e.g. the MCP get_ioc_context tool) must read every applicable store —
// reading only ioc_enrichments silently drops RDAP/AbuseIPDB/IPinfo.
//
// This module is that single collection point. It is:
//  - IOC-aware: a provider is only queried for the IOC types it supports, using
//    the same canonical type helpers the provider's own route uses
//    (isRdapSupportedIocType for RDAP; IP-type gate for the IP providers, whose
//    read fns additionally normalize + reject non-IP input).
//  - Data-aware: a provider entry is emitted only when a stored row exists — a
//    supported-but-never-fetched provider is simply absent, never fabricated.
//  - Provider-complete: every store above is evaluated.
//
// Entries share one shape { provider, status, summary, fetched_at, expires_at,
// error_message } so consumers get a uniform array regardless of the underlying
// store. `provider` values match the enrichmentProviderRegistry keys.

import { getEnrichmentByRootDomain } from '../services/rdapEnrichmentService.js';
import { normalizeRdapTarget, isRdapSupportedIocType } from './domainRoot.js';
import {
  getEnrichmentByIp as getAbuseIpdbEnrichmentByIp,
  ABUSEIPDB_PROVIDER
} from '../services/abuseipdbService.js';
import { getEnrichmentByIp as getIpinfoEnrichmentByIp } from '../services/ipinfoLiteService.js';

const RDAP_PROVIDER = 'rdap';
const IPINFO_LITE_PROVIDER = 'ipinfo_lite';

/** IP-typed observables the IP-only providers (AbuseIPDB, IPinfo Lite) apply to. */
function isIpIocType(type) {
  const t = String(type || '').toLowerCase();
  return t === 'ip' || t === 'ipv4' || t === 'ipv6';
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

/** VirusTotal (and any future generic-table provider) — keyed by ioc_id. */
async function readGenericEnrichments(pool, iocId) {
  const { rows } = await pool.query(
    `SELECT provider, status, normalized_summary, fetched_at, expires_at, error_message
     FROM ioc_enrichments
     WHERE ioc_id = $1
     ORDER BY provider ASC`,
    [iocId]
  );
  return rows.map((e) => ({
    provider: e.provider,
    status: e.status,
    summary: e.normalized_summary || null,
    fetched_at: e.fetched_at || null,
    expires_at: e.expires_at || null,
    error_message: e.error_message || null
  }));
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

/** AbuseIPDB — IP only, keyed by ip. */
async function readAbuseIpdbEnrichment(pool, type, value) {
  if (!isIpIocType(type)) return null;
  const row = await getAbuseIpdbEnrichmentByIp(pool, value);
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

/** IPinfo Lite — IP only, keyed by normalized ip. */
async function readIpinfoEnrichment(pool, type, value) {
  if (!isIpIocType(type)) return null;
  const row = await getIpinfoEnrichmentByIp(pool, value);
  if (!row) return null;
  return {
    provider: IPINFO_LITE_PROVIDER,
    status: row.provider_status || 'unknown',
    summary: {
      asn: row.asn ?? null,
      as_name: row.as_name ?? null,
      as_domain: row.as_domain ?? null,
      country_code: row.country_code ?? null,
      country: row.country ?? null,
      continent_code: row.continent_code ?? null,
      continent: row.continent ?? null,
      derived_signals:
        row.derived_signals && typeof row.derived_signals === 'object' ? row.derived_signals : {}
    },
    fetched_at: row.last_enriched_at || null,
    expires_at: null,
    error_message: row.error_message || null
  };
}

/**
 * Collect every stored enrichment result applicable to one IOC across all
 * provider stores. Returns a provider-sorted array of uniform entries.
 *
 * @param {import('pg').Pool} pool
 * @param {{ iocId: number|string, type: string, value: string }} ioc
 * @returns {Promise<Array<{provider:string,status:string,summary:any,fetched_at:any,expires_at:any,error_message:any}>>}
 */
export async function collectIocEnrichments(pool, { iocId, type, value } = {}) {
  const entries = [];

  // Generic table (VirusTotal today) — always applicable, keyed by ioc_id.
  entries.push(...(await readGenericEnrichments(pool, iocId)));

  // Provider-specific stores. Each is type-gated + data-aware; a missing table
  // on an older schema is non-fatal, but any other error propagates.
  const optionalReads = [
    ['ioc_domain_enrichment', () => readRdapEnrichment(pool, type, value)],
    ['ioc_abuseipdb_enrichment', () => readAbuseIpdbEnrichment(pool, type, value)],
    ['ioc_ip_enrichment', () => readIpinfoEnrichment(pool, type, value)]
  ];
  for (const [table, read] of optionalReads) {
    try {
      const entry = await read();
      if (entry) entries.push(entry);
    } catch (err) {
      if (!isMissingRelationError(err, table)) throw err;
    }
  }

  entries.sort((a, b) => String(a.provider).localeCompare(String(b.provider)));
  return entries;
}
