import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';
import { normalizeObservable } from './observable-normalization.js';

export const USOM_PROVIDER_NAME = 'Siber Güvenlik Başkanlığı / USOM';
export const USOM_PROVIDER_API = 'https://siberguvenlik.gov.tr/api';
export const USOM_SOURCE_NAME = 'USOM:TR-CERT';
export const USOM_FEED_KEY = 'usom-trcert';
export const USOM_SUPPORTED_API_TYPES = Object.freeze(['domain', 'url', 'ip', 'ip6', 'ip6net']);
export const USOM_PERSISTED_IOC_TYPES = Object.freeze(['domain', 'url', 'ip', 'ip6']);

const MAX_IOC_LENGTH = 4096;
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;
const DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function cleanProviderValue(value, maxLength = MAX_IOC_LENGTH) {
  const raw = String(value ?? '').trim();
  if (!raw || raw.length > maxLength || CONTROL_CHARS.test(raw)) return '';
  return raw;
}

function normalizeDomain(value) {
  const raw = cleanProviderValue(value, 253).replace(/\.+$/, '').toLowerCase();
  if (!raw || raw.startsWith('*.') || raw.includes('://') || /[/:?#\s]/.test(raw)) return null;
  const ascii = domainToASCII(raw).toLowerCase();
  if (!ascii || ascii.length > 253) return null;
  const labels = ascii.split('.');
  if (labels.length < 2 || labels.some((label) => !DOMAIN_LABEL.test(label))) return null;
  return ascii;
}

function normalizeUrl(value) {
  const raw = cleanProviderValue(value);
  if (!raw) return null;
  const hasScheme = /^https?:\/\//i.test(raw);
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) && !hasScheme) return null;

  const candidate = hasScheme ? raw : `https://${raw.replace(/^\/+/, '')}`;
  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    return null;
  }
  const host = parsed.hostname.replace(/^\[|\]$/g, '');
  if (
    !['http:', 'https:'].includes(parsed.protocol)
    || !host
    || (!isIP(host) && !normalizeDomain(host))
    || parsed.username
    || parsed.password
  ) {
    return null;
  }

  const normalized = normalizeObservable('url', candidate);
  if (!normalized || CONTROL_CHARS.test(normalized)) return null;
  return hasScheme ? normalized : normalized.replace(/^https:\/\//, '');
}

function normalizeIpv4(value) {
  const raw = cleanProviderValue(value, 64);
  if (!raw || raw.includes('/')) return null;
  return isIP(raw) === 4 ? raw : null;
}

function stripIpv6Artifacts(value) {
  let raw = cleanProviderValue(value, 128).toLowerCase();
  if (!raw) return '';
  const bracketed = /^\[([^\]]+)\](?::\d{1,5})?$/.exec(raw);
  if (bracketed) raw = bracketed[1];
  const zoneIndex = raw.indexOf('%');
  if (zoneIndex >= 0) raw = raw.slice(0, zoneIndex);
  return raw;
}

function normalizeIpv6(value) {
  const raw = stripIpv6Artifacts(value);
  if (!raw || raw.includes('/') || isIP(raw) !== 6) return null;
  try {
    const hostname = new URL(`http://[${raw}]/`).hostname;
    return hostname.replace(/^\[|\]$/g, '').toLowerCase();
  } catch {
    return raw.toLowerCase();
  }
}

function lookupTitles(lookups, group, code) {
  const row = lookups?.[group]?.get?.(String(code ?? '').trim());
  if (!row) return {};
  const prefix = group === 'descriptions'
    ? 'provider_description'
    : group === 'sources'
      ? 'provider_source'
      : 'provider_connection_type';
  return {
    [`${prefix}_title_tr`]: cleanProviderValue(row.tr_title, 512) || null,
    [`${prefix}_title_en`]: cleanProviderValue(row.en_title, 512) || null
  };
}

export function parseProviderDate(value) {
  const raw = cleanProviderValue(value, 128);
  if (!raw) return { raw: null, valid: false, utc: null };
  const explicitZone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(raw);
  if (!explicitZone) {
    const match = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$/.exec(raw);
    if (!match) return { raw, valid: false, utc: null };
    const [, year, month, day, hour, minute, second, fraction = ''] = match;
    const milliseconds = Number(`${fraction}000`.slice(0, 3));
    const date = new Date(Date.UTC(
      Number(year),
      Number(month) - 1,
      Number(day),
      Number(hour),
      Number(minute),
      Number(second),
      milliseconds
    ));
    const valid = date.getUTCFullYear() === Number(year)
      && date.getUTCMonth() === Number(month) - 1
      && date.getUTCDate() === Number(day)
      && date.getUTCHours() === Number(hour)
      && date.getUTCMinutes() === Number(minute)
      && date.getUTCSeconds() === Number(second);
    return { raw, valid, utc: valid ? date.toISOString() : null };
  }
  const parsed = new Date(raw);
  const valid = !Number.isNaN(parsed.getTime());
  return { raw, valid, utc: valid ? parsed.toISOString() : null };
}

export function normalizeProviderId(value) {
  const raw = cleanProviderValue(value, 128);
  return raw || null;
}

export function compareProviderIds(left, right) {
  const a = normalizeProviderId(left) || '';
  const b = normalizeProviderId(right) || '';
  if (/^\d+$/.test(a) && /^\d+$/.test(b)) {
    const ai = BigInt(a);
    const bi = BigInt(b);
    return ai < bi ? -1 : ai > bi ? 1 : 0;
  }
  return a.localeCompare(b, 'en');
}

export function compareUsomHighwaters(left, right) {
  if (!left) return right ? -1 : 0;
  if (!right) return 1;
  const timeComparison = new Date(left.timestamp).getTime() - new Date(right.timestamp).getTime();
  return timeComparison || compareProviderIds(left.providerId, right.providerId);
}

export function highwaterFromModel(model) {
  const parsed = parseProviderDate(model?.date);
  const providerId = normalizeProviderId(model?.id);
  if (!parsed.valid || !providerId) return null;
  return { timestamp: parsed.utc, providerId };
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function computeUsomProviderFingerprint(entry) {
  const metadata = entry?.providerMetadata || {};
  const semantic = {
    observable: entry?.observable || null,
    observable_type: entry?.observableType || null,
    category: entry?.category || null,
    note: entry?.note || null,
    provider_record_id: metadata.provider_record_id ?? null,
    provider_type: metadata.provider_type ?? null,
    provider_description_code: metadata.provider_description_code ?? null,
    provider_description_title_tr: metadata.provider_description_title_tr ?? null,
    provider_description_title_en: metadata.provider_description_title_en ?? null,
    provider_source_code: metadata.provider_source_code ?? null,
    provider_source_title_tr: metadata.provider_source_title_tr ?? null,
    provider_source_title_en: metadata.provider_source_title_en ?? null,
    provider_date: metadata.provider_date_utc ?? metadata.provider_date ?? null,
    provider_criticality_level: metadata.provider_criticality_level ?? null,
    provider_connection_type: metadata.provider_connection_type ?? null,
    provider_connection_type_title_tr: metadata.provider_connection_type_title_tr ?? null,
    provider_connection_type_title_en: metadata.provider_connection_type_title_en ?? null
  };
  return createHash('sha256').update(stableJson(semantic)).digest('hex');
}

export function buildUsomCanonicalSnapshotHash(identities) {
  const canonical = [...new Set(identities || [])].sort();
  return createHash('sha256').update(canonical.join('\n')).digest('hex');
}

export function buildUsomProviderMetadata(model, lookups = null) {
  const providerDate = parseProviderDate(model?.date);
  const descriptionCode = cleanProviderValue(model?.desc, 64) || null;
  const sourceCode = cleanProviderValue(model?.source, 64) || null;
  const connectionCode = cleanProviderValue(model?.connectiontype, 64) || null;
  const criticality = Number(model?.criticality_level);

  return {
    provider_record_id: model?.id ?? null,
    provider_type: cleanProviderValue(model?.type, 32) || null,
    provider_description_code: descriptionCode,
    provider_source_code: sourceCode,
    provider_date: providerDate.raw,
    provider_date_valid: providerDate.valid,
    provider_date_utc: providerDate.utc,
    provider_criticality_level: Number.isFinite(criticality) ? criticality : null,
    provider_connection_type: connectionCode,
    provider: USOM_PROVIDER_NAME,
    provider_api: USOM_PROVIDER_API,
    ...lookupTitles(lookups, 'descriptions', descriptionCode),
    ...lookupTitles(lookups, 'sources', sourceCode),
    ...lookupTitles(lookups, 'connectionTypes', connectionCode)
  };
}

/**
 * Normalize one official API model.
 * @returns {{ok:true,entry:object}|{ok:false,reason:string}}
 */
export function normalizeUsomModel(model, requestedType, lookups = null) {
  const apiType = String(requestedType || model?.type || '').trim().toLowerCase();
  if (!model || typeof model !== 'object' || Array.isArray(model)) {
    return { ok: false, reason: 'invalid_model' };
  }
  if (!USOM_SUPPORTED_API_TYPES.includes(apiType)) return { ok: false, reason: 'unsupported_type' };
  if (apiType === 'ip6net') return { ok: false, reason: 'unsupported_ip_network' };
  if (model.type && String(model.type).trim().toLowerCase() !== apiType) {
    return { ok: false, reason: 'provider_type_mismatch' };
  }

  const raw = model.url;
  let observable = null;
  let observableType = apiType;
  if (apiType === 'domain') observable = normalizeDomain(raw);
  else if (apiType === 'url') observable = normalizeUrl(raw);
  else if (apiType === 'ip') observable = normalizeIpv4(raw);
  else if (apiType === 'ip6') observable = normalizeIpv6(raw);
  if (!observable) return { ok: false, reason: 'invalid_observable' };

  const entry = {
    observable,
    observableType,
    sourceName: USOM_SOURCE_NAME,
    category: 'threat-intel',
    note: `Auto-imported from ${USOM_PROVIDER_NAME}`,
    providerMetadata: buildUsomProviderMetadata(model, lookups)
  };
  entry.providerFingerprint = computeUsomProviderFingerprint(entry);
  return {
    ok: true,
    entry
  };
}

export function sanitizeUsomLogValue(value, maxLength = 160) {
  return String(value ?? '')
    .replace(/[\r\n\t\u0000-\u001f\u007f]+/g, ' ')
    .replace(/([?&](?:key|token|secret|password|auth)=)[^&\s]+/gi, '$1***')
    .slice(0, maxLength);
}
