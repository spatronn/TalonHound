/**
 * Malpedia API fetch/parse helpers.
 * Source: https://malpedia.caad.fkie.fraunhofer.de/ (MISP Galaxy threat-actor dataset)
 */

import {
  mergeThreatActorAliases,
  normalizeThreatActorSlug,
  trimThreatActorText,
  validateThreatActorName
} from './normalization.js';

export const MALPEDIA_ACTORS_URL = 'https://malpedia.caad.fkie.fraunhofer.de/api/get/actors';
export const MALPEDIA_USER_AGENT = 'TalonHound-MalpediaBootstrap/1.0 (+https://malpedia.caad.fkie.fraunhofer.de/)';
export const MALPEDIA_FETCH_TIMEOUT_MS = 60_000;
export const MIN_MALPEDIA_ACTORS = 500;

/**
 * @param {unknown} raw
 * @returns {{ ok: true, records: Array<{ canonicalName: string, slug: string, aliases: string[], description: string|null, malpediaUuid: string|null, active: boolean }>, skippedInvalid: number } | { ok: false, error: string, count?: number }}
 */
export function parseMalpediaActorsResponse(raw, { minActors = MIN_MALPEDIA_ACTORS } = {}) {
  if (raw == null || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, error: 'unexpected_response_shape' };
  }

  const entries = Object.entries(raw);
  if (entries.length < minActors) {
    return { ok: false, error: 'empty_or_incomplete_dataset', count: entries.length };
  }

  const records = [];
  let skippedInvalid = 0;

  for (const [key, value] of entries) {
    if (!value || typeof value !== 'object') {
      skippedInvalid += 1;
      continue;
    }

    const canonicalName = trimThreatActorText(value.value || key);
    const validated = validateThreatActorName(canonicalName);
    if (!validated.ok) {
      skippedInvalid += 1;
      continue;
    }

    const slug = normalizeThreatActorSlug(validated.name);
    if (!slug) {
      skippedInvalid += 1;
      continue;
    }

    const synonyms = Array.isArray(value.meta?.synonyms) ? value.meta.synonyms : [];
    const aliases = mergeThreatActorAliases(validated.name, [], synonyms);
    const description = trimThreatActorText(value.description) || null;

    records.push({
      canonicalName: validated.name,
      slug,
      aliases,
      description,
      malpediaUuid: trimThreatActorText(value.uuid) || null,
      active: true
    });
  }

  if (records.length < minActors) {
    return { ok: false, error: 'empty_or_incomplete_dataset', count: records.length };
  }

  return { ok: true, records, skippedInvalid };
}

export async function fetchMalpediaActors({
  url = MALPEDIA_ACTORS_URL,
  timeoutMs = MALPEDIA_FETCH_TIMEOUT_MS,
  fetchImpl = globalThis.fetch
} = {}) {
  if (typeof fetchImpl !== 'function') {
    throw new Error('fetch is not available in this runtime');
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'User-Agent': MALPEDIA_USER_AGENT
      },
      signal: controller.signal
    });
    if (!res.ok) {
      throw new Error(`Malpedia HTTP ${res.status} ${res.statusText}`);
    }
    return res.json();
  } catch (err) {
    if (err?.name === 'AbortError') {
      throw new Error(`Malpedia request timed out after ${timeoutMs}ms`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}
