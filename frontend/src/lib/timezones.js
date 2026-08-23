import { api } from './api.js';

/** @type {string[]|null} */
let cachedTimezones = null;
/** @type {Promise<string[]>|null} */
let loadPromise = null;

/**
 * Fetch the canonical IANA timezone list from the backend.
 * Results are cached for the lifetime of the page session.
 * @returns {Promise<string[]>}
 */
export async function fetchSupportedTimezones() {
  if (cachedTimezones) return cachedTimezones;
  if (loadPromise) return loadPromise;

  loadPromise = api.get('/system/timezones')
    .then(({ data }) => {
      const list = Array.isArray(data?.timezones) ? data.timezones.map(String) : [];
      if (!list.length) {
        throw new Error('Timezone list is empty');
      }
      cachedTimezones = list;
      return list;
    })
    .finally(() => {
      loadPromise = null;
    });

  return loadPromise;
}

/** Clear cached timezone list (tests). */
export function clearSupportedTimezonesCache() {
  cachedTimezones = null;
  loadPromise = null;
}

/**
 * Filter timezones by a case-insensitive substring match.
 * @param {string[]} zones
 * @param {string} query
 * @returns {string[]}
 */
export function filterTimezones(zones, query) {
  const list = Array.isArray(zones) ? zones : [];
  const q = String(query || '').trim().toLowerCase();
  if (!q) return list;
  return list.filter((z) => z.toLowerCase().includes(q));
}

/**
 * Ensure the current value appears in selectable options even while loading.
 * @param {string[]} zones
 * @param {string} currentValue
 * @returns {string[]}
 */
export function ensureTimezoneInOptions(zones, currentValue) {
  const list = Array.isArray(zones) ? [...zones] : [];
  const current = String(currentValue || '').trim();
  if (current && !list.includes(current)) {
    return [current, ...list];
  }
  return list;
}
