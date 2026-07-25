// Canonical user-facing datetime formatting (Administration / Backup & Restore).
// Backend stores UTC; this formats for the user's preferred IANA timezone.

export const TIMEZONE_CHANGED_EVENT = 'demo-timezone-changed';

export function normalizeUserTimezone(value) {
  const tz = String(value || '').trim() || 'UTC';
  try {
    Intl.DateTimeFormat(undefined, { timeZone: tz });
    return tz;
  } catch {
    return 'UTC';
  }
}

export function getUserTimezone() {
  if (typeof localStorage === 'undefined') return 'UTC';
  return normalizeUserTimezone(localStorage.getItem('demo_timezone') || 'UTC');
}

export function notifyTimezoneChanged() {
  if (typeof window === 'undefined') return;
  window.dispatchEvent(new Event(TIMEZONE_CHANGED_EVENT));
}

/** Parse API/UTC timestamps into a Date; null when invalid. */
export function parseUserInstant(value) {
  if (!value && value !== 0) return null;

  let dt;
  if (value instanceof Date) {
    dt = value;
  } else if (typeof value === 'number') {
    const ms = value > 1e12 ? value : value * 1000;
    dt = new Date(ms);
  } else {
    const raw = String(value).trim();
    if (!raw) return null;

    if (/^\d+$/.test(raw)) {
      const num = Number(raw);
      const ms = num > 1e12 ? num : num * 1000;
      dt = new Date(ms);
    } else {
      const hasTz = /([zZ]|[+\-]\d{2}:?\d{2})$/.test(raw);
      const normalized = raw.includes(' ') ? raw.replace(' ', 'T') : raw;
      dt = new Date(hasTz ? normalized : `${normalized}Z`);
    }
  }

  if (Number.isNaN(dt.getTime())) return null;
  return dt;
}

/**
 * Format a timestamp in the user's timezone (en-GB, 24h). No "UTC" suffix.
 * @param {string|number|Date|null|undefined} value
 * @param {string} [timeZone]
 */
export function formatUserDateTime(value, timeZone) {
  const dt = parseUserInstant(value);
  if (!dt) return '-';
  const tz = normalizeUserTimezone(timeZone || getUserTimezone());

  return dt.toLocaleString('en-GB', {
    timeZone: tz,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  });
}

/**
 * Split date + time for stacked table cells (user timezone).
 * @returns {{ date: string, time: string } | null}
 */
export function formatUserDateParts(value, timeZone) {
  const dt = parseUserInstant(value);
  if (!dt) return null;
  const tz = normalizeUserTimezone(timeZone || getUserTimezone());

  const date = dt.toLocaleDateString('en-GB', {
    timeZone: tz,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  });
  const time = dt.toLocaleTimeString('en-GB', {
    timeZone: tz,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  });
  return { date, time };
}

/** Raw UTC ISO string for tooltips; empty string when invalid. */
export function utcIsoTooltip(value) {
  const dt = parseUserInstant(value);
  if (!dt) return '';
  return dt.toISOString();
}
