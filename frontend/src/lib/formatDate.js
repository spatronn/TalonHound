// Canonical user-facing datetime formatting.
// Backend stores absolute TIMESTAMPTZ instants; this formats them in the
// TalonHound System Timezone (never the browser's local timezone).

export const TIMEZONE_CHANGED_EVENT = 'talonhound-system-timezone-changed';
export const SYSTEM_TIMEZONE_STORAGE_KEY = 'talonhound_system_timezone';

export function normalizeSystemTimezone(value) {
  const tz = String(value || '').trim();
  if (!tz) return null;
  try {
    Intl.DateTimeFormat(undefined, { timeZone: tz });
    return tz;
  } catch {
    return null;
  }
}

/** @deprecated Use normalizeSystemTimezone — kept for BackupRestorePage callers. */
export function normalizeUserTimezone(value) {
  return normalizeSystemTimezone(value) || 'UTC';
}

export function getSystemTimezone() {
  if (typeof localStorage === 'undefined') return 'UTC';
  return normalizeSystemTimezone(localStorage.getItem(SYSTEM_TIMEZONE_STORAGE_KEY)) || 'UTC';
}

/** @deprecated Alias for getSystemTimezone (system-wide, not per-user). */
export function getUserTimezone() {
  return getSystemTimezone();
}

export function setSystemTimezoneCache(timeZone) {
  const tz = normalizeSystemTimezone(timeZone);
  if (typeof localStorage === 'undefined') return tz;
  if (tz) localStorage.setItem(SYSTEM_TIMEZONE_STORAGE_KEY, tz);
  else localStorage.removeItem(SYSTEM_TIMEZONE_STORAGE_KEY);
  // Migrate away from legacy per-user key so old code paths don't diverge.
  localStorage.removeItem('demo_timezone');
  return tz;
}

export function notifyTimezoneChanged() {
  if (typeof window === 'undefined') return;
  window.dispatchEvent(new Event(TIMEZONE_CHANGED_EVENT));
}

/** Parse API timestamps into a Date; null when invalid. */
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
 * Format a timestamp in the system timezone (en-GB, 24h). Never uses browser local zone.
 * @param {string|number|Date|null|undefined} value
 * @param {string} [timeZone]
 */
export function formatUserDateTime(value, timeZone) {
  const dt = parseUserInstant(value);
  if (!dt) return '-';
  const tz = normalizeSystemTimezone(timeZone) || getSystemTimezone();

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
 * Split date + time for stacked table cells (system timezone).
 * @returns {{ date: string, time: string } | null}
 */
export function formatUserDateParts(value, timeZone) {
  const dt = parseUserInstant(value);
  if (!dt) return null;
  const tz = normalizeSystemTimezone(timeZone) || getSystemTimezone();

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

/**
 * Convert a datetime-local wall-clock string in the system timezone to UTC ISO.
 * Used for filters/expiration inputs so browser TZ never affects API bounds.
 * @param {string} localValue - "YYYY-MM-DDTHH:mm" or with seconds
 * @param {string} [timeZone]
 * @returns {string|null}
 */
export function systemLocalInputToUtcIso(localValue, timeZone) {
  const raw = String(localValue || '').trim();
  if (!raw) return null;
  const tz = normalizeSystemTimezone(timeZone) || getSystemTimezone();
  const m = raw.match(
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/
  );
  if (!m) {
    const d = new Date(raw);
    return Number.isNaN(d.getTime()) ? null : d.toISOString();
  }
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const hour = Number(m[4]);
  const minute = Number(m[5]);
  const second = Number(m[6] || 0);

  // Guess UTC instant for this wall clock, then refine against Intl parts.
  let guess = Date.UTC(year, month - 1, day, hour, minute, second);
  for (let i = 0; i < 3; i += 1) {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hourCycle: 'h23'
    }).formatToParts(new Date(guess));
    const pick = (type) => Number(parts.find((p) => p.type === type)?.value || 0);
    const asUtc = Date.UTC(pick('year'), pick('month') - 1, pick('day'), pick('hour'), pick('minute'), pick('second'));
    const target = Date.UTC(year, month - 1, day, hour, minute, second);
    guess += target - asUtc;
  }
  return new Date(guess).toISOString();
}
