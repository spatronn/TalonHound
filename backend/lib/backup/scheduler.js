// Backup schedule: cron matching and next-fire in a configured system timezone.
// Display of timestamps to users uses their preference; schedule execution uses BACKUP_CRON_TIMEZONE
// (falling back to INTEGRATION_SCHEDULE_TIMEZONE / UTC).

import {
  computeNextWeeklyRunAt,
  normalizeScheduleTimezone,
  zonedTimeParts
} from '../integrationSchedule.js';

const WEEKLY_AT_TIME = /^([0-5]?\d) ([01]?\d|2[0-3]) \* \* ([0-6])$/;
const WEEKDAY_NAMES = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

/**
 * Parse a single cron field against a value.
 * Supports: asterisk, N, A-B, step forms like star/N, and A,B lists.
 */
export function matchCronField(field, value) {
  const f = String(field || '*').trim();
  if (f === '*') return true;
  const parts = f.split(',');
  for (const part of parts) {
    if (part.includes('/')) {
      const [range, stepStr] = part.split('/');
      const step = Number(stepStr);
      if (!Number.isFinite(step) || step <= 0) return false;
      const start = range === '*' ? 0 : Number(range.split('-')[0]);
      if ((value - start) % step === 0 && value >= start) return true;
      continue;
    }
    if (part.includes('-')) {
      const [a, b] = part.split('-').map(Number);
      if (value >= a && value <= b) return true;
      continue;
    }
    if (Number(part) === value) return true;
  }
  return false;
}

function weekdayInTimezone(date, timeZone) {
  // Use en-US long weekday then map; more reliable than synthesizing from parts alone.
  const label = new Intl.DateTimeFormat('en-US', { timeZone, weekday: 'short' }).format(date);
  const map = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
  return map[label] ?? 0;
}

/**
 * @param {string} expr - "m h dom mon dow"
 * @param {Date} date
 * @param {string} timeZone
 */
export function cronMatchesInTimezone(expr, date = new Date(), timeZone = 'UTC') {
  const parts = String(expr || '').trim().split(/\s+/);
  if (parts.length !== 5) return false;
  const [min, hour, dom, mon, dow] = parts;
  const tz = normalizeScheduleTimezone(timeZone);
  const d = date instanceof Date ? date : new Date(date);
  const p = zonedTimeParts(d, tz);
  const weekday = weekdayInTimezone(d, tz);
  return (
    matchCronField(min, p.minute) &&
    matchCronField(hour, p.hour) &&
    matchCronField(dom, p.day) &&
    matchCronField(mon, p.month) &&
    matchCronField(dow, weekday)
  );
}

/** @deprecated Prefer cronMatchesInTimezone — kept for UTC-only callers/tests. */
export function cronMatchesUtc(expr, date = new Date()) {
  return cronMatchesInTimezone(expr, date, 'UTC');
}

/**
 * Next fire instant (ISO UTC string) for a backup cron in the given timezone.
 * Weekly patterns use computeNextWeeklyRunAt; others scan ≥8 days of minutes.
 */
export function nextBackupFireAt(expr, from = new Date(), timeZone = 'UTC', horizonHours = 24 * 8) {
  const tz = normalizeScheduleTimezone(timeZone);
  const cron = String(expr || '').trim();
  const weekly = WEEKLY_AT_TIME.exec(cron);
  if (weekly) {
    const next = computeNextWeeklyRunAt(cron, from, tz);
    return next ? next.toISOString() : null;
  }

  const start = new Date(from);
  start.setUTCSeconds(0, 0);
  start.setUTCMilliseconds(0);
  start.setUTCMinutes(start.getUTCMinutes() + 1);
  const end = new Date(start.getTime() + horizonHours * 3600 * 1000);
  for (let t = start.getTime(); t <= end.getTime(); t += 60_000) {
    const d = new Date(t);
    if (cronMatchesInTimezone(cron, d, tz)) return d.toISOString();
  }
  return null;
}

/** @deprecated Prefer nextBackupFireAt — UTC-only wrapper with 8-day default horizon. */
export function nextCronFireUtc(expr, from = new Date(), horizonHours = 24 * 8) {
  return nextBackupFireAt(expr, from, 'UTC', horizonHours);
}

export function describeBackupSchedule(cron, timeZone = 'UTC') {
  const tz = normalizeScheduleTimezone(timeZone);
  const expr = String(cron || '').trim();
  const weekly = WEEKLY_AT_TIME.exec(expr);
  if (weekly) {
    const minute = Number(weekly[1]);
    const hour = Number(weekly[2]);
    const weekday = Number(weekly[3]);
    const hh = String(hour).padStart(2, '0');
    const mm = String(minute).padStart(2, '0');
    const dayName = WEEKDAY_NAMES[weekday] || `day ${weekday}`;
    return {
      summary: `Every ${dayName} at ${hh}:${mm}`,
      timezone: tz
    };
  }
  const daily = /^([0-5]?\d) ([01]?\d|2[0-3]) \* \* \*$/.exec(expr);
  if (daily) {
    const mm = String(Number(daily[1])).padStart(2, '0');
    const hh = String(Number(daily[2])).padStart(2, '0');
    return { summary: `Every day at ${hh}:${mm}`, timezone: tz };
  }
  return { summary: `Cron: ${expr || '—'}`, timezone: tz };
}

export function minuteKeyUtc(date = new Date()) {
  const d = date instanceof Date ? date : new Date(date);
  return d.toISOString().slice(0, 16); // YYYY-MM-DDTHH:MM
}
