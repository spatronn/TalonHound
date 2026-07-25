// Minimal cron matcher for BACKUP_CRON (5-field: min hour dom mon dow).
// Used by the backup worker to decide when to enqueue a scheduled job.
// Duplicate runs in the same minute are suppressed by the caller via lastFire key.

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

/**
 * @param {string} expr - "m h dom mon dow"
 * @param {Date} date - UTC instant to evaluate
 */
export function cronMatchesUtc(expr, date = new Date()) {
  const parts = String(expr || '').trim().split(/\s+/);
  if (parts.length !== 5) return false;
  const [min, hour, dom, mon, dow] = parts;
  const d = date instanceof Date ? date : new Date(date);
  // cron dow: 0=Sun .. 6=Sat (same as JS getUTCDay)
  return (
    matchCronField(min, d.getUTCMinutes()) &&
    matchCronField(hour, d.getUTCHours()) &&
    matchCronField(dom, d.getUTCDate()) &&
    matchCronField(mon, d.getUTCMonth() + 1) &&
    matchCronField(dow, d.getUTCDay())
  );
}

/** Next UTC fire time within the next `horizonHours` (minute resolution). */
export function nextCronFireUtc(expr, from = new Date(), horizonHours = 48) {
  const start = new Date(from);
  start.setUTCSeconds(0, 0);
  start.setUTCMinutes(start.getUTCMinutes() + 1);
  const end = new Date(start.getTime() + horizonHours * 3600 * 1000);
  for (let t = start.getTime(); t <= end.getTime(); t += 60_000) {
    const d = new Date(t);
    if (cronMatchesUtc(expr, d)) return d.toISOString();
  }
  return null;
}

export function minuteKeyUtc(date = new Date()) {
  const d = date instanceof Date ? date : new Date(date);
  return d.toISOString().slice(0, 16); // YYYY-MM-DDTHH:MM
}
