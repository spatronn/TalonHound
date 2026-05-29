export const BASE_SCHEDULE_CRONS = Object.freeze([
  '*/5 * * * *',
  '*/15 * * * *',
  '*/30 * * * *',
  '0 * * * *',
  '0 0 * * *'
]);

const HOURLY_AT_MINUTE = /^([0-5]?\d) \* \* \* \*$/;

export function isHourlyAtMinuteCron(value) {
  return HOURLY_AT_MINUTE.test(String(value || '').trim());
}

export function sanitizeScheduleCron(value) {
  const v = String(value || '').trim();
  if (BASE_SCHEDULE_CRONS.includes(v)) return v;
  if (isHourlyAtMinuteCron(v)) return v;
  return '0 * * * *';
}

export function isHourlyScheduleCron(scheduleCron) {
  return sanitizeScheduleCron(scheduleCron) === '0 * * * *';
}

export function isDailyScheduleCron(scheduleCron) {
  return sanitizeScheduleCron(scheduleCron) === '0 0 * * *';
}

/**
 * Spread hourly active feeds across the clock hour based on how many are enabled.
 * Works for any feed count (5, 15, …) — slots are recomputed when feeds are enabled/disabled.
 */
export function buildHourlySlotMap(activeFeeds = []) {
  const hourlyKeys = (activeFeeds || [])
    .filter((feed) => {
      const key = String(feed?.key || feed || '').trim();
      const schedule = feed?.schedule ?? feed?.schedule_cron ?? feed?.cron ?? '0 * * * *';
      return key && isHourlyScheduleCron(schedule);
    })
    .map((feed) => String(feed.key || feed).trim())
    .sort();

  const count = hourlyKeys.length;
  if (count === 0) return new Map();

  const spacing = count === 1 ? 0 : Math.max(1, Math.floor(60 / count));
  const map = new Map();
  hourlyKeys.forEach((key, index) => {
    map.set(key, Math.min(index * spacing, 59));
  });
  return map;
}

export function hourlySlotMinuteForFeed(feedKey, slotMap) {
  const key = String(feedKey || '').trim();
  if (slotMap?.has(key)) return slotMap.get(key);
  return 0;
}

/** Hourly cron expands to a minute slot derived from currently active feeds. */
export function effectiveCronForFeed(feedKey, scheduleCron, slotMap = null) {
  const cron = sanitizeScheduleCron(scheduleCron);
  if (cron === '0 * * * *') {
    const minute = hourlySlotMinuteForFeed(feedKey, slotMap);
    return `${minute} * * * *`;
  }
  return cron;
}

function alignToIntervalMinutes(date, intervalMinutes) {
  const d = new Date(date);
  d.setSeconds(0, 0);
  const minute = d.getMinutes();
  const remainder = minute % intervalMinutes;
  const add = remainder === 0 ? intervalMinutes : intervalMinutes - remainder;
  d.setMinutes(minute + add);
  return d;
}

export function computeNextRunAt(scheduleCron, feedKey, now = new Date(), slotMap = null) {
  const cron = effectiveCronForFeed(feedKey, scheduleCron, slotMap);
  const ts = now.getTime();

  if (cron === '*/5 * * * *') return alignToIntervalMinutes(now, 5);
  if (cron === '*/15 * * * *') return alignToIntervalMinutes(now, 15);
  if (cron === '*/30 * * * *') return alignToIntervalMinutes(now, 30);

  if (cron === '0 0 * * *') {
    const d = new Date(now);
    d.setHours(0, 0, 0, 0);
    if (d.getTime() <= ts) d.setDate(d.getDate() + 1);
    return d;
  }

  const hourlyMatch = HOURLY_AT_MINUTE.exec(cron);
  if (hourlyMatch) {
    const slotMin = Number(hourlyMatch[1]);
    const d = new Date(now);
    d.setSeconds(0, 0);
    d.setMinutes(slotMin, 0, 0);
    if (d.getTime() <= ts) d.setHours(d.getHours() + 1);
    return d;
  }

  const fallback = new Date(now);
  fallback.setMinutes(0, 0, 0);
  fallback.setHours(fallback.getHours() + 1);
  return fallback;
}

export function buildRepeatableNextRunMap(repeatables = []) {
  const map = new Map();
  for (const row of repeatables) {
    const idRaw = String(row?.id || row?.key || '').trim();
    const feedKey = idRaw.replace(/-scheduled$/, '');
    const nextMs = Number(row?.next);
    if (!feedKey || !Number.isFinite(nextMs) || nextMs <= 0) continue;
    map.set(feedKey, new Date(nextMs));
  }
  return map;
}
