export const BASE_SCHEDULE_CRONS = Object.freeze([
  '*/5 * * * *',
  '*/15 * * * *',
  '*/30 * * * *',
  '0 * * * *',
  '0 0 * * *'
]);

const DEFAULT_SYSTEM_SCHEDULE_TIMEZONE = 'UTC';
const HOURLY_AT_MINUTE = /^([0-5]?\d) \* \* \* \*$/;

/** Validate IANA timezone; fall back to UTC when missing or invalid. */
export function normalizeScheduleTimezone(value) {
  const tz = String(value || '').trim();
  if (!tz) return 'UTC';
  try {
    Intl.DateTimeFormat(undefined, { timeZone: tz });
    return tz;
  } catch {
    return 'UTC';
  }
}

/** Server reference timezone for cron execution (default UTC). Display uses each user's preference. */
export function getSystemScheduleTimezone() {
  const tz = String(process.env.INTEGRATION_SCHEDULE_TIMEZONE || DEFAULT_SYSTEM_SCHEDULE_TIMEZONE).trim();
  return normalizeScheduleTimezone(tz);
}

function zonedTimeParts(date, timeZone) {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  }).formatToParts(date);
  const pick = (type) => Number(parts.find((p) => p.type === type)?.value || 0);
  return {
    year: pick('year'),
    month: pick('month'),
    day: pick('day'),
    hour: pick('hour'),
    minute: pick('minute'),
    second: pick('second')
  };
}

function zonedTimeToUtc({ year, month, day, hour, minute, second }, timeZone) {
  let guess = Date.UTC(year, month - 1, day, hour, minute, second);
  for (let i = 0; i < 6; i += 1) {
    const p = zonedTimeParts(new Date(guess), timeZone);
    const targetMs = Date.UTC(year, month - 1, day, hour, minute, second);
    const actualMs = Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second);
    guess += targetMs - actualMs;
  }
  return new Date(guess);
}

export function computeNextDailyRunAt(now = new Date()) {
  const timeZone = getSystemScheduleTimezone();
  const p = zonedTimeParts(now, timeZone);
  let target = { year: p.year, month: p.month, day: p.day, hour: 0, minute: 0, second: 0 };
  let next = zonedTimeToUtc(target, timeZone);
  if (next.getTime() <= now.getTime()) {
    const tomorrow = new Date(Date.UTC(p.year, p.month - 1, p.day + 1));
    const np = zonedTimeParts(tomorrow, timeZone);
    target = { year: np.year, month: np.month, day: np.day, hour: 0, minute: 0, second: 0 };
    next = zonedTimeToUtc(target, timeZone);
  }
  return next;
}

export function buildRepeatJobConfig(feedKey, scheduleCron, slotMap = null) {
  const pattern = effectiveCronForFeed(feedKey, scheduleCron, slotMap);
  if (isDailyScheduleCron(scheduleCron)) {
    return { pattern, tz: getSystemScheduleTimezone() };
  }
  return { pattern };
}

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
    return computeNextDailyRunAt(now);
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
