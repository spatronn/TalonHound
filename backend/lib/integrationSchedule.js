export const BASE_SCHEDULE_CRONS = Object.freeze([
  '*/5 * * * *',
  '*/15 * * * *',
  '*/30 * * * *',
  '0 * * * *',
  '0 0 * * *'
]);

/** Manual-only schedule — excluded from recurring BullMQ repeatables. */
export const RUN_ONCE_SCHEDULE = 'run_once';

export const ALLOWED_SCHEDULE_CRONS = Object.freeze([
  ...BASE_SCHEDULE_CRONS,
  RUN_ONCE_SCHEDULE
]);

export function isRunOnceSchedule(value) {
  return String(value || '').trim() === RUN_ONCE_SCHEDULE;
}

export function isAllowedScheduleCron(value) {
  return ALLOWED_SCHEDULE_CRONS.includes(String(value || '').trim());
}

export function isRecurringScheduleCron(value) {
  return isAllowedScheduleCron(value) && !isRunOnceSchedule(value);
}

const DEFAULT_SYSTEM_SCHEDULE_TIMEZONE = 'UTC';
const HOURLY_AT_MINUTE = /^([0-5]?\d) \* \* \* \*$/;
const WEEKLY_AT_TIME = /^([0-5]?\d) ([01]?\d|2[0-3]) \* \* ([0-6])$/;

/** Runtime override from system_settings (preferred over env). */
let scheduleTimezoneOverride = null;

export function setSystemScheduleTimezoneOverride(timeZone) {
  if (timeZone == null || timeZone === '') {
    scheduleTimezoneOverride = null;
    return null;
  }
  scheduleTimezoneOverride = normalizeScheduleTimezone(timeZone);
  return scheduleTimezoneOverride;
}

export function getSystemScheduleTimezoneOverride() {
  return scheduleTimezoneOverride;
}

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

/** Server reference timezone for cron execution. DB override > env > UTC. */
export function getSystemScheduleTimezone() {
  if (scheduleTimezoneOverride) return scheduleTimezoneOverride;
  const tz = String(
    process.env.SYSTEM_TIMEZONE
      || process.env.INTEGRATION_SCHEDULE_TIMEZONE
      || DEFAULT_SYSTEM_SCHEDULE_TIMEZONE
  ).trim();
  return normalizeScheduleTimezone(tz);
}

export function zonedTimeParts(date, timeZone) {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23'
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

export function computeNextWeeklyRunAt(scheduleCron, now = new Date(), timeZone = getSystemScheduleTimezone()) {
  const match = WEEKLY_AT_TIME.exec(String(scheduleCron || '').trim());
  if (!match) return null;
  const minute = Number(match[1]);
  const hour = Number(match[2]);
  const weekday = Number(match[3]);
  const p = zonedTimeParts(now, timeZone);
  const localNoon = new Date(Date.UTC(p.year, p.month - 1, p.day, 12));
  const currentWeekday = localNoon.getUTCDay();

  for (let daysAhead = 0; daysAhead <= 7; daysAhead += 1) {
    if ((currentWeekday + daysAhead) % 7 !== weekday) continue;
    const targetDay = new Date(Date.UTC(p.year, p.month - 1, p.day + daysAhead, 12));
    const target = {
      year: targetDay.getUTCFullYear(),
      month: targetDay.getUTCMonth() + 1,
      day: targetDay.getUTCDate(),
      hour,
      minute,
      second: 0
    };
    const next = zonedTimeToUtc(target, timeZone);
    if (next.getTime() > now.getTime()) return next;
  }
  return null;
}

function computeNextHourlyRunAt(slotMinute, now = new Date(), timeZone = getSystemScheduleTimezone()) {
  const p = zonedTimeParts(now, timeZone);
  let target = {
    year: p.year,
    month: p.month,
    day: p.day,
    hour: p.hour,
    minute: slotMinute,
    second: 0
  };
  let next = zonedTimeToUtc(target, timeZone);
  if (next.getTime() <= now.getTime()) {
    const followingHour = new Date(Date.UTC(
      p.year,
      p.month - 1,
      p.day,
      p.hour + 1
    ));
    target = {
      year: followingHour.getUTCFullYear(),
      month: followingHour.getUTCMonth() + 1,
      day: followingHour.getUTCDate(),
      hour: followingHour.getUTCHours(),
      minute: slotMinute,
      second: 0
    };
    next = zonedTimeToUtc(target, timeZone);
  }
  return next;
}

export function buildRepeatJobConfig(feedKey, scheduleCron, slotMap = null, timezone = null) {
  const pattern = effectiveCronForFeed(feedKey, scheduleCron, slotMap);
  if (isDailyScheduleCron(scheduleCron) || isWeeklyScheduleCron(scheduleCron)) {
    return { pattern, tz: normalizeScheduleTimezone(timezone || getSystemScheduleTimezone()) };
  }
  return { pattern };
}

export function isHourlyAtMinuteCron(value) {
  return HOURLY_AT_MINUTE.test(String(value || '').trim());
}

export function sanitizeScheduleCron(value) {
  const v = String(value || '').trim();
  if (isRunOnceSchedule(v)) return RUN_ONCE_SCHEDULE;
  if (BASE_SCHEDULE_CRONS.includes(v)) return v;
  if (isHourlyAtMinuteCron(v)) return v;
  if (WEEKLY_AT_TIME.test(v)) return v;
  return '0 * * * *';
}

export function isHourlyScheduleCron(scheduleCron) {
  return sanitizeScheduleCron(scheduleCron) === '0 * * * *';
}

export function isDailyScheduleCron(scheduleCron) {
  return sanitizeScheduleCron(scheduleCron) === '0 0 * * *';
}

export function isWeeklyScheduleCron(scheduleCron) {
  return WEEKLY_AT_TIME.test(String(scheduleCron || '').trim());
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
      return key && isHourlyScheduleCron(schedule) && !isRunOnceSchedule(schedule);
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
  if (isRunOnceSchedule(scheduleCron)) return null;
  const cron = effectiveCronForFeed(feedKey, scheduleCron, slotMap);

  if (cron === '*/5 * * * *') return alignToIntervalMinutes(now, 5);
  if (cron === '*/15 * * * *') return alignToIntervalMinutes(now, 15);
  if (cron === '*/30 * * * *') return alignToIntervalMinutes(now, 30);

  if (cron === '0 0 * * *') {
    return computeNextDailyRunAt(now);
  }

  if (isWeeklyScheduleCron(cron)) {
    return computeNextWeeklyRunAt(cron, now);
  }

  const hourlyMatch = HOURLY_AT_MINUTE.exec(cron);
  if (hourlyMatch) {
    return computeNextHourlyRunAt(Number(hourlyMatch[1]), now);
  }

  const fallback = new Date(now);
  fallback.setMinutes(0, 0, 0);
  fallback.setHours(fallback.getHours() + 1);
  return fallback;
}

/**
 * Choose the value shown to users as "Next Run".
 *
 * The BullMQ repeatable's `next` (bullNext) is canonical *only while it is in the
 * future*. A stalled or not-yet-recovered repeat chain can leave `next` frozen in the
 * past; such a value must never surface as "Next Run" (it produces Next Run < Last Run).
 * When bullNext is missing or in the past we fall back to the schedule-derived future
 * `computedNext`. Timezone semantics are untouched — both inputs are absolute instants.
 *
 * @param {Date|string|number|null|undefined} bullNext
 * @param {Date|null|undefined} computedNext
 * @param {Date|number} [now]
 * @returns {Date|null}
 */
export function resolveNextRunAt(bullNext, computedNext, now = new Date()) {
  const nowMs = now instanceof Date ? now.getTime() : Number(now);
  let bullMs = NaN;
  if (bullNext instanceof Date) bullMs = bullNext.getTime();
  else if (typeof bullNext === 'number') bullMs = bullNext;
  else if (typeof bullNext === 'string' && bullNext.trim() !== '') bullMs = Date.parse(bullNext);

  if (Number.isFinite(bullMs) && bullMs > nowMs) {
    return bullNext instanceof Date ? bullNext : new Date(bullMs);
  }
  return computedNext || null;
}

export function buildRepeatableNextRunMap(repeatables = []) {
  const map = new Map();
  for (const row of repeatables) {
    const idRaw = String(row?.id || row?.key || '').trim();
    const customPrefix = 'integration-schedule:';
    const nextMs = Number(row?.next);
    if (!Number.isFinite(nextMs) || nextMs <= 0) continue;
    const next = new Date(nextMs);
    if (idRaw.startsWith(customPrefix)) {
      const identity = idRaw.slice(customPrefix.length);
      const [feedKey, mode = 'incremental'] = identity.split('::');
      if (!feedKey) continue;
      map.set(`${feedKey}::${mode}`, next);
      if (mode === 'incremental') map.set(feedKey, next);
      continue;
    }
    const fullSuffix = '-full-reconciliation-scheduled';
    const isFull = idRaw.endsWith(fullSuffix);
    const feedKey = isFull
      ? idRaw.slice(0, -fullSuffix.length)
      : idRaw.replace(/-scheduled$/, '');
    if (!feedKey) continue;
    map.set(`${feedKey}::${isFull ? 'full_reconciliation' : 'incremental'}`, next);
    if (!isFull) map.set(feedKey, next);
  }
  return map;
}
