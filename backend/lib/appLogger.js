/**
 * Structured application logging with system-timezone timestamps (offset included).
 *
 * Example:
 *   {"timestamp":"2026-07-26T14:24:06+03:00","timezone":"Europe/Istanbul","service":"backend","level":"info","message":"..."}
 */

import { formatTimestampWithOffset, getCachedSystemTimezone, isValidIanaTimezone } from './systemTime.js';

function resolveLogTimezone() {
  const cached = getCachedSystemTimezone();
  if (cached && isValidIanaTimezone(cached)) return cached;
  const env = String(process.env.SYSTEM_TIMEZONE || process.env.TZ || '').trim();
  if (env && isValidIanaTimezone(env)) return env;
  return 'UTC';
}

/**
 * @param {string} service
 * @param {'debug'|'info'|'warn'|'error'} level
 * @param {string} message
 * @param {Record<string, unknown>} [fields]
 */
export function logStructured(service, level, message, fields = {}) {
  const timezone = resolveLogTimezone();
  const now = new Date();
  const payload = {
    timestamp: formatTimestampWithOffset(now, timezone) || now.toISOString(),
    timezone,
    service,
    level,
    message,
    ...fields
  };
  const line = JSON.stringify(payload);
  if (level === 'error') console.error(line);
  else if (level === 'warn') console.warn(line);
  else console.log(line);
}

export function createServiceLogger(service) {
  return {
    debug: (message, fields) => logStructured(service, 'debug', message, fields),
    info: (message, fields) => logStructured(service, 'info', message, fields),
    warn: (message, fields) => logStructured(service, 'warn', message, fields),
    error: (message, fields) => logStructured(service, 'error', message, fields)
  };
}
