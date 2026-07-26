// CSV serialization hardened against spreadsheet formula injection.
//
// Two independent concerns:
//   1. RFC-4180 quoting: a field containing a quote, comma, CR or LF is wrapped in
//      double quotes with embedded quotes doubled.
//   2. Formula-injection neutralization: a field whose first character is one of
//      = + - @ (or a leading tab/CR that Excel strips before evaluating) is prefixed
//      with a single quote so spreadsheet software treats it as text, never a formula.

import { formatTimestampWithOffset, isValidIanaTimezone } from '../systemTime.js';

const FORMULA_TRIGGER = /^[=+\-@\t\r]/;

export function csvCell(value) {
  let s = value == null ? '' : String(value);

  // Formula-injection guard runs first, on the raw value, so the neutralizing prefix
  // is itself inside any quoting applied afterwards.
  if (FORMULA_TRIGGER.test(s)) {
    s = `'${s}`;
  }

  if (/[",\n\r]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

export function csvRow(values) {
  return values.map(csvCell).join(',');
}

/**
 * Format a timestamp in the system timezone with offset (ISO-8601).
 * Falls back to UTC ISO when timezone is missing/invalid.
 */
export function csvTimestamp(value, timeZone = null) {
  if (value == null || value === '') return '';
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return '';
  if (timeZone && isValidIanaTimezone(timeZone)) {
    return formatTimestampWithOffset(d, timeZone) || d.toISOString();
  }
  return d.toISOString();
}
