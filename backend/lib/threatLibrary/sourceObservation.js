/**
 * Publisher observation dates of an indicator (format- and vendor-independent).
 *
 * An IOC appendix often prints when the publisher observed each value:
 *
 *   IP Address        First Seen   Last Seen
 *   120.36.250[.]48   5/25/2023    5/25/2023
 *
 * That date is the publisher's observation, not the report's publication date
 * and not the day TalonHound imported the report. This module reads it from
 * the indicator's own table row and returns a structured, conservative record:
 *
 *   earliest / latest   the observation window the row's dates span (always)
 *   first_seen / last_seen  only when a column label says so
 *   dates[]             every date cell read, with its label and whether it
 *                       counts as an observation
 *
 * Rules (never a guess):
 *   - Only the indicator's own row is read; a date elsewhere in the report is
 *     not an observation of this value.
 *   - Slash dates (5/6/2021) are read month-first or day-first only when the
 *     document's own table dates prove the order (a component > 12); an
 *     ambiguous document keeps the raw text and no calendar date.
 *   - A date the publisher qualifies with a footnote marker (`1/18/2027*`) or
 *     a column labelled as a non-observation date (Expiration, Registered,
 *     Compiled, …) is kept as row evidence but is not an observation.
 *   - A date after the report's publication / the extraction instant cannot
 *     be an observation the report made.
 */

import { normalizeHeaderLabel, headerIntent } from './tableSemantics.js';

export const SOURCE_OBSERVATION_VERSION = 'tl-observation-v1';

const MONTHS = Object.freeze({
  jan: 1, january: 1, feb: 2, february: 2, mar: 3, march: 3, apr: 4, april: 4, may: 5, jun: 6, june: 6,
  jul: 7, july: 7, aug: 8, august: 8, sep: 9, sept: 9, september: 9, oct: 10, october: 10,
  nov: 11, november: 11, dec: 12, december: 12
});

const FOOTNOTE_MARK_RE = /[*†‡§¹²³⁴⁵⁶⁷⁸⁹]+$/u;
const SLASH_DATE_RE = /^(\d{1,2})[/.](\d{1,2})[/.](\d{4})$/;
const ISO_DATE_RE = /^(\d{4})-(\d{1,2})-(\d{1,2})(?:[T\s]\d{1,2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:z|[+-]\d{2}:?\d{2})?)?$/i;
const YMD_SLASH_RE = /^(\d{4})\/(\d{1,2})\/(\d{1,2})$/;
const MONTH_FIRST_RE = /^([a-z]{3,9})\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(\d{4})$/i;
const DAY_FIRST_RE = /^(\d{1,2})(?:st|nd|rd|th)?\s+([a-z]{3,9})\.?,?\s+(\d{4})$/i;

/** Column label → what its dates mean (labels are normalized by normalizeHeaderLabel). */
const FIRST_LABEL_RE = /^(?:first|first\s+(?:seen|observed|detected|activity|appearance|sighting|reported)|start|start\s+date|started|from|earliest|earliest\s+(?:seen|observed))$/;
const LAST_LABEL_RE = /^(?:last|last\s+(?:seen|observed|detected|activity|sighting|reported)|end|end\s+date|ended|to|until|latest|latest\s+(?:seen|observed))$/;
const OBSERVED_LABEL_RE = /^(?:date|dates|seen|observed|observed\s+(?:on|at|date)|date\s+(?:observed|seen|detected|reported)|detected|detection\s+date|timestamp|time|activity\s+date|reported|reported\s+(?:on|date)|sighting|sighted)$/;
const NON_OBSERVATION_LABEL_RE = /(?:expir|regist|creat|updat|modif|publish|valid|issued|compil|signed|renew|patch|release)/;

/** Multi-word column labels a header line can be segmented into (normalized). */
const DATE_LABEL_PHRASES = Object.freeze([
  'first seen', 'last seen', 'first observed', 'last observed', 'first detected', 'last detected',
  'date observed', 'date seen', 'date detected', 'observed on', 'detection date', 'activity date',
  'date', 'dates', 'observed', 'seen', 'timestamp'
]);

function pad2(n) {
  return String(n).padStart(2, '0');
}

function validYmd(y, m, d) {
  if (!(y >= 1990 && y <= 2100 && m >= 1 && m <= 12 && d >= 1 && d <= 31)) return null;
  const dt = new Date(Date.UTC(y, m - 1, d));
  if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== m - 1 || dt.getUTCDate() !== d) return null;
  return `${y}-${pad2(m)}-${pad2(d)}`;
}

/**
 * Split a cell into its date text and a trailing footnote marker.
 * @param {string} text
 */
function stripFootnote(text) {
  const raw = String(text || '').trim();
  const m = raw.match(FOOTNOTE_MARK_RE);
  if (!m) return { body: raw, marker: null };
  return { body: raw.slice(0, raw.length - m[0].length).trim(), marker: m[0] };
}

/** True when a cell is a single date in any supported spelling (order not needed). */
export function isDateCell(text) {
  const { body } = stripFootnote(text);
  if (!body || body.length > 40) return false;
  return SLASH_DATE_RE.test(body) || ISO_DATE_RE.test(body) || YMD_SLASH_RE.test(body) ||
    MONTH_FIRST_RE.test(body) || DAY_FIRST_RE.test(body);
}

/**
 * Document-level order of numeric slash dates, decided by the publisher's own
 * values: a first component > 12 proves month-second (day-first), a second
 * component > 12 proves month-first. Conflicting or no proof → null.
 * @param {Iterable<string>} cellTexts
 * @returns {'mdy'|'dmy'|null}
 */
export function inferSlashDateOrder(cellTexts) {
  let mdy = 0;
  let dmy = 0;
  for (const text of cellTexts || []) {
    const m = stripFootnote(text).body.match(SLASH_DATE_RE);
    if (!m) continue;
    const a = Number(m[1]);
    const b = Number(m[2]);
    if (a > 12 && b <= 12) dmy += 1;
    else if (b > 12 && a <= 12) mdy += 1;
  }
  if (mdy > 0 && dmy === 0) return 'mdy';
  if (dmy > 0 && mdy === 0) return 'dmy';
  return null;
}

/**
 * Parse one date cell. Returns null for non-date text.
 * @param {string} text
 * @param {'mdy'|'dmy'|null} slashOrder
 * @returns {{ raw: string, date: string|null, marker: string|null, ambiguous?: true }|null}
 */
export function parseDateCell(text, slashOrder = null) {
  const raw = String(text || '').trim();
  const { body, marker } = stripFootnote(raw);
  if (!body || body.length > 40) return null;
  let m = body.match(ISO_DATE_RE) || body.match(YMD_SLASH_RE);
  if (m) return { raw, date: validYmd(Number(m[1]), Number(m[2]), Number(m[3])), marker };
  m = body.match(SLASH_DATE_RE);
  if (m) {
    const a = Number(m[1]);
    const b = Number(m[2]);
    const y = Number(m[3]);
    if (a === b) return { raw, date: validYmd(y, a, b), marker };
    if (slashOrder === 'mdy') return { raw, date: validYmd(y, a, b), marker };
    if (slashOrder === 'dmy') return { raw, date: validYmd(y, b, a), marker };
    return { raw, date: null, marker, ambiguous: true };
  }
  m = body.match(MONTH_FIRST_RE);
  if (m && MONTHS[m[1].toLowerCase()]) return { raw, date: validYmd(Number(m[3]), MONTHS[m[1].toLowerCase()], Number(m[2])), marker };
  m = body.match(DAY_FIRST_RE);
  if (m && MONTHS[m[2].toLowerCase()]) return { raw, date: validYmd(Number(m[3]), MONTHS[m[2].toLowerCase()], Number(m[1])), marker };
  return null;
}

/**
 * What a column label says about its dates.
 * @param {string|null|undefined} label
 * @returns {'first_seen'|'last_seen'|'observed'|'not_observation'|null}
 */
export function dateColumnMeaning(label) {
  const norm = normalizeHeaderLabel(label);
  if (!norm) return null;
  if (NON_OBSERVATION_LABEL_RE.test(norm)) return 'not_observation';
  if (FIRST_LABEL_RE.test(norm)) return 'first_seen';
  if (LAST_LABEL_RE.test(norm)) return 'last_seen';
  if (OBSERVED_LABEL_RE.test(norm)) return 'observed';
  return null;
}

/**
 * Recover column labels for a headerless table from the short line printed
 * just above it ("IP Address First Seen Last Seen", possibly after page
 * chrome such as "FBI | CISA | NSA"). The line's trailing words must split
 * into exactly `width` known labels, and each label must agree with what its
 * column holds (indicator label over the indicator column, date label over a
 * date column). Anything else returns null — labels are never guessed.
 * @param {string} lineText
 * @param {{ width: number, indicatorColumns: number[], dateColumns: number[] }} shape
 * @returns {string[]|null}
 */
export function recoverHeaderLabels(lineText, shape) {
  const width = Number(shape?.width) || 0;
  if (width < 2 || width > 6) return null;
  const text = String(lineText || '');
  if (!text.trim() || text.length > 240) return null;
  const words = normalizeHeaderLabel(text).split(' ').filter(Boolean);
  if (!words.length) return null;
  const isLabel = (phrase) => DATE_LABEL_PHRASES.includes(phrase) || dateColumnMeaning(phrase) != null || headerIntent(phrase) != null;
  // Right-to-left: the labels are the line's last words; chrome may precede them.
  const labels = [];
  let end = words.length;
  for (let col = width - 1; col >= 0; col -= 1) {
    let matched = null;
    for (let len = 3; len >= 1; len -= 1) {
      if (end - len < 0) continue;
      const phrase = words.slice(end - len, end).join(' ');
      if (isLabel(phrase)) {
        matched = { phrase, len };
        break;
      }
    }
    if (!matched) return null;
    labels.unshift(matched.phrase);
    end -= matched.len;
  }
  const indicatorCols = new Set(shape.indicatorColumns || []);
  const dateCols = new Set(shape.dateColumns || []);
  for (let c = 0; c < width; c += 1) {
    const label = labels[c];
    const meaning = dateColumnMeaning(label);
    const isDateLabel = meaning != null || DATE_LABEL_PHRASES.includes(label);
    if (indicatorCols.has(c) && headerIntent(label) !== 'indicator') return null;
    if (dateCols.has(c) && !isDateLabel) return null;
    if (!dateCols.has(c) && isDateLabel) return null;
  }
  return labels;
}

/**
 * Observation record for one indicator table row.
 * @param {{
 *   cells: string[],
 *   headers?: Array<string|null>|null,
 *   indicatorColumns: number[],
 *   slashOrder?: 'mdy'|'dmy'|null,
 *   notAfter?: string|null  YYYY-MM-DD; later dates cannot be observations
 * }} input
 * @returns {object|null}
 */
export function buildRowObservation(input) {
  const cells = Array.isArray(input?.cells) ? input.cells : [];
  const headers = Array.isArray(input?.headers) ? input.headers : [];
  const indicatorCols = new Set(input?.indicatorColumns || []);
  const dates = [];
  for (let c = 0; c < cells.length; c += 1) {
    if (indicatorCols.has(c)) continue;
    const parsed = parseDateCell(cells[c], input?.slashOrder || null);
    if (!parsed) continue;
    const label = headers[c] ? String(headers[c]).trim() || null : null;
    const meaning = label ? dateColumnMeaning(label) : null;
    let excluded = null;
    if (!parsed.date) excluded = parsed.ambiguous ? 'ambiguous_date_order' : 'invalid_date';
    else if (meaning === 'not_observation') excluded = 'non_observation_column';
    else if (parsed.marker) excluded = 'footnote_qualified';
    else if (input?.notAfter && parsed.date > input.notAfter) excluded = 'after_publication';
    dates.push({
      column_index: c,
      label,
      meaning: meaning === 'not_observation' ? null : meaning,
      raw: parsed.raw,
      date: parsed.date,
      ...(excluded ? { excluded } : {})
    });
  }
  if (!dates.length) return null;
  const observed = dates.filter((d) => !d.excluded);
  const sorted = observed.map((d) => d.date).sort();
  const firstLabelled = observed.filter((d) => d.meaning === 'first_seen').map((d) => d.date).sort();
  const lastLabelled = observed.filter((d) => d.meaning === 'last_seen').map((d) => d.date).sort();
  const labelled = observed.length > 0 && observed.every((d) => d.meaning);
  return {
    earliest: sorted[0] || null,
    latest: sorted[sorted.length - 1] || null,
    first_seen: firstLabelled[0] || null,
    last_seen: lastLabelled[lastLabelled.length - 1] || null,
    precision: 'date',
    basis: labelled ? 'labelled_columns' : 'row_dates',
    dates
  };
}

/**
 * Candidate-level publisher observation from its table rows (all rows of the
 * same value, any table). Null when no row carries an observation date.
 * @param {Array<{ observation?: object|null, table_id?: string|null, page?: number|null }>} tableRows
 */
export function aggregateSourceObservation(tableRows) {
  const rows = (Array.isArray(tableRows) ? tableRows : []).filter((r) => r?.observation && (r.observation.earliest || r.observation.dates?.length));
  if (!rows.length) return null;
  const pick = (key, dir) => {
    const vals = rows.map((r) => r.observation[key]).filter(Boolean).sort();
    if (!vals.length) return null;
    return dir === 'min' ? vals[0] : vals[vals.length - 1];
  };
  const earliest = pick('earliest', 'min');
  const latest = pick('latest', 'max');
  return {
    source: 'publisher_table_row',
    earliest,
    latest,
    first_seen: pick('first_seen', 'min'),
    last_seen: pick('last_seen', 'max'),
    precision: 'date',
    basis: rows.every((r) => r.observation.basis === 'labelled_columns') ? 'labelled_columns' : 'row_dates',
    rows: rows.length,
    version: SOURCE_OBSERVATION_VERSION
  };
}

/**
 * Public shape of a candidate's publisher observation (Threat Context, MCP,
 * report API). Null when the report gives no observation date for the value —
 * never back-filled from the publication or import date.
 * @param {object|null|undefined} evidence persisted candidate evidence
 */
export function serializeSourceObservation(evidence) {
  const o = evidence?.source_observation;
  if (!o || typeof o !== 'object' || (!o.earliest && !o.latest)) return null;
  return {
    source: o.source || 'publisher_table_row',
    earliest: o.earliest || null,
    latest: o.latest || null,
    first_seen: o.first_seen || null,
    last_seen: o.last_seen || null,
    precision: o.precision || 'date',
    basis: o.basis || null
  };
}
