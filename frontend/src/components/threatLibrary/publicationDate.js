/**
 * Presentation of a report's publication date (Overview / Source tab / IOC
 * Threat Context). Publication is shown as the calendar day the source
 * stated (`published_date`), never as an instant: most sources publish a day
 * without a time, and rendering an instant in the system timezone could
 * shift the day the analyst sees on the source page. `created_at`
 * (Imported) stays a real instant and is formatted separately.
 */

import { formatCalendarDate } from '../../lib/formatDate.js';

const SOURCE_LABELS = Object.freeze({
  manual: 'set manually',
  thib: 'from the imported THIB bundle',
  json_ld: 'from the page metadata (JSON-LD datePublished)',
  og_article: 'from the page metadata (article:published_time)',
  meta: 'from the page metadata',
  html_time: 'from the page (time element)',
  visible_date: 'from the visible page date',
  pdf_visible_date: 'from the document cover / front matter',
  ai: 'model-identified, verified against the document text'
});

/** Human label for the provenance, for a tooltip; null when unknown. */
export function publicationDateSourceLabel(source) {
  return SOURCE_LABELS[String(source || '').toLowerCase()] || null;
}

/**
 * Day to display for a report / claim report object. Prefers the API's
 * `published_date` (the day the source stated); a legacy payload that only
 * carries `published_at` falls back to that instant's UTC day.
 * @param {{ published_date?: string|null, published_at?: string|null }|null|undefined} report
 * @returns {string|null} YYYY-MM-DD or null
 */
export function publicationDay(report) {
  if (!report) return null;
  const stated = String(report.published_date || '').trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(stated)) return stated;
  const raw = String(report.published_at || '').trim();
  if (!raw) return null;
  const d = new Date(/([zZ]|[+-]\d{2}:?\d{2})$/.test(raw) ? raw : `${raw}Z`);
  return Number.isNaN(d.getTime()) ? null : d.toISOString().slice(0, 10);
}

/**
 * Display value for the Published row: DD/MM/YYYY, or null when unknown (the
 * row is then omitted — never "Published: —").
 */
export function formatPublicationDate(report) {
  const day = publicationDay(report);
  return day ? formatCalendarDate(day) : null;
}

/** Tooltip text: what the day means and where it came from. */
export function publicationDateTitle(report) {
  const day = publicationDay(report);
  if (!day) return null;
  const source = publicationDateSourceLabel(report?.published_at_source);
  return source ? `Publication date of the original source, ${source}` : 'Publication date of the original source';
}
