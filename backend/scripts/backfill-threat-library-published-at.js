#!/usr/bin/env node
/**
 * One-time backfill of Threat Library `published_at` for reports imported
 * before publication-date extraction existed.
 *
 * Uses exactly the pipeline's canonical extractor (lib/threatLibrary/
 * publicationDate.js): retained source HTML for URL reports (JSON-LD →
 * article:published_time → meta → <time> → visible date), the stored
 * canonical document for PDFs (explicit cover / front-matter date only —
 * never PDF CreationDate, never file timestamps). Nothing is inferred from
 * created_at, the URL path or the file name.
 *
 *   - Only rows with `published_at IS NULL` are ever updated; populated
 *     values (THIB / manual / earlier extraction) are listed and left alone.
 *   - Dry-run by default: prints one line per report with the detected day,
 *     provenance, raw value and the reason when nothing safe was found.
 *   - `--apply` writes the four columns (published_at, _source, _precision,
 *     _raw) with `WHERE published_at IS NULL` in the statement itself.
 *   - `--fetch` allows an SSRF-guarded fetch of the original URL for URL
 *     reports that have no retained HTML (older imports). Without it those
 *     reports fall back to their canonical document and are otherwise skipped.
 *   - `--report <public_id|id>` limits the run to one report.
 *
 *   node scripts/backfill-threat-library-published-at.js [--apply] [--fetch] [--report <id>]
 */

import '../lib/ensure-db-password.js';
import pg from 'pg';
import { detectReportPublicationDate, resolvePublicationDateUpdate } from '../lib/threatLibrary/publicationDate.js';
import { readArtifactBuffer } from '../lib/threatLibrary/artifactStore.js';
import { validateThreatLibraryUrl } from '../lib/threatLibrary/urlIngest.js';
import { fetchFeedUrl } from '../lib/customThreatFeedFetch.js';
import { URL_FETCH_MAX_BYTES, URL_FETCH_TIMEOUT_MS } from '../lib/threatLibrary/constants.js';

const args = process.argv.slice(2);
const apply = args.includes('--apply');
const allowFetch = args.includes('--fetch');
const onlyIdx = args.indexOf('--report');
const only = onlyIdx >= 0 ? args[onlyIdx + 1] : null;

function connectionConfig() {
  return {
    host: process.env.DB_HOST || 'db',
    port: Number(process.env.DB_PORT || 5432),
    user: process.env.DB_USER || 'talonhound',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'talonhound'
  };
}

async function loadRetainedHtml(pool, reportId) {
  const { rows } = await pool.query(
    `SELECT storage_key FROM threat_report_artifacts
     WHERE report_id = $1 AND artifact_type = 'url_fetch' AND storage_key IS NOT NULL
     ORDER BY id DESC LIMIT 1`,
    [reportId]
  );
  if (!rows[0]?.storage_key) return null;
  try {
    return (await readArtifactBuffer(rows[0].storage_key)).toString('utf8');
  } catch {
    return null;
  }
}

async function fetchSourceHtml(url) {
  const policy = validateThreatLibraryUrl(url);
  if (!policy.ok) return { html: null, note: `fetch refused: ${policy.error}` };
  try {
    const result = await fetchFeedUrl(policy.url, { timeoutMs: URL_FETCH_TIMEOUT_MS, maxBytes: URL_FETCH_MAX_BYTES, credentials: null });
    if (result.ok === false) return { html: null, note: `fetch HTTP ${result.httpStatus || 'error'}` };
    return { html: result.bodyText || null, note: `fetched HTTP ${result.httpStatus}` };
  } catch (err) {
    return { html: null, note: `fetch failed: ${err.message}` };
  }
}

/**
 * Plan one report. Pure given its inputs so the decision can be reviewed.
 * @param {object} report threat_reports row
 * @param {{ html: string|null, htmlOrigin: string|null }} input
 */
export function planPublicationDateBackfill(report, input) {
  if (report.published_at) {
    return { decision: 'skip_populated', detection: null, reason: `already populated (${report.published_at_source || 'unknown provenance'})` };
  }
  if (report.source_type === 'thib') {
    return { decision: 'skip', detection: null, reason: 'THIB bundle without a publication date; nothing to derive locally' };
  }
  const detection = detectReportPublicationDate({
    sourceType: report.source_type,
    sourceUrl: report.source_url,
    html: input.html,
    document: report.canonical_document
  });
  const update = resolvePublicationDateUpdate(report, detection);
  if (update.action === 'write') {
    return { decision: 'update', detection, fields: update.fields, reason: `${detection.source} (${input.htmlOrigin || 'canonical document'})` };
  }
  return { decision: 'skip', detection, reason: detection.reason || update.reason };
}

function fmtRow(cells) {
  return cells.map((c) => String(c ?? '')).join(' | ');
}

async function main() {
  const pool = new pg.Pool(connectionConfig());
  try {
    const where = only
      ? (/^\d+$/.test(only) ? 'AND r.id = $1' : 'AND r.public_id = $1::uuid')
      : '';
    const { rows: reports } = await pool.query(
      `SELECT r.* FROM threat_reports r WHERE r.deleted_at IS NULL ${where} ORDER BY r.id`,
      only ? [only] : []
    );

    const summary = { total: reports.length, populated_before: 0, would_update: 0, updated: 0, still_null: 0 };
    const lines = [];
    console.log(fmtRow(['id', 'public_id', 'type', 'source', 'detected', 'precision', 'provenance', 'raw', 'update?', 'reason']));
    for (const report of reports) {
      let html = null;
      let htmlOrigin = null;
      if (!report.published_at && report.source_type === 'url') {
        html = await loadRetainedHtml(pool, report.id);
        htmlOrigin = html ? 'retained HTML' : null;
        if (!html && allowFetch && report.source_url) {
          const fetched = await fetchSourceHtml(report.source_url);
          html = fetched.html;
          htmlOrigin = html ? `live fetch (${fetched.note})` : `no retained HTML; ${fetched.note}`;
        } else if (!html) {
          htmlOrigin = 'no retained HTML (pass --fetch to fetch the source)';
        }
      }
      const plan = planPublicationDateBackfill(report, { html, htmlOrigin });
      if (plan.decision === 'skip_populated') summary.populated_before += 1;
      const d = plan.detection;
      const line = fmtRow([
        report.id,
        report.public_id,
        report.source_type,
        report.source_url || report.source_file_name || report.source_name || '',
        d?.published_date || '',
        d?.precision || '',
        d?.source || '',
        d?.raw_value || '',
        plan.decision === 'update' ? 'yes' : 'no',
        plan.decision === 'update' ? plan.reason : `${plan.reason}${html == null && report.source_type === 'url' && !report.published_at ? ` [${htmlOrigin}]` : ''}`
      ]);
      console.log(line);
      lines.push({ report, plan });
      if (plan.decision === 'update') {
        summary.would_update += 1;
        if (apply) {
          const { rowCount } = await pool.query(
            `UPDATE threat_reports
             SET published_at = $2, published_at_source = $3, published_at_precision = $4, published_at_raw = $5, updated_at = NOW()
             WHERE id = $1 AND published_at IS NULL`,
            [report.id, plan.fields.published_at, plan.fields.published_at_source, plan.fields.published_at_precision, plan.fields.published_at_raw]
          );
          if (rowCount === 1) summary.updated += 1;
        }
      }
    }
    summary.still_null = reports.filter((r) => !r.published_at).length - (apply ? summary.updated : 0);
    console.log(JSON.stringify({ mode: apply ? 'apply' : 'dry-run', fetch: allowFetch, ...summary }));
    const remaining = lines.filter(({ report, plan }) => !report.published_at && plan.decision !== 'update');
    if (remaining.length) {
      console.log('Reports left without a publication date:');
      for (const { report, plan } of remaining) console.log(fmtRow(['  ', report.id, report.title, plan.reason]));
    }
  } finally {
    await pool.end();
  }
}

const invokedDirectly = process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop());
if (invokedDirectly) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
