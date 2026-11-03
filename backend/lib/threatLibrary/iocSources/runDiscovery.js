/**
 * Post-analysis discovery of Additional IOC Sources from retained artifacts.
 * Never fetches, attaches, or extracts: discovery rows and ledger rows only.
 *
 * HTML artifact scan is required: canonical blocks drop href, so destination-
 * only anchors ("Indicators … can be found here") are invisible in block.text.
 */

import { readArtifactBuffer } from '../artifactStore.js';
import {
  discoverIocSourcesFromBlocks,
  discoverIocSourcesFromHtml,
  discoverIocSourcesFromText,
  upsertDiscoveredSources
} from './discover.js';
import { buildReferenceRows, isRelevantRejection, recordDiscoveryRun } from './discoveryLedger.js';

/**
 * Read every report artifact and the canonical document (pure apart from the
 * artifact reader). One artifact failing leaves the pass partial, not failed.
 * @param {object} report
 * @param {object[]} artifacts
 * @param {(key: string) => Promise<Buffer|string>} readArtifact
 * @param {string|null} reportUrl
 */
export async function examineReportReferences(report, artifacts, readArtifact, reportUrl) {
  const accepted = [];
  const rejected = [];
  const readErrors = [];
  const collect = (method) => ({
    reportUrl,
    onRejected: (r) => {
      if (isRelevantRejection(r)) rejected.push({ ...r, reference_method: method === 'html_anchor' ? method : r.linkText ? 'document_link' : 'text_url' });
    }
  });
  for (const art of artifacts) {
    if (art.artifact_type !== 'url_fetch' || !art.storage_key) continue;
    try {
      const bytes = await readArtifact(art.storage_key);
      const html = Buffer.isBuffer(bytes) ? bytes.toString('utf8') : String(bytes || '');
      accepted.push(...discoverIocSourcesFromHtml(html, collect('html_anchor')).map((d) => ({ ...d, reference_method: 'html_anchor' })));
    } catch (err) {
      readErrors.push(String(err?.message || err).slice(0, 160));
    }
  }

  // Canonical blocks (structured links + visible URLs): same evidence model as
  // the section graph's external_ioc_pointer.
  const doc = report.canonical_document;
  if (doc && Array.isArray(doc.blocks)) {
    accepted.push(...discoverIocSourcesFromBlocks(doc.blocks, collect('document')));
    // PDF / text-only fallback when blocks have no structured links.
    if (!doc.blocks.some((b) => Array.isArray(b.links) && b.links.length)) {
      const text = doc.blocks.map((b) => b.text || '').join('\n');
      accepted.push(...discoverIocSourcesFromText(text, collect('text')));
    }
  }
  for (const art of artifacts) {
    if (art.text_excerpt) accepted.push(...discoverIocSourcesFromText(art.text_excerpt, collect('text')));
  }
  return { accepted, rejected, readErrors };
}

/**
 * @param {import('pg').Pool} pool
 * @param {object} report
 * @param {{ logger?: { info?: Function, warn?: Function } }} [opts]
 */
export async function runIocSourceDiscoveryForReport(pool, report, opts = {}) {
  const log = opts.logger || {};
  if (!report?.id) return { inserted: 0, unchanged: 0, skipped: 0 };
  const reportUrl = report.source_url || report.source_url_canonical || null;

  try {
    const { rows: artifacts } = await pool.query(
      `SELECT id, artifact_type, storage_key, mime_type, source_metadata, text_excerpt
       FROM threat_report_artifacts
       WHERE report_id = $1
       ORDER BY id DESC`,
      [report.id]
    );

    const { accepted, rejected, readErrors } = await examineReportReferences(report, artifacts, readArtifactBuffer, reportUrl);
    for (const error of readErrors) {
      log.warn?.('ioc source discovery: failed to read url_fetch artifact', { reportId: report.id, error });
    }

    const byCanon = new Map();
    for (const d of accepted) {
      const prev = byCanon.get(d.canonical_url);
      if (!prev || (d.score || 0) > (prev.score || 0)) byCanon.set(d.canonical_url, d);
    }

    const result = await upsertDiscoveredSources(pool, report.id, [...byCanon.values()]);
    log.info?.('ioc source discovery complete', { reportId: report.id, ...result, found: byCanon.size });
    const refs = buildReferenceRows({ accepted: [...byCanon.values()], rejected, reportUrl });
    const status = result.skipped_finalized ? 'skipped_finalized' : readErrors.length ? 'partial' : 'completed';
    await recordDiscoveryRun(pool, report.id, {
      status,
      rows: refs.rows,
      notRecorded: refs.notRecorded,
      examined: refs.examined,
      sourcesInserted: result.inserted,
      errorDetail: readErrors[0] || null
    });
    return { ...result, found: byCanon.size, status };
  } catch (err) {
    // Discovery must never fail the parent report analysis, and its failure must
    // stay readable as a discovery failure rather than an extraction one.
    const error = String(err?.message || err).slice(0, 200);
    log.warn?.('ioc source discovery failed (non-fatal)', { reportId: report.id, error });
    try {
      await recordDiscoveryRun(pool, report.id, { status: 'failed', errorDetail: error });
    } catch (ledgerErr) {
      log.warn?.('ioc source discovery run not recorded', { reportId: report.id, error: String(ledgerErr?.message || ledgerErr).slice(0, 200) });
    }
    return { inserted: 0, unchanged: 0, skipped: 0, error, status: 'failed' };
  }
}
