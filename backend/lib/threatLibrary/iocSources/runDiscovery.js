/**
 * Post-analysis discovery of Additional IOC Sources from retained artifacts.
 * Never fetches or attaches — discovery rows only.
 */

import { readArtifactBuffer } from '../artifactStore.js';
import {
  discoverIocSourcesFromHtml,
  discoverIocSourcesFromText,
  upsertDiscoveredSources
} from './discover.js';

/**
 * @param {import('pg').Pool} pool
 * @param {object} report
 * @param {{ logger?: { info?: Function, warn?: Function } }} [opts]
 */
export async function runIocSourceDiscoveryForReport(pool, report, opts = {}) {
  const log = opts.logger || {};
  if (!report?.id) return { inserted: 0, unchanged: 0, skipped: 0 };

  try {
    const { rows: artifacts } = await pool.query(
      `SELECT id, artifact_type, storage_key, mime_type, source_metadata, text_excerpt
       FROM threat_report_artifacts
       WHERE report_id = $1
       ORDER BY id DESC`,
      [report.id]
    );

    const discovered = [];
    const reportUrl = report.source_url || report.source_url_canonical || null;

    for (const art of artifacts) {
      if (art.artifact_type === 'url_fetch' && art.storage_key) {
        try {
          const bytes = await readArtifactBuffer(art.storage_key);
          const html = Buffer.isBuffer(bytes) ? bytes.toString('utf8') : String(bytes || '');
          discovered.push(...discoverIocSourcesFromHtml(html, { reportUrl }));
        } catch (err) {
          log.warn?.('ioc source discovery: failed to read url_fetch artifact', {
            reportId: report.id,
            error: String(err?.message || err).slice(0, 160)
          });
        }
      }
    }

    // Fallback / PDF: scan canonical document text + excerpts
    const doc = report.canonical_document;
    if (doc && Array.isArray(doc.blocks)) {
      const text = doc.blocks.map((b) => b.text || '').join('\n');
      discovered.push(...discoverIocSourcesFromText(text, { reportUrl }));
    }
    for (const art of artifacts) {
      if (art.text_excerpt) {
        discovered.push(...discoverIocSourcesFromText(art.text_excerpt, { reportUrl }));
      }
    }

    // Dedupe by canonical_url keeping highest score
    const byCanon = new Map();
    for (const d of discovered) {
      const prev = byCanon.get(d.canonical_url);
      if (!prev || (d.score || 0) > (prev.score || 0)) byCanon.set(d.canonical_url, d);
    }

    const result = await upsertDiscoveredSources(pool, report.id, [...byCanon.values()]);
    log.info?.('ioc source discovery complete', { reportId: report.id, ...result, found: byCanon.size });
    return result;
  } catch (err) {
    // Discovery must never fail the parent report analysis.
    log.warn?.('ioc source discovery failed (non-fatal)', {
      reportId: report.id,
      error: String(err?.message || err).slice(0, 200)
    });
    return { inserted: 0, unchanged: 0, skipped: 0, error: String(err?.message || err).slice(0, 200) };
  }
}
