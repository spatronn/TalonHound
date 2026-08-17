// Bounded-memory streaming generator for Published Feed artifacts (Phase 1).
//
// Reads the deduped, recency-ordered base population through a SERVER-SIDE CURSOR (single
// execution, DB-side sort, no client keyset / no per-page rescan) — including canonical
// hash/file-artifact feeds via a dedicated CTE shape. Each bounded batch resolves sibling
// ioc_ids for the published observable identity (legacy JSON aggregates sources/tags across
// duplicates), then fetches memberships/tags BY ioc id (indexed). Items are normalized with
// the existing publishedFeedJson normalizers and streamed to a .part file. Nothing accumulates
// the base rows, the item objects, or the final artifact in Node memory.

import fs from 'node:fs';
import { normalizeFeedIocTypes, feedCategoryForObservableType, normalizeFeedLine } from './feedFormatter.js';
import {
  buildStreamingBaseSql,
  resolvePublishedFeedFormats,
  resolveJsonIncludeFlags
} from './feedPublisherService.js';
import { normalizePublishedIoc } from './publishedFeedJson.js';
import { metaKey } from './publishedFeedJsonData.js';
import {
  projectionIdentityKey,
  projectionPartitionMetadata,
  projectionContentFingerprint,
  confidenceRank,
  upsertProjectionBatch,
  buildProjectionScanSql
} from './publishedFeedProjection.js';
import {
  getPublishedFeedArtifactConfig,
  newGenerationId,
  openArtifactPartStream,
  finalizeStream,
  commitArtifact,
  removeFileQuiet,
  statArtifact,
  toRelativeStoragePath,
  resolveArtifactPath
} from './publishedFeedArtifact/store.js';
import { StreamingTxtWriter, StreamingJsonBodyWriter, StreamingStixBodyWriter, makeSinkWriter } from './publishedFeedArtifact/streamWriter.js';
import { indicatorFromPublishedItem } from './publishedFeedStix.js';

const CURSOR_BATCH = Math.max(Number(process.env.PUBLISHED_FEED_CURSOR_BATCH || 5000), 100);

function destroyAndWait(stream) {
  return new Promise((resolve) => {
    if (!stream || stream.destroyed) return resolve();
    stream.on('close', resolve);
    stream.on('error', () => resolve());
    stream.destroy();
  });
}

/**
 * Open TXT and/or JSON writers for a shared generationId.
 * @returns {Promise<{ formats: string[], slots: object, cleanupTemp: Function }>}
 */
async function openMultiFormatWriters(cfg, feed, generationId, formats) {
  const slots = {};
  for (const format of formats) {
    const { stream: finalPartStream, finalPath, partPath } = await openArtifactPartStream(
      cfg, feed.id, generationId, format
    );
    if (format === 'json') {
      const bodyPath = `${finalPath}.body`;
      const bodyStream = fs.createWriteStream(bodyPath, { flags: 'w', mode: 0o640 });
      slots.json = {
        format: 'json',
        finalPartStream,
        finalPath,
        partPath,
        bodyPath,
        bodyStream,
        writer: new StreamingJsonBodyWriter(bodyStream, {
          name: feed.name,
          ...resolveJsonIncludeFlags(feed)
        })
      };
    } else if (format === 'stix') {
      const bodyPath = `${finalPath}.body`;
      const bodyStream = fs.createWriteStream(bodyPath, { flags: 'w', mode: 0o640 });
      slots.stix = {
        format: 'stix',
        finalPartStream,
        finalPath,
        partPath,
        bodyPath,
        bodyStream,
        writer: new StreamingStixBodyWriter(bodyStream, { slug: feed.slug })
      };
    } else {
      slots.txt = {
        format: 'txt',
        finalPartStream,
        finalPath,
        partPath,
        bodyPath: null,
        bodyStream: null,
        writer: new StreamingTxtWriter(finalPartStream)
      };
    }
  }
  const cleanupTemp = async () => {
    for (const slot of Object.values(slots)) {
      await destroyAndWait(slot.finalPartStream);
      if (slot.bodyStream) await destroyAndWait(slot.bodyStream);
      await removeFileQuiet(slot.partPath);
      if (slot.bodyPath) await removeFileQuiet(slot.bodyPath);
      await removeFileQuiet(slot.finalPath);
    }
  };
  return { formats, slots, cleanupTemp };
}

async function finalizeMultiFormatWriters(feed, generationId, slots) {
  const generatedAt = new Date().toISOString();
  const artifacts = [];
  let itemCount = 0;
  for (const slot of Object.values(slots)) {
    const finished = slot.writer.finish();
    itemCount = finished.item_count;
    if (slot.format === 'json' || slot.format === 'stix') {
      await finalizeStream(slot.bodyStream);
      const finalWrite = makeSinkWriter(slot.finalPartStream);
      await finalWrite(slot.writer.buildHeader(finished.item_count, generatedAt));
      await pipeFileInto(slot.bodyPath, slot.finalPartStream);
      await finalWrite(slot.writer.buildFooter());
      await finalizeStream(slot.finalPartStream);
      await removeFileQuiet(slot.bodyPath);
    } else {
      await finalizeStream(slot.finalPartStream);
    }
    await commitArtifact(slot.partPath, slot.finalPath);
    const st = await statArtifact(slot.finalPath);
    artifacts.push({
      generationId,
      format: slot.format,
      storagePath: toRelativeStoragePath(feed.id, generationId, slot.format),
      absolutePath: slot.finalPath,
      fileSize: st ? st.size : 0,
      contentHash: finished.content_hash,
      itemCount: finished.item_count
    });
  }
  const FORMAT_ORDER = ['txt', 'json', 'stix'];
  artifacts.sort((a, b) => FORMAT_ORDER.indexOf(a.format) - FORMAT_ORDER.indexOf(b.format));
  return { artifacts, itemCount, generationId };
}

function wrapArtifactResult(base, extras = {}) {
  const primary = base.artifacts[0];
  return {
    generationId: base.generationId,
    itemCount: base.itemCount,
    artifacts: base.artifacts,
    // Backward-compatible single-artifact fields (primary / first format).
    format: primary?.format,
    storagePath: primary?.storagePath,
    absolutePath: primary?.absolutePath,
    fileSize: primary?.fileSize,
    contentHash: primary?.contentHash,
    ...extras
  };
}

/**
 * Bounded metadata fetch for one base batch.
 *
 * Legacy JSON (publishedFeedJsonData) aggregates sources/tags/timestamps across ALL
 * sibling ioc_items rows that share the same lower(observable)+type — not only the
 * DISTINCT ON winner. Streaming preserves that contract:
 *   1) one indexed sibling-id resolve per batch (lower(observable)=ANY + type)
 *   2) sources/tags fetched with ioc_id=ANY(allSiblingIds) — no N+1, no per-source
 *      partition-wide scans beyond the single sibling resolve
 * Results are attached to the selected cursor row id(s) in this batch.
 */
async function fetchBatchMetadataById(db, rows, flags) {
  const byId = new Map();
  for (const r of rows) {
    byId.set(Number(r.id), {
      imported_at: null,
      first_seen_in_source: null,
      last_confirmed_in_source: null,
      sources: [],
      tags: [],
      enrichment: {}
    });
  }
  if (!rows.length) return byId;

  const lowerValues = [...new Set(rows.map((r) => String(r.observable).toLowerCase()))];
  const types = [...new Set(rows.map((r) => String(r.observable_type)))];

  // Selected cursor rows keyed by the public meta identity (type|lower(value)).
  const selectedByKey = new Map();
  for (const r of rows) {
    const k = metaKey(r.observable_type, r.observable);
    if (!selectedByKey.has(k)) selectedByKey.set(k, []);
    selectedByKey.get(k).push(Number(r.id));
  }

  // Sibling resolve: every ioc_items row sharing the published observable identity.
  // Uses the same lower(observable)+type predicate as the legacy JSON path (backed by
  // idx_ioc_items_supplement_lookup / hash lower_observable partial indexes).
  const sib = await db.query(
    `SELECT i.id, lower(i.observable) AS obs, i.observable_type AS otype,
            i.created_at, i.ioc_source_id
     FROM ioc_items i
     WHERE lower(i.observable) = ANY($1::text[])
       AND i.observable_type = ANY($2::text[])`,
    [lowerValues, types]
  );

  /** @type {Map<number, number[]>} sibling ioc id → selected cursor row ids that receive its metadata */
  const siblingToSelected = new Map();
  const allSiblingIds = [];
  for (const row of sib.rows) {
    const k = metaKey(row.otype, row.obs);
    const selectedIds = selectedByKey.get(k);
    if (!selectedIds?.length) continue;
    const sid = Number(row.id);
    allSiblingIds.push(sid);
    siblingToSelected.set(sid, selectedIds);
    for (const selectedId of selectedIds) {
      const e = byId.get(selectedId);
      if (!e) continue;
        // Legacy imported_at = MIN(created_at) across siblings.
      if (row.created_at != null) {
        const cur = e.imported_at != null ? new Date(e.imported_at).getTime() : Infinity;
        const next = new Date(row.created_at).getTime();
        if (Number.isFinite(next) && next < cur) e.imported_at = row.created_at;
      }
    }
  }
  // Fallback if sibling resolve returned nothing (should not happen — selected rows
  // themselves match the predicate): keep selected ids only.
  if (!allSiblingIds.length) {
    for (const r of rows) {
      const id = Number(r.id);
      allSiblingIds.push(id);
      siblingToSelected.set(id, [id]);
      const e = byId.get(id);
      if (e) e.imported_at = r.created_at;
    }
  }

  const attachToSelected = (siblingId, fn) => {
    const selectedIds = siblingToSelected.get(Number(siblingId));
    if (!selectedIds) return;
    for (const selectedId of selectedIds) {
      const e = byId.get(selectedId);
      if (e) fn(e);
    }
  };

  // Feed memberships (sources) — indexed by ioc_item_id across all siblings.
  if (flags.includeSourceMetadata) {
    const mem = await db.query(
      `SELECT m.ioc_item_id, f.key AS feed_key, f.name AS feed_name,
              m.first_seen_in_feed, m.last_seen_in_feed
       FROM ioc_feed_memberships m
       JOIN integration_feeds f ON f.integration_id = m.feed_id
       WHERE m.ioc_item_id = ANY($1::bigint[])
         AND m.status = 'active' AND m.purged_at IS NULL`,
      [allSiblingIds]
    );
    for (const row of mem.rows) {
      attachToSelected(row.ioc_item_id, (e) => {
        e.sources.push({
          feed_key: row.feed_key, feed_name: row.feed_name,
          first_seen_in_source: row.first_seen_in_feed, last_confirmed_in_source: row.last_seen_in_feed
        });
      });
    }
    // Manual provenance across siblings (by name only; never exposes ioc_source_id).
    const man = await db.query(
      `SELECT i.id, COALESCE(s.name, i.source_name) AS feed_name, i.created_at, i.last_seen_at
       FROM ioc_items i LEFT JOIN ioc_sources s ON s.id = i.ioc_source_id
       WHERE i.id = ANY($1::bigint[]) AND i.ioc_source_id IS NOT NULL
         AND COALESCE(i.status, 'active') = 'active'`,
      [allSiblingIds]
    );
    for (const row of man.rows) {
      attachToSelected(row.id, (e) => {
        e.sources.push({
          feed_key: null, feed_name: row.feed_name,
          first_seen_in_source: row.created_at,
          last_confirmed_in_source: row.last_seen_at || row.created_at
        });
      });
    }
  } else {
    // Item-level timestamps (section 6) are published even when sources[] is suppressed.
    const ts = await db.query(
      `SELECT ioc_item_id, MIN(first_seen_in_feed) AS fs, MAX(last_seen_in_feed) AS ls
       FROM ioc_feed_memberships
       WHERE ioc_item_id = ANY($1::bigint[]) AND status = 'active' AND purged_at IS NULL
       GROUP BY ioc_item_id`,
      [allSiblingIds]
    );
    for (const row of ts.rows) {
      attachToSelected(row.ioc_item_id, (e) => {
        if (row.fs && (!e.first_seen_in_source || row.fs < e.first_seen_in_source)) {
          e.first_seen_in_source = row.fs;
        }
        if (row.ls && (!e.last_confirmed_in_source || row.ls > e.last_confirmed_in_source)) {
          e.last_confirmed_in_source = row.ls;
        }
      });
    }
  }

  // Derive item-level first/last from aggregated sibling sources.
  if (flags.includeSourceMetadata) {
    for (const e of byId.values()) {
      for (const s of e.sources) {
        if (s.first_seen_in_source && (!e.first_seen_in_source || s.first_seen_in_source < e.first_seen_in_source)) {
          e.first_seen_in_source = s.first_seen_in_source;
        }
        if (s.last_confirmed_in_source && (!e.last_confirmed_in_source || s.last_confirmed_in_source > e.last_confirmed_in_source)) {
          e.last_confirmed_in_source = s.last_confirmed_in_source;
        }
      }
    }
  }

  if (flags.includeClassification) {
    const tags = await db.query(
      `SELECT it.ioc_id, tg.name FROM ioc_tags it
       JOIN tags tg ON tg.id = it.tag_id
       WHERE it.ioc_id = ANY($1::bigint[]) AND tg.enabled = TRUE`,
      [allSiblingIds]
    );
    for (const row of tags.rows) {
      if (!row.name) continue;
      attachToSelected(row.ioc_id, (e) => { e.tags.push(row.name); });
    }
  }

  if (flags.includeEnrichment) {
    await fetchBatchEnrichment(db, rows, byId);
  }

  return byId;
}

/** Enrichment stays keyed by value (provider tables are keyed by ip/observable_value/ioc_value). */
async function fetchBatchEnrichment(db, rows, byId) {
  const idByLowerValue = new Map();
  for (const r of rows) {
    const lv = String(r.observable).toLowerCase();
    if (!idByLowerValue.has(lv)) idByLowerValue.set(lv, []);
    idByLowerValue.get(lv).push(Number(r.id));
  }
  const attach = (providerRows, provider, valueField) => {
    for (const row of providerRows) {
      const ids = idByLowerValue.get(String(row[valueField] || '').toLowerCase());
      if (!ids) continue;
      for (const id of ids) { const e = byId.get(id); if (e) e.enrichment[provider] = row; }
    }
  };
  const lowerValues = [...idByLowerValue.keys()];
  const ipValues = rows.filter((r) => r.observable_type === 'ip').map((r) => r.observable);
  const domainLower = rows.filter((r) => r.observable_type === 'domain').map((r) => String(r.observable).toLowerCase());

  const vt = await db.query(
    `SELECT ioc_value, normalized_summary FROM ioc_enrichments
     WHERE provider='virustotal' AND status='success' AND lower(ioc_value)=ANY($1::text[])`, [lowerValues]);
  attach(vt.rows, 'virustotal', 'ioc_value');
  if (ipValues.length) {
    const ipinfo = await db.query(`SELECT ip, country, country_code, asn, as_name FROM ioc_ip_enrichment WHERE ip=ANY($1::text[])`, [ipValues]);
    attach(ipinfo.rows, 'ipinfo', 'ip');
    const abuse = await db.query(`SELECT ip, normalized_summary FROM ioc_abuseipdb_enrichment WHERE ip=ANY($1::text[]) AND provider_status='success'`, [ipValues]);
    attach(abuse.rows, 'abuseipdb', 'ip');
    const spam = await db.query(`SELECT lookup_ip, listed, list_type, matched_cidr, provider_status FROM ioc_spamhaus_drop_enrichment WHERE lookup_ip=ANY($1::text[])`, [ipValues]);
    attach(spam.rows, 'spamhaus', 'lookup_ip');
  }
  if (domainLower.length) {
    const rdap = await db.query(`SELECT observable_value, registrar, registration_date, expiration_date FROM ioc_domain_enrichment WHERE lower(observable_value)=ANY($1::text[])`, [domainLower]);
    attach(rdap.rows, 'rdap', 'observable_value');
  }
}

/**
 * Stream-generate feed artifact(s) to file(s). One DB cursor fans out to every enabled
 * format writer. Returns snapshot metadata including `artifacts[]` (same generationId /
 * itemCount). On any error, all .part/body temps are cleaned up and nothing is published.
 *
 * @param {import('pg').PoolClient} db  the generation client (holds the advisory lock)
 * @param {object} feed  normalized feed config
 * @param {string} window
 * @param {{ formatTypes: string[]|string, maxItems: number|null, cfg?: object, populateProjection?: boolean, projectionWindow?: string, formats?: string[] }} opts
 */
export async function generateFeedArtifact(db, feed, window, opts = {}) {
  const cfg = opts.cfg || getPublishedFeedArtifactConfig();
  const formats = opts.formats
    ? resolvePublishedFeedFormats({ formats: opts.formats })
    : resolvePublishedFeedFormats(feed);
  const flags = resolveJsonIncludeFlags(feed);
  const wantTxt = formats.includes('txt');
  const wantJson = formats.includes('json');
  const wantStix = formats.includes('stix');
  const maxItems = opts.maxItems != null && Number.isFinite(Number(opts.maxItems)) ? Number(opts.maxItems) : null;
  const generationId = newGenerationId();
  const norm = normalizeFeedIocTypes(opts.formatTypes);
  const types = norm.ok ? norm.value : [];
  const multi = types.length !== 1;
  const lineTypeFor = (observableType) => (multi
    ? (feedCategoryForObservableType(observableType) || types[0])
    : types[0]);
  const populateProjection = Boolean(opts.populateProjection);
  const projectionWindow = opts.projectionWindow || window;
  // Metadata / item_json needed when JSON or STIX is written OR projection is being bootstrapped
  // (projection stays format-agnostic so later enable-JSON/STIX can use item_json).
  const needJsonItems = wantJson || wantStix || populateProjection;

  const timings = { base_open_ms: 0, fetch_ms: 0, meta_ms: 0, write_ms: 0, projection_ms: 0 };
  const t = () => Number(process.hrtime.bigint() / 1000000n);
  let pageCount = 0;
  let scannedRows = 0;
  let projectionUpserts = 0;

  const { sql, params } = buildStreamingBaseSql(feed, window);
  const { slots, cleanupTemp } = await openMultiFormatWriters(cfg, feed, generationId, formats);

  try {
    let openedCursor = false;
    const t0 = t();
    await db.query('BEGIN');
    await db.query(`DECLARE pf_cur NO SCROLL CURSOR FOR ${sql}`, params);
    openedCursor = true;
    timings.base_open_ms += t() - t0;

    let done = false;
    while (!done) {
      const tf = t();
      const batch = await db.query(`FETCH FORWARD ${CURSOR_BATCH} FROM pf_cur`);
      timings.fetch_ms += t() - tf;
      const rows = batch.rows;
      if (!rows.length) break;
      pageCount += 1;
      scannedRows += rows.length;

      const tm = t();
      const meta = needJsonItems ? await fetchBatchMetadataById(db, rows, flags) : null;
      timings.meta_ms += t() - tm;

      const tw = t();
      const projBatch = [];
      for (const row of rows) {
        const value = normalizeFeedLine(row, lineTypeFor(row.observable_type));
        if (!value) continue;
        let item = null;
        if (needJsonItems) {
          const m = meta.get(Number(row.id)) || {};
          item = normalizePublishedIoc(
            { value, observable_type: row.observable_type, category: row.category, confidence: row.confidence },
            m, flags
          );
        }
        if (wantTxt) await slots.txt.writer.addValue(value);
        if (wantJson) await slots.json.writer.addItem(item);
        if (wantStix) {
          const indicator = indicatorFromPublishedItem(item);
          if (indicator) await slots.stix.writer.addIndicator(indicator);
        }
        if (populateProjection) {
          const fp = projectionContentFingerprint({ txtValue: value, itemJson: item });
          const partition = projectionPartitionMetadata({
            partition_identity: row.partition_identity || null,
            observable: value,
            observable_type: row.observable_type
          }, feed);
          projBatch.push({
            feed_id: feed.id,
            window: projectionWindow,
            identity_key: projectionIdentityKey(value, row.observable_type),
            ioc_item_id: Number(row.id),
            observable: value,
            observable_type: row.observable_type,
            recency_ts: row.recency_ts,
            confidence: row.confidence,
            category: row.category,
            confidence_rank: confidenceRank(row.confidence),
            txt_value: value,
            item_json: item,
            content_fingerprint: fp,
            ...partition
          });
        }
        const count = wantTxt
          ? slots.txt.writer.itemCount
          : (wantJson ? slots.json.writer.itemCount : slots.stix.writer.itemCount);
        if (maxItems != null && count >= maxItems) { done = true; break; }
      }
      timings.write_ms += t() - tw;
      if (projBatch.length) {
        const tp = t();
        projectionUpserts += await upsertProjectionBatch(db, projBatch);
        timings.projection_ms += t() - tp;
      }
    }

    if (openedCursor) await db.query('CLOSE pf_cur').catch(() => {});
    await db.query('COMMIT');

    const finalized = await finalizeMultiFormatWriters(feed, generationId, slots);
    return wrapArtifactResult(finalized, { pageCount, scannedRows, projectionUpserts, timings });
  } catch (err) {
    try { await db.query('ROLLBACK'); } catch { /* ignore */ }
    await cleanupTemp();
    throw err;
  }
}

/**
 * Stream-generate artifacts from an already-populated projection (Phase 2 incremental
 * publish path). One projection scan fans out to all enabled format writers.
 */
export async function generateFeedArtifactFromProjection(db, feed, window, opts = {}) {
  const cfg = opts.cfg || getPublishedFeedArtifactConfig();
  const formats = opts.formats
    ? resolvePublishedFeedFormats({ formats: opts.formats })
    : resolvePublishedFeedFormats(feed);
  const wantTxt = formats.includes('txt');
  const wantJson = formats.includes('json');
  const wantStix = formats.includes('stix');
  const maxItems = opts.maxItems != null && Number.isFinite(Number(opts.maxItems)) ? Number(opts.maxItems) : null;
  const generationId = newGenerationId();
  const { slots, cleanupTemp } = await openMultiFormatWriters(cfg, feed, generationId, formats);

  const { sql, params } = buildProjectionScanSql(feed.id, window);
  const timings = { fetch_ms: 0, write_ms: 0 };
  const t = () => Number(process.hrtime.bigint() / 1000000n);
  let scannedRows = 0;

  try {
    await db.query('BEGIN');
    await db.query(`DECLARE pf_proj_cur NO SCROLL CURSOR FOR ${sql}`, params);
    let done = false;
    while (!done) {
      const tf = t();
      const batch = await db.query(`FETCH FORWARD ${CURSOR_BATCH} FROM pf_proj_cur`);
      timings.fetch_ms += t() - tf;
      const rows = batch.rows;
      if (!rows.length) break;
      scannedRows += rows.length;
      const tw = t();
      for (const row of rows) {
        const item = (wantJson || wantStix)
          ? (row.item_json && typeof row.item_json === 'object'
            ? row.item_json
            : (typeof row.item_json === 'string' ? JSON.parse(row.item_json) : null))
          : null;
        if (wantTxt) await slots.txt.writer.addValue(row.txt_value);
        if (wantJson && item) await slots.json.writer.addItem(item);
        if (wantStix) {
          const indicator = indicatorFromPublishedItem(item);
          if (indicator) await slots.stix.writer.addIndicator(indicator);
        }
        const count = wantTxt
          ? slots.txt.writer.itemCount
          : (wantJson ? slots.json.writer.itemCount : slots.stix.writer.itemCount);
        if (maxItems != null && count >= maxItems) { done = true; break; }
      }
      timings.write_ms += t() - tw;
    }
    await db.query('CLOSE pf_proj_cur').catch(() => {});
    await db.query('COMMIT');

    const finalized = await finalizeMultiFormatWriters(feed, generationId, slots);
    return wrapArtifactResult(finalized, { pageCount: 0, scannedRows, timings, fromProjection: true });
  } catch (err) {
    try { await db.query('ROLLBACK'); } catch { /* ignore */ }
    await cleanupTemp();
    throw err;
  }
}

/**
 * Produce valid EMPTY artifacts (0 items) without opening a cursor — used when the feed's
 * effective population is empty (e.g. all configured source keys are stale).
 */
export async function generateEmptyFeedArtifact(feed, opts = {}) {
  const cfg = opts.cfg || getPublishedFeedArtifactConfig();
  const formats = opts.formats
    ? resolvePublishedFeedFormats({ formats: opts.formats })
    : resolvePublishedFeedFormats(feed);
  const flags = resolveJsonIncludeFlags(feed);
  const generationId = newGenerationId();
  const { slots, cleanupTemp } = await openMultiFormatWriters(cfg, feed, generationId, formats);
  try {
    const finalized = await finalizeMultiFormatWriters(feed, generationId, slots);
    // Empty JSON still needs header/footer from finish()+finalize; finalizeMultiFormatWriters
    // already handles that. Ensure flags are applied via writer ctor above.
    void flags;
    return wrapArtifactResult(finalized, {
      pageCount: 0,
      scannedRows: 0,
      timings: { base_open_ms: 0, fetch_ms: 0, meta_ms: 0, write_ms: 0 }
    });
  } catch (err) {
    await cleanupTemp();
    throw err;
  }
}

/** Stream one file's bytes into an already-open Writable, honoring backpressure. */
function pipeFileInto(srcPath, destStream) {
  return new Promise((resolve, reject) => {
    const rs = fs.createReadStream(srcPath);
    rs.on('error', reject);
    rs.on('end', resolve);
    rs.on('data', (chunk) => {
      if (!destStream.write(chunk)) {
        rs.pause();
        destStream.once('drain', () => rs.resume());
      }
    });
  });
}

export { resolveArtifactPath };
