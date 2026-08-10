import { buildExportQuery, enrichExportBatch } from './exportRows.js';
import { headerRow, formatRecord } from './columns.js';
import { csvRow } from './csv.js';

// Core streaming export loop, factored out of the worker so it can be unit-tested
// deterministically.
//
// The full export query is built ONCE and executed through a NO SCROLL server-side
// PostgreSQL cursor. We FETCH one page at a time, enrich each page (tags, classifications,
// source timestamps) and write CSV rows to `sink` (any Writable: a gzip stream or a file
// stream). Memory stays roughly constant regardless of result size — the whole result set
// is never buffered in Node, and Postgres computes any aggregate/sort a single time (a
// cursor-driven query is not parallelized, so no large dynamic-shared-memory segment is
// allocated for it).
//
// Returns { status: 'completed'|'cancelled'|'hard_limit', recordCount }.
// The caller owns the sink lifecycle (end/close), the file, and status/audit updates.
//
// `db` must be a pg Pool (or anything exposing connect() -> client with query()/release()).
const CURSOR_NAME = 'ioc_export_cur';

export async function streamExportToSink({
  db,
  whereSql,
  dslParams,
  cutoff,
  columns,
  scope,
  batchSize,
  hardLimit,
  previewLimit,
  sink,
  isCancelled = async () => false,
  onProgress = async () => {},
  progressEvery = 10000,
  timeZone = null
}) {
  const write = (chunk) =>
    new Promise((resolve, reject) => {
      sink.write(chunk, (err) => (err ? reject(err) : resolve()));
    });

  const isPreview = scope === 'preview';
  // preview stops exactly at previewLimit; "all" reads up to hardLimit+1 so the
  // (hardLimit+1)th row is observed and the export can abort before producing a file.
  const cap = isPreview ? previewLimit : hardLimit + 1;

  let tz = timeZone;
  if (!tz) {
    try {
      const { requireSystemTimezone } = await import('../systemTime.js');
      tz = await requireSystemTimezone(db);
    } catch {
      tz = process.env.SYSTEM_TIMEZONE || process.env.TZ || 'UTC';
    }
  }

  const { sql, params } = buildExportQuery({ whereSql, dslParams, cutoff });

  const client = await db.connect();
  let recordCount = 0;
  let lastProgressAt = 0;
  let declared = false;
  try {
    // READ ONLY transaction: a single stable snapshot for the whole export, and the cursor
    // is dropped automatically on ROLLBACK. Nothing is written, so ROLLBACK loses no work.
    await client.query('BEGIN READ ONLY');
    await client.query(`DECLARE ${CURSOR_NAME} NO SCROLL CURSOR FOR ${sql}`, params);
    declared = true;

    await write(`${csvRow(headerRow(columns, tz))}\n`);

    for (;;) {
      if (await isCancelled()) return { status: 'cancelled', recordCount };

      const budget = cap - recordCount;
      if (budget <= 0) break;

      const fetchSize = Math.min(batchSize, budget);
      const baseRes = await client.query(`FETCH FORWARD ${Math.trunc(fetchSize)} FROM ${CURSOR_NAME}`);
      const baseRows = baseRes.rows;
      if (baseRows.length === 0) break;

      if (!isPreview && recordCount + baseRows.length > hardLimit) {
        return { status: 'hard_limit', recordCount };
      }

      const enriched = await enrichExportBatch(client, baseRows);
      let chunk = '';
      for (const rec of enriched) chunk += `${csvRow(formatRecord(rec, columns, tz))}\n`;
      await write(chunk);

      recordCount += baseRows.length;

      if (recordCount - lastProgressAt >= progressEvery) {
        lastProgressAt = recordCount;
        await onProgress(recordCount);
      }

      if (baseRows.length < fetchSize) break; // data exhausted
    }

    return { status: 'completed', recordCount };
  } finally {
    // Best-effort teardown: drop the cursor and end the read-only transaction, then always
    // return the client to the pool — on success, cancellation, hard-limit, or error.
    try {
      if (declared) await client.query(`CLOSE ${CURSOR_NAME}`);
    } catch { /* ignore — ROLLBACK also drops it */ }
    try {
      await client.query('ROLLBACK');
    } catch { /* ignore */ }
    client.release();
  }
}
