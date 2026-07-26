import { buildExportBatchQuery, enrichExportBatch } from './exportRows.js';
import { headerRow, formatRecord } from './columns.js';
import { csvRow } from './csv.js';

// Core streaming export loop, factored out of the worker so it can be unit-tested
// deterministically. Reads keyset batches from `db`, enriches each batch (tags,
// classifications, source timestamps) and writes CSV rows to `sink` (any Writable:
// a gzip stream or a file stream). Never buffers the whole result set.
//
// Returns { status: 'completed'|'cancelled'|'hard_limit', recordCount }.
// The caller owns the sink lifecycle (end/close), the file, and status/audit updates.
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
  // Using hardLimit+1 as the read cap (rather than a per-batch +1) guarantees overflow
  // is detected even when hardLimit is an exact multiple of batchSize.
  const cap = isPreview ? previewLimit : hardLimit + 1;
  let recordCount = 0;
  let cursor = null;
  let lastProgressAt = 0;

  let tz = timeZone;
  if (!tz) {
    try {
      const { requireSystemTimezone } = await import('../systemTime.js');
      tz = await requireSystemTimezone(db);
    } catch {
      tz = process.env.SYSTEM_TIMEZONE || process.env.TZ || 'UTC';
    }
  }

  await write(`${csvRow(headerRow(columns, tz))}\n`);

  for (;;) {
    if (await isCancelled()) return { status: 'cancelled', recordCount };

    const budget = cap - recordCount;
    if (budget <= 0) break;

    const fetchSize = Math.min(batchSize, budget);
    const { sql, params } = buildExportBatchQuery({ whereSql, dslParams, cutoff, cursor, batchSize: fetchSize });
    const baseRes = await db.query(sql, params);
    const baseRows = baseRes.rows;
    if (baseRows.length === 0) break;

    if (!isPreview && recordCount + baseRows.length > hardLimit) {
      return { status: 'hard_limit', recordCount };
    }

    const enriched = await enrichExportBatch(db, baseRows);
    let chunk = '';
    for (const rec of enriched) chunk += `${csvRow(formatRecord(rec, columns, tz))}\n`;
    await write(chunk);

    recordCount += baseRows.length;
    const lastBase = baseRows[baseRows.length - 1];
    cursor = { t: new Date(lastBase.created_at).toISOString(), id: String(lastBase.id) };

    if (recordCount - lastProgressAt >= progressEvery) {
      lastProgressAt = recordCount;
      await onProgress(recordCount);
    }

    if (baseRows.length < fetchSize) break; // data exhausted
  }

  return { status: 'completed', recordCount };
}
