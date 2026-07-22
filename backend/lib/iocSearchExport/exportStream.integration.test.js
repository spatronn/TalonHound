import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { streamExportToSink } from './exportStream.js';
import { DEFAULT_EXPORT_COLUMNS } from './columns.js';

// Synthetic dataset ordered by (created_at DESC, id DESC), mirroring the keyset order.
// A few rows carry adversarial values to exercise CSV escaping and formula-injection.
function makeRows(n) {
  const rows = [];
  for (let id = n; id >= 1; id -= 1) {
    let observable = `evil-${id}.example.com`;
    if (id === 1) observable = '=1+2';                 // formula injection (leading =)
    if (id === 2) observable = 'a,b"c';                // comma + quote (no newline here)
    if (id === 3) observable = 'ünïcode-çğışö.example'; // unicode
    rows.push({
      id,
      observable,
      observable_type: 'domain',
      status: 'active',
      source_name: id === 4 ? '+SUM(evil)' : 'USOM',   // leading + formula injection
      confidence: 'high',
      first_seen_at: new Date(1_700_000_000_000 + id).toISOString(),
      created_at: new Date(1_700_000_000_000 + id).toISOString()
    });
  }
  return rows; // already id-descending
}

// Mock pg client. Counts calls per query type so we can prove there is no N+1.
function makeDb(rows) {
  const calls = { base: 0, tags: 0, classifications: 0, memberships: 0 };
  return {
    calls,
    async query(sql, params = []) {
      const s = String(sql);
      if (s.includes('FROM ioc_tags')) {
        calls.tags += 1;
        const ids = params[0];
        return { rows: ids.map((id) => ({ ioc_id: id, names: [`tag-${id}`, 'malware'] })) };
      }
      if (s.includes('FROM ioc_threat_classifications')) {
        calls.classifications += 1;
        const ids = params[0];
        return { rows: ids.map((id) => ({ ioc_id: id, names: ['phishing'] })) };
      }
      if (s.includes('FROM ioc_feed_memberships')) {
        calls.memberships += 1;
        const ids = params[0];
        return { rows: ids.map((id) => ({ ioc_item_id: id, first_seen_in_source: '2026-01-01T00:00:00.000Z', last_changed_in_source: '2026-02-01T00:00:00.000Z' })) };
      }
      // base batch query: params = [cutoff, (cursorT, cursorId)?, limit]
      calls.base += 1;
      const limit = Number(params[params.length - 1]);
      const hasCursor = params.length === 4;
      const startAfterId = hasCursor ? Number(params[2]) : null;
      let start = 0;
      if (startAfterId != null) {
        start = rows.findIndex((r) => r.id < startAfterId);
        if (start === -1) return { rows: [] };
      }
      return { rows: rows.slice(start, start + limit) };
    }
  };
}

function gzipSinkTo(filePath) {
  const fileStream = fs.createWriteStream(filePath);
  const gz = zlib.createGzip();
  gz.pipe(fileStream);
  const finished = new Promise((resolve, reject) => {
    fileStream.on('finish', resolve);
    fileStream.on('error', reject);
    gz.on('error', reject);
  });
  return { sink: gz, finished };
}

test('20,000-record gzip export: correctness, escaping, no N+1', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ioc-export-'));
  const filePath = path.join(dir, 'out.csv.gz');
  const rows = makeRows(20000);
  const db = makeDb(rows);
  const { sink, finished } = gzipSinkTo(filePath);

  const result = await streamExportToSink({
    db,
    whereSql: 'TRUE',
    dslParams: [],
    cutoff: '2026-07-22T00:00:00.000Z',
    columns: [...DEFAULT_EXPORT_COLUMNS],
    scope: 'all',
    batchSize: 5000,
    hardLimit: 2_000_000,
    previewLimit: 2000,
    sink,
    progressEvery: 5000
  });

  await new Promise((resolve, reject) => { sink.end((err) => (err ? reject(err) : resolve())); });
  await finished;

  assert.equal(result.status, 'completed');
  assert.equal(result.recordCount, 20000);

  // No N+1: one base query per batch (4 full + 1 short-circuit at most) and exactly one
  // of each enrichment query per non-empty batch (4).
  assert.ok(db.calls.base <= 5, `base queries=${db.calls.base}`);
  assert.equal(db.calls.tags, 4);
  assert.equal(db.calls.classifications, 4);
  assert.equal(db.calls.memberships, 4);

  // gzip must open, and the content must be intact.
  const buf = zlib.gunzipSync(fs.readFileSync(filePath));
  const text = buf.toString('utf8');
  const lines = text.split('\n');
  // header + 20000 rows + trailing empty from final newline
  assert.equal(lines[lines.length - 1], '');
  const dataLines = lines.slice(1, -1);
  assert.equal(dataLines.length, 20000, `data rows=${dataLines.length}`);

  // Header uses analyst-facing labels; no "Last seen" column.
  assert.match(lines[0], /^IOC,IOC Type,Status,Source,Confidence,Tags,Classifications,First seen in source,Last changed in source$/);
  assert.doesNotMatch(lines[0], /Last seen/);

  // Formula-injection neutralized (leading = and + prefixed with a quote).
  assert.ok(text.includes("'=1+2"), 'formula = neutralized');
  assert.ok(text.includes("'+SUM(evil)"), 'formula + neutralized');
  assert.ok(!/^=1\+2,/m.test(text), 'no raw formula cell at line start');

  // Comma/quote correctly RFC-4180 quoted.
  assert.ok(text.includes('"a,b""c"'), 'comma/quote quoted');

  // Unicode preserved.
  assert.ok(text.includes('ünïcode-çğışö.example'), 'unicode preserved');

  // No duplicate IOC values across the whole export.
  const iocValues = dataLines.map((l) => l.split(',')[0]);
  // Exclude the intentionally multiline/quoted row from the naive split check.
  const simple = iocValues.filter((v) => v && !v.startsWith('"'));
  assert.equal(new Set(simple).size, simple.length, 'no duplicate IOC values');

  fs.rmSync(dir, { recursive: true, force: true });
});

test('embedded newline in a value is RFC-4180 quoted (single logical record)', async () => {
  const rows = [{
    id: 1, observable: 'a,b"c\nd', observable_type: 'domain', status: 'active',
    source_name: 'USOM', confidence: 'high',
    first_seen_at: '2026-01-01T00:00:00.000Z', created_at: '2026-01-01T00:00:00.000Z'
  }];
  const db = makeDb(rows);
  const chunks = [];
  const sink = { write: (c, cb) => { chunks.push(c); cb(); } };
  const result = await streamExportToSink({
    db, whereSql: 'TRUE', dslParams: [], cutoff: 'x', columns: ['ioc'],
    scope: 'all', batchSize: 100, hardLimit: 100, previewLimit: 100, sink
  });
  assert.equal(result.recordCount, 1);
  const out = chunks.join('');
  assert.ok(out.includes('"a,b""c\nd"'), 'embedded comma/quote/newline quoted');
});

test('preview scope caps at the preview limit', async () => {
  const rows = makeRows(20000);
  const db = makeDb(rows);
  const chunks = [];
  const sink = { write: (c, cb) => { chunks.push(c); cb(); } };
  const result = await streamExportToSink({
    db, whereSql: 'TRUE', dslParams: [], cutoff: 'x', columns: ['ioc'],
    scope: 'preview', batchSize: 5000, hardLimit: 2_000_000, previewLimit: 2000, sink
  });
  assert.equal(result.status, 'completed');
  assert.equal(result.recordCount, 2000);
});

test('hard-limit overflow stops before writing the overflow batch', async () => {
  const rows = makeRows(25);
  const db = makeDb(rows);
  const chunks = [];
  const sink = { write: (c, cb) => { chunks.push(c); cb(); } };
  const result = await streamExportToSink({
    db, whereSql: 'TRUE', dslParams: [], cutoff: 'x', columns: ['ioc'],
    scope: 'all', batchSize: 10, hardLimit: 10, previewLimit: 2000, sink
  });
  assert.equal(result.status, 'hard_limit');
  assert.ok(result.recordCount <= 10);
});

test('cancellation between batches stops the stream', async () => {
  const rows = makeRows(20000);
  const db = makeDb(rows);
  const chunks = [];
  const sink = { write: (c, cb) => { chunks.push(c); cb(); } };
  let calls = 0;
  const result = await streamExportToSink({
    db, whereSql: 'TRUE', dslParams: [], cutoff: 'x', columns: ['ioc'],
    scope: 'all', batchSize: 5000, hardLimit: 2_000_000, previewLimit: 2000, sink,
    isCancelled: async () => { calls += 1; return calls > 1; } // cancel after first batch
  });
  assert.equal(result.status, 'cancelled');
  assert.ok(result.recordCount <= 5000);
});
