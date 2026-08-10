import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { streamExportToSink } from './exportStream.js';
import { DEFAULT_EXPORT_COLUMNS } from './columns.js';

// Synthetic dataset ordered by (created_at DESC, id DESC), mirroring the cursor order.
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

// Mock pg Pool. connect() hands out a client backed by a NO SCROLL cursor over `rows`.
// `fetchFailAt` (1-based) makes the Nth FETCH throw, to exercise mid-stream failure.
function makeDb(rows, { fetchFailAt = 0 } = {}) {
  const calls = { base: 0, tags: 0, classifications: 0, memberships: 0, actors: 0 };
  const state = { connects: 0, released: 0, rolledBack: 0, closed: 0 };

  function makeClient() {
    let pos = 0;        // cursor position into rows
    let fetches = 0;
    return {
      async query(sql, params = []) {
        const s = String(sql);
        if (/^BEGIN/i.test(s)) return { rows: [] };
        if (/^DECLARE /i.test(s)) { pos = 0; return { rows: [] }; }
        if (/^CLOSE /i.test(s)) { state.closed += 1; return { rows: [] }; }
        if (/^ROLLBACK/i.test(s) || /^COMMIT/i.test(s)) { state.rolledBack += 1; return { rows: [] }; }
        if (/^FETCH FORWARD/i.test(s)) {
          fetches += 1;
          if (fetchFailAt && fetches === fetchFailAt) throw new Error('simulated mid-stream DB failure');
          calls.base += 1;
          const m = s.match(/FETCH FORWARD (\d+)/i);
          const n = m ? Number(m[1]) : 0;
          const slice = rows.slice(pos, pos + n);
          pos += slice.length;
          return { rows: slice };
        }
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
        if (s.includes('FROM ioc_threat_actors')) {
          calls.actors += 1;
          return { rows: [] };
        }
        if (s.includes('FROM ioc_feed_memberships')) {
          calls.memberships += 1;
          const ids = params[0];
          return { rows: ids.map((id) => ({ ioc_item_id: id, first_seen_in_source: '2026-01-01T00:00:00.000Z', last_changed_in_source: '2026-02-01T00:00:00.000Z' })) };
        }
        return { rows: [] };
      },
      release() { state.released += 1; }
    };
  }

  return {
    calls,
    state,
    async connect() { state.connects += 1; return makeClient(); }
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

test('20,000-record gzip export: correctness, escaping, no N+1, resources released', async () => {
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
    progressEvery: 5000,
    timeZone: 'UTC'
  });

  await new Promise((resolve, reject) => { sink.end((err) => (err ? reject(err) : resolve())); });
  await finished;

  assert.equal(result.status, 'completed');
  assert.equal(result.recordCount, 20000);

  // Cursor drained in bounded pages: one FETCH per page (4 full + 1 empty), exactly one of
  // each enrichment query per non-empty page (4). Never a per-row (N+1) query.
  assert.ok(db.calls.base <= 5, `fetch calls=${db.calls.base}`);
  assert.equal(db.calls.tags, 4);
  assert.equal(db.calls.classifications, 4);
  assert.equal(db.calls.memberships, 4);

  // Exactly one pooled client, and it was returned to the pool.
  assert.equal(db.state.connects, 1);
  assert.equal(db.state.released, 1);
  assert.ok(db.state.rolledBack >= 1, 'read-only txn rolled back');

  // gzip must open, and the content must be intact.
  const buf = zlib.gunzipSync(fs.readFileSync(filePath));
  const text = buf.toString('utf8');
  const lines = text.split('\n');
  assert.equal(lines[lines.length - 1], '');
  const dataLines = lines.slice(1, -1);
  assert.equal(dataLines.length, 20000, `data rows=${dataLines.length}`);

  assert.match(lines[0], /^IOC,IOC Type,Status,Source,Confidence,Tags,Classifications,First seen in source \(UTC\),Last changed in source \(UTC\)$/);
  assert.doesNotMatch(lines[0], /Last seen,/);

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
  const simple = iocValues.filter((v) => v && !v.startsWith('"'));
  assert.equal(new Set(simple).size, simple.length, 'no duplicate IOC values');

  fs.rmSync(dir, { recursive: true, force: true });
});

test('export spans multiple pages and preserves total/order/content', async () => {
  const rows = makeRows(12); // batchSize 5 -> pages of 5,5,2
  const db = makeDb(rows);
  const chunks = [];
  const sink = { write: (c, cb) => { chunks.push(c); cb(); } };
  const result = await streamExportToSink({
    db, whereSql: 'TRUE', dslParams: [], cutoff: 'x', columns: ['ioc'],
    scope: 'all', batchSize: 5, hardLimit: 2_000_000, previewLimit: 2000, sink, timeZone: 'UTC'
  });
  assert.equal(result.status, 'completed');
  assert.equal(result.recordCount, 12);
  assert.equal(db.calls.base, 3, 'three fetch pages (5+5+2)');
  const lines = chunks.join('').split('\n').slice(1).filter(Boolean);
  assert.equal(lines.length, 12);
  // Order preserved: ids 12..1 descending (observable evil-<id>.example.com for id>=5).
  assert.match(lines[0], /evil-12\.example\.com/);
  assert.match(lines[7], /evil-5\.example\.com/);
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
    scope: 'all', batchSize: 100, hardLimit: 100, previewLimit: 100, sink, timeZone: 'UTC'
  });
  assert.equal(result.recordCount, 1);
  const out = chunks.join('');
  assert.ok(out.includes('"a,b""c\nd"'), 'embedded comma/quote/newline quoted');
  assert.equal(db.state.released, 1);
});

test('preview scope caps at the preview limit', async () => {
  const rows = makeRows(20000);
  const db = makeDb(rows);
  const chunks = [];
  const sink = { write: (c, cb) => { chunks.push(c); cb(); } };
  const result = await streamExportToSink({
    db, whereSql: 'TRUE', dslParams: [], cutoff: 'x', columns: ['ioc'],
    scope: 'preview', batchSize: 5000, hardLimit: 2_000_000, previewLimit: 2000, sink, timeZone: 'UTC'
  });
  assert.equal(result.status, 'completed');
  assert.equal(result.recordCount, 2000);
  assert.equal(db.state.released, 1);
});

test('hard-limit overflow stops before writing the overflow batch', async () => {
  const rows = makeRows(25);
  const db = makeDb(rows);
  const chunks = [];
  const sink = { write: (c, cb) => { chunks.push(c); cb(); } };
  const result = await streamExportToSink({
    db, whereSql: 'TRUE', dslParams: [], cutoff: 'x', columns: ['ioc'],
    scope: 'all', batchSize: 10, hardLimit: 10, previewLimit: 2000, sink, timeZone: 'UTC'
  });
  assert.equal(result.status, 'hard_limit');
  assert.ok(result.recordCount <= 10);
  assert.equal(db.state.released, 1);
});

test('cancellation between batches stops the stream and releases the client', async () => {
  const rows = makeRows(20000);
  const db = makeDb(rows);
  const chunks = [];
  const sink = { write: (c, cb) => { chunks.push(c); cb(); } };
  let calls = 0;
  const result = await streamExportToSink({
    db, whereSql: 'TRUE', dslParams: [], cutoff: 'x', columns: ['ioc'],
    scope: 'all', batchSize: 5000, hardLimit: 2_000_000, previewLimit: 2000, sink,
    isCancelled: async () => { calls += 1; return calls > 1; }, // cancel after first batch
    timeZone: 'UTC'
  });
  assert.equal(result.status, 'cancelled');
  assert.ok(result.recordCount <= 5000);
  assert.equal(db.state.released, 1);
});

test('mid-stream DB failure propagates and still releases the client', async () => {
  const rows = makeRows(20000);
  const db = makeDb(rows, { fetchFailAt: 2 }); // second FETCH throws
  const chunks = [];
  const sink = { write: (c, cb) => { chunks.push(c); cb(); } };
  await assert.rejects(
    () => streamExportToSink({
      db, whereSql: 'TRUE', dslParams: [], cutoff: 'x', columns: ['ioc'],
      scope: 'all', batchSize: 5000, hardLimit: 2_000_000, previewLimit: 2000, sink, timeZone: 'UTC'
    }),
    /simulated mid-stream DB failure/
  );
  assert.equal(db.state.released, 1, 'client released on failure');
  assert.ok(db.state.rolledBack >= 1, 'transaction rolled back on failure');
});

test('file-write failure propagates and still releases the client', async () => {
  const rows = makeRows(100);
  const db = makeDb(rows);
  let writes = 0;
  const sink = {
    write: (c, cb) => {
      writes += 1;
      if (writes === 2) return cb(new Error('disk write failed')); // fail on first data page
      return cb();
    }
  };
  await assert.rejects(
    () => streamExportToSink({
      db, whereSql: 'TRUE', dslParams: [], cutoff: 'x', columns: ['ioc'],
      scope: 'all', batchSize: 50, hardLimit: 2_000_000, previewLimit: 2000, sink, timeZone: 'UTC'
    }),
    /disk write failed/
  );
  assert.equal(db.state.released, 1, 'client released on write failure');
});
