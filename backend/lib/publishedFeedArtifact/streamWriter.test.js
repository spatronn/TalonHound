import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { StreamingTxtWriter, StreamingJsonBodyWriter } from './streamWriter.js';
import { buildPlainTextFeed } from '../feedFormatter.js';
import { JsonFeedWriter } from '../publishedFeedJson.js';

function sink() {
  const s = new PassThrough();
  const chunks = [];
  s.on('data', (c) => chunks.push(c));
  return { s, text: () => Buffer.concat(chunks).toString('utf8') };
}

describe('StreamingTxtWriter — byte + hash parity with buildPlainTextFeed', () => {
  it('matches content bytes and content_hash for the same ordered values', async () => {
    const rows = [
      { observable: '1.1.1.1', observable_type: 'ip', confidence: 'high', recency_ts: '2026-08-09T00:00:00Z' },
      { observable: '2.2.2.2', observable_type: 'ip', confidence: 'low', recency_ts: '2026-08-08T00:00:00Z' }
    ];
    const inMem = buildPlainTextFeed(rows, ['ip'], null); // recency-sorted values
    const { s, text } = sink();
    const w = new StreamingTxtWriter(s);
    for (const line of inMem.lines) await w.addValue(line);
    const res = w.finish();
    assert.equal(text(), inMem.content);
    assert.equal(res.content_hash, inMem.content_hash);
    assert.equal(res.item_count, inMem.item_count);
  });

  it('empty feed → empty bytes, hash of ""', () => {
    const inMem = buildPlainTextFeed([], ['ip'], null);
    const { s } = sink();
    const w = new StreamingTxtWriter(s);
    const res = w.finish();
    assert.equal(res.item_count, 0);
    assert.equal(res.content_hash, inMem.content_hash);
  });
});

describe('StreamingJsonBodyWriter — hash parity with JsonFeedWriter', () => {
  const meta = { name: 'Feed', includeSourceMetadata: true, includeClassification: true, includeEnrichment: false };
  const items = [
    { type: 'domain', value: 'a.com', timestamps: {} },
    { type: 'domain', value: 'b.com', timestamps: {}, classification: { tags: ['c2'] } }
  ];

  it('logical content_hash equals JsonFeedWriter for identical items/flags', async () => {
    const inMem = new JsonFeedWriter(meta);
    for (const it of items) inMem.addItem(it);
    const memRes = inMem.finish({ generatedAt: '2026-08-09T00:00:00Z' });

    const { s } = sink();
    const w = new StreamingJsonBodyWriter(s, meta);
    for (const it of items) await w.addItem(it);
    const res = w.finish();
    assert.equal(res.content_hash, memRes.content_hash);
    assert.equal(res.item_count, memRes.item_count);
  });

  it('assembled header+body+footer parses and item_count is exact', async () => {
    const { s, text } = sink();
    const w = new StreamingJsonBodyWriter(s, meta);
    for (const it of items) await w.addItem(it);
    const res = w.finish();
    const full = `${w.buildHeader(res.item_count, '2026-08-09T12:00:00Z')}${text()}${w.buildFooter()}`;
    const parsed = JSON.parse(full);
    assert.equal(parsed.schema_version, '1.0');
    assert.equal(parsed.feed.item_count, 2);
    assert.equal(parsed.items.length, 2);
    assert.equal(parsed.items[0].value, 'a.com');
  });

  it('empty JSON body → valid []', async () => {
    const { s, text } = sink();
    const w = new StreamingJsonBodyWriter(s, meta);
    const res = w.finish();
    const full = `${w.buildHeader(0, '2026-08-09T12:00:00Z')}${text()}${w.buildFooter()}`;
    const parsed = JSON.parse(full);
    assert.deepEqual(parsed.items, []);
    assert.equal(res.item_count, 0);
  });
});
