import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { registerPublicFeedRoutes } from './publicFeeds.js';
import { hashApiKey, generatePublishedFeedApiKey } from '../lib/publishedFeedApiKey.js';
import { computeResponseEtag } from '../lib/feedFormatter.js';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pfserve-'));
process.env.PUBLISHED_FEED_STORAGE_DIR = dir;

const FEED = { id: 5, slug: 'json-feed', enabled: true, ioc_types: ['ip'], time_window: 'all', max_items: null, formats: ['json'] };
const BODY = '{"schema_version":"1.0","feed":{"name":"J","generated_at":"2026-08-01T12:00:00.000Z","item_count":1},"items":[{"type":"ip","value":"9.9.9.9","timestamps":{}}]}\n';
const GEN = 'gen1';
const STORAGE_PATH = `${FEED.id}/${GEN}.json`;

function writeArtifact() {
  const p = path.join(dir, String(FEED.id));
  fs.mkdirSync(p, { recursive: true });
  fs.writeFileSync(path.join(p, `${GEN}.json`), BODY);
}
function removeArtifact() { fs.rmSync(path.join(dir, String(FEED.id)), { recursive: true, force: true }); }

function mockPool() {
  return {
    async query(sql, params = []) {
      const s = String(sql);
      if (s.includes('FROM published_feed_access_keys') && s.includes('key_type = $2')) {
        return { rows: [{ id: 1, token_hash: params[0], key_type: 'published_feed', enabled: true, revoked_at: null, deleted_at: null, expires_at: null }], rowCount: 1 };
      }
      if (s.includes('FROM published_feeds WHERE slug = $1')) {
        return { rows: [FEED], rowCount: 1 };
      }
      if (s.includes('octet_length(content)')) { // getLatestSnapshotMeta
        return { rows: [{ id: 50, content_hash: 'jh', item_count: 1, generated_at: new Date('2026-08-01T12:00:00Z').toISOString(), params: { ioc_type: 'ip', window: 'all' }, storage_path: STORAGE_PATH, artifact_format: 'json', content_bytes: BODY.length }], rowCount: 1 };
      }
      if (s.includes('storage_path IS NOT NULL')) { // getSnapshotArtifactByIdAndHash
        return { rows: [{ id: 50, storage_path: STORAGE_PATH, file_size: BODY.length, artifact_format: 'json', content_hash: 'jh', generated_at: new Date('2026-08-01T12:00:00Z').toISOString() }], rowCount: 1 };
      }
      if (s.includes('UPDATE published_feed_access_keys')) return { rows: [], rowCount: 1 };
      return { rows: [], rowCount: 0 };
    }
  };
}

function makeApp() {
  const app = express();
  registerPublicFeedRoutes(app, mockPool());
  return app;
}
async function get(app, p, headers = {}) {
  const { createServer } = await import('node:http');
  const server = createServer(app);
  await new Promise((r) => server.listen(0, r));
  const { port } = server.address();
  try {
    const res = await fetch(`http://127.0.0.1:${port}${p}`, { headers });
    return { status: res.status, text: await res.text(), contentType: res.headers.get('content-type'), contentLength: res.headers.get('content-length'), etag: res.headers.get('etag') };
  } finally { server.close(); }
}

test('file-backed JSON snapshot streams with application/json + Content-Length', async () => {
  writeArtifact();
  const raw = generatePublishedFeedApiKey();
  const res = await get(makeApp(), `/api/published-feeds/json-feed?api_key=${raw}`);
  assert.equal(res.status, 200);
  assert.match(res.contentType, /application\/json/);
  assert.equal(res.contentLength, String(BODY.length));
  assert.equal(res.text, BODY);
  assert.equal(JSON.parse(res.text).schema_version, '1.0');
  removeArtifact();
});

test('file-backed snapshot honors If-None-Match → 304 without reading the file', async () => {
  writeArtifact();
  const raw = generatePublishedFeedApiKey();
  const etag = computeResponseEtag('jh', 'ip', 'all', 'all');
  const res = await get(makeApp(), `/api/published-feeds/json-feed?api_key=${raw}`, { 'if-none-match': etag });
  assert.equal(res.status, 304);
  removeArtifact(); // 304 path must not have depended on the file
});

test('missing artifact file fails safely (503, not a crash)', async () => {
  removeArtifact(); // ensure the file is absent
  const raw = generatePublishedFeedApiKey();
  const res = await get(makeApp(), `/api/published-feeds/json-feed?api_key=${raw}`);
  assert.equal(res.status, 503);
});
