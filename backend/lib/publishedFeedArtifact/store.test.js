import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  resolveArtifactPath, resolveStoredArtifactPath, resolveFeedDir, toRelativeStoragePath,
  newGenerationId, openArtifactPartStream, finalizeStream, commitArtifact,
  reconcileStaleParts, cleanupSupersededArtifacts, removeFeedArtifacts, statArtifact
} from './store.js';

let dir;
const cfg = () => ({ storageDir: dir, supersededRetentionMinutes: 60, stalePartMinutes: 30 });

before(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pfstore-')); });
after(() => { fs.rmSync(dir, { recursive: true, force: true }); });

describe('publishedFeedArtifact store — path safety', () => {
  it('rejects traversal in generation id', () => {
    assert.throws(() => resolveArtifactPath(dir, 5, '../../etc/passwd', 'json'), /Invalid generation id/);
  });
  it('rejects traversal in stored path', () => {
    assert.throws(() => resolveStoredArtifactPath(dir, '../../../etc/passwd'), /escapes storage directory/);
  });
  it('rejects invalid feed id', () => {
    assert.throws(() => resolveFeedDir(dir, 0), /Invalid feed id/);
    assert.throws(() => resolveFeedDir(dir, -1), /Invalid feed id/);
  });
  it('resolves a normal artifact under the feed dir', () => {
    const gen = newGenerationId();
    const p = resolveArtifactPath(dir, 7, gen, 'json');
    assert.ok(p.startsWith(path.resolve(dir, '7') + path.sep));
    assert.ok(p.endsWith('.json'));
    assert.equal(toRelativeStoragePath(7, gen, 'json'), `7/${gen}.json`);
    assert.equal(toRelativeStoragePath(7, gen, 'txt'), `7/${gen}.txt`);
    assert.ok(resolveArtifactPath(dir, 7, gen, 'stix').endsWith('.stix'));
    assert.equal(toRelativeStoragePath(7, gen, 'stix'), `7/${gen}.stix`);
  });
});

describe('publishedFeedArtifact store — write + publish + cleanup', () => {
  it('writes a .part then atomically publishes; .part gone, final present', async () => {
    const gen = newGenerationId();
    const { stream, finalPath, partPath } = await openArtifactPartStream(cfg(), 9, gen, 'txt');
    stream.write('1.1.1.1\n');
    await finalizeStream(stream);
    assert.ok(fs.existsSync(partPath));
    assert.ok(!fs.existsSync(finalPath));
    await commitArtifact(partPath, finalPath);
    assert.ok(!fs.existsSync(partPath));
    assert.equal(fs.readFileSync(finalPath, 'utf8'), '1.1.1.1\n');
  });

  it('reconcileStaleParts removes old .part files but keeps published + fresh parts', async () => {
    const feedDir = resolveFeedDir(cfg().storageDir, 11);
    fs.mkdirSync(feedDir, { recursive: true });
    const stale = path.join(feedDir, 'old.json.part');
    const fresh = path.join(feedDir, 'new.json.part');
    const published = path.join(feedDir, 'g1.json');
    fs.writeFileSync(stale, 'x'); fs.writeFileSync(fresh, 'x'); fs.writeFileSync(published, 'x');
    const past = Date.now() / 1000 - 3600; // 1h ago
    fs.utimesSync(stale, past, past);
    const removed = await reconcileStaleParts(cfg());
    assert.ok(removed >= 1);
    assert.ok(!fs.existsSync(stale));
    assert.ok(fs.existsSync(fresh));      // recent .part kept
    assert.ok(fs.existsSync(published));  // published never touched
  });

  it('cleanupSupersededArtifacts removes old non-current files, keeps current', async () => {
    const feedDir = resolveFeedDir(cfg().storageDir, 12);
    fs.mkdirSync(feedDir, { recursive: true });
    const current = path.join(feedDir, 'cur.json');
    const old = path.join(feedDir, 'old.json');
    fs.writeFileSync(current, 'x'); fs.writeFileSync(old, 'x');
    const past = Date.now() / 1000 - 7200;
    fs.utimesSync(old, past, past);
    const removed = await cleanupSupersededArtifacts(cfg(), 12, '12/cur.json');
    assert.equal(removed, 1);
    assert.ok(fs.existsSync(current));
    assert.ok(!fs.existsSync(old));
  });

  it('cleanupSupersededArtifacts keeps every referenced format/window file', async () => {
    const feedDir = resolveFeedDir(cfg().storageDir, 14);
    fs.mkdirSync(feedDir, { recursive: true });
    const txt = path.join(feedDir, 'a.txt');
    const json = path.join(feedDir, 'b.json');
    const old = path.join(feedDir, 'c.stix');
    fs.writeFileSync(txt, 't');
    fs.writeFileSync(json, 'j');
    fs.writeFileSync(old, 's');
    const past = Date.now() / 1000 - 7200;
    fs.utimesSync(old, past, past);
    const removed = await cleanupSupersededArtifacts(cfg(), 14, ['14/a.txt', '14/b.json']);
    assert.equal(removed, 1);
    assert.ok(fs.existsSync(txt));
    assert.ok(fs.existsSync(json));
    assert.ok(!fs.existsSync(old));
  });

  it('cleanupSupersededArtifacts removes zero-byte abandoned finals immediately', async () => {
    const feedDir = resolveFeedDir(cfg().storageDir, 15);
    fs.mkdirSync(feedDir, { recursive: true });
    const current = path.join(feedDir, 'cur.json');
    const empty = path.join(feedDir, 'failed.txt');
    fs.writeFileSync(current, 'x');
    fs.writeFileSync(empty, '');
    const removed = await cleanupSupersededArtifacts(cfg(), 15, '15/cur.json');
    assert.equal(removed, 1);
    assert.ok(fs.existsSync(current));
    assert.ok(!fs.existsSync(empty));
  });

  it('cleanupSupersededArtifacts never deletes in-flight .body temps (hash ENOENT guard)', async () => {
    const feedDir = resolveFeedDir(cfg().storageDir, 25);
    fs.mkdirSync(feedDir, { recursive: true });
    const current = path.join(feedDir, 'cur.json');
    const body = path.join(feedDir, 'mtg0zt4k-deadbeef.json.body');
    const stixBody = path.join(feedDir, 'mtg0zt4k-deadbeef.stix.body');
    fs.writeFileSync(current, 'x');
    // Zero-byte .body is the exact race: stream opened, retention sweep runs before first write.
    fs.writeFileSync(body, '');
    fs.writeFileSync(stixBody, '');
    const removed = await cleanupSupersededArtifacts(cfg(), 25, '25/cur.json');
    assert.equal(removed, 0);
    assert.ok(fs.existsSync(body), 'json.body must survive concurrent cleanup');
    assert.ok(fs.existsSync(stixBody), 'stix.body must survive concurrent cleanup');
    assert.ok(fs.existsSync(current));
  });

  it('removeFeedArtifacts deletes the whole feed dir', async () => {
    const feedDir = resolveFeedDir(cfg().storageDir, 13);
    fs.mkdirSync(feedDir, { recursive: true });
    fs.writeFileSync(path.join(feedDir, 'a.json'), 'x');
    await removeFeedArtifacts(cfg(), 13);
    assert.ok(!fs.existsSync(feedDir));
  });

  it('statArtifact returns null for missing files', async () => {
    assert.equal(await statArtifact(path.join(dir, 'nope')), null);
  });
});
