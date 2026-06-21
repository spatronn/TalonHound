import test from 'node:test';
import assert from 'node:assert/strict';
import {
  validateFeedUrl,
  syncIntervalToCron,
  mapFixedIocTypeToObservableType,
  sanitizeUrlForDisplay
} from './customThreatFeedUtils.js';
import {
  parseTxtFeedContent,
  parseCsvFeedContent,
  parseFeedContent,
  detectFormatFromContent
} from './customThreatFeedParser.js';
import { requireRole, ROLES, rbacHttpPolicy } from './rbac.js';

test('validateFeedUrl rejects file and localhost', () => {
  assert.equal(validateFeedUrl('file:///etc/passwd').ok, false);
  assert.equal(validateFeedUrl('http://127.0.0.1/feed.txt').ok, false);
  assert.equal(validateFeedUrl('http://192.168.1.1/feed.txt').ok, false);
  assert.equal(validateFeedUrl('https://ti.example.com/feed.txt').ok, true);
});

test('sanitizeUrlForDisplay strips credentials', () => {
  const display = sanitizeUrlForDisplay('https://user:secret@ti.example.com/path/feed.txt');
  assert.equal(display.includes('secret'), false);
  assert.equal(display.includes('ti.example.com'), true);
});

test('syncIntervalToCron maps common intervals', () => {
  assert.equal(syncIntervalToCron(5), '*/5 * * * *');
  assert.equal(syncIntervalToCron(60), '0 * * * *');
});

test('mapFixedIocTypeToObservableType maps file_hash to hash', () => {
  assert.equal(mapFixedIocTypeToObservableType('file_hash'), 'hash');
  assert.equal(mapFixedIocTypeToObservableType('domain'), 'domain');
});

test('parseTxtFeedContent parses lines and ignores comments', () => {
  const text = '# comment\nevil.com\n// skip\n!!!bad\n';
  const { valid, invalidRows, totalRows } = parseTxtFeedContent(text, { iocTypeMode: 'auto' });
  assert.equal(totalRows, 2);
  assert.equal(valid.length, 1);
  assert.equal(valid[0].observable, 'evil.com');
  assert.equal(invalidRows.length, 1);
});

test('parseTxtFeedContent fixed domain mode rejects non-domain', () => {
  const { valid, invalidRows } = parseTxtFeedContent('1.2.3.4\nevil.com\n', {
    iocTypeMode: 'fixed',
    fixedIocType: 'domain'
  });
  assert.equal(valid.length, 1);
  assert.equal(valid[0].observable, 'evil.com');
  assert.equal(invalidRows.length, 1);
});

test('parseCsvFeedContent reads header columns', () => {
  const text = 'value,type,confidence\nevil.com,domain,high\nbad,,';
  const { valid } = parseCsvFeedContent(text, { iocTypeMode: 'auto' });
  assert.equal(valid.length, 1);
  assert.equal(valid[0].observable, 'evil.com');
  assert.equal(valid[0].confidence, 'high');
});

test('parseCsvFeedContent without header uses first column', () => {
  const { valid } = parseCsvFeedContent('evil.com\nbad-value\n', { iocTypeMode: 'auto' });
  assert.ok(valid.length >= 1);
});

test('detectFormatFromContent detects csv by delimiter', () => {
  assert.equal(detectFormatFromContent('a,b\n1,2'), 'csv');
  assert.equal(detectFormatFromContent('evil.com\nbad.net'), 'txt');
});

test('parseFeedContent auto mode txt', () => {
  const parsed = parseFeedContent('evil.com\n', { format: 'auto', iocTypeMode: 'auto' });
  assert.equal(parsed.detectedFormat, 'txt');
  assert.equal(parsed.valid.length, 1);
});

test('requireRole admin allows admin only on mock', () => {
  const handler = requireRole(ROLES.ADMIN);
  let status = null;
  const req = { user: { role: 'analyst' }, authVia: 'session' };
  const res = { status(code) { status = code; return this; }, json() { return this; } };
  handler(req, res, () => { status = 200; });
  assert.equal(status, 403);

  const reqAdmin = { user: { role: 'admin' }, authVia: 'session' };
  let adminStatus = null;
  handler(reqAdmin, { status(c) { adminStatus = c; return this; }, json() { return this; } }, () => { adminStatus = 200; });
  assert.equal(adminStatus, 200);
});

test('requireRole analyst allowed for test-fetch policy endpoints', () => {
  const handler = requireRole(ROLES.ADMIN, ROLES.ANALYST);
  let status = null;
  handler(
    { user: { role: 'analyst' }, authVia: 'session' },
    { status(c) { status = c; return this; }, json() { return this; } },
    () => { status = 200; }
  );
  assert.equal(status, 200);

  handler(
    { user: { role: 'readonly' }, authVia: 'session' },
    { status(c) { status = c; return this; }, json() { return this; } },
    () => { status = 200; }
  );
  assert.equal(status, 403);
});

test('rbacHttpPolicy blocks readonly POST', () => {
  let blocked = false;
  rbacHttpPolicy(
    { method: 'POST', path: '/api/custom-threat-feeds/abc/sync', user: { role: 'readonly' } },
    { status() { blocked = true; return this; }, json() { return this; } },
    () => { blocked = false; }
  );
  assert.equal(blocked, true);
});

test('invalid rows do not prevent valid parse batch', () => {
  const text = 'not-a-valid-ioc\n8.8.8.8\n';
  const parsed = parseFeedContent(text, { format: 'txt', iocTypeMode: 'auto' });
  assert.equal(parsed.valid.length, 1);
  assert.equal(parsed.invalidRows.length, 1);
});
