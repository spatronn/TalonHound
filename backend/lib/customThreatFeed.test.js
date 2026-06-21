import test from 'node:test';
import assert from 'node:assert/strict';
import {
  validateFeedUrl,
  mapFixedIocTypeToObservableType,
  sanitizeUrlForDisplay
} from './customThreatFeedUtils.js';
import {
  assertCustomFeedSettingsAllowed,
  isCustomThreatFeedKey
} from './customThreatFeedAccess.js';
import { loadCustomThreatFeedSchedules } from './integrationFeedScheduleSync.js';
import { BASE_SCHEDULE_CRONS } from './integrationSchedule.js';
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

test('custom feed schedule uses integration_feeds schedule_cron model', async () => {
  let capturedSql = '';
  const pool = {
    query: async (sql) => {
      capturedSql = sql;
      return { rows: [{ key: 'ctf-abc123', schedule_cron: '*/15 * * * *' }] };
    }
  };
  const rows = await loadCustomThreatFeedSchedules(pool);
  assert.match(capturedSql, /f\.schedule_cron/);
  assert.match(capturedSql, /f\.active = TRUE/);
  assert.match(capturedSql, /c\.deactivated_at IS NULL/);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].key, 'ctf-abc123');
  assert.equal(rows[0].cron, '*/15 * * * *');
});

test('feed schedule crons align with standard feed options', () => {
  const allowed = new Set(BASE_SCHEDULE_CRONS);
  assert.equal(allowed.has('*/5 * * * *'), true);
  assert.equal(allowed.has('*/15 * * * *'), true);
  assert.equal(allowed.has('*/30 * * * *'), true);
  assert.equal(allowed.has('0 * * * *'), true);
  assert.equal(allowed.has('0 0 * * *'), true);
  assert.equal(allowed.has('0 */2 * * *'), false);
});

test('assertCustomFeedSettingsAllowed blocks analyst on custom feed keys', () => {
  let statusCode = null;
  const res = {
    status(code) {
      statusCode = code;
      return this;
    },
    json() {
      return this;
    }
  };
  const analystReq = { user: { role: ROLES.ANALYST } };
  const allowedVendor = assertCustomFeedSettingsAllowed(analystReq, 'usom-trcert', res);
  assert.equal(allowedVendor, true);
  assert.equal(statusCode, null);

  const blocked = assertCustomFeedSettingsAllowed(analystReq, 'ctf-abc123', res);
  assert.equal(blocked, false);
  assert.equal(statusCode, 403);
});

test('assertCustomFeedSettingsAllowed allows admin on custom feed keys', () => {
  const res = { status() { return this; }, json() { return this; } };
  const adminReq = { user: { role: ROLES.ADMIN } };
  assert.equal(assertCustomFeedSettingsAllowed(adminReq, 'ctf-abc123', res), true);
});

test('isCustomThreatFeedKey detects ctf prefix', () => {
  assert.equal(isCustomThreatFeedKey('ctf-abc'), true);
  assert.equal(isCustomThreatFeedKey('usom-trcert'), false);
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
