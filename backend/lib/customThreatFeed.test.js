import test from 'node:test';
import assert from 'node:assert/strict';
import {
  validateFeedUrl,
  mapFixedIocTypeToObservableType,
  sanitizeUrlForDisplay,
  normalizeCustomFeedName,
  customFeedNameComparisonKey,
  findCustomFeedNameConflict,
  DUPLICATE_CUSTOM_FEED_NAME_ERROR
} from './customThreatFeedUtils.js';
import {
  assertCustomFeedSettingsAllowed,
  isCustomThreatFeedKey
} from './customThreatFeedAccess.js';
import { loadCustomThreatFeedSchedules } from './integrationFeedScheduleSync.js';
import { BASE_SCHEDULE_CRONS, ALLOWED_SCHEDULE_CRONS, RUN_ONCE_SCHEDULE } from './integrationSchedule.js';
import {
  parseTxtFeedContent,
  parseCsvFeedContent,
  parseFeedContent,
  detectFormatFromContent
} from './customThreatFeedParser.js';
import { requireRole, ROLES, rbacHttpPolicy } from './rbac.js';
import { registerCustomThreatFeedRoutes } from '../routes/customThreatFeeds.js';

test('validateFeedUrl rejects file and localhost', () => {
  assert.equal(validateFeedUrl('file:///etc/passwd').ok, false);
  assert.equal(validateFeedUrl('http://127.0.0.1/feed.txt').ok, false);
  assert.equal(validateFeedUrl('http://192.168.1.1/feed.txt').ok, false);
  assert.equal(validateFeedUrl('https://ti.example.com/feed.txt').ok, true);
});

test('validateFeedUrl SSRF-02 rejects IPv4-mapped and IPv6 special literals', () => {
  assert.equal(validateFeedUrl('http://[::ffff:127.0.0.1]/feed.txt').ok, false);
  assert.equal(validateFeedUrl('http://[::ffff:169.254.169.254]/').ok, false);
  assert.equal(validateFeedUrl('http://[::ffff:10.1.2.3]/').ok, false);
  assert.equal(validateFeedUrl('http://[::1]/').ok, false);
  assert.equal(validateFeedUrl('http://[fe80::1]/').ok, false);
  assert.equal(validateFeedUrl('http://[fd00::1]/').ok, false);
  assert.equal(validateFeedUrl('http://169.254.169.254/').ok, false);
  assert.equal(validateFeedUrl('ftp://ti.example.com/feed.txt').ok, false);
  assert.equal(validateFeedUrl('http://[::ffff:8.8.8.8]/feed.txt').ok, true);
  assert.equal(validateFeedUrl('http://1.1.1.1/feed.txt').ok, true);
});

test('sanitizeUrlForDisplay strips credentials', () => {
  const display = sanitizeUrlForDisplay('https://user:secret@ti.example.com/path/feed.txt');
  assert.equal(display.includes('secret'), false);
  assert.equal(display.includes('ti.example.com'), true);
});

test('custom feed name normalization is trim + case-insensitive key', () => {
  assert.equal(normalizeCustomFeedName(' validin-phish-feed-1 '), 'validin-phish-feed-1');
  assert.equal(customFeedNameComparisonKey('VALIDIN-PHISH-FEED-1'), 'validin-phish-feed-1');
  assert.equal(customFeedNameComparisonKey('Validin-Phish-Feed-1'), 'validin-phish-feed-1');
  assert.equal(DUPLICATE_CUSTOM_FEED_NAME_ERROR, 'A custom threat feed with this name already exists.');
});

test('findCustomFeedNameConflict ignores deactivated and archived feeds', async () => {
  let capturedSql = '';
  const pool = {
    query: async (sql, params) => {
      capturedSql = sql;
      assert.equal(params[0], 'validin-phish-feed-7');
      return { rows: [] };
    }
  };
  const conflict = await findCustomFeedNameConflict(pool, 'validin-phish-feed-7');
  assert.equal(conflict, null);
  assert.match(capturedSql, /c\.deactivated_at IS NULL/);
  assert.match(capturedSql, /f\.archived_at IS NULL/);
});

test('findCustomFeedNameConflict returns active feed with same name', async () => {
  const pool = {
    query: async () => ({
      rows: [{ id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', name: 'validin-phish-feed-7' }]
    })
  };
  const conflict = await findCustomFeedNameConflict(pool, ' Validin-Phish-Feed-7 ');
  assert.equal(conflict?.name, 'validin-phish-feed-7');
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

test('custom feed schedule loader excludes run_once feeds', async () => {
  let capturedSql = '';
  const pool = {
    query: async (sql) => {
      capturedSql = sql;
      return { rows: [] };
    }
  };
  await loadCustomThreatFeedSchedules(pool);
  assert.match(capturedSql, /schedule_cron <> 'run_once'/);
});

test('custom feed update persists run_once schedule and removes repeatable scheduler job', async () => {
  const routeHandlers = {};
  const app = {
    get() {},
    post() {},
    put(path, ...handlers) {
      routeHandlers[path] = handlers.at(-1);
    },
    delete() {}
  };

  const executedSql = [];
  let fetchCount = 0;
  const feedRow = {
    id: '11111111-1111-1111-1111-111111111111',
    feed_id: '22222222-2222-2222-2222-222222222222',
    integration_key: 'ctf-abc123',
    feed_name: 'Run Once Feed',
    url: 'https://ti.example.com/feed.txt',
    url_host: 'ti.example.com',
    format: 'txt',
    ioc_type_mode: 'auto',
    fixed_ioc_type: null,
    description: null,
    timeout_ms: 30000,
    default_confidence: 'medium',
    integration_active: true,
    deactivated_at: null,
    archived_at: null,
    schedule: '0 * * * *'
  };
  const client = {
    query: async (sql, params = []) => {
      executedSql.push({ sql, params });
      return { rows: [], rowCount: 1 };
    },
    release() {}
  };
  const pool = {
    connect: async () => client,
    query: async (sql) => {
      if (String(sql).includes('FROM custom_threat_feeds c')) {
        fetchCount += 1;
        return {
          rows: [{
            ...feedRow,
            schedule: fetchCount > 1 ? RUN_ONCE_SCHEDULE : feedRow.schedule
          }],
          rowCount: 1
        };
      }
      if (String(sql).includes('SELECT f.key, f.schedule_cron')) {
        return { rows: [], rowCount: 0 };
      }
      return { rows: [], rowCount: 0 };
    }
  };
  const removedRepeatableKeys = [];
  const importQueue = {
    getRepeatableJobs: async () => [{
      id: 'ctf-abc123-scheduled',
      key: 'repeat-key-1',
      name: 'custom-threat-feed-sync',
      pattern: '0 * * * *'
    }],
    removeRepeatableByKey: async (key) => {
      removedRepeatableKeys.push(key);
    }
  };
  const audit = { auditSuccess: async () => {} };
  registerCustomThreatFeedRoutes(app, pool, audit, { importQueue, manualJobPriority: 1 });

  let statusCode = 200;
  let jsonBody = null;
  const res = {
    status(code) { statusCode = code; return this; },
    json(body) { jsonBody = body; return this; }
  };

  await routeHandlers['/api/custom-threat-feeds/:id'](
    {
      params: { id: feedRow.id },
      body: { schedule_cron: RUN_ONCE_SCHEDULE },
      user: { role: ROLES.ADMIN, username: 'admin' }
    },
    res
  );

  assert.equal(statusCode, 200);
  assert.equal(jsonBody.feed.schedule, RUN_ONCE_SCHEDULE);
  assert.ok(
    executedSql.some(({ sql, params }) => (
      /UPDATE integration_feeds\s+SET schedule_cron = \$2/i.test(String(sql))
      && params[0] === feedRow.feed_id
      && params[1] === RUN_ONCE_SCHEDULE
    )),
    'expected custom feed update to persist schedule_cron on integration_feeds'
  );
  assert.deepEqual(removedRepeatableKeys, ['repeat-key-1']);
});

test('feed schedule crons align with standard feed options', () => {
  const allowed = new Set(ALLOWED_SCHEDULE_CRONS);
  assert.equal(allowed.has('*/5 * * * *'), true);
  assert.equal(allowed.has('*/15 * * * *'), true);
  assert.equal(allowed.has('*/30 * * * *'), true);
  assert.equal(allowed.has('0 * * * *'), true);
  assert.equal(allowed.has('0 0 * * *'), true);
  assert.equal(allowed.has(RUN_ONCE_SCHEDULE), true);
  assert.equal(allowed.has('0 */2 * * *'), false);
  assert.equal(BASE_SCHEDULE_CRONS.length, 5);
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

// delete-check logic tests
// These tests verify computeDeleteCheck behaviour via the GET /delete-check route.

function makeDeleteCheckPool(overrides = {}) {
  const defaults = {
    successfulRunCount: 1,
    activeMemberCount: 0,
    historicalMemberCount: 0,
    queuedOrRunningCount: 0,
    publishedDepCount: 0,
    integration_active: true
  };
  const cfg = { ...defaults, ...overrides };
  const feedRow = {
    id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    feed_id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
    integration_key: 'ctf-testkey',
    feed_name: 'Test Feed',
    url: 'https://ti.example.com/feed.txt',
    url_host: 'ti.example.com',
    format: 'txt',
    ioc_type_mode: 'auto',
    fixed_ioc_type: null,
    description: null,
    timeout_ms: 30000,
    default_confidence: 'medium',
    integration_active: cfg.integration_active,
    deactivated_at: null,
    archived_at: null,
    schedule: '0 * * * *'
  };
  return {
    feedRow,
    pool: {
      query: async (sql, _params) => {
        const s = String(sql);
        if (s.includes('FROM custom_threat_feeds c')) return { rows: [feedRow] };
        if (s.includes("status IN ('success', 'partial_success')") && s.includes('custom_threat_feed_runs')) return { rows: [{ cnt: cfg.successfulRunCount }] };
        if (s.includes("status = 'active'") && s.includes('ioc_feed_memberships')) return { rows: [{ cnt: cfg.activeMemberCount }] };
        if (s.includes("status != 'active'") && s.includes('ioc_feed_memberships')) return { rows: [{ cnt: cfg.historicalMemberCount }] };
        if (s.includes('integration_queue_jobs')) return { rows: [{ cnt: cfg.queuedOrRunningCount }] };
        if (s.includes('published_feeds')) return { rows: [{ cnt: cfg.publishedDepCount }] };
        return { rows: [] };
      }
    }
  };
}

function makeDeleteCheckRoute(pool) {
  const routeHandlers = {};
  const app = {
    get(path, ...handlers) { routeHandlers[path] = handlers.at(-1); },
    post() {}, put() {}, delete() {}
  };
  const audit = { auditSuccess: async () => {} };
  const importQueue = { getRepeatableJobs: async () => [], removeRepeatableByKey: async () => {} };
  registerCustomThreatFeedRoutes(app, pool, audit, { importQueue, manualJobPriority: 1 });
  return routeHandlers['/api/custom-threat-feeds/:id/delete-check'];
}

test('delete-check: disabled feed + published dep + 0 active IOC → cleanup_delete', async () => {
  const { pool, feedRow } = makeDeleteCheckPool({
    successfulRunCount: 3,
    activeMemberCount: 0,
    historicalMemberCount: 10,
    publishedDepCount: 2,
    integration_active: false
  });
  const handler = makeDeleteCheckRoute(pool);
  let body = null;
  const res = { json(b) { body = b; return this; }, status(c) { return this; } };
  await handler({ params: { id: feedRow.id }, user: { role: ROLES.ADMIN } }, res);
  assert.equal(body.can_delete, true, 'disabled feed with published dep and 0 active IOC should allow cleanup_delete');
  assert.equal(body.delete_mode, 'cleanup_delete');
  assert.equal(body.published_feed_dependency_count, 2);
});

test('delete-check: enabled feed + published dep + 0 active IOC → cleanup_delete', async () => {
  const { pool, feedRow } = makeDeleteCheckPool({
    successfulRunCount: 1,
    activeMemberCount: 0,
    historicalMemberCount: 0,
    publishedDepCount: 1,
    integration_active: true
  });
  const handler = makeDeleteCheckRoute(pool);
  let body = null;
  const res = { json(b) { body = b; return this; }, status(c) { return this; } };
  await handler({ params: { id: feedRow.id }, user: { role: ROLES.ADMIN } }, res);
  assert.equal(body.can_delete, true, 'enabled feed with published dep and 0 active IOC should allow cleanup_delete');
  assert.equal(body.delete_mode, 'cleanup_delete');
});

test('delete-check: active IOC > 0 + published dep → requires_purge, not cleanup_delete', async () => {
  const { pool, feedRow } = makeDeleteCheckPool({
    successfulRunCount: 5,
    activeMemberCount: 42,
    publishedDepCount: 1,
    integration_active: false
  });
  const handler = makeDeleteCheckRoute(pool);
  let body = null;
  const res = { json(b) { body = b; return this; }, status(c) { return this; } };
  await handler({ params: { id: feedRow.id }, user: { role: ROLES.ADMIN } }, res);
  assert.equal(body.can_delete, false, 'active IOC memberships should block delete regardless of published dep');
  assert.equal(body.reason, 'requires_purge');
  assert.equal(body.published_feed_dependency_count, 1, 'published dep count should still be visible');
});

test('delete-check: disabled feed + no published dep + historical members → soft_delete', async () => {
  const { pool, feedRow } = makeDeleteCheckPool({
    successfulRunCount: 2,
    activeMemberCount: 0,
    historicalMemberCount: 5,
    publishedDepCount: 0,
    integration_active: false
  });
  const handler = makeDeleteCheckRoute(pool);
  let body = null;
  const res = { json(b) { body = b; return this; }, status(c) { return this; } };
  await handler({ params: { id: feedRow.id }, user: { role: ROLES.ADMIN } }, res);
  assert.equal(body.can_delete, true, 'disabled feed with no active IOC and no published dep should allow soft_delete');
  assert.equal(body.delete_mode, 'soft_delete');
});

test('delete-check: enabled feed + no deps + no runs → direct_delete', async () => {
  const { pool, feedRow } = makeDeleteCheckPool({
    successfulRunCount: 0,
    activeMemberCount: 0,
    historicalMemberCount: 0,
    publishedDepCount: 0,
    integration_active: true
  });
  const handler = makeDeleteCheckRoute(pool);
  let body = null;
  const res = { json(b) { body = b; return this; }, status(c) { return this; } };
  await handler({ params: { id: feedRow.id }, user: { role: ROLES.ADMIN } }, res);
  assert.equal(body.can_delete, true);
  assert.equal(body.delete_mode, 'direct_delete');
});
