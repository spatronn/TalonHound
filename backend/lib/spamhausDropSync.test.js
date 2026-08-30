import test from 'node:test';
import assert from 'node:assert/strict';
import {
  SPAMHAUS_DROP_PROVIDER,
  SPAMHAUS_DROP_LIST_TYPES,
  ALLOWED_SYNC_INTERVALS,
  validateSyncIntervalHours,
  parseDropJson,
  parseCidrItem,
  buildSpamhausLookupResponse
} from './spamhausDropSync.js';

// ---------------------------------------------------------------------------
// constants
// ---------------------------------------------------------------------------

test('SPAMHAUS_DROP_PROVIDER is spamhaus_drop', () => {
  assert.equal(SPAMHAUS_DROP_PROVIDER, 'spamhaus_drop');
});

test('SPAMHAUS_DROP_LIST_TYPES contains drop_v4 and drop_v6', () => {
  assert.deepEqual([...SPAMHAUS_DROP_LIST_TYPES], ['drop_v4', 'drop_v6']);
});

test('ALLOWED_SYNC_INTERVALS contains exactly 6, 12, 24', () => {
  assert.deepEqual([...ALLOWED_SYNC_INTERVALS].sort((a, b) => a - b), [6, 12, 24]);
});

// ---------------------------------------------------------------------------
// validateSyncIntervalHours
// ---------------------------------------------------------------------------

test('validateSyncIntervalHours: accepts 6', () => {
  const r = validateSyncIntervalHours(6);
  assert.equal(r.ok, true);
  assert.equal(r.value, 6);
});

test('validateSyncIntervalHours: accepts 12', () => {
  const r = validateSyncIntervalHours(12);
  assert.equal(r.ok, true);
  assert.equal(r.value, 12);
});

test('validateSyncIntervalHours: accepts 24', () => {
  const r = validateSyncIntervalHours(24);
  assert.equal(r.ok, true);
  assert.equal(r.value, 24);
});

test('validateSyncIntervalHours: accepts string "24"', () => {
  const r = validateSyncIntervalHours('24');
  assert.equal(r.ok, true);
  assert.equal(r.value, 24);
});

test('validateSyncIntervalHours: rejects 1', () => {
  const r = validateSyncIntervalHours(1);
  assert.equal(r.ok, false);
  assert.match(r.error, /Invalid sync interval/);
  assert.match(r.error, /6, 12, 24/);
});

test('validateSyncIntervalHours: rejects 48', () => {
  assert.equal(validateSyncIntervalHours(48).ok, false);
});

test('validateSyncIntervalHours: rejects 0', () => {
  assert.equal(validateSyncIntervalHours(0).ok, false);
});

test('validateSyncIntervalHours: rejects non-numeric string', () => {
  assert.equal(validateSyncIntervalHours('daily').ok, false);
});

test('validateSyncIntervalHours: rejects null', () => {
  assert.equal(validateSyncIntervalHours(null).ok, false);
});

// ---------------------------------------------------------------------------
// parseDropJson
// ---------------------------------------------------------------------------

test('parseDropJson: parses valid JSON array', () => {
  const json = JSON.stringify([{ cidr: '1.2.3.0/24', sblid: 'SBL123', rir: 'ripencc' }]);
  const result = parseDropJson(json, 'drop_v4');
  assert.equal(result.length, 1);
  assert.equal(result[0].cidr, '1.2.3.0/24');
});

test('parseDropJson: throws on invalid JSON', () => {
  assert.throws(() => parseDropJson('not json', 'drop_v4'), { code: 'parse_error' });
});

test('parseDropJson: single JSON object line treated as one NDJSON entry', () => {
  const result = parseDropJson('{"cidr":"1.2.0.0/16"}', 'drop_v4');
  assert.equal(result.length, 1);
  assert.equal(result[0].cidr, '1.2.0.0/16');
});

test('parseDropJson: throws on JSON null', () => {
  assert.throws(() => parseDropJson('null', 'drop_v4'), { code: 'parse_error' });
});

test('parseDropJson: throws on JSON string', () => {
  assert.throws(() => parseDropJson('"hello"', 'drop_v4'), { code: 'parse_error' });
});

test('parseDropJson: empty array is valid (empty array check is done upstream)', () => {
  const result = parseDropJson('[]', 'drop_v4');
  assert.equal(result.length, 0);
});

// ---------------------------------------------------------------------------
// parseCidrItem
// ---------------------------------------------------------------------------

test('parseCidrItem: parses full item', () => {
  const item = { cidr: '5.183.60.0/22', sblid: 'SBL463004', rir: 'ripencc' };
  const r = parseCidrItem(item);
  assert.equal(r.cidr, '5.183.60.0/22');
  assert.equal(r.sblid, 'SBL463004');
  assert.equal(r.rir, 'ripencc');
  assert.deepEqual(r.raw_json, item);
});

test('parseCidrItem: null for null input', () => {
  assert.equal(parseCidrItem(null), null);
});

test('parseCidrItem: null for missing cidr', () => {
  assert.equal(parseCidrItem({ sblid: 'SBL1' }), null);
});

test('parseCidrItem: null for cidr without slash', () => {
  assert.equal(parseCidrItem({ cidr: '1.2.3.4' }), null);
});

test('parseCidrItem: null for non-object', () => {
  assert.equal(parseCidrItem('1.2.3.0/24'), null);
  assert.equal(parseCidrItem(42), null);
});

test('parseCidrItem: handles missing optional fields', () => {
  const r = parseCidrItem({ cidr: '2001:db8::/32' });
  assert.equal(r.cidr, '2001:db8::/32');
  assert.equal(r.sblid, null);
  assert.equal(r.rir, null);
});

test('parseCidrItem: truncates overly long sblid', () => {
  const r = parseCidrItem({ cidr: '1.0.0.0/8', sblid: 'A'.repeat(100) });
  assert.equal(r.sblid.length, 64);
});

// ---------------------------------------------------------------------------
// buildSpamhausLookupResponse
// ---------------------------------------------------------------------------

const healthyState = [
  { list_type: 'drop_v4', status: 'healthy', last_success_at: new Date('2026-07-05T10:00:00Z') },
  { list_type: 'drop_v6', status: 'healthy', last_success_at: new Date('2026-07-05T10:00:00Z') }
];
const enabledConfig = { enabled: true, sync_interval_hours: 24, timeout_ms: 30000 };
const disabledConfig = { enabled: false, sync_interval_hours: 24, timeout_ms: 30000 };

test('buildSpamhausLookupResponse: disabled provider returns disabled status', () => {
  const r = buildSpamhausLookupResponse({ lookup: null, syncState: healthyState, config: disabledConfig, targetIp: '1.2.3.4' });
  assert.equal(r.status, 'disabled');
  assert.equal(r.listed, null);
});

test('buildSpamhausLookupResponse: notApplicable returns not_applicable', () => {
  const r = buildSpamhausLookupResponse({ lookup: null, syncState: healthyState, config: enabledConfig, targetIp: null, notApplicable: true });
  assert.equal(r.status, 'not_applicable');
  assert.equal(r.listed, null);
  assert.match(r.reason, /IP IOCs/);
});

test('buildSpamhausLookupResponse: never synced returns dataset_not_synced', () => {
  const neverSyncedState = [
    { list_type: 'drop_v4', status: 'never_synced', last_success_at: null },
    { list_type: 'drop_v6', status: 'never_synced', last_success_at: null }
  ];
  const r = buildSpamhausLookupResponse({ lookup: null, syncState: neverSyncedState, config: enabledConfig, targetIp: '1.2.3.4' });
  assert.equal(r.status, 'dataset_not_synced');
  assert.equal(r.listed, null);
});

test('buildSpamhausLookupResponse: listed IP returns listed status', () => {
  const lookup = { found: true, cidr: '1.2.3.0/24', sblid: 'SBL123', rir: 'ripencc', list_type: 'drop_v4', synced_at: new Date() };
  const r = buildSpamhausLookupResponse({ lookup, syncState: healthyState, config: enabledConfig, targetIp: '1.2.3.5' });
  assert.equal(r.status, 'listed');
  assert.equal(r.listed, true);
  assert.equal(r.target_ip, '1.2.3.5');
  assert.equal(r.matched_cidr, '1.2.3.0/24');
  assert.equal(r.sblid, 'SBL123');
  assert.equal(r.rir, 'ripencc');
  assert.equal(r.list_type, 'drop_v4');
  assert.equal(r.dataset_status, 'healthy');
});

test('buildSpamhausLookupResponse: not listed IP returns not_listed status', () => {
  const r = buildSpamhausLookupResponse({ lookup: { found: false }, syncState: healthyState, config: enabledConfig, targetIp: '8.8.8.8' });
  assert.equal(r.status, 'not_listed');
  assert.equal(r.listed, false);
  assert.equal(r.target_ip, '8.8.8.8');
  assert.equal(r.dataset_status, 'healthy');
});

test('buildSpamhausLookupResponse: failed sync state reflected in dataset_status', () => {
  const failedState = [
    { list_type: 'drop_v4', status: 'failed', last_success_at: new Date('2026-07-04T00:00:00Z') },
    { list_type: 'drop_v6', status: 'healthy', last_success_at: new Date('2026-07-05T10:00:00Z') }
  ];
  const r = buildSpamhausLookupResponse({ lookup: { found: false }, syncState: failedState, config: enabledConfig, targetIp: '1.2.3.4' });
  assert.equal(r.dataset_status, 'failed');
});

test('buildSpamhausLookupResponse: provider field is always spamhaus_drop', () => {
  const r = buildSpamhausLookupResponse({ lookup: null, syncState: healthyState, config: disabledConfig, targetIp: '1.2.3.4' });
  assert.equal(r.provider, 'spamhaus_drop');
});
