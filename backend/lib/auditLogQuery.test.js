import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_AUDIT_LIMIT,
  MAX_AUDIT_LIMIT,
  DEFAULT_AUDIT_RANGE_MS,
  parseAuditLimit,
  resolveAuditTimeRange,
  encodeAuditCursor,
  decodeAuditCursor,
  AuditQueryError
} from './auditLogQuery.js';

// ---------------------------------------------------------------------------
// parseAuditLimit
// ---------------------------------------------------------------------------

test('parseAuditLimit defaults to 50 when missing/invalid', () => {
  assert.equal(parseAuditLimit(undefined), DEFAULT_AUDIT_LIMIT);
  assert.equal(parseAuditLimit(''), DEFAULT_AUDIT_LIMIT);
  assert.equal(parseAuditLimit('abc'), DEFAULT_AUDIT_LIMIT);
  assert.equal(parseAuditLimit(0), DEFAULT_AUDIT_LIMIT);
  assert.equal(parseAuditLimit(-5), DEFAULT_AUDIT_LIMIT);
});

test('parseAuditLimit clamps to [1, MAX] and floors', () => {
  assert.equal(parseAuditLimit(1), 1);
  assert.equal(parseAuditLimit(50), 50);
  assert.equal(parseAuditLimit(75.9), 75);
  assert.equal(parseAuditLimit(1000), MAX_AUDIT_LIMIT);
});

// ---------------------------------------------------------------------------
// resolveAuditTimeRange
// ---------------------------------------------------------------------------

test('resolveAuditTimeRange defaults to Last 24 hours when range omitted', () => {
  const now = new Date('2026-08-08T12:00:00.000Z');
  const { from, to } = resolveAuditTimeRange({ now });
  assert.equal(to, null);
  assert.equal(from.toISOString(), '2026-08-07T12:00:00.000Z');
  assert.equal(now.getTime() - from.getTime(), DEFAULT_AUDIT_RANGE_MS);
});

test('resolveAuditTimeRange honors explicit from/to', () => {
  const { from, to } = resolveAuditTimeRange({
    from: '2026-01-01T00:00:00Z',
    to: '2026-02-01T00:00:00Z',
    now: new Date('2026-08-08T12:00:00Z')
  });
  assert.equal(from.toISOString(), '2026-01-01T00:00:00.000Z');
  assert.equal(to.toISOString(), '2026-02-01T00:00:00.000Z');
});

test('resolveAuditTimeRange anchors default lower bound to `to` when only `to` given', () => {
  const { from, to } = resolveAuditTimeRange({
    to: '2026-05-10T00:00:00Z',
    now: new Date('2026-08-08T12:00:00Z')
  });
  assert.equal(to.toISOString(), '2026-05-10T00:00:00.000Z');
  assert.equal(from.toISOString(), '2026-05-09T00:00:00.000Z');
});

test('resolveAuditTimeRange rejects from >= to', () => {
  assert.throws(
    () => resolveAuditTimeRange({ from: '2026-02-01T00:00:00Z', to: '2026-01-01T00:00:00Z' }),
    AuditQueryError
  );
  assert.throws(
    () => resolveAuditTimeRange({ from: '2026-01-01T00:00:00Z', to: '2026-01-01T00:00:00Z' }),
    AuditQueryError
  );
});

test('resolveAuditTimeRange rejects invalid timestamps', () => {
  assert.throws(() => resolveAuditTimeRange({ from: 'not-a-date' }), AuditQueryError);
  assert.throws(() => resolveAuditTimeRange({ to: 'garbage' }), AuditQueryError);
});

// ---------------------------------------------------------------------------
// cursor encode / decode
// ---------------------------------------------------------------------------

test('encode/decode cursor round-trips (Date input)', () => {
  const encoded = encodeAuditCursor({ created_at: new Date('2026-08-08T10:00:00.123Z'), id: 987 });
  assert.equal(typeof encoded, 'string');
  const decoded = decodeAuditCursor(encoded);
  assert.deepEqual(decoded, { created_at: '2026-08-08T10:00:00.123Z', id: '987' });
});

test('encode/decode cursor round-trips (string input, bigint id)', () => {
  const encoded = encodeAuditCursor({ created_at: '2026-08-08T10:00:00.000Z', id: '9007199254740993' });
  const decoded = decodeAuditCursor(encoded);
  assert.equal(decoded.id, '9007199254740993'); // preserved as string, no float loss
});

test('encodeAuditCursor returns null for incomplete rows', () => {
  assert.equal(encodeAuditCursor(null), null);
  assert.equal(encodeAuditCursor({ created_at: '', id: 1 }), null);
  assert.equal(encodeAuditCursor({ created_at: '2026-08-08T10:00:00Z', id: null }), null);
});

test('decodeAuditCursor returns null for empty cursor (first page)', () => {
  assert.equal(decodeAuditCursor(undefined), null);
  assert.equal(decodeAuditCursor(''), null);
  assert.equal(decodeAuditCursor('   '), null);
});

test('decodeAuditCursor throws on malformed / tampered cursor', () => {
  assert.throws(() => decodeAuditCursor('!!!not-base64!!!'), AuditQueryError);
  assert.throws(
    () => decodeAuditCursor(Buffer.from('{"c":"nope","i":"1"}', 'utf8').toString('base64url')),
    AuditQueryError
  );
  assert.throws(
    () => decodeAuditCursor(Buffer.from('{"c":"2026-08-08T10:00:00Z","i":"x"}', 'utf8').toString('base64url')),
    AuditQueryError
  );
  // No SQL metacharacters survive decode — id must be digits only.
  assert.throws(
    () => decodeAuditCursor(Buffer.from('{"c":"2026-08-08T10:00:00Z","i":"1); DROP TABLE"}', 'utf8').toString('base64url')),
    AuditQueryError
  );
});
