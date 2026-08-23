import test from 'node:test';
import assert from 'node:assert/strict';
import { parseDurationMs, getSessionConfig, validateSessionConfig } from './sessionConfig.js';

test('parseDurationMs: unit suffixes and bare seconds', () => {
  assert.equal(parseDurationMs('15m', 0), 15 * 60 * 1000);
  assert.equal(parseDurationMs('60m', 0), 60 * 60 * 1000);
  assert.equal(parseDurationMs('24h', 0), 24 * 60 * 60 * 1000);
  assert.equal(parseDurationMs('30s', 0), 30 * 1000);
  assert.equal(parseDurationMs('500ms', 0), 500);
  assert.equal(parseDurationMs('2d', 0), 2 * 24 * 60 * 60 * 1000);
  assert.equal(parseDurationMs('90', 0), 90 * 1000, 'bare number = seconds');
});

test('parseDurationMs: empty/absent uses fallback; invalid throws', () => {
  assert.equal(parseDurationMs('', 42), 42);
  assert.equal(parseDurationMs(undefined, 42), 42);
  assert.equal(parseDurationMs(null, 42), 42);
  assert.throws(() => parseDurationMs('abc', 0), /Invalid duration/);
  assert.throws(() => parseDurationMs('0m', 0), /must be > 0/);
  assert.throws(() => parseDurationMs('-5m', 0), /Invalid duration/);
});

test('getSessionConfig: secure defaults when unset', () => {
  const c = getSessionConfig({});
  assert.equal(c.accessTtlSeconds, 15 * 60);
  assert.equal(c.idleMs, 60 * 60 * 1000);
  assert.equal(c.absoluteMs, 24 * 60 * 60 * 1000);
  assert.equal(c.refreshGraceMs, 30 * 1000);
  assert.equal(c.cleanupRetentionDays, 7);
});

test('getSessionConfig: env overrides parsed', () => {
  const c = getSessionConfig({
    ACCESS_TOKEN_TTL: '30s',
    SESSION_IDLE_TIMEOUT: '3m',
    SESSION_ABSOLUTE_TIMEOUT: '10m'
  });
  assert.equal(c.accessTtlSeconds, 30);
  assert.equal(c.idleMs, 3 * 60 * 1000);
  assert.equal(c.absoluteMs, 10 * 60 * 1000);
});

test('validateSessionConfig: rejects access > idle', () => {
  assert.throws(
    () => validateSessionConfig({ ACCESS_TOKEN_TTL: '2h', SESSION_IDLE_TIMEOUT: '1h' }),
    /ACCESS_TOKEN_TTL must be <= SESSION_IDLE_TIMEOUT/
  );
});

test('validateSessionConfig: rejects idle > absolute', () => {
  assert.throws(
    () => validateSessionConfig({ SESSION_IDLE_TIMEOUT: '48h', SESSION_ABSOLUTE_TIMEOUT: '24h' }),
    /SESSION_IDLE_TIMEOUT must be <= SESSION_ABSOLUTE_TIMEOUT/
  );
});

test('validateSessionConfig: defaults are valid, no warnings', () => {
  const { warnings } = validateSessionConfig({});
  assert.deepEqual(warnings, []);
});
