import test from 'node:test';
import assert from 'node:assert/strict';
import {
  hashSecret,
  parseRefreshToken,
  createSession,
  validateAccessSession,
  touchActivity,
  rotateRefresh,
  revokeAllForUser,
  cleanupSessions
} from './authSessions.js';

const CONFIG = { accessTtlSeconds: 900, idleMs: 3600_000, absoluteMs: 86_400_000, activityMinUpdateMs: 60_000, refreshGraceMs: 30_000, cleanupRetentionDays: 7 };

test('parseRefreshToken: splits sid.secret; rejects malformed', () => {
  assert.deepEqual(parseRefreshToken('abc.def'), { sessionId: 'abc', secret: 'def' });
  assert.deepEqual(parseRefreshToken('id.longsecrethex.with.dots'), {
    sessionId: 'id',
    secret: 'longsecrethex.with.dots'
  });
  assert.equal(parseRefreshToken('nodot'), null);
  assert.equal(parseRefreshToken('.leading'), null);
  assert.equal(parseRefreshToken('trailing.'), null);
  assert.equal(parseRefreshToken(''), null);
});

test('hashSecret: stable sha256 hex, never the raw secret', () => {
  const h = hashSecret('super-secret');
  assert.match(h, /^[0-9a-f]{64}$/);
  assert.notEqual(h, 'super-secret');
  assert.equal(h, hashSecret('super-secret'));
});

test('createSession: inserts hashed secret and returns sid.secret token', async () => {
  let captured = null;
  const db = {
    async query(sql, params) {
      captured = { sql, params };
      return { rowCount: 1 };
    }
  };
  const now = new Date('2026-08-23T00:00:00Z');
  const out = await createSession(db, { userId: 7, authVersion: 3, userAgent: 'jest' }, { now, config: CONFIG });
  assert.match(captured.sql, /INSERT INTO auth_sessions/);
  const parsed = parseRefreshToken(out.refreshToken);
  assert.equal(parsed.sessionId, out.sessionId);
  // The DB stores only the hash of the secret, never the secret itself.
  const storedHash = captured.params[2];
  assert.equal(storedHash, hashSecret(parsed.secret));
  assert.notEqual(storedHash, parsed.secret);
  assert.equal(captured.params[1], 7); // user_id
  assert.equal(captured.params[3], 3); // auth_version_at_issue
  // idle + absolute derived from config
  assert.equal(new Date(out.idleExpiresAt).getTime(), now.getTime() + CONFIG.idleMs);
  assert.equal(new Date(out.absoluteExpiresAt).getTime(), now.getTime() + CONFIG.absoluteMs);
});

test('validateAccessSession: ok / revoked / idle / absolute / not_found', async () => {
  const now = new Date('2026-08-23T12:00:00Z');
  const mk = (row) => ({ async query() { return { rows: row ? [row] : [] }; } });

  const future = new Date(now.getTime() + 1000).toISOString();
  const past = new Date(now.getTime() - 1000).toISOString();

  assert.deepEqual(
    await validateAccessSession(mk({ user_id: 1, revoked_at: null, idle_expires_at: future, absolute_expires_at: future }), 'sid', { now }),
    { ok: true, userId: 1 }
  );
  assert.equal((await validateAccessSession(mk(null), 'sid', { now })).reason, 'not_found');
  assert.equal(
    (await validateAccessSession(mk({ user_id: 1, revoked_at: past, idle_expires_at: future, absolute_expires_at: future }), 'sid', { now })).reason,
    'revoked'
  );
  assert.equal(
    (await validateAccessSession(mk({ user_id: 1, revoked_at: null, idle_expires_at: future, absolute_expires_at: past }), 'sid', { now })).reason,
    'absolute'
  );
  assert.equal(
    (await validateAccessSession(mk({ user_id: 1, revoked_at: null, idle_expires_at: past, absolute_expires_at: future }), 'sid', { now })).reason,
    'idle'
  );
});

test('touchActivity: throttled UPDATE guarded by last_activity cutoff', async () => {
  let captured = null;
  const db = { async query(sql, params) { captured = { sql, params }; return { rowCount: 1 }; } };
  const now = new Date('2026-08-23T12:00:00Z');
  const res = await touchActivity(db, 'sid-1', { now, config: CONFIG });
  assert.equal(res.updated, true);
  assert.match(captured.sql, /UPDATE auth_sessions/);
  assert.match(captured.sql, /last_activity_at\s*<= \$4/); // server-side throttle guard present
  // new idle_expires_at = now + idle
  assert.equal(new Date(captured.params[2]).getTime(), now.getTime() + CONFIG.idleMs);
});

test('revokeAllForUser: updates only active rows for the user', async () => {
  let captured = null;
  const db = { async query(sql, params) { captured = { sql, params }; return { rowCount: 2 }; } };
  const out = await revokeAllForUser(db, 42, 'password_change');
  assert.equal(out.revoked, 2);
  assert.match(captured.sql, /revoked_at IS NULL/);
  assert.equal(captured.params[0], 42);
  assert.equal(captured.params[2], 'password_change');
});

test('cleanupSessions: bounded delete of terminal rows', async () => {
  let captured = null;
  const db = { async query(sql, params) { captured = { sql, params }; return { rowCount: 5 }; } };
  const out = await cleanupSessions(db, { batchSize: 500, config: CONFIG, now: new Date('2026-08-23T00:00:00Z') });
  assert.equal(out.deleted, 5);
  assert.match(captured.sql, /DELETE FROM auth_sessions/);
  assert.match(captured.sql, /LIMIT \$2/);
  assert.equal(captured.params[1], 500);
});

// --- rotateRefresh: scripted transaction mock -----------------------------------

function makeRotatePool(sessionRow) {
  const queries = [];
  const client = {
    async query(sql, params) {
      queries.push({ sql: String(sql), params });
      if (/^BEGIN/.test(sql.trim())) return {};
      if (/^COMMIT/.test(sql.trim())) return {};
      if (/^ROLLBACK/.test(sql.trim())) return {};
      if (/FOR UPDATE/.test(sql)) return { rows: sessionRow ? [sessionRow] : [] };
      if (/UPDATE auth_sessions/.test(sql)) return { rowCount: 1 };
      return { rows: [], rowCount: 0 };
    },
    release() {}
  };
  return { pool: { async connect() { return client; } }, queries };
}

const NOW = new Date('2026-08-23T12:00:00Z');
const future = (ms) => new Date(NOW.getTime() + ms).toISOString();
const past = (ms) => new Date(NOW.getTime() - ms).toISOString();

function validRow(secret) {
  return {
    id: 1,
    session_id: 'sess-1',
    user_id: 5,
    refresh_token_hash: hashSecret(secret),
    prev_refresh_token_hash: null,
    rotated_at: past(1000),
    auth_version_at_issue: 4,
    revoked_at: null,
    idle_expires_at: future(1000),
    absolute_expires_at: future(10_000),
    user_auth_version: 4,
    user_status: 'active'
  };
}

test('rotateRefresh: success rotates secret, keeps sid, does not extend clocks', async () => {
  const secret = 'the-old-secret';
  const { pool, queries } = makeRotatePool(validRow(secret));
  const out = await rotateRefresh(pool, { rawRefresh: `sess-1.${secret}`, userAgent: 'ua' }, { now: NOW, config: CONFIG });
  assert.equal(out.ok, true);
  assert.equal(out.sessionId, 'sess-1');
  assert.equal(out.userId, 5);
  assert.equal(out.authVersion, 4);
  const parsed = parseRefreshToken(out.refreshToken);
  assert.equal(parsed.sessionId, 'sess-1');
  assert.notEqual(parsed.secret, secret, 'secret rotated');
  // Rotation must NOT touch idle/absolute (refresh is not activity).
  const upd = queries.find((q) => /UPDATE auth_sessions/.test(q.sql));
  assert.doesNotMatch(upd.sql, /idle_expires_at/);
  assert.doesNotMatch(upd.sql, /absolute_expires_at/);
  assert.doesNotMatch(upd.sql, /last_activity_at/);
});

test('rotateRefresh: replayed/rotated secret is reuse → revoke', async () => {
  const { pool } = makeRotatePool(validRow('current-secret'));
  const out = await rotateRefresh(pool, { rawRefresh: 'sess-1.an-old-rotated-secret' }, { now: NOW, config: CONFIG });
  assert.equal(out.ok, false);
  assert.equal(out.reason, 'reuse');
});

test('rotateRefresh: previous secret within grace window succeeds without re-rotating', async () => {
  const row = validRow('current-secret');
  row.prev_refresh_token_hash = hashSecret('previous-secret');
  row.rotated_at = past(5_000); // 5s ago, within 30s grace
  const { pool, queries } = makeRotatePool(row);
  const out = await rotateRefresh(pool, { rawRefresh: 'sess-1.previous-secret' }, { now: NOW, config: CONFIG });
  assert.equal(out.ok, true);
  assert.equal(out.rotated, false);
  assert.equal(out.refreshToken, null, 'grace hit leaves the shared cookie untouched');
  assert.equal(queries.some((q) => /UPDATE auth_sessions/.test(q.sql)), false, 'no re-rotation');
});

test('rotateRefresh: previous secret AFTER grace window is reuse → revoke', async () => {
  const row = validRow('current-secret');
  row.prev_refresh_token_hash = hashSecret('previous-secret');
  row.rotated_at = past(60_000); // 60s ago, past 30s grace
  const { pool } = makeRotatePool(row);
  const out = await rotateRefresh(pool, { rawRefresh: 'sess-1.previous-secret' }, { now: NOW, config: CONFIG });
  assert.equal(out.ok, false);
  assert.equal(out.reason, 'reuse');
});

test('rotateRefresh: idle-expired session refused', async () => {
  const row = validRow('s'); row.idle_expires_at = past(1000);
  const { pool } = makeRotatePool(row);
  const out = await rotateRefresh(pool, { rawRefresh: 'sess-1.s' }, { now: NOW, config: CONFIG });
  assert.equal(out.ok, false);
  assert.equal(out.reason, 'idle');
});

test('rotateRefresh: absolute-expired session refused even with valid secret', async () => {
  const row = validRow('s'); row.absolute_expires_at = past(1000);
  const { pool } = makeRotatePool(row);
  const out = await rotateRefresh(pool, { rawRefresh: 'sess-1.s' }, { now: NOW, config: CONFIG });
  assert.equal(out.ok, false);
  assert.equal(out.reason, 'absolute');
});

test('rotateRefresh: auth_version bump (password/disable) invalidates', async () => {
  const row = validRow('s'); row.user_auth_version = 9; // bumped since issue (4)
  const { pool } = makeRotatePool(row);
  const out = await rotateRefresh(pool, { rawRefresh: 'sess-1.s' }, { now: NOW, config: CONFIG });
  assert.equal(out.ok, false);
  assert.equal(out.reason, 'auth_version');
});

test('rotateRefresh: passive (disabled) user refused', async () => {
  const row = validRow('s'); row.user_status = 'passive';
  const { pool } = makeRotatePool(row);
  const out = await rotateRefresh(pool, { rawRefresh: 'sess-1.s' }, { now: NOW, config: CONFIG });
  assert.equal(out.ok, false);
  assert.equal(out.reason, 'user_disabled');
});

test('rotateRefresh: already-revoked session refused', async () => {
  const row = validRow('s'); row.revoked_at = past(5000);
  const { pool } = makeRotatePool(row);
  const out = await rotateRefresh(pool, { rawRefresh: 'sess-1.s' }, { now: NOW, config: CONFIG });
  assert.equal(out.ok, false);
  assert.equal(out.reason, 'revoked');
});

test('rotateRefresh: unknown session refused', async () => {
  const { pool } = makeRotatePool(null);
  const out = await rotateRefresh(pool, { rawRefresh: 'sess-x.s' }, { now: NOW, config: CONFIG });
  assert.equal(out.ok, false);
  assert.equal(out.reason, 'not_found');
});
