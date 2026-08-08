/**
 * JWT auth regressions for JWT-01 (role fail-closed) and related signing helpers.
 * Sets JWT_SECRET before dynamic import because auth.js loads ensure-jwt-secret.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import jwt from 'jsonwebtoken';

if (!process.env.JWT_SECRET || String(process.env.JWT_SECRET).trim().length < 32) {
  process.env.JWT_SECRET = 'test-jwt-secret-for-unit-tests-only!!';
}

const { signUserToken, requireAuth, AUTH_COOKIE_NAME } = await import('./auth.js');
const { ROLES } = await import('./rbac.js');

const secret = process.env.JWT_SECRET;

function invokeRequireAuth({ cookieToken, bearerToken } = {}) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (payload) => {
      if (settled) return;
      settled = true;
      resolve(payload);
    };

    const req = {
      headers: bearerToken ? { authorization: `Bearer ${bearerToken}` } : {},
      cookies: cookieToken ? { [AUTH_COOKIE_NAME]: cookieToken } : {}
    };
    const res = {
      status(code) {
        this.statusCode = code;
        return this;
      },
      json(body) {
        finish({
          statusCode: this.statusCode,
          body,
          user: req.user,
          authVia: req.authVia,
          next: false
        });
        return this;
      }
    };
    requireAuth(req, res, () => {
      finish({
        statusCode: null,
        body: null,
        user: req.user,
        authVia: req.authVia,
        next: true
      });
    });
  });
}

test('JWT-01: valid admin JWT authenticates as admin', async () => {
  const token = signUserToken({
    userId: 1,
    email: 'admin@talonhound.local',
    username: 'admin@talonhound.local',
    role: ROLES.ADMIN,
    authVersion: 1
  });
  const result = await invokeRequireAuth({ cookieToken: token });
  assert.equal(result.next, true);
  assert.equal(result.user.role, ROLES.ADMIN);
  assert.equal(result.user.id, 1);
});

test('JWT-01: valid readonly JWT remains readonly', async () => {
  const token = signUserToken({
    userId: 2,
    email: 'ro@talonhound.local',
    username: 'ro@talonhound.local',
    role: ROLES.READONLY,
    authVersion: 1
  });
  const result = await invokeRequireAuth({ cookieToken: token });
  assert.equal(result.next, true);
  assert.equal(result.user.role, ROLES.READONLY);
});

test('JWT-01: valid analyst JWT authenticates as analyst', async () => {
  const token = signUserToken({
    userId: 3,
    email: 'analyst@talonhound.local',
    username: 'analyst@talonhound.local',
    role: ROLES.ANALYST,
    authVersion: 1
  });
  const result = await invokeRequireAuth({ cookieToken: token });
  assert.equal(result.next, true);
  assert.equal(result.user.role, ROLES.ANALYST);
});

test('JWT-01: JWT missing role claim is rejected (401)', async () => {
  const token = jwt.sign(
    { email: 'legacy@talonhound.local', username: 'legacy@talonhound.local', userId: 9 },
    secret,
    { subject: 'legacy@talonhound.local', expiresIn: '1h' }
  );
  const result = await invokeRequireAuth({ cookieToken: token });
  assert.equal(result.next, false);
  assert.equal(result.statusCode, 401);
  assert.equal(result.user, undefined);
});

test('JWT-01: JWT with empty role claim is rejected', async () => {
  const token = jwt.sign(
    { email: 'legacy@talonhound.local', role: '', userId: 9 },
    secret,
    { subject: 'legacy@talonhound.local', expiresIn: '1h' }
  );
  const result = await invokeRequireAuth({ cookieToken: token });
  assert.equal(result.next, false);
  assert.equal(result.statusCode, 401);
});

test('JWT-01: JWT with unknown role claim is rejected', async () => {
  const token = jwt.sign(
    { email: 'legacy@talonhound.local', role: 'superadmin', userId: 9 },
    secret,
    { subject: 'legacy@talonhound.local', expiresIn: '1h' }
  );
  const result = await invokeRequireAuth({ cookieToken: token });
  assert.equal(result.next, false);
  assert.equal(result.statusCode, 401);
});

test('JWT-01: JWT with malformed non-string role is rejected', async () => {
  const token = jwt.sign(
    { email: 'legacy@talonhound.local', role: { nested: 'admin' }, userId: 9 },
    secret,
    { subject: 'legacy@talonhound.local', expiresIn: '1h' }
  );
  const result = await invokeRequireAuth({ cookieToken: token });
  assert.equal(result.next, false);
  assert.equal(result.statusCode, 401);
});

test('JWT-01: signUserToken refuses string payload (no implicit admin)', () => {
  assert.throws(() => signUserToken('admin@talonhound.local'), /explicit role|object payload/i);
});

test('JWT-01: signUserToken refuses omitted or invalid role (no default elevation)', () => {
  assert.throws(
    () => signUserToken({ email: 'x@talonhound.local', userId: 1, authVersion: 1 }),
    /explicit valid role/i
  );
  assert.throws(
    () => signUserToken({ email: 'x@talonhound.local', userId: 1, role: 'root', authVersion: 1 }),
    /explicit valid role/i
  );
  assert.throws(
    () => signUserToken({ email: 'x@talonhound.local', userId: 1, role: '', authVersion: 1 }),
    /explicit valid role/i
  );
});

test('JWT-01: Bearer path uses the same role rejection (when enabled)', async () => {
  const prev = process.env.ALLOW_JWT_BEARER;
  process.env.ALLOW_JWT_BEARER = '1';
  try {
    const token = jwt.sign(
      { email: 'legacy@talonhound.local', userId: 9 },
      secret,
      { subject: 'legacy@talonhound.local', expiresIn: '1h' }
    );
    const result = await invokeRequireAuth({ bearerToken: token });
    assert.equal(result.next, false);
    assert.equal(result.statusCode, 401);
  } finally {
    if (prev === undefined) delete process.env.ALLOW_JWT_BEARER;
    else process.env.ALLOW_JWT_BEARER = prev;
  }
});
