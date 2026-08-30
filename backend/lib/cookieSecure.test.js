import test from 'node:test';
import assert from 'node:assert/strict';

if (!process.env.JWT_SECRET || String(process.env.JWT_SECRET).trim().length < 32) {
  process.env.JWT_SECRET = 'test-jwt-secret-for-unit-tests-only!!';
}

const { cookieSecureFlag } = await import('./auth.js');

test('JWT-05: production forces Secure even if forwarded proto is http', () => {
  const req = { headers: { 'x-forwarded-proto': 'http' }, secure: false };
  assert.equal(cookieSecureFlag(req, { NODE_ENV: 'production' }), true);
});

test('JWT-05: AUTH_COOKIE_SECURE=1 forces Secure', () => {
  assert.equal(
    cookieSecureFlag({ headers: {}, secure: false }, { AUTH_COOKIE_SECURE: '1', NODE_ENV: 'development' }),
    true
  );
});

test('JWT-05: AUTH_COOKIE_SECURE=0 allows non-Secure for local HTTP', () => {
  assert.equal(
    cookieSecureFlag(
      { headers: { 'x-forwarded-proto': 'https' }, secure: true },
      { AUTH_COOKIE_SECURE: '0', NODE_ENV: 'development' }
    ),
    false
  );
});

test('JWT-05: production ignores AUTH_COOKIE_SECURE=0 downgrade', () => {
  assert.equal(
    cookieSecureFlag(
      { headers: { 'x-forwarded-proto': 'http' }, secure: false },
      { AUTH_COOKIE_SECURE: '0', NODE_ENV: 'production' }
    ),
    true
  );
});

test('JWT-05: non-production still upgrades when forwarded proto is https', () => {
  assert.equal(
    cookieSecureFlag({ headers: { 'x-forwarded-proto': 'https' }, secure: false }, { NODE_ENV: 'development' }),
    true
  );
});

test('JWT-05: non-production HTTP stays non-Secure without override', () => {
  assert.equal(
    cookieSecureFlag({ headers: {}, secure: false }, { NODE_ENV: 'development' }),
    false
  );
});
