import test from 'node:test';
import assert from 'node:assert/strict';
import {
  maskSecret,
  validateCustomFeedAuth,
  normalizeCustomFeedAuth,
  buildCustomFeedAuthHeaders,
  buildCustomFeedAuthSummary,
  redactCustomFeedSecrets,
  ALLOWED_AUTH_TYPES
} from './customThreatFeedAuth.js';

// ---------------------------------------------------------------------------
// maskSecret
// ---------------------------------------------------------------------------

test('maskSecret returns null for empty/null input', () => {
  assert.equal(maskSecret(''), null);
  assert.equal(maskSecret(null), null);
  assert.equal(maskSecret(undefined), null);
});

test('maskSecret returns **** for short secrets', () => {
  assert.equal(maskSecret('ab'), '****');
  assert.equal(maskSecret('abcd'), '****');
});

test('maskSecret shows first+last chars for longer secrets', () => {
  const result = maskSecret('super-secret-token');
  assert.match(result, /\*{4}/);
  assert.equal(result.includes('super-secret-token'), false);
});

// ---------------------------------------------------------------------------
// validateCustomFeedAuth
// ---------------------------------------------------------------------------

test('validateCustomFeedAuth returns null for omitted auth (no-change semantics)', () => {
  assert.deepEqual(validateCustomFeedAuth(undefined), { ok: true, value: null });
  assert.deepEqual(validateCustomFeedAuth(null), { ok: true, value: null });
});

test('validateCustomFeedAuth accepts auth_type none', () => {
  const r = validateCustomFeedAuth({ auth_type: 'none' });
  assert.equal(r.ok, true);
  assert.equal(r.value.auth_type, 'none');
});

test('validateCustomFeedAuth rejects unknown auth_type', () => {
  const r = validateCustomFeedAuth({ auth_type: 'oauth2' });
  assert.equal(r.ok, false);
  assert.match(r.error, /auth_type must be one of/);
});

test('validateCustomFeedAuth rejects non-object', () => {
  assert.equal(validateCustomFeedAuth('bearer_token').ok, false);
  assert.equal(validateCustomFeedAuth(42).ok, false);
});

test('validateCustomFeedAuth bearer_token: accepts token', () => {
  const r = validateCustomFeedAuth({ auth_type: 'bearer_token', token: 'abc123' });
  assert.equal(r.ok, true);
  assert.equal(r.value.token, 'abc123');
});

test('validateCustomFeedAuth bearer_token: rejects empty token without clear flag', () => {
  const r = validateCustomFeedAuth({ auth_type: 'bearer_token', token: '' });
  assert.equal(r.ok, false);
  assert.match(r.error, /token must not be empty/);
});

test('validateCustomFeedAuth bearer_token: allows clear_token flag', () => {
  const r = validateCustomFeedAuth({ auth_type: 'bearer_token', clear_token: true });
  assert.equal(r.ok, true);
  assert.equal(r.value.clear_token, true);
});

test('validateCustomFeedAuth bearer_token: token omitted is allowed (preserve existing)', () => {
  const r = validateCustomFeedAuth({ auth_type: 'bearer_token' });
  assert.equal(r.ok, true);
  assert.equal(r.value.token, undefined);
});

test('validateCustomFeedAuth api_key_header: requires header_name', () => {
  const r = validateCustomFeedAuth({ auth_type: 'api_key_header', header_value: 'secret' });
  assert.equal(r.ok, false);
  assert.match(r.error, /header_name/);
});

test('validateCustomFeedAuth api_key_header: accepts valid header_name', () => {
  const r = validateCustomFeedAuth({ auth_type: 'api_key_header', header_name: 'X-API-Key', header_value: 'val' });
  assert.equal(r.ok, true);
  assert.equal(r.value.header_name, 'X-API-Key');
});

test('validateCustomFeedAuth api_key_header: rejects colon in header_name', () => {
  const r = validateCustomFeedAuth({ auth_type: 'api_key_header', header_name: 'X-Key:Bad', header_value: 'v' });
  assert.equal(r.ok, false);
  assert.match(r.error, /colon/);
});

test('validateCustomFeedAuth api_key_header: rejects newline in header_name', () => {
  const r = validateCustomFeedAuth({ auth_type: 'api_key_header', header_name: 'X-Key\nInjected', header_value: 'v' });
  assert.equal(r.ok, false);
  assert.match(r.error, /newline/);
});

test('validateCustomFeedAuth api_key_header: rejects blocked header Host', () => {
  const r = validateCustomFeedAuth({ auth_type: 'api_key_header', header_name: 'Host', header_value: 'evil.com' });
  assert.equal(r.ok, false);
  assert.match(r.error, /not allowed/);
});

test('validateCustomFeedAuth api_key_header: rejects blocked header transfer-encoding', () => {
  const r = validateCustomFeedAuth({ auth_type: 'api_key_header', header_name: 'Transfer-Encoding', header_value: 'chunked' });
  assert.equal(r.ok, false);
});

test('validateCustomFeedAuth api_key_header: Authorization header allowed', () => {
  const r = validateCustomFeedAuth({ auth_type: 'api_key_header', header_name: 'Authorization', header_value: 'Token abc' });
  assert.equal(r.ok, true);
});

test('validateCustomFeedAuth basic_auth: requires username', () => {
  const r = validateCustomFeedAuth({ auth_type: 'basic_auth', password: 'pass' });
  assert.equal(r.ok, false);
  assert.match(r.error, /username/);
});

test('validateCustomFeedAuth basic_auth: rejects empty password without clear flag', () => {
  const r = validateCustomFeedAuth({ auth_type: 'basic_auth', username: 'user', password: '' });
  assert.equal(r.ok, false);
  assert.match(r.error, /password must not be empty/);
});

test('validateCustomFeedAuth basic_auth: accepts with password omitted (preserve existing)', () => {
  const r = validateCustomFeedAuth({ auth_type: 'basic_auth', username: 'user' });
  assert.equal(r.ok, true);
  assert.equal(r.value.password, undefined);
});

test('ALLOWED_AUTH_TYPES contains exactly the four expected types', () => {
  assert.deepEqual([...ALLOWED_AUTH_TYPES].sort(), ['api_key_header', 'basic_auth', 'bearer_token', 'none']);
});

// ---------------------------------------------------------------------------
// normalizeCustomFeedAuth
// ---------------------------------------------------------------------------

test('normalizeCustomFeedAuth: null validatedAuth preserves existing', () => {
  const existing = { auth_type: 'bearer_token', token: 'oldtoken' };
  assert.deepEqual(normalizeCustomFeedAuth(null, existing), existing);
});

test('normalizeCustomFeedAuth: none clears everything', () => {
  const result = normalizeCustomFeedAuth({ auth_type: 'none' }, { auth_type: 'bearer_token', token: 'old' });
  assert.deepEqual(result, { auth_type: 'none' });
});

test('normalizeCustomFeedAuth: bearer_token with new token stores it', () => {
  const result = normalizeCustomFeedAuth(
    { auth_type: 'bearer_token', token: 'new-token' },
    { auth_type: 'bearer_token', token: 'old-token' }
  );
  assert.equal(result.token, 'new-token');
});

test('normalizeCustomFeedAuth: bearer_token with token omitted preserves existing', () => {
  const result = normalizeCustomFeedAuth(
    { auth_type: 'bearer_token', token: undefined },
    { auth_type: 'bearer_token', token: 'old-token' }
  );
  assert.equal(result.token, 'old-token');
});

test('normalizeCustomFeedAuth: bearer_token clear_token removes secret', () => {
  const result = normalizeCustomFeedAuth(
    { auth_type: 'bearer_token', clear_token: true },
    { auth_type: 'bearer_token', token: 'old-token' }
  );
  assert.equal(result.token, null);
});

test('normalizeCustomFeedAuth: auth_type change drops old secret', () => {
  const result = normalizeCustomFeedAuth(
    { auth_type: 'bearer_token', token: undefined },
    { auth_type: 'api_key_header', header_name: 'X-Key', header_value: 'old' }
  );
  assert.equal(result.token, null);
});

test('normalizeCustomFeedAuth: api_key_header preserves existing for same header_name', () => {
  const result = normalizeCustomFeedAuth(
    { auth_type: 'api_key_header', header_name: 'X-API-Key', header_value: undefined },
    { auth_type: 'api_key_header', header_name: 'X-API-Key', header_value: 'old-val' }
  );
  assert.equal(result.header_value, 'old-val');
});

test('normalizeCustomFeedAuth: api_key_header drops existing when header_name changes', () => {
  const result = normalizeCustomFeedAuth(
    { auth_type: 'api_key_header', header_name: 'X-New-Key', header_value: undefined },
    { auth_type: 'api_key_header', header_name: 'X-Old-Key', header_value: 'old-val' }
  );
  assert.equal(result.header_value, null);
});

test('normalizeCustomFeedAuth: basic_auth with clear_password removes it', () => {
  const result = normalizeCustomFeedAuth(
    { auth_type: 'basic_auth', username: 'user', clear_password: true },
    { auth_type: 'basic_auth', username: 'user', password: 'secret' }
  );
  assert.equal(result.password, null);
});

test('normalizeCustomFeedAuth: basic_auth preserves existing password when omitted', () => {
  const result = normalizeCustomFeedAuth(
    { auth_type: 'basic_auth', username: 'user', password: undefined },
    { auth_type: 'basic_auth', username: 'user', password: 'old-pass' }
  );
  assert.equal(result.password, 'old-pass');
});

// ---------------------------------------------------------------------------
// buildCustomFeedAuthHeaders
// ---------------------------------------------------------------------------

test('buildCustomFeedAuthHeaders: none returns empty headers', () => {
  assert.deepEqual(buildCustomFeedAuthHeaders({ auth_type: 'none' }), {});
  assert.deepEqual(buildCustomFeedAuthHeaders(null), {});
  assert.deepEqual(buildCustomFeedAuthHeaders({}), {});
});

test('buildCustomFeedAuthHeaders: bearer_token builds Authorization Bearer', () => {
  const headers = buildCustomFeedAuthHeaders({ auth_type: 'bearer_token', token: 'tok123' });
  assert.equal(headers['Authorization'], 'Bearer tok123');
});

test('buildCustomFeedAuthHeaders: bearer_token with null token returns empty', () => {
  const headers = buildCustomFeedAuthHeaders({ auth_type: 'bearer_token', token: null });
  assert.equal(headers['Authorization'], undefined);
});

test('buildCustomFeedAuthHeaders: api_key_header builds custom header', () => {
  const headers = buildCustomFeedAuthHeaders({ auth_type: 'api_key_header', header_name: 'X-API-Key', header_value: 'val123' });
  assert.equal(headers['X-API-Key'], 'val123');
});

test('buildCustomFeedAuthHeaders: basic_auth builds Basic Authorization', () => {
  const headers = buildCustomFeedAuthHeaders({ auth_type: 'basic_auth', username: 'user', password: 'pass' });
  const expected = `Basic ${Buffer.from('user:pass').toString('base64')}`;
  assert.equal(headers['Authorization'], expected);
});

test('buildCustomFeedAuthHeaders: basic_auth with missing password returns empty', () => {
  const headers = buildCustomFeedAuthHeaders({ auth_type: 'basic_auth', username: 'user', password: null });
  assert.equal(headers['Authorization'], undefined);
});

// ---------------------------------------------------------------------------
// buildCustomFeedAuthSummary
// ---------------------------------------------------------------------------

test('buildCustomFeedAuthSummary: none returns safe summary', () => {
  const s = buildCustomFeedAuthSummary({ auth_type: 'none' });
  assert.equal(s.auth_type, 'none');
  assert.equal(s.configured, false);
});

test('buildCustomFeedAuthSummary: bearer_token masks token', () => {
  const s = buildCustomFeedAuthSummary({ auth_type: 'bearer_token', token: 'super-secret-token-value' });
  assert.equal(s.auth_type, 'bearer_token');
  assert.equal(s.configured, true);
  assert.equal(s.masked_token.includes('super-secret-token-value'), false);
  assert.match(s.masked_token, /\*{4}/);
});

test('buildCustomFeedAuthSummary: bearer_token unconfigured', () => {
  const s = buildCustomFeedAuthSummary({ auth_type: 'bearer_token', token: null });
  assert.equal(s.configured, false);
  assert.equal(s.masked_token, null);
});

test('buildCustomFeedAuthSummary: api_key_header shows header_name but masks value', () => {
  const s = buildCustomFeedAuthSummary({ auth_type: 'api_key_header', header_name: 'X-API-Key', header_value: 'secret-api-key-123' });
  assert.equal(s.header_name, 'X-API-Key');
  assert.equal(s.masked_header_value.includes('secret-api-key-123'), false);
  assert.match(s.masked_header_value, /\*{4}/);
});

test('buildCustomFeedAuthSummary: basic_auth shows username but not password', () => {
  const s = buildCustomFeedAuthSummary({ auth_type: 'basic_auth', username: 'feed-user', password: 'topsecret' });
  assert.equal(s.username, 'feed-user');
  assert.equal(s.password_configured, true);
  assert.equal('password' in s, false);
});

test('buildCustomFeedAuthSummary: null credentials returns none', () => {
  assert.equal(buildCustomFeedAuthSummary(null).auth_type, 'none');
  assert.equal(buildCustomFeedAuthSummary({}).auth_type, 'none');
});

// ---------------------------------------------------------------------------
// redactCustomFeedSecrets
// ---------------------------------------------------------------------------

test('redactCustomFeedSecrets: bearer_token removes token from message', () => {
  const msg = 'Request failed: Authorization: Bearer super-secret-token';
  const result = redactCustomFeedSecrets(msg, { auth_type: 'bearer_token', token: 'super-secret-token' });
  assert.equal(result.includes('super-secret-token'), false);
  assert.match(result, /\[REDACTED\]/);
});

test('redactCustomFeedSecrets: api_key_header removes header_value', () => {
  const msg = 'Error: X-API-Key: my-secret-api-key not accepted';
  const result = redactCustomFeedSecrets(msg, { auth_type: 'api_key_header', header_name: 'X-API-Key', header_value: 'my-secret-api-key' });
  assert.equal(result.includes('my-secret-api-key'), false);
});

test('redactCustomFeedSecrets: basic_auth removes password and base64', () => {
  const pass = 'topsecret';
  const encoded = Buffer.from(`user:${pass}`).toString('base64');
  const msg = `Auth failed: ${pass} and encoded ${encoded}`;
  const result = redactCustomFeedSecrets(msg, { auth_type: 'basic_auth', username: 'user', password: pass });
  assert.equal(result.includes(pass), false);
  assert.equal(result.includes(encoded), false);
});

test('redactCustomFeedSecrets: null credentials returns message unchanged', () => {
  const msg = 'some error';
  assert.equal(redactCustomFeedSecrets(msg, null), msg);
  assert.equal(redactCustomFeedSecrets(msg, undefined), msg);
});

test('redactCustomFeedSecrets: null message returns null', () => {
  assert.equal(redactCustomFeedSecrets(null, { auth_type: 'bearer_token', token: 'tok' }), null);
});
