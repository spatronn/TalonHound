import test from 'node:test';
import assert from 'node:assert/strict';

/** Side-effect import requires REDIS_PASSWORD or REDIS_URL; set a local fixture before load. */
async function loadValidateRedisPasswordEnv() {
  if (!process.env.REDIS_PASSWORD && !process.env.REDIS_URL?.trim()) {
    process.env.REDIS_PASSWORD = 'local-only-test-secret';
  }
  const mod = await import('./ensure-redis-password.js');
  return mod.validateRedisPasswordEnv;
}

test('validateRedisPasswordEnv accepts REDIS_PASSWORD', async () => {
  const validateRedisPasswordEnv = await loadValidateRedisPasswordEnv();
  assert.doesNotThrow(() => validateRedisPasswordEnv({ REDIS_PASSWORD: 'local-only-test-secret' }));
});

test('validateRedisPasswordEnv accepts REDIS_URL when password unset', async () => {
  const validateRedisPasswordEnv = await loadValidateRedisPasswordEnv();
  assert.doesNotThrow(() =>
    validateRedisPasswordEnv({ REDIS_URL: 'redis://:local-only-test-secret@127.0.0.1:6379' })
  );
});

test('validateRedisPasswordEnv throws when both unset', async () => {
  const validateRedisPasswordEnv = await loadValidateRedisPasswordEnv();
  assert.throws(() => validateRedisPasswordEnv({}), /REDIS_PASSWORD is required/);
});

test('validateRedisPasswordEnv throws for empty REDIS_PASSWORD without REDIS_URL', async () => {
  const validateRedisPasswordEnv = await loadValidateRedisPasswordEnv();
  assert.throws(() => validateRedisPasswordEnv({ REDIS_PASSWORD: '' }), /REDIS_PASSWORD is required/);
});

test('validateRedisPasswordEnv throws for whitespace-only REDIS_URL without password', async () => {
  const validateRedisPasswordEnv = await loadValidateRedisPasswordEnv();
  assert.throws(() => validateRedisPasswordEnv({ REDIS_URL: '   ' }), /REDIS_PASSWORD is required/);
});
