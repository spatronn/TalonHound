import test from 'node:test';
import assert from 'node:assert/strict';
import { getProductVersionInfo, readCanonicalVersion } from './productVersion.js';

function withEnv(vars, fn) {
  const previous = {};
  for (const [key, value] of Object.entries(vars)) {
    previous[key] = process.env[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  try {
    return fn();
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

test('readCanonicalVersion reads repository VERSION file', () => {
  assert.equal(readCanonicalVersion(), '0.1.1-beta.5');
});

test('Docker placeholder TALONHOUND_VERSION=dev falls back to VERSION file', () => {
  withEnv({
    TALONHOUND_VERSION: 'dev',
    TALONHOUND_COMMIT: 'dev',
    TALONHOUND_BUILD_DATE: 'unknown'
  }, () => {
    const info = getProductVersionInfo();
    assert.equal(info.version, '0.1.1-beta.5');
    assert.equal(info.channel, 'beta');
    assert.equal(info.commit, 'unknown');
  });
});

test('explicit SemVer TALONHOUND_VERSION overrides VERSION file', () => {
  withEnv({
    TALONHOUND_VERSION: '0.1.0-beta.9',
    TALONHOUND_COMMIT: 'abc1234'
  }, () => {
    const info = getProductVersionInfo();
    assert.equal(info.version, '0.1.0-beta.9');
    assert.equal(info.channel, 'beta');
    assert.equal(info.commit, 'abc1234');
  });
});
