/**
 * Unit tests for disposable File Artifact DB guardrails (no live DB).
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { assertFileArtifactDbTestAllowed } from './dbTestGuard.js';

describe('assertFileArtifactDbTestAllowed', () => {
  it('allows localhost test DB with explicit allow flag', () => {
    const cfg = assertFileArtifactDbTestAllowed({
      ALLOW_FILE_ARTIFACT_DB_TESTS: '1',
      NODE_ENV: 'test',
      DB_HOST: '127.0.0.1',
      DB_PORT: '55432',
      DB_NAME: 'talonhound_file_artifact_test',
      DB_USER: 'demo',
      DB_PASSWORD: 'test'
    });
    assert.equal(cfg.database, 'talonhound_file_artifact_test');
    assert.equal(cfg.port, 55432);
  });

  it('rejects missing allow flag', () => {
    assert.throws(
      () => assertFileArtifactDbTestAllowed({
        DB_HOST: '127.0.0.1',
        DB_NAME: 'foo_test',
        NODE_ENV: 'test'
      }),
      /ALLOW_FILE_ARTIFACT_DB_TESTS/
    );
  });

  it('rejects non-local host', () => {
    assert.throws(
      () => assertFileArtifactDbTestAllowed({
        ALLOW_FILE_ARTIFACT_DB_TESTS: '1',
        DB_HOST: 'prod-db.example',
        DB_NAME: 'demo_test',
        NODE_ENV: 'test'
      }),
      /DB_HOST/
    );
  });

  it('rejects DB name without _test', () => {
    assert.throws(
      () => assertFileArtifactDbTestAllowed({
        ALLOW_FILE_ARTIFACT_DB_TESTS: '1',
        DB_HOST: 'localhost',
        DB_NAME: 'demo',
        NODE_ENV: 'test'
      }),
      /_test/
    );
  });

  it('rejects production NODE_ENV', () => {
    assert.throws(
      () => assertFileArtifactDbTestAllowed({
        ALLOW_FILE_ARTIFACT_DB_TESTS: '1',
        DB_HOST: '127.0.0.1',
        DB_NAME: 'x_test',
        NODE_ENV: 'production'
      }),
      /NODE_ENV=production/
    );
  });
});
