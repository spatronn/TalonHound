/**
 * Threat Library route permission / response contract smoke tests (no live DB).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { maskAiSettingsForClient } from '../lib/threatLibrary/ai/providers.js';

const routeSrc = readFileSync(
  path.join(path.dirname(fileURLToPath(import.meta.url)), 'threatLibrary.js'),
  'utf8'
);

test('AI settings routes are admin-gated', () => {
  assert.match(routeSrc, /\/api\/threat-library\/ai-settings[\s\S]*?requireRole\(ROLES\.ADMIN\)/);
  assert.match(routeSrc, /\/api\/threat-library\/ai-settings\/api-key[\s\S]*?requireRole\(ROLES\.ADMIN\)/);
});

test('import routes require analyst or admin', () => {
  assert.match(routeSrc, /import\/url[\s\S]*?requireRole\(ROLES\.ADMIN, ROLES\.ANALYST\)/);
  assert.match(routeSrc, /import\/pdf[\s\S]*?requireRole\(ROLES\.ADMIN, ROLES\.ANALYST\)/);
  assert.match(routeSrc, /import\/thib[\s\S]*?requireRole\(ROLES\.ADMIN, ROLES\.ANALYST\)/);
});

test('delete is admin-only', () => {
  assert.match(routeSrc, /reports\/:publicId'[\s\S]*?requireRole\(ROLES\.ADMIN\)/);
});

test('THIB import path does not call AI analyze', () => {
  assert.equal(routeSrc.includes('analyzeThreatDocument'), false);
  assert.equal(routeSrc.includes('runAnalysisPipeline'), false);
  assert.match(routeSrc, /importThibBundle/);
  assert.match(routeSrc, /previewThibImport/);
});

test('masked settings never include api_key field', () => {
  const m = maskAiSettingsForClient({ api_key: 'super-secret-key-value', provider: 'openai', enabled: true });
  assert.equal('api_key' in m, false);
  assert.ok(!JSON.stringify(m).includes('super-secret-key-value'));
});
