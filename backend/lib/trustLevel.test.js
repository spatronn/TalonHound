import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import {
  TRUST_LEVELS,
  TRUST_LEVEL_VALUES,
  isValidTrustLevel,
  TRUST_LEVEL_TRUSTED,
  TRUST_LEVEL_MEDIUM,
  TRUST_LEVEL_NOT_CATEGORIZED
} from './trustLevel.js';

const migrationsDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '../migrations');

test('canonical trust levels are exactly trusted, medium, not_categorized', () => {
  assert.deepEqual([...TRUST_LEVEL_VALUES].sort(), ['medium', 'not_categorized', 'trusted']);
  assert.equal(TRUST_LEVELS.size, 3);
  assert.equal(TRUST_LEVEL_TRUSTED, 'trusted');
  assert.equal(TRUST_LEVEL_MEDIUM, 'medium');
  assert.equal(TRUST_LEVEL_NOT_CATEGORIZED, 'not_categorized');
});

test('isValidTrustLevel accepts only English canonical values', () => {
  assert.equal(isValidTrustLevel('trusted'), true);
  assert.equal(isValidTrustLevel('medium'), true);
  assert.equal(isValidTrustLevel('not_categorized'), true);
  assert.equal(isValidTrustLevel('guvenilir'), false);
  assert.equal(isValidTrustLevel('orta'), false);
  assert.equal(isValidTrustLevel('güvenilir'), false);
  assert.equal(isValidTrustLevel(''), false);
  assert.equal(isValidTrustLevel(null), false);
});

test('001_core CHECK and seeds use English trust levels only', () => {
  const sql = readFileSync(path.join(migrationsDir, '001_core.sql'), 'utf8');
  assert.match(
    sql,
    /CONSTRAINT integration_feeds_trust_level_check CHECK \(\(trust_level = ANY \(ARRAY\['trusted'::text, 'medium'::text, 'not_categorized'::text\]\)\)\)/
  );
  assert.equal(sql.includes("'guvenilir'"), false);
  // Legacy medium literal must not appear as a trust_level seed value.
  assert.equal(sql.includes(", 'orta', true"), false);
  assert.match(sql, /'certpl-warning-list', 'CERT\.PL Dangerous Websites', 'https:\/\/hole\.cert\.pl\/domains\/v2\/domains\.json', '\*\/5 \* \* \* \*', 'trusted'/);
  assert.match(sql, /'alienvault-otx', 'AlienVault OTX', 'https:\/\/otx\.alienvault\.com\/api\/v1\/pulses\/subscribed', '0 \* \* \* \*', 'medium'/);
  assert.match(sql, /'usom-trcert'[\s\S]{0,200}'trusted'/);
});

test('010_certpl seeds trusted trust_level', () => {
  const sql = readFileSync(path.join(migrationsDir, '010_certpl_warning_list.sql'), 'utf8');
  assert.match(sql, /'trusted'/);
  assert.equal(sql.includes("'guvenilir'"), false);
});

test('011 migration converts legacy Turkish values and recreates English CHECK', () => {
  const sql = readFileSync(path.join(migrationsDir, '011_trust_level_english_values.sql'), 'utf8');
  assert.match(sql, /DROP CONSTRAINT IF EXISTS integration_feeds_trust_level_check/);
  assert.match(sql, /SET trust_level = 'trusted'[\s\S]*WHERE trust_level = 'guvenilir'/);
  assert.match(sql, /SET trust_level = 'medium'[\s\S]*WHERE trust_level = 'orta'/);
  assert.match(
    sql,
    /ADD CONSTRAINT integration_feeds_trust_level_check[\s\S]*ARRAY\['trusted'::text, 'medium'::text, 'not_categorized'::text\]/
  );
  assert.match(sql, /RAISE EXCEPTION/);
  assert.match(sql, /unexpected trust_level/);
});
