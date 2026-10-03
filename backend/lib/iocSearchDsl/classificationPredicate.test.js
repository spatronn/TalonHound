import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildEffectiveClassificationPredicate,
  resolveClassificationTargets,
  storedClassificationSpellings,
  FEED_EVIDENCE_CLASSIFICATION_FN
} from './classificationPredicate.js';

function bindFactory() {
  const params = [];
  return {
    params,
    bind: (value) => {
      params.push(value);
      return `$${params.length}`;
    }
  };
}

test('resolveClassificationTargets keeps slug and normalized aliases', () => {
  const { slugs, unresolvedLabels } = resolveClassificationTargets(['c2', 'phishing'], {
    registry: [{ slug: 'command_and_control', name: 'Command and Control' }, { slug: 'phishing', name: 'Phishing' }]
  });
  assert.ok(slugs.includes('c2'));
  assert.ok(slugs.includes('command_and_control'));
  assert.ok(slugs.includes('phishing'));
  assert.deepEqual(unresolvedLabels, []);
});

test('storedClassificationSpellings includes underscore/space/hyphen forms', () => {
  const spellings = storedClassificationSpellings(['command_and_control']);
  assert.ok(spellings.includes('command_and_control'));
  assert.ok(spellings.includes('command and control') || spellings.includes('c2'));
});

test('equals predicate unions junction, stored, and indexed feed evidence', () => {
  const { bind, params } = bindFactory();
  const sql = buildEffectiveClassificationPredicate({
    bind,
    iocAlias: 'i',
    operator: 'equals',
    values: ['credential_theft'],
    fileArtifactsReadEnabled: false,
    registry: [{ slug: 'credential_theft', name: 'Credential Theft' }]
  });
  assert.match(sql, /\(i\.observable_type, i\.id\) IN \(/);
  assert.match(sql, /FROM ioc_threat_classifications itc/);
  assert.match(sql, /x\.threat_classification = ANY\(/);
  assert.match(sql, new RegExp(FEED_EVIDENCE_CLASSIFICATION_FN.replace('.', '\\.')));
  assert.match(sql, /ioc_threat_classification_overrides/);
  assert.ok(params.some((p) => Array.isArray(p) && p.includes('credential_theft')));
});

test('not_equals uses identity-closure anti-join', () => {
  const { bind } = bindFactory();
  const sql = buildEffectiveClassificationPredicate({
    bind,
    iocAlias: 'i',
    operator: 'not_equals',
    values: ['malware'],
    fileArtifactsReadEnabled: true,
    registry: [{ slug: 'malware', name: 'Malware' }]
  });
  assert.match(sql, /^NOT EXISTS \(/);
  assert.match(sql, /file_artifact_ioc_links/);
  assert.match(sql, /FROM ioc_threat_classifications itc/);
});

test('NOT classification equals is compiled by the query builder as identity negation', async () => {
  const { buildWhereClause } = await import('./queryBuilder.js');
  const { parseSearchQuery } = await import('./index.js');
  const ast = parseSearchQuery('NOT classification equals "phishing"').ast;
  const { sql } = buildWhereClause(ast, { fileArtifactsReadEnabled: false });
  assert.match(sql, /NOT EXISTS \(/);
  assert.match(sql, /ioc_feed_evidence_classification_slugs/);
});
