import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeThreatClassification,
  validateThreatClassification,
  threatClassificationLabel,
  listThreatClassifications
} from './threatClassification.js';

describe('threatClassification', () => {
  it('normalizes legacy c2 to command_and_control', () => {
    assert.equal(normalizeThreatClassification('c2'), 'command_and_control');
    assert.equal(normalizeThreatClassification('C2'), 'command_and_control');
  });

  it('returns unknown for invalid values', () => {
    assert.equal(normalizeThreatClassification('not-a-real-class'), 'unknown');
  });

  it('labels C2 correctly without typo', () => {
    assert.equal(threatClassificationLabel('command_and_control'), 'Command and Control (C2)');
    assert.equal(threatClassificationLabel('exploit'), 'Exploit / Exploitation');
  });

  it('validates canonical values', () => {
    const ok = validateThreatClassification('phishing');
    assert.equal(ok.ok, true);
    assert.equal(ok.value, 'phishing');
  });

  it('exports full canonical list', () => {
    const list = listThreatClassifications();
    assert.ok(list.some((x) => x.value === 'unknown'));
    assert.ok(list.some((x) => x.value === 'command_and_control'));
    assert.equal(list.find((x) => x.value === 'exploit')?.label, 'Exploit / Exploitation');
  });
});
