import test from 'node:test';
import assert from 'node:assert/strict';
import { computeCustomThreatFeedContentFingerprint } from './customThreatFeedFingerprint.js';

test('custom threat feed fingerprint is stable for identical source content', () => {
  const a = computeCustomThreatFeedContentFingerprint({
    observable: 'evil.example',
    observableType: 'domain',
    confidence: 'medium'
  });
  const b = computeCustomThreatFeedContentFingerprint({
    observable: 'evil.example',
    observableType: 'domain',
    confidence: 'medium'
  });
  assert.equal(a, b);
  assert.match(a, /^[a-f0-9]{64}$/);
});

test('custom threat feed fingerprint changes when confidence changes', () => {
  const a = computeCustomThreatFeedContentFingerprint({
    observable: 'evil.example',
    observableType: 'domain',
    confidence: 'medium'
  });
  const b = computeCustomThreatFeedContentFingerprint({
    observable: 'evil.example',
    observableType: 'domain',
    confidence: 'high'
  });
  assert.notEqual(a, b);
});

test('custom threat feed fingerprint ignores confidence casing/whitespace', () => {
  const a = computeCustomThreatFeedContentFingerprint({
    observable: 'evil.example',
    observableType: 'domain',
    confidence: ' Medium '
  });
  const b = computeCustomThreatFeedContentFingerprint({
    observable: 'evil.example',
    observableType: 'domain',
    confidence: 'medium'
  });
  assert.equal(a, b);
});

test('custom threat feed fingerprint changes when observable changes', () => {
  const a = computeCustomThreatFeedContentFingerprint({
    observable: 'a.example',
    observableType: 'domain',
    confidence: 'medium'
  });
  const b = computeCustomThreatFeedContentFingerprint({
    observable: 'b.example',
    observableType: 'domain',
    confidence: 'medium'
  });
  assert.notEqual(a, b);
});
