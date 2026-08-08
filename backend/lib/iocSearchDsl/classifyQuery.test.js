import test from 'node:test';
import assert from 'node:assert/strict';
import { parseSearchQuery } from './index.js';
import { classifyQuery, DEEP_SEARCH_REASONS } from './classifyQuery.js';

function classify(query) {
  const { ast } = parseSearchQuery(query);
  return classifyQuery(ast);
}

test('exact sha256 lookup stays interactive', () => {
  const r = classify(`sha256 equals "${'a'.repeat(64)}"`);
  assert.equal(r.mode, 'interactive');
  assert.equal(r.reason, null);
});

test('exact md5 stays interactive', () => {
  const r = classify(`md5 equals "${'b'.repeat(32)}"`);
  assert.equal(r.mode, 'interactive');
});

test('exact IP equals stays interactive', () => {
  const r = classify('ioc equals "8.8.8.8"');
  assert.equal(r.mode, 'interactive');
});

test('exact domain equals stays interactive', () => {
  const r = classify('ioc equals "example.com"');
  assert.equal(r.mode, 'interactive');
});

test('enum type equals stays interactive', () => {
  const r = classify('type equals "domain"');
  assert.equal(r.mode, 'interactive');
});

test('classification equals stays interactive', () => {
  const r = classify('classification equals "phishing"');
  assert.equal(r.mode, 'interactive');
});

test('date range stays interactive', () => {
  const r = classify('created_at after "2026-01-01"');
  assert.equal(r.mode, 'interactive');
});

test('ioc contains with a full trigram stays interactive', () => {
  const r = classify('ioc contains "evil"');
  assert.equal(r.mode, 'interactive');
});

test('source contains is routed to deep_search (correlated EXISTS scan)', () => {
  const r = classify('source contains "Siber"');
  assert.equal(r.mode, 'deep_search');
  assert.equal(r.reason, DEEP_SEARCH_REASONS.SOURCE_SCAN);
});

test('source equals is also routed to deep_search', () => {
  const r = classify('source equals "USOM"');
  assert.equal(r.mode, 'deep_search');
  assert.equal(r.reason, DEEP_SEARCH_REASONS.SOURCE_SCAN);
});

test('short leading-wildcard contains is deep_search', () => {
  const r = classify('ioc contains "ab"');
  assert.equal(r.mode, 'deep_search');
  assert.equal(r.reason, DEEP_SEARCH_REASONS.LEADING_WILDCARD);
});

test('negative contains is deep_search', () => {
  const r = classify('ioc not_contains "evil"');
  assert.equal(r.mode, 'deep_search');
  assert.equal(r.reason, DEEP_SEARCH_REASONS.NEGATIVE_PREDICATE);
});

test('AND with a selective hash rescues an expensive sibling', () => {
  const r = classify(`sha256 equals "${'c'.repeat(64)}" AND source contains "USOM"`);
  assert.equal(r.mode, 'interactive');
});

test('AND without a selective predicate stays deep_search', () => {
  const r = classify('source contains "x" AND type equals "domain"');
  assert.equal(r.mode, 'deep_search');
});

test('OR with an expensive branch is deep_search', () => {
  const r = classify('ioc equals "example.com" OR source contains "USOM"');
  assert.equal(r.mode, 'deep_search');
  assert.equal(r.reason, DEEP_SEARCH_REASONS.SOURCE_SCAN);
});

test('a wide OR of individually-cheap branches is broad_or', () => {
  const r = classify('ioc equals "a.com" OR ioc equals "b.com" OR ioc equals "c.com" OR ioc equals "d.com" OR ioc equals "e.com"');
  assert.equal(r.mode, 'deep_search');
  assert.equal(r.reason, DEEP_SEARCH_REASONS.BROAD_OR);
});

test('a small OR of selective branches stays interactive', () => {
  const r = classify('ioc equals "a.com" OR ioc equals "b.com"');
  assert.equal(r.mode, 'interactive');
});

test('tag equals stays interactive; tag contains is deep_search', () => {
  assert.equal(classify('tag equals "apt"').mode, 'interactive');
  assert.equal(classify('tag contains "ap"').mode, 'deep_search');
});

test('classifier reads the AST, not raw text (normalized equivalence)', () => {
  // Parenthesized/space variants normalize to the same AST and classify identically.
  assert.equal(classify('(source contains "Siber")').mode, 'deep_search');
});
