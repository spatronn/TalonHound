import test from 'node:test';
import assert from 'node:assert/strict';
import { buildEmptyStateModel } from './emptyState.js';

test('empty state hides CTA when read-only', () => {
  const m = buildEmptyStateModel({
    title: 'No tags',
    description: 'Create a tag to get started.',
    ctaLabel: 'Add Tag',
    canWrite: false
  });
  assert.equal(m.showCta, false);
});

test('empty state shows CTA when writable', () => {
  const m = buildEmptyStateModel({
    title: 'No tags',
    ctaLabel: 'Add Tag',
    canWrite: true
  });
  assert.equal(m.showCta, true);
  assert.equal(m.ctaLabel, 'Add Tag');
});
