import test from 'node:test';
import assert from 'node:assert/strict';
import { formatDnsmaniaCount, getDnsmaniaPresentation } from './dnsmaniaPresentation.js';

function relations(count) {
  return Array.from({ length: count }, (_, index) => ({ domain: `example-${index}.com` }));
}

test('shows five of a 423710 exact global total', () => {
  const presentation = getDnsmaniaPresentation({
    lookupType: 'ip',
    summary: {
      associated_domain_count: 423710,
      associated_domain_count_is_exact: true,
      associated_domains_returned: 5
    },
    relations: relations(5)
  });

  assert.equal(presentation.totalCount, 423710);
  assert.equal(presentation.shownCount, 5);
  assert.equal(presentation.shownRelations.length, 5);
  assert.equal(presentation.showHint, true);
  assert.equal(presentation.formattedTotal, '423,710');
});

test('does not show a hint when all three relations are returned', () => {
  const presentation = getDnsmaniaPresentation({
    lookupType: 'ip',
    summary: { associated_domain_count: 3, associated_domain_count_is_exact: true },
    relations: relations(3)
  });

  assert.equal(presentation.totalCount, 3);
  assert.equal(presentation.shownCount, 3);
  assert.equal(presentation.showHint, false);
});

test('preserves the empty no-data presentation', () => {
  const presentation = getDnsmaniaPresentation({
    lookupType: 'ip',
    summary: { associated_domain_count: 0, associated_domain_count_is_exact: true },
    relations: []
  });

  assert.deepEqual(presentation.shownRelations, []);
  assert.equal(presentation.totalCount, 0);
  assert.equal(presentation.shownCount, 0);
  assert.equal(presentation.showHint, false);
  assert.equal(presentation.formattedTotal, '0');
});

test('legacy payload falls back to distinct persisted domains only', () => {
  const presentation = getDnsmaniaPresentation({
    lookupType: 'ip',
    summary: {},
    relations: [
      { domain: 'A.example' },
      { domain: 'a.example' },
      { domain: 'b.example' }
    ]
  });

  assert.equal(presentation.totalCount, 2);
  assert.equal(presentation.shownCount, 2);
  assert.equal(presentation.showHint, false);
});

test('valid persisted count survives reload instead of falling to returned length', () => {
  const presentation = getDnsmaniaPresentation({
    lookupType: 'ip',
    summary: { associated_domain_count: 423710, associated_domain_count_is_exact: true },
    relations: relations(5)
  });

  assert.equal(presentation.totalCount, 423710);
  assert.notEqual(presentation.totalCount, presentation.shownCount);
});

test('limits a defensive oversized relation array to five', () => {
  const presentation = getDnsmaniaPresentation({
    lookupType: 'ip',
    summary: { associated_domain_count: 12 },
    relations: relations(12)
  });

  assert.equal(presentation.shownRelations.length, 5);
  assert.equal(presentation.showHint, true);
});

test('formats counts with en-US grouping', () => {
  assert.equal(formatDnsmaniaCount(423710), '423,710');
});
