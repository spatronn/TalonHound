import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  MULTI_SELECT_MAX_CHIPS,
  MULTI_SELECT_LIST_MAX_HEIGHT,
  MULTI_SELECT_INLINE_LIST_MAX_HEIGHT,
  multiSelectListMaxHeight,
  filterMultiSelectOptions,
  toggleMultiSelectValue,
  summarizeMultiSelectChips
} from './searchableMultiSelect.js';

describe('filterMultiSelectOptions', () => {
  const options = [
    { value: 'malware', label: 'Malware' },
    { value: 'phishing', label: 'Phishing' },
    { value: 'c2', label: 'Command & Control' }
  ];

  it('returns all options for empty/whitespace query', () => {
    assert.deepEqual(filterMultiSelectOptions(options, ''), options);
    assert.deepEqual(filterMultiSelectOptions(options, '   '), options);
  });

  it('filters by label case-insensitively (substring)', () => {
    assert.deepEqual(filterMultiSelectOptions(options, 'phi').map((o) => o.value), ['phishing']);
    assert.deepEqual(filterMultiSelectOptions(options, 'MAL').map((o) => o.value), ['malware']);
    assert.deepEqual(filterMultiSelectOptions(options, 'control').map((o) => o.value), ['c2']);
  });

  it('returns empty array when nothing matches', () => {
    assert.deepEqual(filterMultiSelectOptions(options, 'zzz'), []);
  });

  it('supports a custom label accessor', () => {
    const actors = [{ id: 1, name: 'APT28' }, { id: 2, name: 'Lazarus' }];
    const res = filterMultiSelectOptions(actors, 'laz', (a) => a.name);
    assert.deepEqual(res.map((a) => a.id), [2]);
  });

  it('is null-safe', () => {
    assert.deepEqual(filterMultiSelectOptions(null, 'x'), []);
    assert.deepEqual(filterMultiSelectOptions(undefined, ''), []);
  });
});

describe('multiSelectListMaxHeight', () => {
  it('keeps the bounded popover height for the default (collapsed) variant', () => {
    // Guards the page-embedded collapsed pickers (e.g. IOC Add form) against
    // accidental resizing when the inline modal variant changes.
    assert.equal(multiSelectListMaxHeight(false), MULTI_SELECT_LIST_MAX_HEIGHT);
    assert.equal(multiSelectListMaxHeight(undefined), MULTI_SELECT_LIST_MAX_HEIGHT);
    assert.equal(MULTI_SELECT_LIST_MAX_HEIGHT, 260);
  });

  it('uses the larger, viewport-aware height for the inline modal variant', () => {
    assert.equal(multiSelectListMaxHeight(true), MULTI_SELECT_INLINE_LIST_MAX_HEIGHT);
    // Viewport aware (vh-clamped) so short screens stay usable.
    assert.match(String(MULTI_SELECT_INLINE_LIST_MAX_HEIGHT), /vh/);
    assert.notEqual(MULTI_SELECT_INLINE_LIST_MAX_HEIGHT, MULTI_SELECT_LIST_MAX_HEIGHT);
  });
});

describe('toggleMultiSelectValue', () => {
  it('adds a value when absent', () => {
    assert.deepEqual(toggleMultiSelectValue(['a'], 'b'), ['a', 'b']);
  });

  it('removes a value when present', () => {
    assert.deepEqual(toggleMultiSelectValue(['a', 'b'], 'a'), ['b']);
  });

  it('compares as strings and de-duplicates', () => {
    assert.deepEqual(toggleMultiSelectValue([1, 2], 3), ['1', '2', '3']);
    assert.deepEqual(toggleMultiSelectValue(['1', '1'], '2'), ['1', '2']);
  });

  it('is null-safe', () => {
    assert.deepEqual(toggleMultiSelectValue(null, 'a'), ['a']);
  });
});

describe('summarizeMultiSelectChips', () => {
  const labelFor = (v) => ({ malware: 'Malware', phishing: 'Phishing', c2: 'C2' }[v] || v);

  it('returns empty summary for no selection', () => {
    const { chips, overflowCount } = summarizeMultiSelectChips([], labelFor);
    assert.deepEqual(chips, []);
    assert.equal(overflowCount, 0);
  });

  it('maps selected values to labelled chips with no overflow when under the cap', () => {
    const { chips, overflowCount } = summarizeMultiSelectChips(['malware', 'phishing'], labelFor);
    assert.deepEqual(chips, [
      { value: 'malware', label: 'Malware' },
      { value: 'phishing', label: 'Phishing' }
    ]);
    assert.equal(overflowCount, 0);
  });

  it('caps chips and reports +N overflow', () => {
    const many = ['a', 'b', 'c', 'd', 'e', 'f'];
    const { chips, overflowCount } = summarizeMultiSelectChips(many, (v) => v, 4);
    assert.equal(chips.length, 4);
    assert.deepEqual(chips.map((c) => c.value), ['a', 'b', 'c', 'd']);
    assert.equal(overflowCount, 2);
  });

  it('defaults to MULTI_SELECT_MAX_CHIPS', () => {
    const many = Array.from({ length: MULTI_SELECT_MAX_CHIPS + 3 }, (_, i) => `v${i}`);
    const { chips, overflowCount } = summarizeMultiSelectChips(many, (v) => v);
    assert.equal(chips.length, MULTI_SELECT_MAX_CHIPS);
    assert.equal(overflowCount, 3);
  });

  it('falls back to the raw value when the label is empty/nullish', () => {
    const { chips } = summarizeMultiSelectChips(['x'], () => '');
    assert.deepEqual(chips, [{ value: 'x', label: 'x' }]);
  });
});

// Contract the ThreatClassification / ThreatActor wrappers rely on. The
// wrappers (in main.jsx) build their picker options WITHOUT the synthetic
// 'unknown'/'Not selected' rows and represent "none" as an empty array.
describe('wrapper selection semantics', () => {
  it('Threat Classifications: multi-select then unselect, never introducing "unknown"', () => {
    let sel = [];
    sel = toggleMultiSelectValue(sel, 'malware');
    sel = toggleMultiSelectValue(sel, 'phishing');
    assert.deepEqual(sel, ['malware', 'phishing']);
    sel = toggleMultiSelectValue(sel, 'malware'); // unselect
    assert.deepEqual(sel, ['phishing']);
    assert.ok(!sel.includes('unknown'));
  });

  it('Threat Classifications: "Unknown" == empty selection (no chips to summarize)', () => {
    const { chips, overflowCount } = summarizeMultiSelectChips([], (v) => v);
    assert.deepEqual(chips, []);
    assert.equal(overflowCount, 0); // closed field shows the "Unknown" none-label, not a chip
  });

  it('Threat Actors: empty selection produces no chips (placeholder is shown instead)', () => {
    const { chips } = summarizeMultiSelectChips([], (v) => v);
    assert.deepEqual(chips, []);
  });

  it('Threat Actors: ids are compared as strings so repeated toggles are stable', () => {
    let sel = [];
    sel = toggleMultiSelectValue(sel, 7);
    sel = toggleMultiSelectValue(sel, '7'); // same actor, string vs number
    assert.deepEqual(sel, []);
  });

  it('search filters the visible actor options by name', () => {
    const actors = [
      { value: '1', label: 'APT28' },
      { value: '2', label: 'Lazarus Group' },
      { value: '3', label: 'FIN7' }
    ];
    assert.deepEqual(filterMultiSelectOptions(actors, 'group', (o) => o.label).map((o) => o.value), ['2']);
  });
});
