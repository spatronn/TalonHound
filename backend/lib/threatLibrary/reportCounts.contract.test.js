/**
 * Report list/detail count contract: matched Indicators are union-scoped.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  unionReportIndicatorMembershipSql
} from './indicatorMembership.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const storeSrc = readFileSync(path.join(here, 'store.js'), 'utf8');
const listQuerySrc = readFileSync(path.join(here, 'reportListQuery.js'), 'utf8');

test('matched_count SQL is scoped to Total Unique Indicator membership', () => {
  assert.match(
    storeSrc,
    /matched_ioc_id IS NOT NULL AND \(\$\{UNION_INDICATOR_WHERE\}\)/,
    'matched_count must AND the union Indicator predicate'
  );
  assert.match(
    storeSrc,
    /AS matched_count,\s*\n\s*\(SELECT COUNT\(\*\)::int FROM threat_report_entities/,
    'matched_count remains the last candidate-count column before entities'
  );
  // Union SQL itself stays the canonical membership generator.
  assert.match(unionReportIndicatorMembershipSql('c'), /has_original_document_occurrence|linked_source|threat_report_candidate_source_links/);
});

test('Indicators list sort uses total_unique_indicator_count', () => {
  assert.match(listQuerySrc, /indicators:\s*`total_unique_indicator_count/);
  assert.doesNotMatch(
    listQuerySrc,
    /indicators:\s*`indicator_count/,
    'do not sort Indicators by raw all-candidate count'
  );
});

test('count column comments document the analyst-facing contract', () => {
  assert.match(storeSrc, /total_unique_indicator_count\s*=\s*Original ∪ linked-source Indicators/);
  assert.match(storeSrc, /matched_count\s+=\s+union Indicators with matched_ioc_id/);
  assert.match(storeSrc, /never exceeds total_unique/);
});
