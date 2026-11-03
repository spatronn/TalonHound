#!/usr/bin/env node
/**
 * CI gate for Threat Library extraction changes.
 *
 * If a change touches code that decides extraction or membership, it must also
 * carry evaluation evidence: a new or changed benchmark case, metamorphic case
 * or sealed label. Refreshing baseline.json alone is not evidence, because an
 * old fixture staying unchanged says nothing about the new behavior.
 *
 *   node scripts/release/check-extraction-contract-change.js <base-ref>
 */
import { execFileSync } from 'node:child_process';

const base = process.argv[2] || 'origin/main';

const LIB = 'backend/lib/threatLibrary/';
const DECISION_CODE = [
  'candidateExtraction.js', 'candidateValue.js', 'candidateTyping.js', 'defang.js', 'digestSemantics.js', 'documentZones.js',
  'evidencePolicy.js', 'indicatorMembership.js', 'indicatorScope.js', 'ipv4VersionContext.js', 'ipv6Tokens.js', 'membershipDecision.js',
  'observableTypeResolver.js', 'pdfLayout.js', 'sourceOccurrence.js', 'tableSemantics.js', 'extract/htmlBlocks.js', 'extract/extractHtml.js',
  'sectionTree/annotate.js', 'sectionTree/authority.js'
].map((f) => LIB + f);

const EVIDENCE = [
  /^backend\/lib\/threatLibrary\/benchmark\/(?:cases|real-reports|heldOut\/cases|sealed\/cases)\//,
  /^backend\/lib\/threatLibrary\/benchmark\/.*[mM]etamorphic.*\.(?:js|json)$/,
  /^backend\/lib\/threatLibrary\/benchmark\/layoutVariants\.js$/
];

const changed = execFileSync('git', ['diff', '--name-only', `${base}...HEAD`], { encoding: 'utf8' })
  .split('\n')
  .map((s) => s.trim())
  .filter(Boolean);

const decisionChanges = changed.filter((f) => DECISION_CODE.includes(f));
if (!decisionChanges.length) {
  console.log('No extraction decision code changed.');
  process.exit(0);
}
const evidence = changed.filter((f) => EVIDENCE.some((re) => re.test(f)));
console.log(`Extraction decision code changed:\n  ${decisionChanges.join('\n  ')}`);
if (!evidence.length) {
  console.error(
    '\nThis change alters extraction decisions but adds no evaluation evidence.\n' +
    'Add or change a benchmark case, a metamorphic case or a label under backend/lib/threatLibrary/benchmark/.\n' +
    'Refreshing baseline.json alone does not count.'
  );
  process.exit(1);
}
console.log(`Evaluation evidence in this change:\n  ${evidence.join('\n  ')}`);
