import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  formatMitreConfidence,
  groupMitreByTactic,
  mergeReportIntelPayload,
  normalizeMitreMappings
} from './reportMitre.js';

const here = path.dirname(fileURLToPath(import.meta.url));

test('normalizeMitreMappings drops invalid rows and de-duplicates by technique id', () => {
  assert.deepEqual(
    normalizeMitreMappings([
      { technique_id: 'T1566.002', technique_name: 'Phishing: Spearphishing Link', tactics: [{ id: 'TA0001', name: 'Initial Access' }], confidence: 0.9, evidence: 'links' },
      { technique_id: 'T1566.002', technique_name: 'dup' },
      { technique_id: '  ' },
      null
    ]),
    [{
      technique_id: 'T1566.002',
      technique_name: 'Phishing: Spearphishing Link',
      attack_type: null,
      url: null,
      tactics: [{ id: 'TA0001', name: 'Initial Access' }],
      confidence: 0.9,
      evidence: 'links'
    }]
  );
  assert.deepEqual(normalizeMitreMappings(undefined), []);
});

test('groupMitreByTactic lists a multi-tactic technique under each tactic once per group', () => {
  const groups = groupMitreByTactic([
    {
      technique_id: 'T1078',
      technique_name: 'Valid Accounts',
      tactics: [
        { id: 'TA0001', name: 'Initial Access' },
        { id: 'TA0003', name: 'Persistence' }
      ]
    },
    {
      technique_id: 'T1566.002',
      technique_name: 'Phishing: Spearphishing Link',
      tactics: [{ id: 'TA0001', name: 'Initial Access' }]
    }
  ]);
  assert.deepEqual(groups.map((g) => g.id), ['TA0001', 'TA0003']);
  assert.deepEqual(groups[0].items.map((i) => i.technique_id), ['T1078', 'T1566.002']);
  assert.deepEqual(groups[1].items.map((i) => i.technique_id), ['T1078']);
});

test('empty mappings produce no tactic groups', () => {
  assert.deepEqual(groupMitreByTactic([]), []);
  assert.equal(formatMitreConfidence(null), null);
  assert.equal(formatMitreConfidence(0.91), '91%');
});

test('mergeReportIntelPayload keeps tags and MITRE when a later payload omits them', () => {
  const prev = { id: 'r', tags: [{ id: 1, name: 'atm' }], mitre_attack: [{ technique_id: 'T1566' }] };
  assert.deepEqual(mergeReportIntelPayload(prev, { id: 'r', title: 'x' }).tags, prev.tags);
  assert.deepEqual(mergeReportIntelPayload(prev, { id: 'r', title: 'x' }).mitre_attack, prev.mitre_attack);
  assert.deepEqual(mergeReportIntelPayload(prev, { id: 'r', tags: [], mitre_attack: [] }).mitre_attack, []);
});

test('Overview renders Tags and MITRE without putting them on Source', () => {
  const pageSrc = readFileSync(path.join(here, 'ThreatLibraryReportPage.jsx'), 'utf8');
  assert.match(pageSrc, /data-testid="overview-tags"/);
  assert.match(pageSrc, /<ReportMitreSection/);
  assert.match(pageSrc, /mappings=\{report\.mitre_attack\}/);
  const source = pageSrc.slice(pageSrc.indexOf('view === REPORT_VIEWS.SOURCE'));
  assert.doesNotMatch(source, /ReportMitreSection|overview-tags/);
  assert.match(pageSrc, /<ReportTagsEditor[\s\S]*canWrite=\{canWrite\}/);
});

test('MITRE section hides when empty for read-only users and shows technique ids', () => {
  const src = readFileSync(path.join(here, 'ReportMitreSection.jsx'), 'utf8');
  assert.match(src, /if \(!items\.length && !canWrite\) return null;/);
  assert.match(src, /className="tl-mitre__id"/);
  assert.match(src, /data-technique-id=\{m\.technique_id\}/);
  assert.match(src, /max-height|tl-mitre/);
  assert.match(src, /Remove/);
  assert.match(src, /\+ Technique/);
});
