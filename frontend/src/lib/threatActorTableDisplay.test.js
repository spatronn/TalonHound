import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import {
  THREAT_ACTOR_ACTIONS_COL_CLASS,
  THREAT_ACTOR_ACTION_BUTTONS_CLASS,
  THREAT_ACTOR_ACTIONS_COL_WIDTH_PX,
  THREAT_ACTOR_ALIASES_CLAMP_CLASS,
  THREAT_ACTOR_DESCRIPTION_CLAMP_CLASS,
  THREAT_ACTOR_DESCRIPTION_TRUNCATE_MIN_CHARS,
  THREAT_ACTOR_PAGE_CLASS,
  THREAT_ACTOR_TABLE_CLASS,
  buildThreatActorDescriptionModalState,
  formatThreatActorAliasesCell,
  formatThreatActorDescriptionCell,
  threatActorDescriptionModalTitle
} from './threatActorTableDisplay.js';

const mainJsxPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '../main.jsx');
const mainJsx = readFileSync(mainJsxPath, 'utf8');

test('formatThreatActorDescriptionCell keeps empty placeholder', () => {
  const cell = formatThreatActorDescriptionCell('');
  assert.equal(cell.displayText, '—');
  assert.equal(cell.isPlaceholder, true);
  assert.equal(cell.expandable, false);
});

test('formatThreatActorDescriptionCell treats short descriptions as non-expandable', () => {
  const cell = formatThreatActorDescriptionCell('Short note.');
  assert.equal(cell.expandable, false);
  assert.equal(cell.fullText, 'Short note.');
});

test('formatThreatActorDescriptionCell marks long descriptions expandable', () => {
  const long = 'A'.repeat(THREAT_ACTOR_DESCRIPTION_TRUNCATE_MIN_CHARS + 1);
  const cell = formatThreatActorDescriptionCell(long);
  assert.equal(cell.expandable, true);
  assert.equal(cell.fullText, long);
});

test('buildThreatActorDescriptionModalState preserves full description text', () => {
  const description = `${'Long description. '.repeat(12).trim()}`;
  const modal = buildThreatActorDescriptionModalState({ name: 'APT28', description });
  assert.ok(modal);
  assert.equal(modal.name, 'APT28');
  assert.equal(modal.description, description);
});

test('formatThreatActorAliasesCell exposes full alias list in title', () => {
  const cell = formatThreatActorAliasesCell(['Fancy Bear', 'Sofacy', 'Pawn Storm']);
  assert.equal(cell.displayText, 'Fancy Bear, Sofacy, Pawn Storm');
  assert.equal(cell.title, cell.displayText);
});

test('threatActorDescriptionModalTitle falls back safely', () => {
  assert.equal(threatActorDescriptionModalTitle('APT29'), 'APT29');
  assert.equal(threatActorDescriptionModalTitle(''), 'Threat Actor');
});

test('ThreatActorManagerPage wires clamp classes and description modal', () => {
  assert.match(mainJsx, new RegExp(THREAT_ACTOR_TABLE_CLASS));
  assert.match(mainJsx, new RegExp(THREAT_ACTOR_DESCRIPTION_CLAMP_CLASS));
  assert.match(mainJsx, new RegExp(THREAT_ACTOR_ALIASES_CLAMP_CLASS));
  assert.match(mainJsx, /buildThreatActorDescriptionModalState/);
  assert.match(mainJsx, /disableActor\(actor\)/);
  assert.match(mainJsx, /openEditModal\(actor\)/);
  assert.match(mainJsx, /buildThreatActorManagerQueryParams/);
  assert.match(mainJsx, /Show inactive/);
});

test('Actions column layout contract keeps View IOCs + Edit + Disable inside a constrained flex cell', () => {
  assert.equal(THREAT_ACTOR_ACTIONS_COL_CLASS, 'ta-col-actions');
  assert.equal(THREAT_ACTOR_ACTION_BUTTONS_CLASS, 'ta-action-buttons');
  assert.ok(THREAT_ACTOR_ACTIONS_COL_WIDTH_PX >= 220);
  assert.ok(mainJsx.includes(THREAT_ACTOR_PAGE_CLASS));
  assert.ok(mainJsx.includes('width: ${THREAT_ACTOR_ACTIONS_COL_WIDTH_PX}px'));
  assert.ok(mainJsx.includes('ta-col-iocs'));
  assert.ok(mainJsx.includes('View IOCs'));
  assert.ok(mainJsx.includes('threatActorDetailHref'));
});
