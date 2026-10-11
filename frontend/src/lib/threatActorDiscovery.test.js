import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  THREAT_ACTOR_DETAIL_BASE,
  threatActorDetailHref
} from './threatActorDiscovery.js';
import {
  THREAT_ACTOR_ACTIONS_COL_CLASS,
  THREAT_ACTOR_ACTION_BUTTONS_CLASS,
  THREAT_ACTOR_ACTIONS_COL_WIDTH_PX,
  THREAT_ACTOR_PAGE_CLASS
} from './threatActorTableDisplay.js';

test('threatActorDetailHref uses canonical actor UUID path', () => {
  assert.equal(
    threatActorDetailHref('e59f43dd-6d19-46a7-842c-b1a52ccd1717'),
    `${THREAT_ACTOR_DETAIL_BASE}/e59f43dd-6d19-46a7-842c-b1a52ccd1717`
  );
  assert.equal(threatActorDetailHref(''), null);
  assert.equal(threatActorDetailHref(null), null);
});

test('Threat Actors table exposes IOCS column and View IOCs action like Malware Families', () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const mainJsx = readFileSync(join(here, '../main.jsx'), 'utf8');
  assert.ok(mainJsx.includes('ta-col-iocs'));
  assert.ok(mainJsx.includes('>IOCs</th>') || mainJsx.includes('>IOCs<'));
  assert.ok(mainJsx.includes('threatActorDetailHref'));
  assert.ok(mainJsx.includes('View IOCs'));
  assert.ok(mainJsx.includes('formatAssociatedIocCount'));
  assert.ok(mainJsx.includes('associated_iocs'));
  assert.ok(mainJsx.includes('ThreatActorIocsPage'));
  assert.ok(mainJsx.includes('/threat-intelligence/threat-actors/:actorId'));
  assert.equal(THREAT_ACTOR_ACTIONS_COL_CLASS, 'ta-col-actions');
  assert.equal(THREAT_ACTOR_ACTION_BUTTONS_CLASS, 'ta-action-buttons');
  assert.ok(THREAT_ACTOR_ACTIONS_COL_WIDTH_PX >= 220);
  assert.ok(mainJsx.includes(THREAT_ACTOR_PAGE_CLASS));
  assert.ok(mainJsx.includes('width: ${THREAT_ACTOR_ACTIONS_COL_WIDTH_PX}px'));
  const buttonsCssStart = mainJsx.indexOf(`.${THREAT_ACTOR_PAGE_CLASS} .${THREAT_ACTOR_ACTION_BUTTONS_CLASS} {`);
  assert.ok(buttonsCssStart >= 0);
  const buttonsCss = mainJsx.slice(buttonsCssStart, buttonsCssStart + 280);
  assert.match(buttonsCss, /width:\s*100%/);
  assert.match(buttonsCss, /max-width:\s*100%/);
  assert.match(buttonsCss, /min-width:\s*0/);
  assert.match(buttonsCss, /flex-wrap:\s*wrap/);
});
