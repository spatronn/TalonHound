import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { formatSourceObservation, SOURCE_OBSERVATION_TITLE } from './sourceObservation.js';

const here = path.dirname(fileURLToPath(import.meta.url));

test('labelled first/last seen render as the publisher observation (DD/MM/YYYY)', () => {
  assert.equal(
    formatSourceObservation({ earliest: '2023-05-25', latest: '2023-05-25', first_seen: '2023-05-25', last_seen: '2023-05-25' }),
    'Publisher observed 25/05/2023'
  );
  assert.equal(
    formatSourceObservation({ earliest: '2021-03-15', latest: '2021-03-18', first_seen: '2021-03-15', last_seen: '2021-03-18' }),
    'Publisher first seen 15/03/2021 · last seen 18/03/2021'
  );
  assert.equal(formatSourceObservation({ earliest: '2019-01-18', latest: '2019-01-18', first_seen: '2019-01-18', last_seen: null }), 'Publisher first seen 18/01/2019');
});

test('unlabelled row dates render as a window; no observation renders nothing', () => {
  assert.equal(formatSourceObservation({ earliest: '2020-06-29', latest: '2024-05-09' }), 'Publisher observed 29/06/2020 – 09/05/2024');
  assert.equal(formatSourceObservation(null), null);
  assert.equal(formatSourceObservation({}), null);
});

test('tooltip separates publisher observation from publication, import and current reputation', () => {
  assert.match(SOURCE_OBSERVATION_TITLE, /Not the report publication date and not the TalonHound import time/);
});

test('IOC Details Threat Context renders claim.source_observation', () => {
  const src = fs.readFileSync(path.join(here, 'IocThreatContextSection.jsx'), 'utf8');
  assert.match(src, /formatSourceObservation\(c\.source_observation\)/);
});
