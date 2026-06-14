import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import {
  INCIDENTS_DEFAULT_SCOPE_WHERE,
  incidentMatchesDefaultScope
} from './incidentListScope.js';

const serverSource = readFileSync(
  path.join(path.dirname(fileURLToPath(import.meta.url)), '../server.js'),
  'utf8'
);

const DAY_MS = 24 * 60 * 60 * 1000;
const NOW = Date.parse('2026-06-14T21:00:00.000Z');

test('server uses updated_at based default scope for incidents list', () => {
  assert.match(serverSource, /INCIDENTS_DEFAULT_SCOPE_WHERE/);
  assert.doesNotMatch(
    serverSource,
    /if \(!fromStr && !toStr\) \{\s*where\.push\(`\(a\.status = 'open' OR a\.created_at >= NOW\(\) - INTERVAL '7 days'\)`\)/s
  );
  assert.match(serverSource, /where\.push\(INCIDENTS_DEFAULT_SCOPE_WHERE\)/);
  assert.match(INCIDENTS_DEFAULT_SCOPE_WHERE, /a\.updated_at >= NOW\(\) - INTERVAL '7 days'/);
});

test('closed incident with old created_at and recent updated_at matches default scope', () => {
  assert.equal(
    incidentMatchesDefaultScope(
      {
        status: 'closed',
        created_at: '2026-05-03T19:39:50.992Z',
        updated_at: '2026-06-14T18:33:07.017Z'
      },
      NOW
    ),
    true
  );
});

test('closed incident with old updated_at is excluded from default scope', () => {
  assert.equal(
    incidentMatchesDefaultScope(
      {
        status: 'closed',
        created_at: '2026-05-03T19:39:50.992Z',
        updated_at: '2026-05-10T10:00:00.000Z'
      },
      NOW
    ),
    false
  );
});

test('open incident with old created_at matches default scope', () => {
  assert.equal(
    incidentMatchesDefaultScope(
      {
        status: 'open',
        created_at: '2026-01-01T00:00:00.000Z',
        updated_at: '2026-01-02T00:00:00.000Z'
      },
      NOW
    ),
    true
  );
});

test('closed incident updated exactly at 7-day boundary matches default scope', () => {
  assert.equal(
    incidentMatchesDefaultScope(
      {
        status: 'closed',
        created_at: '2026-01-01T00:00:00.000Z',
        updated_at: new Date(NOW - 7 * DAY_MS).toISOString()
      },
      NOW
    ),
    true
  );
});
