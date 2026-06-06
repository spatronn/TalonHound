import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const routeSource = readFileSync(
  path.join(path.dirname(fileURLToPath(import.meta.url)), '../routes/iocExport.js'),
  'utf8'
);

test('ioc export queries use ioc_tags junction and tags catalog', () => {
  assert.doesNotMatch(routeSource, /ioc_item_tags/);
  assert.match(routeSource, /FROM ioc_tags it/);
  assert.match(routeSource, /JOIN tags t ON t\.id = it\.tag_id/);
  assert.match(routeSource, /it\.ioc_id = i\.id/);
  assert.match(routeSource, /it\.ioc_observable_type = i\.observable_type/);
});
