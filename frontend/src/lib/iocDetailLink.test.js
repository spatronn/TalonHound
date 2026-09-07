import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  IOC_DETAIL_BASE,
  normalizeIocPublicId,
  iocDetailHref
} from './iocDetailLink.js';

test('base route matches the canonical IOC detail route', () => {
  assert.equal(IOC_DETAIL_BASE, '/ioc/details');
});

test('normalizeIocPublicId trims and stringifies, empty for absent', () => {
  assert.equal(normalizeIocPublicId('  abc  '), 'abc');
  assert.equal(normalizeIocPublicId(123), '123');
  assert.equal(normalizeIocPublicId(null), '');
  assert.equal(normalizeIocPublicId(undefined), '');
  assert.equal(normalizeIocPublicId('   '), '');
});

test('iocDetailHref builds the canonical, encoded href', () => {
  assert.equal(
    iocDetailHref('550e8400-e29b-41d4-a716-446655440000'),
    '/ioc/details/550e8400-e29b-41d4-a716-446655440000'
  );
});

test('iocDetailHref returns null when there is no usable public id', () => {
  assert.equal(iocDetailHref(null), null);
  assert.equal(iocDetailHref(undefined), null);
  assert.equal(iocDetailHref(''), null);
  assert.equal(iocDetailHref('   '), null);
});

// The href is addressed by public_id, so IOC *type* is irrelevant to link
// safety — but the id is still percent-encoded so no stray path-significant
// character can ever break the route, whatever the observable behind it was.
test('iocDetailHref percent-encodes path-significant characters', () => {
  assert.equal(iocDetailHref('a/b'), '/ioc/details/a%2Fb');
  assert.equal(iocDetailHref('id?x=1&y=2'), '/ioc/details/id%3Fx%3D1%26y%3D2');
  assert.equal(iocDetailHref('a#frag'), '/ioc/details/a%23frag');
  assert.equal(iocDetailHref('50%'), '/ioc/details/50%25');
  assert.equal(iocDetailHref('a b'), '/ioc/details/a%20b');
});

// Every supported IOC type reaches detail through the same public_id route,
// so a representative id for each still produces one valid, decodable href.
test('iocDetailHref works across IOC types via public_id', () => {
  for (const id of ['ip-1', 'domain-2', 'url-3', 'md5-4', 'sha1-5', 'sha256-6']) {
    const href = iocDetailHref(id);
    assert.equal(href, `/ioc/details/${id}`);
    assert.equal(decodeURIComponent(href.slice(IOC_DETAIL_BASE.length + 1)), id);
  }
});
