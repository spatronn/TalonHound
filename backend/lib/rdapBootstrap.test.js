import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildTldBootstrapMap,
  joinRdapDomainUrl,
  publicSuffixForDomain
} from './rdapBootstrap.js';

test('joinRdapDomainUrl builds RFC-style domain path', () => {
  assert.equal(
    joinRdapDomainUrl('https://rdap.radix.host/rdap/', 'boatbeach.online'),
    'https://rdap.radix.host/rdap/domain/boatbeach.online'
  );
  assert.equal(
    joinRdapDomainUrl('https://rdap.verisign.com/com/v1/', 'example.com'),
    'https://rdap.verisign.com/com/v1/domain/example.com'
  );
});

test('publicSuffixForDomain uses registrable public suffix', () => {
  assert.equal(publicSuffixForDomain('boatbeach.online'), 'online');
  assert.equal(publicSuffixForDomain('example.co.uk'), 'co.uk');
});

test('buildTldBootstrapMap indexes TLD to base URLs', () => {
  const map = buildTldBootstrapMap({
    services: [
      [['online'], ['https://rdap.radix.host/rdap/']],
      [['com', 'net'], ['https://rdap.verisign.com/com/v1/']]
    ]
  });
  assert.deepEqual(map.get('online'), ['https://rdap.radix.host/rdap/']);
  assert.deepEqual(map.get('com'), ['https://rdap.verisign.com/com/v1/']);
});
